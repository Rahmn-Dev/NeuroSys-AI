"""Bounded provider invocation shared by adapters and deterministic backtests."""
import asyncio
import itertools
import threading
from dataclasses import dataclass
from typing import Awaitable, Callable, Any

from .canonical_lifecycle import normalize_provider_error


_ROUND_ROBIN_COUNTER = itertools.count()
_ROUND_ROBIN_LOCK = threading.Lock()


def next_round_robin_start(size: int) -> int:
    if size <= 0:
        raise ValueError("round-robin requires at least one model")
    with _ROUND_ROBIN_LOCK:
        return next(_ROUND_ROBIN_COUNTER) % size


def is_model_failover_error(exc: Exception) -> bool:
    error = normalize_provider_error(exc)
    # The caller invokes this only for an exception raised by one configured
    # model. With Auto Models enabled, treat provider-level failures (including
    # auth/configuration and malformed responses) as candidate-local and try
    # the next active model/provider. Cancellation is a BaseException and does
    # not enter this path.
    return error["category"] in {
        "auth", "quota", "rate_limit", "transient", "context_overflow",
        "malformed", "provider_error",
    }


def model_failover_reason(exc: Exception) -> str:
    text = str(exc).lower()
    if any(term in text for term in (
        "freetiererror", "free tier can only be used", "only be used from within",
    )):
        return "model_restricted"
    if any(term in text for term in (
        "archived and unavailable", "unavailable for the organization",
        "model is archived", "model has been archived", "no longer available",
        "unknown model", "model does not exist",
    )):
        return "model_unavailable"
    return normalize_provider_error(exc)["category"]


class RoundRobinChatModel:
    """Runnable-compatible pool that fails over across configured providers."""
    def __init__(self, candidates, *, start_index=0, state=None, on_switch=None):
        if not candidates:
            raise ValueError("No compatible active models are available for automatic rotation")
        self.candidates = list(candidates)
        self._state = state or {"index": start_index % len(self.candidates), "lock": threading.RLock()}
        self.on_switch = on_switch

    @property
    def active_label(self):
        return self.candidates[self._state["index"]][0]

    def _order(self):
        start = self._state["index"] % len(self.candidates)
        return [(start + offset) % len(self.candidates) for offset in range(len(self.candidates))]

    def _switch(self, previous, next_index, error):
        with self._state["lock"]:
            self._state["index"] = next_index
        if self.on_switch and previous != next_index:
            self.on_switch({"from": self.candidates[previous][0], "to": self.candidates[next_index][0],
                            "reason": model_failover_reason(error)})

    @staticmethod
    def _pool_exhausted(error, count):
        exhausted = ModelPoolExhausted(error, count)
        raise exhausted from error

    def bind_tools(self, tools, **kwargs):
        bound = [(label, model.bind_tools(tools, **kwargs)) for label, model in self.candidates]
        return RoundRobinChatModel(bound, state=self._state, on_switch=self.on_switch)

    def with_config(self, config):
        configured = [(label, model.with_config(config)) for label, model in self.candidates]
        return RoundRobinChatModel(configured, state=self._state, on_switch=self.on_switch)

    def invoke(self, input, *args, **kwargs):
        order, last = self._order(), None
        for position, index in enumerate(order):
            try:
                result = self.candidates[index][1].invoke(input, *args, **kwargs)
                self._state["index"] = index
                return result
            except Exception as exc:
                last = exc
                if not is_model_failover_error(exc) or position == len(order) - 1:
                    self._pool_exhausted(exc, len(order))
                self._switch(index, order[position + 1], exc)
        self._pool_exhausted(last or RuntimeError("Unknown provider failure"), len(order))

    async def ainvoke(self, input, *args, **kwargs):
        order, last = self._order(), None
        for position, index in enumerate(order):
            try:
                result = await self.candidates[index][1].ainvoke(input, *args, **kwargs)
                self._state["index"] = index
                return result
            except Exception as exc:
                last = exc
                if not is_model_failover_error(exc) or position == len(order) - 1:
                    self._pool_exhausted(exc, len(order))
                self._switch(index, order[position + 1], exc)
        self._pool_exhausted(last or RuntimeError("Unknown provider failure"), len(order))

    async def astream(self, input, *args, **kwargs):
        order, last = self._order(), None
        for position, index in enumerate(order):
            emitted = False
            try:
                async for chunk in self.candidates[index][1].astream(input, *args, **kwargs):
                    emitted = True
                    yield chunk
                self._state["index"] = index
                return
            except Exception as exc:
                last = exc
                # Once content reached the caller it cannot safely be replayed
                # from another provider without duplicating the response.
                if emitted:
                    self._pool_exhausted(exc, position + 1)
                if not is_model_failover_error(exc) or position == len(order) - 1:
                    self._pool_exhausted(exc, len(order))
                self._switch(index, order[position + 1], exc)
        self._pool_exhausted(last or RuntimeError("Unknown provider failure"), len(order))


class ModelPoolExhausted(RuntimeError):
    """Signals that every configured candidate was tried; don't repeat pool."""

    no_retry = True

    def __init__(self, last_error, attempted):
        self.last_error = last_error
        self.attempted = attempted
        super().__init__(f"All {attempted} configured model(s) failed; last provider error: {last_error}")


@dataclass(frozen=True)
class ProviderPolicy:
    providers: tuple[str, ...]
    max_attempts: int = 3
    allow_fallback: bool = True


async def invoke_provider_chain(callers: dict[str, Callable[[], Awaitable[Any]]], policy: ProviderPolicy,
                                *, lifecycle=None, context: dict | None = None) -> tuple[str, Any]:
    """Try one provider at a time; checkpoint before policy-approved fallback."""
    last = None
    for index, provider in enumerate(policy.providers):
        if provider not in callers:
            raise RuntimeError(f"unknown provider: {provider}")
        try:
            value = await invoke_with_retry(callers[provider], max_attempts=policy.max_attempts)
            return provider, value
        except Exception as exc:
            last = exc
            error = normalize_provider_error(exc)
            if not policy.allow_fallback or not error["retryable"] or index == len(policy.providers) - 1:
                raise
            if lifecycle is not None:
                await lifecycle.atransition("provider", "paused", "provider_fallback", {
                    "from": provider, "to": policy.providers[index + 1], "error": error["category"],
                    "context_keys": sorted((context or {}).keys()),
                })
    raise last or RuntimeError("provider chain exhausted")


async def invoke_with_retry(call: Callable[[], Awaitable[Any]], *, max_attempts: int = 3,
                            base_delay: float = 0.05, cancel_event: asyncio.Event | None = None,
                            on_retry: Callable[[dict, int], Any] | None = None) -> Any:
    """Retry transient/rate-limit/malformed failures only, with bounded backoff."""
    attempt = 0
    while True:
        if cancel_event and cancel_event.is_set():
            raise asyncio.CancelledError()
        attempt += 1
        try:
            return await call()
        except Exception as exc:
            if getattr(exc, "no_retry", False):
                raise
            error = normalize_provider_error(exc)
            if not error["retryable"] or attempt >= max_attempts:
                raise
            if on_retry:
                result = on_retry(error, attempt)
                if hasattr(result, "__await__"):
                    await result
            await asyncio.sleep(base_delay * (2 ** (attempt - 1)))


def invoke_sync_with_retry(call, *, max_attempts=3, base_delay=0.05):
    """Retry a selected provider without changing provider/model identity."""
    import time
    for attempt in range(max(1, min(max_attempts, 3))):
        try:
            return call()
        except Exception as exc:
            if getattr(exc, "no_retry", False):
                raise
            if not normalize_provider_error(exc)['retryable'] or attempt >= min(max_attempts, 3) - 1:
                raise
            time.sleep(min(1, base_delay * (2 ** attempt)))
