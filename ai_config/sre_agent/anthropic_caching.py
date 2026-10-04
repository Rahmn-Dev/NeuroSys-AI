"""Anthropic prompt-caching wiring (explicit 5-minute breakpoints).

The installed langchain-anthropic (0.3.x) has no automatic-caching switch, so
this module marks the end of the static prefix explicitly:

* system blocks      -> cache_control ephemeral (the big stable instructions)
* tool definitions   -> cached by the API as part of the prefix automatically

Cache prefixes must be byte-identical to hit. Dynamic tails (the user goal,
fresh tool results) stay outside the cached prefix by construction.

Verified live: marker + >4096 prompt tokens -> second identical-prefix call
reads from cache (cache_read_input_tokens > 0, fresh input ~14 tokens).

Savings (Haiku 4.5): cache reads 0.1x base input; writes 1.25x.
Minimum cacheable length for Haiku 4.5 is 4096 tokens — smaller calls simply
skip caching without errors.
"""
from __future__ import annotations


CACHE_MARKER = {"type": "ephemeral"}

# Skip marking tiny prompts where bookkeeping outweighs any gain.
MIN_CACHEABLE_CHARS = 8000


def mark_system_blocks(messages):
    """Add a cache breakpoint at the end of system content.

    Pure function (unit-testable). Non-list inputs pass through untouched.
    str system content becomes a single marked text block; existing list
    content gets the marker on its last text block.
    """
    if not isinstance(messages, list):
        return messages
    out = []
    for msg in messages:
        content = getattr(msg, "content", None)
        if getattr(msg, "type", "") != "system" or content is None:
            out.append(msg)
            continue
        if isinstance(content, str):
            if len(content) < MIN_CACHEABLE_CHARS:
                out.append(msg)
                continue
            try:
                out.append(msg.model_copy(update={"content": [
                    {"type": "text", "text": content, "cache_control": dict(CACHE_MARKER)},
                ]}))
            except Exception:
                out.append(msg)
            continue
        if isinstance(content, list) and content:
            blocks = [dict(b) if isinstance(b, dict) else b for b in content]
            for block in reversed(blocks):
                if isinstance(block, dict) and block.get("type") == "text":
                    block["cache_control"] = dict(CACHE_MARKER)
                    break
            try:
                out.append(msg.model_copy(update={"content": blocks}))
            except Exception:
                out.append(msg)
            continue
        out.append(msg)
    return out


def build_caching_anthropic(*args, **kwargs):
    """Build a ChatAnthropic that marks system prefixes + tracks spend.

    Returns the client; call ``client.get_usage_summary()`` for
    ``{calls, input_tokens, output_tokens, cache_read, cache_write}``.
    Marking lives in subclass overrides so it survives ``bind_tools``.
    """
    from langchain_anthropic import ChatAnthropic

    usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
             "cache_read": 0, "cache_write": 0}

    def _tally(response):
        try:
            raw = (getattr(response, "response_metadata", {}) or {}).get("usage", {}) or {}
            usage["calls"] += 1
            usage["input_tokens"] += int(raw.get("input_tokens", 0) or 0)
            usage["output_tokens"] += int(raw.get("output_tokens", 0) or 0)
            usage["cache_read"] += int(raw.get("cache_read_input_tokens", 0) or 0)
            usage["cache_write"] += int(raw.get("cache_creation_input_tokens", 0) or 0)
        except Exception:
            pass

    class _CachingChatAnthropic(ChatAnthropic):
        async def ainvoke(self, input_data, *a, **k):
            response = await super().ainvoke(mark_system_blocks(input_data), *a, **k)
            _tally(response)
            return response

        def invoke(self, input_data, *a, **k):
            response = super().invoke(mark_system_blocks(input_data), *a, **k)
            _tally(response)
            return response

        def bind_tools(self, *a, **k):
            bound = super().bind_tools(*a, **k)
            object.__setattr__(bound, "get_usage_summary", lambda: dict(usage))
            return bound

    client = _CachingChatAnthropic(*args, **kwargs)
    object.__setattr__(client, "get_usage_summary", lambda: dict(usage))
    return client
