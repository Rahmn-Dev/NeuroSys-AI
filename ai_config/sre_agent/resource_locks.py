"""Bounded resource locking and idempotency for concurrent workers."""
from __future__ import annotations
import asyncio
import hashlib
import time
import uuid
from datetime import timedelta
from contextlib import asynccontextmanager
from django.db import transaction
from django.utils import timezone


class ResourceConflict(RuntimeError):
    pass


class ResourceLockManager:
    def __init__(self, max_concurrency: int = 5):
        self._locks: dict[str, asyncio.Lock] = {}
        self._guard = asyncio.Lock()
        self._seen: set[str] = set()
        self._semaphore = asyncio.Semaphore(max_concurrency)

    def idempotency_key(self, resource: str, action: str, args: dict) -> str:
        raw = f"{resource}|{action}|{sorted(args.items())}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @asynccontextmanager
    async def acquire(self, resource: str, *, timeout: float = 5.0):
        async with self._guard:
            lock = self._locks.setdefault(resource, asyncio.Lock())
        try:
            await asyncio.wait_for(lock.acquire(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise ResourceConflict(f"resource busy: {resource}") from exc
        try:
            async with self._semaphore:
                yield
        finally:
            lock.release()

    def mark_once(self, key: str) -> bool:
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def clear(self):
        self._seen.clear()

    def claim_db(self, *, run, task_key: str, resource: str, lease_seconds: int = 30):
        """Claim a durable lease; stale leases are reclaimable."""
        from chatbot.models import AgentResourceLock
        token = uuid.uuid4().hex
        with transaction.atomic():
            existing = AgentResourceLock.objects.select_for_update().filter(resource_key=resource).first()
            if existing and existing.expires_at > timezone.now():
                raise ResourceConflict(f"resource busy: {resource}")
            if existing:
                existing.run = run; existing.task_key = task_key; existing.lease_token = token
                existing.expires_at = timezone.now() + timedelta(seconds=lease_seconds)
                existing.save(update_fields=["run", "task_key", "lease_token", "expires_at"])
                return existing
            return AgentResourceLock.objects.create(
                run=run, task_key=task_key, resource_key=resource, lease_token=token,
                expires_at=timezone.now() + timedelta(seconds=lease_seconds))

    def release_db(self, lease_token: str) -> None:
        from chatbot.models import AgentResourceLock
        AgentResourceLock.objects.filter(lease_token=lease_token).delete()
