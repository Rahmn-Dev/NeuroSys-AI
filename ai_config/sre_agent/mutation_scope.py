"""Canonical-run mutation serialization shared by all registered tool adapters."""
import time
from contextlib import contextmanager, asynccontextmanager
from contextvars import ContextVar
from asgiref.sync import sync_to_async
from django.db import IntegrityError
from .resource_locks import ResourceLockManager, ResourceConflict

active_run = ContextVar('canonical_execution_run', default=None)


def claim_mutation(meta, args):
    from .security_boundary import evaluate
    run = active_run.get()
    if run is None or evaluate(meta, args)[0] == 'approved':
        return None
    manager = ResourceLockManager()
    deadline = time.monotonic() + 5
    while True:
        try:
            return manager.claim_db(run=run, task_key=meta.name,
                resource='canonical:mutations', lease_seconds=330).lease_token
        except (ResourceConflict, IntegrityError):
            if time.monotonic() >= deadline:
                raise ResourceConflict('Mutation resource is busy; no action was executed')
            time.sleep(0.05)


@contextmanager
def mutation_scope(meta, args):
    lease = claim_mutation(meta, args)
    try:
        yield
    finally:
        if lease:
            ResourceLockManager().release_db(lease)


@asynccontextmanager
async def async_mutation_scope(meta, args):
    lease = await sync_to_async(claim_mutation)(meta, args)
    try:
        yield
    finally:
        if lease:
            await sync_to_async(ResourceLockManager().release_db)(lease)
