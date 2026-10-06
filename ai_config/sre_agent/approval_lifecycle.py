"""Pause the actual guarded callable while the server owns the approval deadline."""
import asyncio
from contextvars import ContextVar
from asgiref.sync import sync_to_async
from django.utils import timezone
from .approvals import request_approval, approve, deny, expire, current_context, bind_approval_id

active_lifecycle = ContextVar('active_approval_lifecycle', default=None)

# Sync tools (terminal_execute, filesystem writes, ...) run in worker threads,
# and a ContextVar does not follow a call into a thread. Without this registry a
# guarded sync tool found no lifecycle, so an action that genuinely needed
# operator approval raised a bare PermissionError instead of opening the prompt:
# the operator saw "action denied" and no Allow/Deny dialog.
_BY_SESSION: dict = {}


def register_session_lifecycle(session_id, lifecycle):
    if not session_id or lifecycle is None:
        return
    _BY_SESSION[str(session_id)] = lifecycle


def unregister_session_lifecycle(session_id, lifecycle=None):
    key = str(session_id or '')
    if key and (lifecycle is None or _BY_SESSION.get(key) is lifecycle):
        _BY_SESSION.pop(key, None)


def resolve_lifecycle():
    """The lifecycle for this call: the contextvar first, then the session."""
    lifecycle = active_lifecycle.get()
    if lifecycle is not None:
        return lifecycle
    try:
        from .approvals import current_context
        session_id = (current_context() or {}).get('session_id')
    except Exception:
        session_id = None
    if not session_id:
        return None
    return _BY_SESSION.get(str(session_id))

class ApprovalStopped(asyncio.CancelledError):
    """Raised when the operator denies an action.

    Carries the ending so the run can be persisted as a denial instead of a
    generic cancellation, which is what left denied turns empty on reload.
    """

    def __init__(self, message: str = "", ending: str = "denied"):
        super().__init__(message or ending)
        self.ending = ending

class ApprovalLifecycle:
    def __init__(self, send):
        self.send = send
        self.loop = asyncio.get_running_loop()
        self.lock = asyncio.Lock()
        self.pending = None

    async def authorize(self, meta, args):
        async with self.lock:
            ctx = current_context()
            if not ctx.get('user_id') or ctx['user_id'] == 'anonymous':
                raise PermissionError('Authenticated approval required')
            obj = await sync_to_async(request_approval)(session_id=ctx['session_id'],
                user_id=ctx['user_id'], tool_name=meta.name, args=args, risk=str(int(meta.risk_level)),
                reason='This action requires operator approval.')
            future = self.loop.create_future()
            self.pending = (obj, future)
            await self.send({'type':'approval_required', 'status':'awaiting_approval',
                'approval_id':obj.pk, 'request_id':obj.request_id, 'tool':meta.name,
                'args':obj.arguments_preview, 'risk':obj.risk, 'content':obj.reason,
                'expires_at':obj.expires_at.isoformat(), 'session_id':obj.session_id})
            try:
                remaining = max(0, (obj.expires_at-timezone.now()).total_seconds())
                # A replacement socket can write the same durable decision.
                # Poll only while an approval is pending, bounded by its original deadline.
                allowed = False
                while remaining > 0:
                    try:
                        allowed = await asyncio.wait_for(asyncio.shield(future), min(1.0, remaining))
                        break
                    except asyncio.TimeoutError:
                        await sync_to_async(obj.refresh_from_db)()
                        if obj.status != 'pending':
                            break
                        remaining = max(0, (obj.expires_at-timezone.now()).total_seconds())
                kwargs = dict(session_id=obj.session_id, user_id=obj.user_id)
                if obj.status != 'pending':
                    result = obj
                elif obj.expires_at <= timezone.now():
                    result = await sync_to_async(expire)(obj.pk, **kwargs)
                elif allowed:
                    result = await sync_to_async(approve)(obj.pk, **kwargs)
                else:
                    result = await sync_to_async(deny)(obj.pk, **kwargs)
                await self.send({'type':'approval_approved' if result.status == 'approved' else result.status,
                                 'status':result.status, 'approval_id':obj.pk, 'content':result.status})
                if result.status != 'approved':
                    ending = 'denied_timeout' if result.status == 'denied_timeout' else 'denied'
                    raise ApprovalStopped(ending)
                return obj.pk
            finally:
                self.pending = None

    def decide(self, data, user_id):
        if not self.pending:
            return False
        obj, future = self.pending
        if (str(data.get('approval_id')) != str(obj.pk) or
            str(data.get('session_id')) != str(obj.session_id) or
            str(user_id) != str(obj.user_id) or future.done()):
            return False
        future.set_result(data.get('approved') is True)
        return True

async def enforce_async(meta, args):
    from .approvals import consume_for
    try:
        return await sync_to_async(consume_for)(meta, args)
    except PermissionError as exc:
        lifecycle = resolve_lifecycle()
        if not str(exc).startswith('approval_required:') or lifecycle is None:
            raise
        approval_id = await lifecycle.authorize(meta, args)
        bind_approval_id(approval_id)
        return await sync_to_async(consume_for)(meta, args)

def enforce_sync(meta, args):
    from .approvals import consume_for
    lifecycle = resolve_lifecycle()
    if lifecycle is None:
        return consume_for(meta, args)
    if lifecycle.loop is asyncio._get_running_loop():
        raise PermissionError('Synchronous tool must run in a worker')
    future = asyncio.run_coroutine_threadsafe(enforce_async(meta, args), lifecycle.loop)
    try:
        return future.result()
    except __import__('concurrent.futures', fromlist=['CancelledError']).CancelledError:
        raise ApprovalStopped()
