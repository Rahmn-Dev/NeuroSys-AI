"""Transactional, exact-match approvals for controlled and full-access modes."""
import hashlib
import json
import uuid
import re
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import timedelta
from django.db import transaction
from django.utils import timezone
from django.conf import settings
from chatbot.models import AgentApproval
from .security_boundary import audit, evaluate, _sensitive_read_path

_CTX = ContextVar("neurosys_approval_context", default={})

def canonical_args(args):
    return json.dumps(args or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def args_hash(args):
    return hashlib.sha256(canonical_args(args).encode()).hexdigest()

def _preview(args):
    # UI gets enough to identify the action, never credentials or full payloads.
    # Commands and paths can contain arbitrary positional secrets; do not echo them.
    return {"keys": sorted((args or {}).keys()), "target": "[redacted action arguments]"}


def derive_goal_scope(goal, workspace=""):
    """Derive a small exact-action scope from explicit, unambiguous user wording.

    This is deliberately not an LLM decision. Arbitrary shell execution and
    credential-bearing actions are never placed in Full Access scope.

    When the goal explicitly asks for file output (a report, a new file, an
    edit), writes confined to the active workspace are pre-authorized so the
    agent can finish read-only investigations without a human click per file.
    Only absolute paths inside the workspace qualify; anything else still
    requires an explicit approval.
    """
    text = str(goal or "").strip()
    candidates = []
    service = re.search(r"\b(start|stop|restart)\s+(?:service\s+)?([A-Za-z0-9_][A-Za-z0-9_.@-]*)\b", text, re.I)
    if service:
        candidates.append(("service_manager", {
            "action": service.group(1).lower(), "service_name": service.group(2)
        }))
    package = re.search(r"\b(install|remove|upgrade)\s+(?:package\s+)?([A-Za-z0-9_][A-Za-z0-9_.+-]*)\b", text, re.I)
    if package:
        candidates.append(("package_manager", {
            "action": package.group(1).lower(), "package": package.group(2)
        }))
    scope = []
    for tool_name, args in candidates:
        meta = type("Meta", (), {"name": tool_name, "risk_level": 3, "required_permission": "sudo"})()
        if evaluate(meta, args)[0] != "blocked":
            scope.append({"tool": tool_name, "args_hash": args_hash(args)})
    ws = str(workspace or "").strip()
    if ws and re.search(
        r"\b(tulis|tuliskan|buatkan|buat|buatlah|simpan|simpanlah|ubah|edit|laporan|report|write|create|generate)\b",
        text, re.I,
    ):
        from pathlib import Path as _Path
        try:
            resolved_ws = str(_Path(ws).expanduser().resolve())
        except Exception:
            resolved_ws = ""
        if resolved_ws and resolved_ws not in {"", "/"}:
            for tool_name in ("write_file", "edit_file"):
                scope.append({"tool": tool_name, "path_prefix": resolved_ws})
    return scope

@contextmanager
def execution_context(session_id, user_id, mode="controlled", scope=None, goal="", approval_id=None):
    token = _CTX.set({"session_id": str(session_id), "user_id": str(user_id),
                      "mode": mode, "scope": scope or [], "goal": goal,
                      "approval_id": approval_id})
    try:
        yield
    finally:
        _CTX.reset(token)

def current_context():
    return _CTX.get()


def full_access_auto_approves() -> bool:
    """True when the bound context is Full Access with auto-approve enabled.

    This is the user-facing on/off switch for the approval layer:
    per-user mode (`full_access`) AND the global
    `AGENT_FULL_ACCESS_AUTO_APPROVE` setting must both allow it.
    Hard blocks are NOT affected — they are evaluated before this helper
    is ever consulted.
    """
    ctx = current_context()
    if ctx.get("mode") != "full":
        return False
    try:
        return bool(getattr(settings, "AGENT_FULL_ACCESS_AUTO_APPROVE", True))
    except Exception:
        return True

def bind_context(session_id, user_id, mode="controlled", scope=None, goal=""):
    """Bind execution authorization to the current async task."""
    return _CTX.set({"session_id": str(session_id), "user_id": str(user_id),
                     "mode": mode, "scope": scope or [], "goal": goal,
                     "approval_id": None})

def bind_approval_id(approval_id):
    context = dict(current_context())
    context["approval_id"] = approval_id
    return _CTX.set(context)

def request_approval(*, session_id, user_id, tool_name, args, risk="high", reason="", correlation_id=None):
    check = evaluate(type("Meta", (), {"name": tool_name, "risk_level": 3,
                                        "required_permission": ""})(), args)
    if check[0] == "blocked":
        raise PermissionError(check[1])
    request_id = uuid.uuid4().hex
    obj = AgentApproval.objects.create(
        session_id=str(session_id), user_id=str(user_id), tool_name=tool_name,
        request_id=request_id, correlation_id=correlation_id or request_id,
        arguments_hash=args_hash(args), arguments_preview=_preview(args), risk=risk,
        reason=reason, expires_at=timezone.now() + timedelta(seconds=getattr(settings, "AGENT_APPROVAL_TIMEOUT_SECONDS", 30)))
    audit("approval_requested", tool_name, "pending", request_id,
          request_id=request_id, approval_id=obj.id, session_id=session_id,
          user_id=user_id, risk=risk)
    return obj

def approve(approval_id, *, session_id, user_id):
    with transaction.atomic():
        obj = AgentApproval.objects.select_for_update().get(pk=approval_id)
        if str(obj.session_id) != str(session_id) or str(obj.user_id) != str(user_id):
            audit("approval_denied", obj.tool_name, "identity_mismatch", str(obj.id))
            raise PermissionError("Approval identity mismatch")
        if obj.status != "pending" or obj.expires_at <= timezone.now():
            obj.status = "expired" if obj.expires_at <= timezone.now() else obj.status
            obj.save(update_fields=["status"])
            audit("approval_expired", obj.tool_name, obj.status, str(obj.id))
            raise PermissionError("Approval is no longer pending")
        obj.status, obj.approved_at = "approved", timezone.now()
        obj.save(update_fields=["status", "approved_at"])
        audit("approval_approved", obj.tool_name, "approved", obj.correlation_id,
              request_id=obj.request_id, approval_id=obj.id, session_id=session_id,
              user_id=user_id, risk=obj.risk)
        return obj

def _reject(approval_id, *, session_id, user_id, timeout=False):
    with transaction.atomic():
        obj = AgentApproval.objects.select_for_update().get(pk=approval_id)
        if str(obj.session_id) != str(session_id) or str(obj.user_id) != str(user_id):
            raise PermissionError("Approval identity mismatch")
        if obj.status != "pending":
            raise PermissionError("Approval is no longer pending")
        if timeout and obj.expires_at > timezone.now():
            raise PermissionError("Approval has not expired")
        obj.status = "denied_timeout" if timeout or obj.expires_at <= timezone.now() else "denied"
        obj.save(update_fields=["status"])
    audit("approval_auto_denied" if obj.status == "denied_timeout" else "approval_denied",
          obj.tool_name, obj.status, obj.correlation_id, request_id=obj.request_id,
          approval_id=obj.id, session_id=session_id, user_id=user_id, risk=obj.risk)
    return obj

def deny(approval_id, *, session_id, user_id):
    return _reject(approval_id, session_id=session_id, user_id=user_id)

def expire(approval_id, *, session_id, user_id):
    return _reject(approval_id, session_id=session_id, user_id=user_id, timeout=True)

def _scope_allows(ctx, tool_name, args):
    if tool_name in {"terminal_session", "start_background_process", "safe_execute", "execute_command"}:
        return False
    if evaluate(type("Meta", (), {"name": tool_name, "risk_level": 3,
                                   "required_permission": ""})(), args)[0] == "blocked":
        return False
    wanted = {"tool": tool_name, "args_hash": args_hash(args)}
    for item in ctx.get("scope", []):
        if item == wanted or (item.get("tool") == tool_name and
                              item.get("args_hash") == wanted["args_hash"]):
            return True
        # Workspace-confined file writes: only absolute paths strictly inside
        # the pre-authorized prefix, never credential/secret paths.
        prefix = item.get("path_prefix")
        if prefix and item.get("tool") == tool_name and tool_name in {"write_file", "edit_file"}:
            from pathlib import Path as _Path
            target = str((args or {}).get("path") or (args or {}).get("file_path")
                         or (args or {}).get("target_file") or (args or {}).get("file") or "")
            if not target.startswith("/"):
                continue
            try:
                resolved = _Path(target).expanduser().resolve()
                base = _Path(prefix).expanduser().resolve()
            except Exception:
                continue
            if resolved.is_relative_to(base) and not _sensitive_read_path(resolved):
                return True
    return False

def consume_for(meta, args):
    """Return a call id or raise; approval consumption is atomic and single-use."""
    ctx = current_context()
    call_id = __import__("uuid").uuid4().hex
    if meta.name in {"terminal_execute", "terminal_session", "start_background_process"}:
        command = str(args.get("command", ""))
        if __import__("re").search(r"(?:rm\s+-rf\s+/|mkfs\b|dd\s+if=/dev/|shutdown\b|reboot\b|curl\s+[^|]+\|\s*(?:ba)?sh|/etc/shadow|\.env\b|private[_ -]?key|password|secret|token)", command, __import__("re").I):
            audit("tool_decision", meta.name, "hard_block", call_id)
            raise PermissionError("blocked: destructive command")
    verdict, reason = evaluate(meta, args)
    if verdict == "blocked":
        audit("tool_decision", meta.name, "hard_block", call_id)
        raise PermissionError("blocked: " + reason)
    if verdict == "approved":
        audit("tool_decision", meta.name, "approved", call_id)
        return call_id
    if full_access_auto_approves():
        # Full Access: the user pre-authorized non-blocked actions. The
        # decision and its scope are audited; nothing is sent for approval.
        audit("tool_decision", meta.name, "full_access_auto_approved", call_id)
        return call_id
    if ctx.get("mode") == "full" and _scope_allows(ctx, meta.name, args):
        audit("tool_decision", meta.name, "full_scope_approved", call_id)
        return call_id
    approval_id = ctx.get("approval_id")
    if not approval_id:
        audit("approval_required", meta.name, "approval_required")
        raise PermissionError("approval_required: action needs Allow Once")
    expired = False
    mismatch = False
    with transaction.atomic():
        obj = AgentApproval.objects.select_for_update().get(pk=approval_id)
        if (obj.status != "approved" or obj.expires_at <= timezone.now() or
            str(obj.session_id) != str(ctx.get("session_id")) or
            str(obj.user_id) != str(ctx.get("user_id")) or
            obj.tool_name != meta.name or obj.arguments_hash != args_hash(args)):
            if obj.expires_at <= timezone.now() and obj.status == "approved":
                obj.status = "expired"; obj.save(update_fields=["status"])
                audit("approval_expired", meta.name, "expired", str(obj.id))
                expired = True
            else:
                audit("approval_denied", meta.name, "mismatch", str(obj.id))
                mismatch = True
        else:
            obj.status, obj.consumed_at = "consumed", timezone.now()
            obj.save(update_fields=["status", "consumed_at"])
    if expired:
        raise PermissionError("approval mismatch or expired")
    if mismatch:
        raise PermissionError("approval mismatch or expired")
    if obj.status != "consumed":
        raise PermissionError("approval mismatch or expired")
    audit("approval_consumed", meta.name, "consumed", obj.correlation_id,
          request_id=obj.request_id, approval_id=obj.id,
          session_id=ctx.get("session_id"), user_id=ctx.get("user_id"), risk=obj.risk)
    return call_id
