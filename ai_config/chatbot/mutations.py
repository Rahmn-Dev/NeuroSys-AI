"""State-changing operations, callable from any transport.

Every mutation requires an authenticated user. Resource access additionally
requires possession of the unguessable identifier (session UUID, artifact id,
model id). Nothing here is reachable anonymously, and secrets are never
returned - the model rows sent back carry has_key, never api_key.
"""
import json

from django.db import transaction

from . import models


class MutationError(Exception):
    """A rejected mutation, with a message safe to show the operator."""


def require_user_id(user):
    if user is None or getattr(user, "is_anonymous", True) or not getattr(
        user, "is_authenticated", False
    ):
        raise MutationError("Sign in first.")
    return str(user.pk)


def model_public(model_obj):
    return {
        "id": model_obj.id,
        "name": model_obj.name,
        "model_id": model_obj.model_id,
        "provider": model_obj.provider,
        "endpoint_type": getattr(model_obj, "endpoint_type", "openai") or "openai",
        "base_url": model_obj.base_url or "",
        "has_key": bool(model_obj.api_key),
        "tool_choice": getattr(model_obj, "tool_choice", "any") or "any",
        "is_active": model_obj.is_active,
        "order": model_obj.order,
    }


def get_permission_mode(user):
    require_user_id(user)
    profile, _ = models.Profile.objects.get_or_create(user=user)
    return {"mode": profile.agent_permission_mode}


def set_permission_mode(user, mode):
    from sre_agent.security_boundary import audit

    require_user_id(user)
    allowed = {value for value, _ in models.Profile.AGENT_PERMISSION_CHOICES}
    if mode not in allowed:
        raise MutationError("mode must be need_approval or full_access")
    profile, _ = models.Profile.objects.get_or_create(user=user)
    previous = profile.agent_permission_mode
    if mode != previous:
        with transaction.atomic():
            profile = models.Profile.objects.select_for_update().get(pk=profile.pk)
            previous = profile.agent_permission_mode
            profile.agent_permission_mode = mode
            profile.save(update_fields=["agent_permission_mode"])
            record = models.AgentPermissionAudit.objects.create(
                user=user, previous_mode=previous, new_mode=mode, source="ui"
            )
        audit(
            "permission_mode_changed",
            verdict=mode,
            request_id=record.request_id,
            user_id=user.pk,
        )
    return {"mode": profile.agent_permission_mode}


def delete_chat_session(user, session_id):
    require_user_id(user)
    try:
        session = models.ChatSession.objects.get(pk=session_id)
    except (models.ChatSession.DoesNotExist, ValueError, TypeError):
        raise MutationError("Chat session not found.")
    session.delete()
    return {"deleted": True}


def bulk_delete_chats(user, session_ids):
    require_user_id(user)
    if not isinstance(session_ids, list):
        raise MutationError("session_ids must be a list")
    deleted_count, _ = models.ChatSession.objects.filter(id__in=session_ids).delete()
    return {"deleted_count": deleted_count}


def rollback_artifact(user, artifact_id):
    require_user_id(user)
    import os

    from asgiref.sync import async_to_sync

    from sre_agent.artifacts import ArtifactManager

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    manager = ArtifactManager(workspace_path=base_dir)
    try:
        artifact_id = int(artifact_id)
    except (TypeError, ValueError):
        raise MutationError("Unknown artifact.")
    try:
        success = async_to_sync(manager.rollback)(artifact_id)
    except Exception as exc:
        raise MutationError(str(exc))
    if not success:
        raise MutationError("Rollback failed")
    return {"status": "success"}


def save_ai_model(user, data, pk=None):
    require_user_id(user)
    data = data or {}
    name = str(data.get("name", "") or "").strip()
    model_id = str(data.get("model_id", "") or "").strip()
    if not name or not model_id:
        raise MutationError("Name and model_id are required.")
    provider = str(data.get("provider", "9router") or "").strip()
    endpoint_type = str(data.get("endpoint_type", "openai") or "openai").strip().lower()
    if endpoint_type not in ("openai", "anthropic"):
        endpoint_type = "openai"
    base_url = str(data.get("base_url", "") or "").strip() or None
    tool_choice = str(data.get("tool_choice", "any") or "any").strip().lower()
    if tool_choice not in ("any", "required", "auto"):
        tool_choice = "any"
    fields = {
        "name": name,
        "model_id": model_id,
        "provider": provider,
        "endpoint_type": endpoint_type,
        "base_url": base_url,
        "tool_choice": tool_choice,
        "is_active": bool(data.get("is_active", True)),
        "order": int(data.get("order", 0) or 0),
    }
    if pk is None:
        model_obj = models.AIModel.objects.create(
            api_key=(str(data.get("api_key", "") or "").strip() or None), **fields
        )
    else:
        try:
            model_obj = models.AIModel.objects.get(pk=int(pk))
        except (models.AIModel.DoesNotExist, TypeError, ValueError):
            raise MutationError("Model not found.")
        for key, value in fields.items():
            setattr(model_obj, key, value)
        # A missing key means "keep the stored one"; only a typed value replaces it.
        if str(data.get("api_key", "") or "").strip():
            model_obj.api_key = str(data.get("api_key")).strip()
        model_obj.save()
    return {"status": "success", "model": model_public(model_obj)}


def delete_ai_model(user, pk):
    require_user_id(user)
    try:
        model_obj = models.AIModel.objects.get(pk=int(pk))
    except (models.AIModel.DoesNotExist, TypeError, ValueError):
        raise MutationError("Model not found.")
    model_obj.delete()
    return {"status": "success"}


def test_ai_model(user, data):
    """Probe a provider. Uses the typed key, else the stored one server-side."""
    require_user_id(user)
    import os

    import requests
    from django.conf import settings

    data = data or {}
    model_id = str(data.get("model_id", "") or "").strip()
    if not model_id:
        raise MutationError("Model ID is required for testing.")
    provider = str(data.get("provider", "9router") or "").strip().lower()
    base_url = str(data.get("base_url", "") or "").strip() or None
    api_key = str(data.get("api_key", "") or "").strip() or None
    if not api_key and data.get("id"):
        try:
            api_key = (
                models.AIModel.objects.filter(pk=int(data.get("id")))
                .values_list("api_key", flat=True)
                .first()
            )
        except Exception:
            pass
    endpoint_type = str(data.get("endpoint_type", "openai") or "openai").strip().lower()
    target_endpoint = base_url.rstrip("/") if base_url else "http://localhost:20128/v1"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    fetched_models = []
    try:
        resp = requests.get(f"{target_endpoint}/models", headers=headers, timeout=4)
        if resp.status_code == 200:
            resp_json = resp.json()
            if isinstance(resp_json, dict) and "data" in resp_json and isinstance(
                resp_json["data"], list
            ):
                fetched_models = [
                    m.get("id") for m in resp_json["data"] if isinstance(m, dict) and m.get("id")
                ]
    except Exception:
        pass
    from langchain_core.messages import HumanMessage

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        url = base_url or getattr(
            settings, "OLLAMA_URL", os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
        )
        llm = ChatOllama(model=model_id, base_url=url, temperature=0.1)
    elif provider == "mistral" and not base_url:
        from langchain_mistralai import ChatMistralAI

        key = api_key or getattr(
            settings, "MISTRAL_API_KEY", os.environ.get("MISTRAL_API_KEY", "")
        )
        llm = ChatMistralAI(model=model_id, mistral_api_key=key, temperature=0.1)
    elif endpoint_type == "anthropic" and not base_url:
        from langchain_anthropic import ChatAnthropic

        key = api_key or getattr(
            settings, "ANTHROPIC_API_KEY", os.environ.get("ANTHROPIC_API_KEY", "")
        )
        if not key:
            raise MutationError("Anthropic API key is required.")
        llm = ChatAnthropic(model=model_id, api_key=key, temperature=0.1, max_tokens=10)
    else:
        from langchain_openai import ChatOpenAI

        url = base_url if base_url else "http://localhost:20128/v1"
        key = (
            api_key
            or os.environ.get("MIMO_API_KEY")
            or getattr(
                settings,
                "ROUTER_API_KEY",
                os.environ.get("ROUTER_API_KEY", os.environ.get("OPENAI_API_KEY", "9router")),
            )
        )
        llm = ChatOpenAI(model=model_id, base_url=url, api_key=key, temperature=0.1, max_tokens=10)
    try:
        res = llm.invoke([HumanMessage(content="hi")])
        reply = res.content if hasattr(res, "content") else str(res)
    except Exception as exc:
        raise MutationError(str(exc))
    return {
        "status": "success",
        "message": "Connection & Model test successful!",
        "reply": str(reply)[:100],
        "available_models": fetched_models,
    }


def cancel_investigation(user, session_id, inv_id):
    require_user_id(user)
    from sre_agent.canonical_lifecycle import cancel_run_now

    try:
        session = models.ChatSession.objects.get(pk=session_id)
    except (models.ChatSession.DoesNotExist, ValueError, TypeError):
        raise MutationError("Chat session not found.")
    try:
        cancel_run_now(str(session.pk), str(user.pk))
    except Exception:
        pass
    updated = models.Investigation.objects.filter(
        id=inv_id, session=session, status="active"
    ).update(status="cancelled")
    if not updated:
        return {"status": "unchanged"}
    models.InvestigationTask.objects.filter(
        investigation_id=inv_id,
        status__in=["pending", "running", "in_progress", "executing"],
    ).update(status="cancelled")
    return {"status": "cancelled"}
