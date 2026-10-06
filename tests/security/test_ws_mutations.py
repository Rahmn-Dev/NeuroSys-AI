"""Mutations travel over the authenticated websocket, not cookie-based HTTP.

Transport is proven over a real socket below (routing, correlation, auth
gate). The service logic itself is covered synchronously in
test_permission_preference.py, because the in-memory test database cannot
cross the thread boundary the socket machinery runs on.
"""
import asyncio
import json

from channels.testing import WebsocketCommunicator
from django.contrib.auth.models import AnonymousUser, User

from ai_config.asgi import application


async def _connect(user):
    communicator = WebsocketCommunicator(application, "/ws/sre-agent/")
    communicator.scope["user"] = user
    connected, _ = await communicator.connect()
    assert connected
    # Drain exactly the two connect-time messages. In this channels version a
    # receive timeout cancels the app under test, so never wait for a message
    # that may not come.
    for _ in range(2):
        await communicator.receive_from(timeout=30)
    return communicator


async def _call(communicator, rpc_type, payload):
    await communicator.send_to(text_data=json.dumps(
        dict({"type": rpc_type, "request_id": "t-1"}, **payload)))
    for _ in range(10):
        raw = await communicator.receive_from(timeout=30)
        msg = json.loads(raw)
        if msg.get("type") == "rpc_result" and msg.get("request_id") == "t-1":
            return msg
        # presence pushes and other traffic share the socket; keep listening
    raise AssertionError("no correlated answer")


def _run(coro):
    # Sync wrapper: the in-memory test database cannot cross into the socket
    # machinery's threads, so these transport tests touch no tables at all.
    return asyncio.new_event_loop().run_until_complete(coro)


async def _anonymous_case():
    communicator = await _connect(AnonymousUser())
    try:
        return await _call(communicator, "agent_permission.set", {"mode": "full_access"})
    finally:
        await communicator.disconnect()


async def _unknown_case():
    communicator = await _connect(User(username="ws-operator"))
    try:
        return await _call(communicator, "does.not.exist", {})
    finally:
        await communicator.disconnect()


def test_anonymous_socket_cannot_mutate():
    assert _run(_anonymous_case())["ok"] is False


def test_unknown_call_is_rejected_not_routed():
    assert _run(_unknown_case())["ok"] is False
