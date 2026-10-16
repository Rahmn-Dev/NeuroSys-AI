"""WebSocket handshake must carry a logged-in session.

AuthMiddlewareStack only fills scope['user']; it never refuses a handshake.
Before the guard in consumers.socket_is_anonymous, nine consumers accepted an
unauthenticated socket, and TerminalConsumer went on to spawn an interactive
bash shell for whoever dialled in.

These tests pin both directions, because a guard that also blocks the operator
would be worse than the hole: anonymous is refused, an authenticated staff
operator is still admitted.
"""
import asyncio
import pytest
from channels.testing import WebsocketCommunicator
from django.contrib.auth.models import User
from django.test import RequestFactory

from ai_config.consumers import (
    WS_AUTH_REJECT_CODE,
    ArchitectureConsumer,
    ChatConsumer,
    SecurityConsumer,
    ServiceControlConsumer,
    SystemMonitorConsumer,
    TerminalConsumer,
    socket_is_anonymous,
)
from ai_config.asgi import application

pytestmark = pytest.mark.django_db(transaction=True)

# TerminalConsumer would spawn a real shell, so it is asserted on its guard
# rather than driven end to end.
GUARDED_CONSUMERS = [
    ("/ws/system_monitor/", SystemMonitorConsumer),
    ("/ws/services/", ServiceControlConsumer),
    ("/ws/chat/", ChatConsumer),
    ("/ws/terminal/", TerminalConsumer),
    ("/ws/security/", SecurityConsumer),
    ("/ws/architecture/", ArchitectureConsumer),
]


def _staff_user():
    user = User.objects.create_user("operator", password="x", is_staff=True)
    user.profile.is_active_session = True
    user.profile.save()
    return user


def _session_cookie():
    """A real signed session cookie string, the way the browser would send it."""
    from importlib import import_module

    from django.conf import settings
    from django.contrib.auth import (BACKEND_SESSION_KEY, HASH_SESSION_KEY,
                                     SESSION_KEY)

    user = _staff_user()
    store = import_module(settings.SESSION_ENGINE).SessionStore()
    store[SESSION_KEY] = str(user.pk)
    store[BACKEND_SESSION_KEY] = settings.AUTHENTICATION_BACKENDS[0]
    store[HASH_SESSION_KEY] = user.get_session_auth_hash()
    store.create()
    return f"{settings.SESSION_COOKIE_NAME}={store.session_key}"


# --- the rule itself -------------------------------------------------------

def test_anonymous_scope_is_rejected():
    from django.contrib.auth.models import AnonymousUser
    assert socket_is_anonymous({"user": AnonymousUser()}) is True


def test_missing_user_key_is_rejected():
    assert socket_is_anonymous({}) is True


def test_logged_in_user_passes():
    assert socket_is_anonymous({"user": _staff_user()}) is False


def test_a_non_staff_operator_is_still_admitted():
    # is_authenticated, not is_staff: chat3 is only @login_required, so a
    # stricter bar here would lock a legitimate operator out of their own app.
    user = User.objects.create_user("plain", password="x", is_staff=False)
    assert socket_is_anonymous({"user": user}) is False


# --- every guarded consumer ------------------------------------------------

@pytest.mark.parametrize("path,consumer_cls", GUARDED_CONSUMERS)
@pytest.mark.asyncio
async def test_anonymous_handshake_hands_over_nothing(path, consumer_cls):
    """A refused socket yields no accept and no greeting payload."""
    communicator = WebsocketCommunicator(application, path)
    connected, _ = await communicator.connect()
    assert connected is False, (
        f"{consumer_cls.__name__} ({path}) accepted a socket with no login"
    )
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(communicator.receive_output(), timeout=0.3)


@pytest.mark.asyncio
async def test_logged_in_operator_is_admitted_to_the_agent_socket():
    """The real page path: chat3 opens this socket straight after login.

    AuthMiddlewareStack reads the session from a cookie header, so the test has
    to hand over a genuine session key rather than assert the scope directly.
    """
    from channels.db import database_sync_to_async
    cookie = await database_sync_to_async(_session_cookie)()
    communicator = WebsocketCommunicator(
        application, "/ws/sre-agent/", headers=[(b"cookie", cookie.encode())]
    )
    connected, _ = await communicator.connect()
    assert connected is True
    await communicator.disconnect()
