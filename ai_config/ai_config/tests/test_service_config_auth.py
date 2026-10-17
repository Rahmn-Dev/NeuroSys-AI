"""The service configuration endpoints read and write systemd units as root.

Both used to be @api_view with no permission class and no name validation:

    config_path = f"/etc/systemd/system/{service_name}.service"
    subprocess.run(['sudo', '-S', 'tee', config_path], input=f"{password}\n{config}")

so an unauthenticated caller could read any unit file, write arbitrary ones
through a path traversal in service_name, and probe the sudo password without
any limit. The password also travelled as plaintext JSON.

Each test pins one of those three properties plus the fact that the operator
still gets a working flow.
"""
import pytest
from django.contrib.auth.models import User
from django.test import Client

from ai_config.views import (SERVICE_CONFIG_MAX_BYTES, _service_name_ok,
                             _service_config_attempts)

pytestmark = pytest.mark.django_db


def _operator():
    user = User.objects.create_user("svc-operator", password="x")
    user.profile.is_active_session = True
    user.profile.save()
    client = Client()
    client.force_login(user)
    return client


def _anon():
    return Client()


# --- 1. authentication ----------------------------------------------------

@pytest.mark.parametrize("url,method", [
    ("/api/get-service-config/sshd/", "get"),
    ("/api/save-service-config/sshd/", "post"),
])
def test_anonymous_is_refused(url, method):
    client = _anon()
    kwargs = {"content_type": "application/json", "data": "{}"} if method == "post" else {}
    response = getattr(client, method)(url, **kwargs)
    assert response.status_code in (401, 403), (
        f"{url} answered {response.status_code} with no session"
    )


# --- 2. service_name cannot escape /etc/systemd/system ---------------------

@pytest.mark.parametrize("bad", [
    "../../etc/passwd",
    "../../../etc/systemd/system/sshd",
    "sshd.service/../../evil",
    "/etc/systemd/system/sshd",
    "..",
    ".",
    "",
    "   ",
    "ssh d",
    "ssh;d",
    "ssh|d",
    "ssh$(id)",
    "ssh`id`",
    "ssh\nd",
    "ssh\x00d",
    "a" * 80,
])
def test_traversal_and_shell_metacharacters_are_refused(bad):
    assert _service_name_ok(bad) is None


@pytest.mark.parametrize("good,expected", [
    ("sshd", "sshd"),
    ("nginx", "nginx"),
    ("my-service_2", "my-service_2"),
    ("sshd.service", "sshd"),
    ("postgresql@16-main", "postgresql@16-main"),
])
def test_ordinary_unit_names_are_accepted(good, expected):
    assert _service_name_ok(good) == expected


def test_anonymous_cannot_read_a_unit_file_by_traversal():
    response = _anon().get("/api/get-service-config/..%2F..%2Fetc%2Fpasswd/")
    assert response.status_code in (400, 403, 404)


def test_operator_gets_rejected_for_traversal_not_a_crash():
    # Django's <str:...> converter does not match an encoded slash, so this is
    # refused by URL routing (404) before the view is even reached. Either way
    # nothing is read, which is the property that matters.
    response = _operator().get("/api/get-service-config/..%2F..%2Fetc%2Fpasswd/")
    assert response.status_code in (400, 404)


# --- 3. the password is never accepted in the clear -----------------------

def test_plaintext_password_field_is_refused():
    response = _operator().post(
        "/api/save-service-config/sshd/",
        data='{"config": "[Unit]", "password": "hunter2"}',
        content_type="application/json")
    assert response.status_code == 400
    assert "encrypted" in response.json().get("error", "").lower()


def test_garbage_ciphertext_does_not_reach_sudo():
    response = _operator().post(
        "/api/save-service-config/sshd/",
        data='{"config": "[Unit]", "encrypted_password": "not-base64-rsa"}',
        content_type="application/json")
    assert response.status_code == 400


def test_rate_limit_engages_after_repeated_attempts():
    """No unlimited guessing from a public tunnel."""
    _service_config_attempts.clear()
    client = _operator()
    codes = []
    for _ in range(8):
        response = client.post(
            "/api/save-service-config/sshd/",
            data='{"config": "[Unit]", "encrypted_password": "junk"}',
            content_type="application/json")
        codes.append(response.status_code)
    assert 429 in codes, f"rate limit never engaged: {codes}"
    _service_config_attempts.clear()


def test_oversized_config_is_refused():
    _service_config_attempts.clear()
    response = _operator().post(
        "/api/save-service-config/sshd/",
        data='{"config": "%s", "encrypted_password": "junk"}' % ("A" * (SERVICE_CONFIG_MAX_BYTES + 10)),
        content_type="application/json")
    assert response.status_code == 400
    _service_config_attempts.clear()


# --- the operator path still exists ---------------------------------------

def test_operator_reaches_the_endpoint_and_gets_a_domain_error():
    """Not a 403: the session is honoured and the name is valid, so the request
    is allowed to proceed and only fails on the encrypted payload."""
    response = _operator().post(
        "/api/save-service-config/sshd/",
        data='{"config": "[Unit]", "encrypted_password": "junk"}',
        content_type="application/json")
    assert response.status_code == 400
    body = response.json().get("error", "")
    # The message must not tell the caller whether sudo or the ciphertext failed.
    assert "password" not in body.lower() or "verify" in body.lower()

# --- regression: reading a real unit file ----------------------------------

def test_reading_a_unit_file_does_not_blow_up(tmp_path, monkeypatch):
    """A TextIOWrapper.read(limit=...) TypeError made every lookup a 500.

    Reading is capped, but positionally: `limit=` is readline's keyword.
    """
    from ai_config import views

    unit = tmp_path / "demo.service"
    unit.write_text("[Unit]\nDescription=Demo\nExecStart=/bin/true\n")

    monkeypatch.setattr(views, "find_service_file", lambda name: str(unit))

    client = _operator()
    response = client.get("/api/get-service-config/demo/")
    assert response.status_code == 200, (
        f"reading a valid unit file returned {response.status_code}"
    )
    body = response.json()
    assert "Description=Demo" in body["config"]
    # The page needs the public key to encrypt the sudo password later.
    assert "BEGIN PUBLIC KEY" in body["public_key"]


def test_oversized_unit_file_is_refused_not_truncated_silently(tmp_path, monkeypatch):
    from ai_config import views

    unit = tmp_path / "big.service"
    unit.write_text("A" * (views.SERVICE_CONFIG_MAX_BYTES + 100))
    monkeypatch.setattr(views, "find_service_file", lambda name: str(unit))

    response = _operator().get("/api/get-service-config/big/")
    assert response.status_code == 400
