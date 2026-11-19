import pytest
import requests

import config
import storage
from api_backend import ApiError, BackendClient


class Resp:
    def __init__(self, status, body):
        self.status_code, self._b = status, body
        self.content = b"x" if body is not None else b""

    def json(self):
        return self._b


def fake(monkeypatch, status, body):
    monkeypatch.setattr(requests.Session, "request", lambda *a, **k: Resp(status, body))


def test_login_ok(monkeypatch):
    fake(monkeypatch, 200, {"token": "t", "user_id": "u_1", "expires_at": "x"})
    c = BackendClient()
    c.login("alice", "motdepasse12")
    assert c.token == "t" and c.user_id == "u_1" and c.username == "alice"


@pytest.mark.parametrize("status,code", [(401, "INVALID_CREDENTIALS"), (403, "ACCOUNT_LOCKED")])
def test_login_errors(monkeypatch, status, code):
    fake(monkeypatch, status, {"error": code, "message": "m"})
    with pytest.raises(ApiError) as e:
        BackendClient().login("alice", "x")
    assert e.value.code == code and e.value.status == status


def test_unreachable(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError()
    monkeypatch.setattr(requests.Session, "request", boom)
    with pytest.raises(ApiError) as e:
        BackendClient().login("a", "b")
    assert e.value.code == "BACKEND_UNREACHABLE"


def test_register(monkeypatch):
    fake(monkeypatch, 201, {"user_id": "u_9"})
    assert BackendClient().register("bob", "motdepasse12", "PEM")["user_id"] == "u_9"


def test_private_key_stays_local(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "user_dir", lambda u: (tmp_path / u).mkdir(exist_ok=True) or tmp_path / u)
    assert not storage.has_private_key("alice")
    storage.save_private_key("alice", "PRIVATE")
    assert storage.load_private_key("alice") == "PRIVATE"
