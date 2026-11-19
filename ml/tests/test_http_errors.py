import pytest
from fastapi.testclient import TestClient
from service.main import app

client = TestClient(app)
HEAD = {"Content-Type": "application/json"}
BODY = '{"message_id":"m1","sender_id":"u_1a","receiver_id":"u_2b","conversation_id":"c","text":"vérifier","urls":[]}'


def test_utf8_body_ok():
    assert client.post("/v1/analyze", content=BODY.encode("utf-8"), headers=HEAD).status_code == 200


@pytest.mark.parametrize("raw", [BODY.encode("latin-1"), b"{pas du json", b"", b"\xff\xfe\x00"])
def test_unreadable_bodies_give_contract_error(raw):
    r = client.post("/v1/analyze", content=raw, headers=HEAD)
    assert r.status_code == 400
    assert set(r.json()) == {"error", "message"} and r.json()["error"] == "INVALID_FORMAT"


def test_other_http_errors_use_contract_format():
    r = client.get("/nimporte-quoi")
    assert r.status_code == 404 and r.json()["error"] == "NOT_FOUND"
    assert client.get("/v1/analyze").json()["error"] == "METHOD_NOT_ALLOWED"
