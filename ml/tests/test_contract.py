from fastapi.testclient import TestClient
from service.main import app
from service.config import label_from_score
from service.schemas import REASON_CODES

client = TestClient(app)

EXAMPLE = {
    "message_id": "6c0e4b7a-1d2f-4e55-8f10-0a9b9c1d2e3f",
    "sender_id": "u_1a", "receiver_id": "u_2b",
    "conversation_id": "conv_u_1a_u_2b",
    "text": "Cliquez ici pour vérifier votre compte",
    "urls": ["http://micros0ft-login.com/verify"],
}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok" and "model_version" in r.json()


def test_analyze_matches_contract():
    r = client.post("/v1/analyze", json=EXAMPLE)
    assert r.status_code == 200
    d = r.json()
    assert d["message_id"] == EXAMPLE["message_id"]
    assert set(d) == {"message_id", "score", "label", "reasons", "model_version", "latency_ms"}
    assert d["label"] == "Phishing" and d["score"] >= 0.80
    codes = {x["code"] for x in d["reasons"]}
    assert "URL_BRAND_IMITATION" in codes and "TEXT_ACCOUNT_VERIFICATION" in codes
    assert codes <= REASON_CODES


def test_empty_text_and_no_urls_ok():
    body = {**EXAMPLE, "text": "", "urls": []}
    assert client.post("/v1/analyze", json=body).status_code == 200


def test_very_long_text_no_500():
    body = {**EXAMPLE, "text": "a" * 20000, "urls": ["http://x.com"] * 50}
    assert client.post("/v1/analyze", json=body).status_code == 200


def test_missing_field_gives_400_contract_error():
    r = client.post("/v1/analyze", json={"text": "salut"})
    assert r.status_code == 400
    assert r.json()["error"] == "INVALID_FORMAT"


def test_thresholds():
    assert label_from_score(0.39) == "Safe"
    assert label_from_score(0.40) == "Suspicious"
    assert label_from_score(0.79) == "Suspicious"
    assert label_from_score(0.80) == "Phishing"
