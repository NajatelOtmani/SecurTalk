import asyncio
import json
import re
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from service import main, soc_client
from tools.fake_soc import EVENTS, app as fake_soc

SCAN = dict(message_id="m1", sender_id="u_1a", receiver_id="u_2b", conversation_id="conv_u_1a_u_2b",
            score=0.94, label="Phishing", reason_codes=["URL_BRAND_IMITATION"],
            url_domains=["micros0ft-login.com"], text_length=40)


class Resp:
    def __init__(self, code): self.status_code = code


def lines(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def test_event_matches_contract_2_2_and_2_10(monkeypatch):
    sent = []
    monkeypatch.setenv("SOC_KEY_PHISHING", "k")
    monkeypatch.setattr(soc_client.httpx, "post", lambda url, json, timeout, headers: (sent.append((json, headers, timeout)), Resp(202))[1])
    assert soc_client.emit_scan_event(**SCAN) == "sent"
    ev, headers, timeout = sent[0]
    assert uuid.UUID(ev["event_id"]).version == 4 and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ev["timestamp"])
    assert (ev["source"], ev["event_type"], ev["severity"]) == ("phishing", "PHISHING_DETECTED", "medium")
    assert ev["actor"] == {"user_id": "u_1a", "username": None, "ip": None}
    assert ev["target"] == {"user_id": "u_2b", "conversation_id": "conv_u_1a_u_2b"}
    assert set(ev["details"]) == {"message_id", "score", "label", "reason_codes", "url_domains", "text_length"}
    assert headers["X-API-Key"] == "k" and headers["X-Contract-Version"] == "1.0" and timeout == 1.0


@pytest.mark.parametrize("label,etype,sev", [("Safe", "MESSAGE_SCANNED_SAFE", "info"),
                                             ("Suspicious", "SUSPICIOUS_MESSAGE", "low"),
                                             ("Phishing", "PHISHING_DETECTED", "medium")])
def test_event_type_per_label(label, etype, sev, tmp_path):
    soc_client.emit_scan_event(**{**SCAN, "label": label})
    ev = lines(soc_client.LOCAL_PATH)[0]
    assert (ev["event_type"], ev["severity"]) == (etype, sev)


def test_no_key_writes_local_mock_file():
    assert soc_client.emit_event("phishing", "HEARTBEAT") == "local"
    assert lines(soc_client.LOCAL_PATH)[0]["event_type"] == "HEARTBEAT"


def test_soc_down_never_raises_and_queues(monkeypatch):
    monkeypatch.setenv("SOC_KEY_PHISHING", "k")
    def boom(*a, **k): raise httpx.ConnectError("down")
    monkeypatch.setattr(soc_client.httpx, "post", boom)
    assert soc_client.emit_scan_event(**SCAN) == "retry"
    assert len(lines(soc_client.PENDING_PATH)) == 1


def test_4xx_is_rejected_not_queued(monkeypatch):
    monkeypatch.setenv("SOC_KEY_PHISHING", "k")
    monkeypatch.setattr(soc_client.httpx, "post", lambda *a, **k: Resp(401))
    assert soc_client.emit_scan_event(**SCAN) == "rejected"
    assert not soc_client.PENDING_PATH.exists()


def test_privacy_guard_blocks_text_and_long_strings(monkeypatch):
    monkeypatch.setenv("SOC_KEY_PHISHING", "k")
    called = []
    monkeypatch.setattr(soc_client.httpx, "post", lambda *a, **k: called.append(1) or Resp(202))
    assert soc_client.emit_event("phishing", "X", details={"text": "bonjour"}) == "blocked"
    assert soc_client.emit_event("phishing", "X", details={"note": "a" * 201}) == "blocked"
    assert soc_client.emit_event("phishing", "X", details={"nested": {"password": "x"}}) == "blocked"
    assert not called


def test_flush_pending(monkeypatch):
    monkeypatch.setenv("SOC_KEY_PHISHING", "k")
    monkeypatch.setattr(soc_client.httpx, "post", lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("down")))
    soc_client.emit_scan_event(**SCAN); soc_client.emit_scan_event(**SCAN)
    assert soc_client.flush_pending() == 0 and len(lines(soc_client.PENDING_PATH)) == 2     # toujours éteint : rien perdu
    monkeypatch.setattr(soc_client.httpx, "post", lambda *a, **k: Resp(202))
    assert soc_client.flush_pending() == 2 and not soc_client.PENDING_PATH.exists()


def test_clean_domains():
    out = soc_client.clean_domains(["a.com", "a.com", "b\n.com", "x" * 100] + [f"d{i}.com" for i in range(20)])
    assert out[:2] == ["a.com", "b.com"] and len(out[2]) == 60 and len(out) == 10


def test_endpoint_emits_one_event_without_text():
    secret = "MOT-SECRET-XYZ vérifiez votre compte http://micros0ft-login.com/verify"
    body = {"message_id": "m9", "sender_id": "u_1a", "receiver_id": "u_2b",
            "conversation_id": "conv_u_1a_u_2b", "text": secret, "urls": []}
    assert TestClient(main.app).post("/v1/analyze", json=body).status_code == 200
    evs = lines(soc_client.LOCAL_PATH)
    assert len(evs) == 1 and evs[0]["event_type"] == "PHISHING_DETECTED"
    assert evs[0]["details"]["text_length"] == len(secret) and evs[0]["details"]["url_domains"] == ["micros0ft-login.com"]
    assert "MOT-SECRET" not in json.dumps(evs[0])


def test_heartbeat_loop_beats_repeatedly(monkeypatch):
    beats = []
    monkeypatch.setattr(soc_client, "beat", lambda v: beats.append(v))
    async def run():
        t = asyncio.create_task(soc_client.heartbeat_loop(0.01, lambda: "v1"))
        await asyncio.sleep(0.1); t.cancel()
    asyncio.run(run())
    assert len(beats) >= 3 and set(beats) == {"v1"}


def test_fake_soc_behaviour(monkeypatch):
    c = TestClient(fake_soc)
    ev = soc_client.make_event("phishing", "HEARTBEAT", "info", None, None, {"model_version": "v"})
    assert c.post("/soc/events", json=ev).status_code == 401
    assert c.post("/soc/events", json=ev, headers={"X-API-Key": "k"}).status_code == 202
    assert c.post("/soc/events", json={**ev, "details": {"text": "x"}}, headers={"X-API-Key": "k"}).status_code == 400
    assert c.post("/soc/events", json={"event_id": "x"}, headers={"X-API-Key": "k"}).status_code == 400
