import json

import pytest

from app.soc_client import PrivacyError, SocEmitter, build_event
from conftest import make_settings


def test_evenement_conforme_au_contrat_2_2():
    e = build_event("auth", "LOGIN_FAIL", actor={"user_id": None, "username": "alice", "ip": "192.168.1.20"},
                    target={"user_id": "u_8f3a1c"}, details={"reason": "bad_password", "attempt_number": 3})
    assert set(e) == {"event_id", "timestamp", "source", "event_type", "severity", "actor", "target", "details"}
    assert e["severity"] == "low" and e["timestamp"].endswith("Z") and len(e["event_id"]) == 36
    assert e["target"]["conversation_id"] is None


@pytest.mark.parametrize("details", [{"text": "bonjour"}, {"a": {"password": "x"}}, {"token": "t"},
                                     {"x": "a" * 201}, {"x": "QUJD" * 20}])
def test_privacy_guard_cote_emetteur(details):
    with pytest.raises(PrivacyError):
        build_event("relay", "PACKET_ROUTED", actor={"ip": "1.2.3.4"}, details=details)


def test_text_length_autorise():
    build_event("phishing", "PHISHING_DETECTED", "medium", actor={"user_id": "u_1"}, details={"text_length": 12})


def test_actor_vide_refuse_sauf_heartbeat():
    with pytest.raises(ValueError):
        build_event("relay", "PACKET_ROUTED", actor={})
    assert build_event("relay", "HEARTBEAT")["actor"] == {"user_id": None, "username": None, "ip": None}


def test_emit_ne_plante_jamais():
    em = SocEmitter(make_settings())
    assert em.emit("relay", "PACKET_ROUTED", actor={"ip": "1.2.3.4"}, details={"text": "interdit"}) is None
    assert em.emit("inconnue", "X") is None
    assert em.events == []


def test_mode_file(tmp_path):
    f = tmp_path / "events.jsonl"
    em = SocEmitter(make_settings(soc_mode="file", events_file=str(f)))
    em.emit("auth", "LOGOUT", actor={"user_id": "u_1"})
    assert json.loads(f.read_text().splitlines()[0])["event_type"] == "LOGOUT"


def test_soc_injoignable_ecrit_events_pending(tmp_path, monkeypatch):
    pend = tmp_path / "events_pending.jsonl"
    em = SocEmitter(make_settings(soc_mode="http", pending_file=str(pend), soc_keys={"auth": "k", "relay": "k"}))

    def boom(*a, **k):
        raise ConnectionError("SOC arrete")
    monkeypatch.setattr("app.soc_client.requests.post", boom)
    ev = em.emit("auth", "LOGOUT", actor={"user_id": "u_1"})
    em._pool.shutdown(wait=True)
    assert ev and json.loads(pend.read_text().splitlines()[0])["event_id"] == ev["event_id"]


def test_flush_pending_renvoie_puis_vide(tmp_path, monkeypatch):
    pend = tmp_path / "events_pending.jsonl"
    em = SocEmitter(make_settings(soc_mode="http", pending_file=str(pend), soc_keys={"auth": "k", "relay": "k"}))
    pend.write_text(json.dumps(build_event("auth", "LOGOUT", actor={"user_id": "u_1"})) + "\n" +
                    json.dumps(build_event("auth", "LOGOUT", actor={"user_id": "u_2"})) + "\n")
    envoyes = []

    class R:
        status_code = 202
    monkeypatch.setattr("app.soc_client.requests.post",
                        lambda url, json=None, headers=None, timeout=None: envoyes.append(headers["X-API-Key"]) or R())
    assert em.flush_pending() == 2 and envoyes == ["k", "k"] and not pend.exists()
    em._pool.shutdown(wait=True)
