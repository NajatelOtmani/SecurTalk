import json
import pytest
import requests
import soc_events as se


def lines(p):
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]


def mk(tmp_path, mode="file"):
    return se.SocEmitter(mode=mode, url="http://127.0.0.1:9", base_dir=tmp_path, async_=False)


def test_format_contrat_et_gravite_par_defaut(tmp_path):
    e = mk(tmp_path)
    ev = e.emit("crypto", "GCM_AUTH_FAIL", actor={"user_id": "u_a"},
                target={"user_id": "u_b", "conversation_id": "conv_u_a_u_b"}, details={"mode": "GCM", "counter": 3})
    assert ev["severity"] == "high" and ev["source"] == "crypto"
    assert ev["timestamp"].endswith("Z") and len(ev["event_id"]) == 36
    assert lines(tmp_path / "events.jsonl")[0]["actor"] == {"user_id": "u_a", "username": None, "ip": None}


@pytest.mark.parametrize("bad", [{"text": "bonjour"}, {"ciphertext": "x"}, {"session_key": "k"},
                                 {"x": "A" * 300}, {"x": "QUJD" * 20}, {"nested": {"password": "p"}}])
def test_privacy_refuse_donnees_sensibles(tmp_path, bad):
    e = mk(tmp_path)
    assert e.emit("client", "WARNING_SHOWN", actor={"user_id": "u_a"}, details=bad) is None
    assert not (tmp_path / "events.jsonl").exists()


def test_text_length_est_autorise(tmp_path):
    ev = mk(tmp_path).emit("client", "WARNING_SHOWN", actor={"user_id": "u_a"},
                           details={"text_length": 12, "reason_codes": ["TEXT_URGENCY"]})
    assert ev is not None


def test_acteur_vide_refuse(tmp_path):
    assert mk(tmp_path).emit("client", "WARNING_SHOWN", actor={}) is None


def test_soc_en_panne_fichier_attente_puis_renvoi(tmp_path, monkeypatch):
    e = mk(tmp_path, "http")

    def boom(*a, **k):
        raise requests.ConnectionError()
    monkeypatch.setattr(requests, "post", boom)
    e.emit("client", "WARNING_SHOWN", actor={"user_id": "u_a"})
    e.emit("client", "MESSAGE_BLOCKED", actor={"user_id": "u_a"})
    assert len(lines(tmp_path / "events_pending.jsonl")) == 2
    sent = []

    class R:
        status_code = 202
    monkeypatch.setattr(requests, "post", lambda *a, **k: (sent.append(k["json"]["event_type"]), R())[1])
    e.emit("client", "USER_OVERRODE_WARNING", actor={"user_id": "u_a"})
    assert sorted(sent) == ["MESSAGE_BLOCKED", "USER_OVERRODE_WARNING", "WARNING_SHOWN"]
    assert not (tmp_path / "events_pending.jsonl").exists()


def test_clef_envoyee_dans_l_entete(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_KEY_CRYPTO", "cle-crypto")
    seen = {}

    class R:
        status_code = 202
    monkeypatch.setattr(requests, "post", lambda *a, **k: (seen.update(k["headers"]), R())[1])
    mk(tmp_path, "http").emit("crypto", "REPLAY_DETECTED", actor={"user_id": "u_a"})
    assert seen["X-API-Key"] == "cle-crypto"


def test_refus_4xx_pas_de_boucle(tmp_path, monkeypatch):
    class R:
        status_code = 403
    monkeypatch.setattr(requests, "post", lambda *a, **k: R())
    mk(tmp_path, "http").emit("client", "WARNING_SHOWN", actor={"user_id": "u_a"})
    assert not (tmp_path / "events_pending.jsonl").exists()
