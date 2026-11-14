"""Compatibilité avec le dossier contracts/ de l'équipe (guide section 2 : on teste avec ces exemples).
Si un test échoue ici : l'exemple de l'équipe et ton service ne parlent pas le même format -> en parler
AVANT de modifier du code (règle d'or n°1 : le contrat gagne, on le change d'abord dans le guide)."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from service import main, soc_client

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
client = TestClient(main.app)


def load(name):
    p = CONTRACTS / name
    if not p.exists():
        pytest.skip(f"contracts/{name} absent")
    return json.loads(p.read_text(encoding="utf-8"))


def _same_kind(got, expected):
    num = (int, float)
    if isinstance(expected, bool):
        return isinstance(got, bool)
    if isinstance(expected, num):
        return isinstance(got, num) and not isinstance(got, bool)
    return isinstance(got, type(expected))


def test_request_example_is_accepted():
    assert client.post("/v1/analyze", json=load("analyze_request.json")).status_code == 200


def test_response_has_same_shape_as_example():
    req, ex = load("analyze_request.json"), load("analyze_response.json")
    got = client.post("/v1/analyze", json=req).json()
    assert set(got) == set(ex), f"champs différents : {set(got) ^ set(ex)}"
    for k in ex:
        assert _same_kind(got[k], ex[k]), f"type différent pour '{k}'"
    assert got["message_id"] == req["message_id"]
    if ex["reasons"]:
        assert all(set(r) == set(ex["reasons"][0]) for r in got["reasons"])


def test_scan_event_has_same_shape_as_example():
    ex = load("event_example.json")
    soc_client.emit_scan_event(message_id="m1", sender_id="u_1a", receiver_id="u_2b",
                               conversation_id="conv_u_1a_u_2b", score=0.9, label="Phishing",
                               reason_codes=["URL_BRAND_IMITATION"], url_domains=["x.top"], text_length=10)
    ev = json.loads(soc_client.LOCAL_PATH.read_text(encoding="utf-8").splitlines()[0])
    assert set(ev) == set(ex), f"champs différents : {set(ev) ^ set(ex)}"
    assert set(ev["actor"]) == set(ex["actor"]) and set(ev["target"]) == set(ex["target"])
    assert ev["source"] in {"auth", "relay", "crypto", "phishing", "client"}
