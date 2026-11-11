import pytest

from conftest import INTERNAL, bearer, make_settings, types

sdk = pytest.importorskip("securetalk_crypto")
from securetalk_crypto import KeyManager, RSAKeyExchange, encrypt_message  # noqa: E402
from app.main import create_app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def conv(duo):
    a, b = sorted([duo["alice"]["id"], duo["bob"]["id"]])
    return f"conv_{a}_{b}"


def envoyer_cle(client, duo, key, de="alice", a="bob"):
    return client.post("/keys/exchange", headers=bearer(duo[de]["token"]),
                       json={"conversation_id": conv(duo), "to_user_id": duo[a]["id"], "key_id": key.key_id,
                             "wrapped_key_b64": RSAKeyExchange.wrap_key(duo[a]["pub"], key)})


def message(client, duo, key, counter):
    p = encrypt_message("salut", key, "GCM", duo["alice"]["id"], duo["bob"]["id"], conv(duo), counter)
    return client.post("/messages", headers=bearer(duo["alice"]["token"]), json=p)


def test_cles_en_attente_puis_plus_rien(client, duo):
    key = KeyManager().generate_key(256)
    assert envoyer_cle(client, duo, key).status_code == 202
    r = client.get("/keys/pending", headers=bearer(duo["bob"]["token"]))
    assert r.status_code == 200 and len(r.json()) == 1
    item = r.json()[0]
    assert set(item) == {"conversation_id", "from_user_id", "key_id", "wrapped_key_b64"}
    assert RSAKeyExchange.unwrap_key(duo["bob"]["priv"], item["wrapped_key_b64"]) == key     # le backend n'a rien casse
    assert client.get("/keys/pending", headers=bearer(duo["bob"]["token"])).json() == []
    assert client.get("/keys/pending", headers=bearer(duo["alice"]["token"])).json() == []


def test_exchange_validations(client, duo):
    key = KeyManager().generate_key(256)
    h = bearer(duo["alice"]["token"])
    base = {"conversation_id": conv(duo), "to_user_id": duo["bob"]["id"], "key_id": "k_0001", "wrapped_key_b64": "QUJD"}
    assert client.post("/keys/exchange", json=base).status_code == 401
    assert client.post("/keys/exchange", headers=h, json={**base, "conversation_id": "conv_x"}).status_code == 400
    assert client.post("/keys/exchange", headers=h, json={**base, "to_user_id": "u_inconnu"}).status_code == 404
    assert client.post("/keys/exchange", headers=h, json={**base, "wrapped_key_b64": "!!"}).status_code == 400
    assert client.post("/keys/exchange", headers=h, json={**base, "to_user_id": duo["alice"]["id"]}).status_code == 400


def test_scenario_rotation_forcee_T8(client, app, duo):
    """Le SOC ordonne une rotation : 409, nouvelle cle, message livre."""
    km = KeyManager()
    key1 = km.generate_key(256)
    envoyer_cle(client, duo, key1)
    assert message(client, duo, key1, 1).status_code == 202
    r = client.post(f"/internal/conversations/{conv(duo)}/force-rotation", headers=INTERNAL)
    assert r.status_code == 200 and r.json()["changed"] is True
    assert client.post(f"/internal/conversations/{conv(duo)}/force-rotation", headers=INTERNAL).json()["changed"] is False
    assert client.get(f"/conversations/{conv(duo)}/status", headers=bearer(duo["alice"]["token"])).json() == {"rotation_required": True}
    r = message(client, duo, key1, 2)
    assert r.status_code == 409 and r.json()["error"] == "KEY_ROTATION_REQUIRED"
    assert envoyer_cle(client, duo, key1).status_code == 409                 # meme key_id : refuse
    key2 = km.generate_key(256)
    assert key2.key_id != key1.key_id
    assert envoyer_cle(client, duo, key2).status_code == 202
    assert message(client, duo, key2, 3).status_code == 202
    assert client.get(f"/conversations/{conv(duo)}/status", headers=bearer(duo["alice"]["token"])).json() == {"rotation_required": False}


def test_force_rotation_all(client, duo):
    key = KeyManager().generate_key(256)
    envoyer_cle(client, duo, key)
    r = client.post(f"/internal/accounts/{duo['alice']['id']}/force-rotation-all", headers=INTERNAL)
    assert r.json() == {"user_id": duo["alice"]["id"], "conversations_marked": 1}
    assert client.post(f"/internal/accounts/{duo['alice']['id']}/force-rotation-all", headers=INTERNAL).json()["conversations_marked"] == 0
    assert message(client, duo, key, 1).status_code == 409
    assert client.post("/internal/conversations/conv_inconnue/force-rotation", headers=INTERNAL).status_code == 404


def test_lock_idempotent_audit_evenement_et_unlock(client, app, duo):
    uid = duo["alice"]["id"]
    r1 = client.post(f"/internal/accounts/{uid}/lock", headers=INTERNAL)
    r2 = client.post(f"/internal/accounts/{uid}/lock", headers=INTERNAL)
    assert r1.json() == {"user_id": uid, "status": "locked", "changed": True}
    assert r2.status_code == 200 and r2.json()["changed"] is False          # idempotent : succes sans erreur
    ev = types(app, "ACCOUNT_LOCKED")
    assert len(ev) == 1 and ev[0]["target"]["user_id"] == uid and ev[0]["severity"] == "medium"
    assert client.get("/users/bob/publickey", headers=bearer(duo["alice"]["token"])).status_code == 401
    r = client.post(f"/internal/accounts/{uid}/unlock", headers=INTERNAL)
    assert r.json()["status"] == "active" and types(app, "ACCOUNT_UNLOCKED")
    from sqlalchemy import text
    with app.state.engine.connect() as c:
        assert c.execute(text("select count(*) from audit_log where actor='soc'")).scalar() == 3
    assert client.post("/internal/accounts/u_inconnu/lock", headers=INTERNAL).status_code == 404


def test_lock_coupe_le_websocket(client, duo):
    from starlette.websockets import WebSocketDisconnect
    with client.websocket_connect(f"/ws?token={duo['alice']['token']}") as ws:
        client.post(f"/internal/accounts/{duo['alice']['id']}/lock", headers=INTERNAL)
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()


def test_internal_protege(client, duo, rsa_pems):
    uid = duo["alice"]["id"]
    assert client.post(f"/internal/accounts/{uid}/lock").status_code == 401
    assert client.post(f"/internal/accounts/{uid}/lock", headers={"X-API-Key": "faux"}).status_code == 401
    assert client.post(f"/internal/accounts/{uid}/lock", headers={"X-API-Key": ""}).status_code == 401
    assert client.post(f"/internal/accounts/{uid}/lock", headers=bearer(duo["alice"]["token"])).status_code == 401
    # IP non autorisee : meme avec la bonne cle
    app2 = create_app(make_settings(internal_allowed_ips=("127.0.0.1",)))
    with TestClient(app2, client=("203.0.113.9", 1)) as c2:
        r = c2.post("/internal/accounts/u_1/lock", headers=INTERNAL)
        assert r.status_code == 403 and r.json()["error"] == "FORBIDDEN_IP"
    # cle interne non configuree : tout est refuse, meme une cle vide
    app3 = create_app(make_settings(internal_key=""))
    with TestClient(app3, client=("203.0.113.9", 1)) as c3:
        assert c3.post("/internal/accounts/u_1/lock", headers={"X-API-Key": ""}).status_code == 401


def test_heartbeat_emis(rsa_pems):
    import time
    app = create_app(make_settings(heartbeat_seconds=3600))
    with TestClient(app) as c:
        time.sleep(0.3)
    hb = types(app, "HEARTBEAT")
    assert {e["source"] for e in hb} == {"auth", "relay"}
