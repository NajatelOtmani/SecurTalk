import json

import pytest
from sqlalchemy import text

from conftest import PW, bearer, make_settings, types

sdk = pytest.importorskip("securetalk_crypto")
from securetalk_crypto import KeyManager, RSAKeyExchange, ReplayGuard, decrypt_message, encrypt_message  # noqa: E402
from app.main import create_app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def conv(duo):
    a, b = sorted([duo["alice"]["id"], duo["bob"]["id"]])
    return f"conv_{a}_{b}"


def paquet(duo, texte="Bonjour", mode="GCM", counter=1, key=None, de="alice", a="bob"):
    key = key or KeyManager().generate_key(256)
    return encrypt_message(texte, key, mode, duo[de]["id"], duo[a]["id"], conv(duo), counter), key


@pytest.mark.parametrize("mode", ["GCM", "CMAC"])
def test_aller_retour_complet_avec_le_sdk(client, app, duo, mode):
    """T2 : Alice -> Bob, le relais ne voit rien, Bob dechiffre, ack -> MESSAGE_DELIVERED."""
    alice, bob = duo["alice"], duo["bob"]
    key = KeyManager().generate_key(256)
    wrapped = RSAKeyExchange.wrap_key(bob["pub"], key)
    with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
        r = client.post("/keys/exchange", headers=bearer(alice["token"]),
                        json={"conversation_id": conv(duo), "to_user_id": bob["id"],
                              "key_id": key.key_id, "wrapped_key_b64": wrapped})
        assert r.status_code == 202
        m = ws.receive_json()
        assert m["type"] == "key" and m["from_user_id"] == alice["id"]
        cle_bob = RSAKeyExchange.unwrap_key(bob["priv"], m["wrapped_key_b64"])
        p, _ = paquet(duo, "Bonjour Bob éàç 😀", mode, 1, key)
        r = client.post("/messages", headers=bearer(alice["token"]), json=p)
        assert r.status_code == 202 and r.json() == {"message_id": p["message_id"]}
        m = ws.receive_json()
        assert m["type"] == "message" and m["packet"] == p
        assert decrypt_message(m["packet"], cle_bob) == "Bonjour Bob éàç 😀"
        ReplayGuard().check(p["conversation_id"], p["sender_id"], p["key_id"], p["counter"])
        assert client.post(f"/messages/{p['message_id']}/ack", headers=bearer(bob["token"])).status_code == 204
        assert client.post(f"/messages/{p['message_id']}/ack", headers=bearer(bob["token"])).status_code == 204
    assert len(types(app, "PACKET_ROUTED")) == 1 and len(types(app, "MESSAGE_DELIVERED")) == 1
    routed = types(app, "PACKET_ROUTED")[0]
    assert routed["actor"]["user_id"] == alice["id"] and routed["target"]["user_id"] == bob["id"]
    assert routed["target"]["conversation_id"] == conv(duo) and routed["details"]["mode"] == mode
    # T3 : le texte en clair n'est nulle part dans la base ni dans les evenements
    with app.state.engine.connect() as c:
        dump = json.dumps([list(map(str, r)) for t in ("messages", "key_exchanges", "sessions", "users")
                           for r in c.execute(text(f"select * from {t}")).fetchall()])
    assert "Bonjour Bob" not in dump and "Bonjour Bob" not in json.dumps(app.state.emitter.events)


def test_livraison_differee_a_la_connexion_websocket(client, duo):
    alice, bob = duo["alice"], duo["bob"]
    for i in (1, 2):
        p, _ = paquet(duo, f"msg {i}", counter=i)
        assert client.post("/messages", headers=bearer(alice["token"]), json=p).status_code == 202
    with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
        assert [ws.receive_json()["packet"]["counter"] for _ in range(2)] == [1, 2]
    with client.websocket_connect(f"/ws?token={bob['token']}") as ws:      # pas de doublon
        p, _ = paquet(duo, "msg 3", counter=3)
        client.post("/messages", headers=bearer(alice["token"]), json=p)
        assert ws.receive_json()["packet"]["counter"] == 3


def test_websocket_jeton_invalide_refuse(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?token=nimporte"):
            pass
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws"):
            pass


@pytest.mark.parametrize("headers,raison", [({}, "missing_token"),
                                            ({"Authorization": "Bearer faux"}, "invalid_token"),
                                            ({"Authorization": "Basic abc"}, "invalid_token")])
def test_sans_jeton_valide_401_et_evenement(client, app, duo, headers, raison):
    p, _ = paquet(duo)
    r = client.post("/messages", headers=headers, json=p)
    assert r.status_code == 401
    ev = types(app, "PACKET_REJECTED_UNAUTH")[-1]
    assert ev["details"]["reason"] == raison and ev["actor"]["ip"] == "203.0.113.9"
    assert ev["severity"] == "medium" and ev["source"] == "relay"


def test_jeton_expire_sur_messages(client, app, duo):
    with app.state.engine.begin() as c:
        c.execute(text("update sessions set expires_at = '2000-01-01 00:00:00'"))
    p, _ = paquet(duo)
    assert client.post("/messages", headers=bearer(duo["alice"]["token"]), json=p).status_code == 401
    assert types(app, "PACKET_REJECTED_UNAUTH")[-1]["details"]["reason"] == "expired_token"


def test_usurpation_sender_mismatch(client, app, duo):
    p, _ = paquet(duo, de="bob", a="alice")                      # paquet "de Bob" envoye avec le jeton d'Alice
    r = client.post("/messages", headers=bearer(duo["alice"]["token"]), json=p)
    assert r.status_code == 403 and r.json()["error"] == "SENDER_MISMATCH"
    ev = types(app, "PACKET_REJECTED_UNAUTH")[-1]
    assert ev["details"]["reason"] == "sender_mismatch" and ev["actor"]["user_id"] == duo["bob"]["id"]
    assert ev["details"]["authenticated_user_id"] == duo["alice"]["id"]


def test_formats_invalides(client, duo):
    h = bearer(duo["alice"]["token"])
    p, _ = paquet(duo)
    for mauvais in ({**p, "mode": "ECB"}, {**p, "counter": 0}, {**p, "counter": "1"}, {**p, "message_id": "x"},
                    {**p, "tag_b64": "pas du base64 !"}, {**p, "extra": 1}, {k: v for k, v in p.items() if k != "tag_b64"},
                    {**p, "timestamp": "hier"}):
        r = client.post("/messages", headers=h, json=mauvais)
        assert r.status_code == 400 and r.json()["error"] == "INVALID_FORMAT", mauvais
    assert client.post("/messages", headers=h, content=b"pas du json").status_code == 400
    assert client.post("/messages", headers=h, content=b"[1,2]").status_code == 400
    r = client.post("/messages", headers=h, json={**p, "conversation_id": "conv_autre"})
    assert r.status_code == 400 and r.json()["error"] == "INVALID_CONVERSATION"
    assert "Bonjour" not in r.text


def test_destinataire_inconnu_et_doublon(client, duo):
    h = bearer(duo["alice"]["token"])
    p, _ = paquet(duo)
    r = client.post("/messages", headers=h, json={**p, "receiver_id": "u_inexistant",
                                                  "conversation_id": "conv_u_inexistant_" + duo["alice"]["id"]})
    assert r.status_code == 404
    assert client.post("/messages", headers=h, json=p).status_code == 202
    assert client.post("/messages", headers=h, json=p).status_code == 409


def test_paquet_trop_gros_413(client, duo):
    h = bearer(duo["alice"]["token"])
    p, _ = paquet(duo)
    r = client.post("/messages", headers=h, content=json.dumps({**p, "ciphertext_b64": "A" * 70000}))
    assert r.status_code == 413 and r.json()["error"] == "PACKET_TOO_LARGE"


def test_limitation_de_debit_429(duo, rsa_pems):
    app = create_app(make_settings(rate_limit_per_minute=3))
    with TestClient(app, client=("203.0.113.9", 1)) as c:
        ids = {}
        for nom, (_, pub) in zip(("alice", "bob"), rsa_pems):
            ids[nom] = c.post("/auth/register", json={"username": nom, "password": PW, "public_key_pem": pub}).json()["user_id"]
        tok = c.post("/auth/login", json={"username": "alice", "password": PW}).json()["token"]
        a, b = sorted(ids.values())
        key, codes = KeyManager().generate_key(256), []
        for i in range(1, 6):
            p = encrypt_message("x", key, "GCM", ids["alice"], ids["bob"], f"conv_{a}_{b}", i)
            codes.append(c.post("/messages", headers=bearer(tok), json=p).status_code)
        assert codes == [202, 202, 202, 429, 429]
        ev = types(app, "RATE_LIMIT_EXCEEDED")
        assert len(ev) == 2 and ev[0]["actor"]["user_id"] == ids["alice"] and ev[0]["severity"] == "medium"


def test_conversation_status_reserve_aux_membres(client, duo):
    assert client.get(f"/conversations/{conv(duo)}/status", headers=bearer(duo["bob"]["token"])).json() == {"rotation_required": False}
    assert client.get("/conversations/conv_u_x_u_y/status", headers=bearer(duo["bob"]["token"])).status_code == 403
    assert client.get(f"/conversations/{conv(duo)}/status").status_code == 401


def test_ack_reserve_au_destinataire(client, duo):
    p, _ = paquet(duo)
    client.post("/messages", headers=bearer(duo["alice"]["token"]), json=p)
    assert client.post(f"/messages/{p['message_id']}/ack", headers=bearer(duo["alice"]["token"])).status_code == 404
    assert client.post("/messages/inconnu/ack", headers=bearer(duo["bob"]["token"])).status_code == 404


def test_release_annule_la_reservation(client, app, duo):
    p, _ = paquet(duo)
    client.post("/messages", headers=bearer(duo["alice"]["token"]), json=p)
    relay = app.state.relay
    assert relay.claim("message", p["message_id"]) is True
    assert relay.claim("message", p["message_id"]) is False          # deja reserve : pas de doublon
    relay.release("message", p["message_id"])
    assert [k for k, _, _ in relay.list_undelivered(duo["bob"]["id"])] == ["message"]
