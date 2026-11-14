import copy
import pytest


def test_aller_retour_et_texte_absent(pair):
    a, b, net = pair
    p = a.send_text("u_b", "Bonjour Bob")
    assert "Bonjour" not in str(p)
    b.receive_key(net.keys[0])
    assert b.read(p) == "Bonjour Bob"


def test_paquet_falsifie(pair):
    a, b, net = pair
    p = a.send_text("u_b", "salut")
    b.receive_key(net.keys[0])
    bad = copy.deepcopy(p)
    bad["sender_id"] = "u_x"
    with pytest.raises(b.sdk.AuthTagError):
        b.read(bad)


def test_rejeu(pair):
    a, b, net = pair
    p = a.send_text("u_b", "salut")
    b.receive_key(net.keys[0])
    b.read(p)
    with pytest.raises(b.sdk.ReplayError):
        b.read(p)


def test_mode_cmac(pair):
    a, b, net = pair
    a.mode = "CMAC"
    p = a.send_text("u_b", "en CMAC")
    b.receive_key(net.keys[0])
    assert p["mode"] == "CMAC" and b.read(p) == "en CMAC"


def test_409_rotation_puis_renvoi(pair):
    """T8 : le SOC exige une rotation -> 409 -> nouvelle clé -> message livré."""
    a, b, net = pair
    a.send_text("u_b", "premier")
    old_id = a.key_info("u_b")[0]
    net.rotation_required = True
    p = a.send_text("u_b", "deuxième")
    assert a.last_rotated is True
    assert p["key_id"] != old_id and len(net.keys) == 2
    assert net.pkts[-1]["message_id"] == p["message_id"]
    for k in net.keys:
        b.receive_key(k)
    assert b.read(p) == "deuxième"


def test_pas_de_rotation_normale(pair):
    a, _, _ = pair
    a.send_text("u_b", "x")
    assert a.last_rotated is False


def test_cles_rechargees_apres_redemarrage(pair):
    from chat_service import ChatService
    a, b, net = pair
    a.send_text("u_b", "un")
    a2 = ChatService(a.client)
    a2.pubkeys["u_b"] = net.pubs["bob"]
    p = a2.send_text("u_b", "deux")
    assert len(net.keys) == 1 and p["counter"] == 2


def test_cles_sur_disque_enveloppees(pair, net):
    import storage
    a, _, _ = pair
    a.send_text("u_b", "x")
    contenu = (storage.user_dir("alice") / "keys.json").read_text()
    assert "wrapped" in contenu and "key_bytes" not in contenu


def test_age_et_format():
    from datetime import datetime, timedelta, timezone
    from chat_service import key_age_seconds, format_age
    now = datetime.now(timezone.utc)
    assert 590 <= key_age_seconds(now - timedelta(minutes=10)) <= 610
    assert 590 <= key_age_seconds((now - timedelta(minutes=10)).isoformat()) <= 610
    assert 590 <= key_age_seconds(now.timestamp() - 600) <= 610
    assert key_age_seconds(None) is None and key_age_seconds("pas une date") is None
    assert format_age(5) == "à l'instant" and format_age(300) == "5 min" and format_age(3900) == "1 h 05"
    assert format_age(None) == "—"


def test_key_details_envoi_puis_reception(pair):
    a, b, net = pair
    assert a.key_details("u_b") is None
    a.send_text("u_b", "x")
    d = a.key_details("u_b")
    assert d["direction"] == "envoi" and d["bits"] == 256 and d["needs_rotation"] is False
    assert d["age_s"] is None or d["age_s"] >= 0
    b.receive_key(net.keys[0])
    assert b.key_details("u_a")["direction"] == "réception"
