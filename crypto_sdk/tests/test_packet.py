import base64
import copy

import pytest

from securetalk_crypto import (AuthTagError, KeyManager, ReplayError, ReplayGuard,
                               decrypt_message, encrypt_message)

MODES = ["GCM", "CMAC"]
MESSAGES = ["", "a", "Bonjour", "x" * 5000, "éàçùœ ñ ü", "Salam 😀🔐 ça va ?", "ligne1\nligne2\t|pipe"]


def chiffre(cle, mode, texte="Bonjour", counter=1):
    return encrypt_message(texte, cle, mode, "u_1a", "u_2b", "conv_u_1a_u_2b", counter)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("texte", MESSAGES)
def test_aller_retour(cle, mode, texte):
    assert decrypt_message(chiffre(cle, mode, texte), cle) == texte


@pytest.mark.parametrize("mode", MODES)
def test_champs_du_contrat(cle, mode):
    p = chiffre(cle, mode)
    assert set(p) == {"message_id", "conversation_id", "sender_id", "receiver_id", "mode",
                      "key_id", "counter", "nonce_b64", "ciphertext_b64", "tag_b64", "timestamp"}
    assert p["mode"] == mode and p["key_id"] == cle.key_id and p["counter"] == 1
    assert len(base64.b64decode(p["nonce_b64"])) == (12 if mode == "GCM" else 16)
    assert len(base64.b64decode(p["tag_b64"])) == 16
    assert p["timestamp"].endswith("Z")


def _flip(b64):
    b = bytearray(base64.b64decode(b64))
    b[0] ^= 0x01
    return base64.b64encode(bytes(b)).decode()


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("champ", ["ciphertext_b64", "tag_b64", "nonce_b64"])
def test_bit_modifie_dans_les_octets(cle, mode, champ):
    p = chiffre(cle, mode)
    p[champ] = _flip(p[champ])
    with pytest.raises(AuthTagError):
        decrypt_message(p, cle)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("champ,valeur", [
    ("sender_id", "u_evil"), ("receiver_id", "u_evil"), ("conversation_id", "conv_x"),
    ("counter", 2), ("key_id", "k_autre"), ("message_id", "autre-id"),
    ("mode", "GCM"),  # change ci-dessous selon le mode
])
def test_champ_authentifie_modifie(cle, mode, champ, valeur):
    p = chiffre(cle, mode)
    if champ == "mode":
        valeur = "CMAC" if mode == "GCM" else "GCM"
    p[champ] = valeur
    with pytest.raises(AuthTagError):
        decrypt_message(p, cle)


@pytest.mark.parametrize("mode", MODES)
def test_mauvaise_cle(cle, mode):
    autre = KeyManager().generate_key(256)
    with pytest.raises(AuthTagError):
        decrypt_message(chiffre(cle, mode), autre)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("bits", [128, 192, 256])
def test_toutes_les_tailles(mode, bits):
    k = KeyManager().generate_key(bits)
    assert decrypt_message(chiffre(k, mode, "ok"), k) == "ok"


@pytest.mark.parametrize("mode", MODES)
def test_deux_chiffrements_differents(cle, mode):
    a, b = chiffre(cle, mode), chiffre(cle, mode)
    assert a["nonce_b64"] != b["nonce_b64"]
    assert a["ciphertext_b64"] != b["ciphertext_b64"]


@pytest.mark.parametrize("mode", MODES)
def test_rejeu_meme_paquet(cle, mode):
    g = ReplayGuard()
    p = chiffre(cle, mode)
    assert decrypt_message(p, cle, g) == "Bonjour"
    with pytest.raises(ReplayError):
        decrypt_message(p, cle, g)


@pytest.mark.parametrize("mode", MODES)
def test_compteur_plus_ancien(cle, mode):
    g = ReplayGuard()
    decrypt_message(chiffre(cle, mode, counter=5), cle, g)
    with pytest.raises(ReplayError):
        decrypt_message(chiffre(cle, mode, counter=3), cle, g)
    assert decrypt_message(chiffre(cle, mode, counter=6), cle, g) == "Bonjour"


def test_replay_guard_api_du_guide(cle):
    g = ReplayGuard()
    p = chiffre(cle, "GCM")
    assert g.check(p["conversation_id"], p["sender_id"], p["key_id"], p["counter"]) is None
    with pytest.raises(ReplayError):
        g.check(p["conversation_id"], p["sender_id"], p["key_id"], p["counter"])


def test_faux_paquet_ne_brule_pas_le_compteur(cle):
    """Un paquet au tag faux ne doit PAS avancer le compteur (guide 3.2 point 6)."""
    g = ReplayGuard()
    bon = chiffre(cle, "GCM", counter=1)
    faux = copy.deepcopy(bon)
    faux["counter"] = 99
    with pytest.raises(AuthTagError):
        decrypt_message(faux, cle, g)
    assert decrypt_message(bon, cle, g) == "Bonjour"


@pytest.mark.parametrize("mauvais", [None, "texte", {}, {"mode": "GCM"}])
def test_paquet_mal_forme(cle, mauvais):
    with pytest.raises(AuthTagError):
        decrypt_message(mauvais, cle)


def test_base64_invalide_et_longueurs(cle):
    for mode in MODES:
        p = chiffre(cle, mode)
        q = dict(p, ciphertext_b64="!!pas-base64!!")
        with pytest.raises(AuthTagError):
            decrypt_message(q, cle)
        q = dict(p, tag_b64=base64.b64encode(b"court").decode())
        with pytest.raises(AuthTagError):
            decrypt_message(q, cle)
        q = dict(p, nonce_b64=base64.b64encode(b"x").decode())
        with pytest.raises(AuthTagError):
            decrypt_message(q, cle)


def test_arguments_invalides_a_l_envoi(cle):
    with pytest.raises(ValueError):
        encrypt_message("a", cle, "RC4", "u_1a", "u_2b", "c", 1)
    with pytest.raises(ValueError):
        encrypt_message("a", cle, "GCM", "u_1a", "u_2b", "c", 0)
    with pytest.raises(ValueError):
        encrypt_message("a", cle, "GCM", "u|1a", "u_2b", "c", 1)


def test_compteur_de_messages_pour_rotation(cle):
    km = KeyManager()
    for i in range(1, 4):
        chiffre(cle, "GCM", counter=i)
    assert cle.messages_sent == 3
    assert not km.should_rotate(cle)
    assert km.should_rotate(cle, max_messages=3)
