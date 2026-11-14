"""Chiffrement / dechiffrement d'un message : le paquet du guide (section 2.6).

Deux modes :
  GCM  : AES-GCM avec la SessionKey, AAD liee au tag.
  CMAC : AES-CBC + AES-CMAC (Encrypt-then-MAC). Deux cles derivees par HKDF.
         tag = CMAC_kmac( len(AAD) || AAD || IV || texte_chiffre )

Ordre au dechiffrement : (a) tag -> (b) anti-rejeu -> (c) dechiffrement.
"""
import base64
import os
import struct
import uuid
from datetime import datetime, timezone

from . import modes
from .errors import AuthTagError
from .kdf import hkdf_sha256

MODE_GCM = "GCM"
MODE_CMAC = "CMAC"
MODES_VALIDES = (MODE_GCM, MODE_CMAC)
TAILLE_IV_CBC = 16
TAILLE_TAG = 16

CHAMPS = ("message_id", "conversation_id", "sender_id", "receiver_id", "mode",
          "key_id", "counter", "nonce_b64", "ciphertext_b64", "tag_b64", "timestamp")


def _b64e(octets):
    return base64.b64encode(octets).decode("ascii")


def _b64d(texte):
    if not isinstance(texte, str):
        raise AuthTagError("Paquet invalide")
    try:
        return base64.b64decode(texte.encode("ascii"), validate=True)
    except Exception:
        raise AuthTagError("Paquet invalide") from None


def _aad(message_id, conversation_id, sender_id, receiver_id, mode, key_id, counter):
    """message_id|conversation_id|sender_id|receiver_id|mode|key_id|counter"""
    champs = [message_id, conversation_id, sender_id, receiver_id, mode, key_id]
    for c in champs:
        if not isinstance(c, str) or not c or "|" in c:
            raise ValueError("Champ invalide (vide ou contenant '|')")
    return "|".join(champs + [str(counter)]).encode("utf-8")


def _cles_cmac(cle_session):
    """Deux cles independantes (meme taille que la SessionKey) via HKDF."""
    taille = len(cle_session)
    return (hkdf_sha256(cle_session, b"securetalk-v1 cbc-encryption", taille),
            hkdf_sha256(cle_session, b"securetalk-v1 cmac-authentication", taille))


def _donnees_cmac(aad, iv, chiffre):
    return struct.pack(">I", len(aad)) + aad + iv + chiffre


def encrypt_message(plaintext, key, mode, sender_id, receiver_id, conversation_id, counter):
    """Retourne le dictionnaire Message (guide 2.6). Le SDK ne touche pas au reseau."""
    if mode not in MODES_VALIDES:
        raise ValueError("mode doit valoir 'GCM' ou 'CMAC'")
    if isinstance(counter, bool) or not isinstance(counter, int) or counter < 1:
        raise ValueError("counter doit etre un entier >= 1")
    message_id = str(uuid.uuid4())
    aad = _aad(message_id, conversation_id, sender_id, receiver_id, mode, key.key_id, counter)
    clair = plaintext.encode("utf-8")
    cle = key.key_bytes

    if mode == MODE_GCM:
        nonce = os.urandom(modes.TAILLE_NONCE)                  # jamais reutilise
        chiffre, tag = modes.gcm_chiffre(clair, cle, nonce, aad)
    else:
        k_enc, k_mac = _cles_cmac(cle)
        nonce = os.urandom(TAILLE_IV_CBC)                        # IV aleatoire a chaque message
        chiffre = modes.cbc_chiffre(clair, k_enc, nonce)
        tag = modes.cmac(_donnees_cmac(aad, nonce, chiffre), k_mac)

    key.register_use()
    return {
        "message_id": message_id,
        "conversation_id": conversation_id,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "mode": mode,
        "key_id": key.key_id,
        "counter": counter,
        "nonce_b64": _b64e(nonce),
        "ciphertext_b64": _b64e(chiffre),
        "tag_b64": _b64e(tag),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def decrypt_message(packet, key, replay_guard=None):
    """Verifie le tag, (anti-rejeu), puis dechiffre. Retourne le texte.

    Leve AuthTagError (tag faux, paquet mal forme, mauvaise cle) ou, si
    `replay_guard` est fourni, ReplayError (paquet rejoue).
    """
    try:
        if not isinstance(packet, dict) or any(c not in packet for c in CHAMPS):
            raise AuthTagError("Paquet invalide")
        mode = packet["mode"]
        counter = packet["counter"]
        if mode not in MODES_VALIDES or isinstance(counter, bool) or not isinstance(counter, int) or counter < 1:
            raise AuthTagError("Paquet invalide")
        aad = _aad(packet["message_id"], packet["conversation_id"], packet["sender_id"],
                   packet["receiver_id"], mode, packet["key_id"], counter)
    except ValueError:
        raise AuthTagError("Paquet invalide") from None

    nonce = _b64d(packet["nonce_b64"])
    chiffre = _b64d(packet["ciphertext_b64"])
    tag = _b64d(packet["tag_b64"])
    cle = key.key_bytes

    if len(tag) != TAILLE_TAG:
        raise AuthTagError("Paquet invalide")

    # (a) verification du tag AVANT tout dechiffrement
    if mode == MODE_GCM:
        if len(nonce) != modes.TAILLE_NONCE:
            raise AuthTagError("Paquet invalide")
        if not _egal(tag, modes.gcm_tag(chiffre, cle, nonce, aad)):
            raise AuthTagError("Tag invalide")
    else:
        if len(nonce) != TAILLE_IV_CBC or len(chiffre) == 0 or len(chiffre) % 16 != 0:
            raise AuthTagError("Paquet invalide")
        k_enc, k_mac = _cles_cmac(cle)
        if not modes.cmac_verifie(tag, _donnees_cmac(aad, nonce, chiffre), k_mac):
            raise AuthTagError("Tag invalide")

    # (b) anti-rejeu : seulement apres un tag valide
    if replay_guard is not None:
        replay_guard.check(packet["conversation_id"], packet["sender_id"],
                           packet["key_id"], counter)

    # (c) dechiffrement
    try:
        if mode == MODE_GCM:
            clair = modes.gcm_ctr(chiffre, cle, nonce)
        else:
            clair = modes.cbc_dechiffre(chiffre, k_enc, nonce)
        return clair.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise AuthTagError("Tag invalide") from None


def _egal(a, b):
    import hmac
    return hmac.compare_digest(a, b)
