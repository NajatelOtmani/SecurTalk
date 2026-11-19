"""Stockage LOCAL : la clé privée RSA ne quitte jamais cette machine (guide 7.5)."""
import os
from pathlib import Path


def user_dir(username):
    d = Path.home() / ".securetalk" / username
    d.mkdir(parents=True, exist_ok=True)
    return d


class PasswordRequired(Exception):
    """La clé privée locale est chiffrée : il faut le mot de passe."""


class WrongPassword(Exception):
    pass


_AAD = b"securetalk-private-key-v1"


def _derive(password, salt):
    import hashlib
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def _encrypt(pem, password):
    import base64, json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_derive(password, salt)).encrypt(nonce, pem.encode("utf-8"), _AAD)
    b = lambda x: base64.b64encode(x).decode()  # noqa: E731
    return json.dumps({"v": 1, "kdf": "scrypt-n14-r8-p1", "salt": b(salt), "nonce": b(nonce), "ct": b(ct)})


def _decrypt(blob, password):
    import base64, json
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    d = json.loads(blob)
    key = _derive(password, base64.b64decode(d["salt"]))
    try:
        return AESGCM(key).decrypt(base64.b64decode(d["nonce"]), base64.b64decode(d["ct"]), _AAD).decode("utf-8")
    except InvalidTag:
        raise WrongPassword()


def has_private_key(username):
    d = user_dir(username)
    return (d / "private.pem.enc").exists() or (d / "private.pem").exists()


def generate_keypair():
    """Retourne (private_pem, public_pem) via le SDK crypto."""
    from securetalk_crypto import RSAKeyExchange
    return RSAKeyExchange.generate_keypair()


def save_private_key(username, private_pem, password=None):
    """Avec mot de passe : fichier chiffré private.pem.enc (recommandé, guide 7.5).
    Sans mot de passe : ancien fichier en clair (compatibilité et tests uniquement)."""
    pem = private_pem if isinstance(private_pem, str) else private_pem.decode()
    d = user_dir(username)
    if password:
        (d / "private.pem.enc").write_text(_encrypt(pem, password), encoding="utf-8")
        target = d / "private.pem.enc"
        old = d / "private.pem"
        if old.exists():
            old.unlink()  # on ne garde plus de copie en clair
    else:
        target = d / "private.pem"
        target.write_text(pem)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def load_private_key(username, password=None):
    """Déchiffre la clé. Si l'ancien fichier en clair existe et qu'on a le mot de passe : migration automatique."""
    d = user_dir(username)
    enc, plain = d / "private.pem.enc", d / "private.pem"
    if enc.exists():
        if not password:
            raise PasswordRequired()
        return _decrypt(enc.read_text(encoding="utf-8"), password)
    pem = plain.read_text()
    if password:
        save_private_key(username, pem, password)
    return pem


def next_counter(username, conversation_id, key_id):
    """Compteur croissant sauvegardé sur disque (sinon ReplayError après redémarrage)."""
    import json
    f = user_dir(username) / "counters.json"
    try:
        data = json.loads(f.read_text())
    except (OSError, ValueError):
        data = {}
    k = f"{conversation_id}|{key_id}"
    data[k] = int(data.get(k, 0)) + 1
    f.write_text(json.dumps(data))
    return data[k]


def save_keys(username, data):
    """data ne contient que des clés ENVELOPPÉES en RSA (wrapped_key_b64), jamais d'octets de clé."""
    import json
    (user_dir(username) / "keys.json").write_text(json.dumps(data))


def load_keys(username):
    import json
    try:
        return json.loads((user_dir(username) / "keys.json").read_text())
    except (OSError, ValueError):
        return {}
