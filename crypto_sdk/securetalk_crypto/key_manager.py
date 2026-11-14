"""Cles de session et rotation."""
import hmac
import secrets
import threading
import time

from .errors import UnknownKeyError

TAILLES_BITS = (128, 192, 256)


class SessionKey:
    """Cle AES d'une conversation. Ne montre JAMAIS ses octets dans repr/str."""

    def __init__(self, key_id, bits, key_bytes, created_at=None):
        if bits not in TAILLES_BITS or len(key_bytes) * 8 != bits:
            raise ValueError("Cle AES : 128, 192 ou 256 bits")
        self.key_id = key_id
        self.bits = bits
        self._key = bytearray(key_bytes)
        self.created_at = time.time() if created_at is None else created_at
        self.messages_sent = 0

    @property
    def key_bytes(self):
        return bytes(self._key)

    def register_use(self):
        """Appelee a chaque message chiffre (sert a should_rotate)."""
        self.messages_sent += 1

    def wipe(self):
        """Efface la cle de la memoire (au mieux de ce que Python permet)."""
        for i in range(len(self._key)):
            self._key[i] = 0

    def __repr__(self):
        return f"SessionKey(key_id={self.key_id}, bits={self.bits})"

    __str__ = __repr__

    def __eq__(self, other):
        return (isinstance(other, SessionKey) and self.key_id == other.key_id
                and hmac.compare_digest(self.key_bytes, other.key_bytes))

    __hash__ = None


class KeyManager:
    """Cree les cles, les fait tourner, garde l'ancienne quelques minutes."""

    def __init__(self, retention_seconds=300, clock=time.time):
        self._retention = retention_seconds
        self._clock = clock
        self._current = {}      # conversation_id -> SessionKey
        self._old = {}          # conversation_id -> [(SessionKey, expire_a)]
        self._lock = threading.RLock()

    def generate_key(self, bits=256):
        if bits not in TAILLES_BITS:
            raise ValueError("bits doit valoir 128, 192 ou 256")
        return SessionKey("k_" + secrets.token_hex(4), bits,
                          secrets.token_bytes(bits // 8), self._clock())

    def rotate_key(self, conversation_id, bits=None):
        """Nouvelle cle ; l'ancienne reste valable `retention_seconds`.

        Sans `bits`, on applique ta rotation du cours : 128 -> 192 -> 256 -> 128.
        """
        with self._lock:
            ancienne = self._current.get(conversation_id)
            if bits is None:
                if ancienne is None:
                    bits = 256
                else:
                    bits = TAILLES_BITS[(TAILLES_BITS.index(ancienne.bits) + 1) % 3]
            nouvelle = self.generate_key(bits)
            if ancienne is not None:
                self._old.setdefault(conversation_id, []).append(
                    (ancienne, self._clock() + self._retention))
            self._current[conversation_id] = nouvelle
            return nouvelle

    def add_key(self, conversation_id, key):
        """Cote receveur : enregistre la cle recue (apres unwrap_key)."""
        with self._lock:
            ancienne = self._current.get(conversation_id)
            if ancienne is not None and ancienne.key_id != key.key_id:
                self._old.setdefault(conversation_id, []).append(
                    (ancienne, self._clock() + self._retention))
            self._current[conversation_id] = key

    def current_key(self, conversation_id):
        with self._lock:
            cle = self._current.get(conversation_id)
        if cle is None:
            raise UnknownKeyError("Aucune cle pour cette conversation")
        return cle

    def get_key(self, conversation_id, key_id):
        """Retrouve une cle par son key_id (courante, ou ancienne non expiree)."""
        with self._lock:
            cle = self._current.get(conversation_id)
            if cle is not None and cle.key_id == key_id:
                return cle
            maintenant = self._clock()
            gardees = [(k, t) for (k, t) in self._old.get(conversation_id, []) if t > maintenant]
            self._old[conversation_id] = gardees
            for k, _t in gardees:
                if k.key_id == key_id:
                    return k
        raise UnknownKeyError("Cle inconnue ou expiree")

    def should_rotate(self, key, max_messages=500, max_age_seconds=3600):
        """Vrai si la cle a servi pour trop de messages ou est trop vieille."""
        return (key.messages_sent >= max_messages
                or self._clock() - key.created_at >= max_age_seconds)
