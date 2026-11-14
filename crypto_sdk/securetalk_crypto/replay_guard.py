"""Protection contre le rejeu (replay)."""
import threading

from .errors import ReplayError


class ReplayGuard:
    """Accepte un paquet seulement si counter > dernier compteur vu.

    Le compteur est suivi par (conversation_id, sender_id, key_id).
    A appeler APRES verification du tag (decrypt_message le fait pour toi
    si tu lui passes replay_guard=...), sinon un attaquant pourrait
    "bruler" tes compteurs avec de faux paquets.
    """

    def __init__(self):
        self._last = {}
        self._lock = threading.Lock()

    def check(self, conversation_id, sender_id, key_id, counter):
        if isinstance(counter, bool) or not isinstance(counter, int) or counter < 1:
            raise ReplayError("Compteur invalide")
        cle = (conversation_id, sender_id, key_id)
        with self._lock:
            if counter <= self._last.get(cle, 0):
                raise ReplayError("Paquet rejoue ou trop ancien")
            self._last[cle] = counter

    def last_counter(self, conversation_id, sender_id, key_id):
        with self._lock:
            return self._last.get((conversation_id, sender_id, key_id), 0)
