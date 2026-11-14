"""Logique du chat, SANS interface (guide 7.1). Utilise le SDK crypto (étape 5).

Principe : chaque côté crée SA clé de session pour envoyer (send_keys) et garde
les clés reçues de l'autre (recv_keys). Les clés ne sont jamais écrites en clair :
sur disque on garde uniquement leur version enveloppée en RSA (keys.json)."""
import threading
from datetime import datetime, timezone
import storage
from api_backend import ApiError


def conversation_id(a, b):
    x, y = sorted([a, b])
    return f"conv_{x}_{y}"


def local_time(iso):
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone().strftime("%H:%M")
    except (ValueError, AttributeError):
        return datetime.now().strftime("%H:%M")


def key_age_seconds(created):
    """Âge d'une clé en secondes. Accepte datetime, timestamp ou texte ISO (selon le SDK)."""
    try:
        if created is None:
            return None
        if isinstance(created, (int, float)):
            return max(0, int(datetime.now(timezone.utc).timestamp() - created))
        if isinstance(created, str):
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - created).total_seconds()))
    except (ValueError, TypeError, AttributeError, OverflowError, OSError):
        return None


def format_age(seconds):
    if seconds is None:
        return "—"
    if seconds < 60:
        return "à l'instant"
    m = seconds // 60
    return f"{m} min" if m < 60 else f"{m // 60} h {m % 60:02d}"


class ChatService:
    def __init__(self, client, mode="GCM"):
        import securetalk_crypto as sdk  # ImportError si le SDK n'est pas installé
        self.sdk, self.client, self.mode = sdk, client, mode
        self.km, self.guard, self._lock = sdk.KeyManager(), sdk.ReplayGuard(), threading.Lock()
        self.priv = getattr(client, "private_pem", None) or storage.load_private_key(client.username)
        self.pubkeys = {}          # user_id -> clé publique PEM du contact
        self._my_pub = None
        self.last_rotated = False  # True si le dernier envoi a dû renouveler la clé (409)
        self.send_keys = {}        # conv -> {"key", "wrapped"}
        self.recv_keys = {}        # (conv, key_id) -> {"key", "wrapped"}
        self._load()

    # ----- persistance (clés enveloppées uniquement) -----
    def _load(self):
        data = storage.load_keys(self.client.username)
        try:
            for conv, e in data.get("send", {}).items():
                self.send_keys[conv] = {"key": self.sdk.RSAKeyExchange.unwrap_key(self.priv, e["wrapped"]),
                                        "wrapped": e["wrapped"]}
            for e in data.get("recv", []):
                self.recv_keys[(e["conv"], e["key_id"])] = {
                    "key": self.sdk.RSAKeyExchange.unwrap_key(self.priv, e["wrapped"]), "wrapped": e["wrapped"]}
        except Exception:  # noqa: BLE001  (clé locale changée : on repart de zéro)
            self.send_keys.clear()
            self.recv_keys.clear()

    def _save(self):
        storage.save_keys(self.client.username, {
            "send": {c: {"wrapped": e["wrapped"]} for c, e in self.send_keys.items()},
            "recv": [{"conv": c, "key_id": k, "wrapped": e["wrapped"]} for (c, k), e in self.recv_keys.items()]})

    # ----- clés d'envoi -----
    def _my_public(self):
        if not self._my_pub:
            self._my_pub = self.client.public_key(self.client.username)["public_key_pem"]
        return self._my_pub

    def _new_send_key(self, conv, peer_id, rotate):
        if peer_id not in self.pubkeys:
            raise KeyError("peer_unknown")
        old = self.send_keys.get(conv)
        try:
            key = self.km.rotate_key(conv) if rotate else self.km.generate_key(256)
        except Exception:  # noqa: BLE001
            key = self.km.generate_key(256)
        for _ in range(3):  # après un 409, le key_id DOIT être nouveau (guide 2.8)
            if not old or key.key_id != old["key"].key_id:
                break
            key = self.km.generate_key(256)
        RSA = self.sdk.RSAKeyExchange
        self.client.exchange_key(conv, peer_id, key.key_id, RSA.wrap_key(self.pubkeys[peer_id], key))
        self.send_keys[conv] = {"key": key, "wrapped": RSA.wrap_key(self._my_public(), key)}
        self._save()
        return self.send_keys[conv]

    def rotate(self, peer_id):
        with self._lock:
            return self._new_send_key(conversation_id(self.client.user_id, peer_id), peer_id, True)["key"]

    def key_info(self, peer_id):
        conv = conversation_id(self.client.user_id, peer_id)
        e = self.send_keys.get(conv)
        if e is None:  # conversation où l'on n'a fait que recevoir : on affiche la dernière clé reçue
            for (c, _k), r in reversed(list(self.recv_keys.items())):
                if c == conv:
                    e = r
                    break
        return (e["key"].key_id, e["key"].bits) if e else None

    def key_details(self, peer_id):
        """Infos réelles pour le panneau de sécurité (None si aucune clé)."""
        conv = conversation_id(self.client.user_id, peer_id)
        e, direction = self.send_keys.get(conv), "envoi"
        if e is None:
            direction = "réception"
            for (c, _k), r in reversed(list(self.recv_keys.items())):
                if c == conv:
                    e = r
                    break
        if e is None:
            return None
        k = e["key"]
        try:
            need = direction == "envoi" and bool(self.km.should_rotate(k))
        except Exception:  # noqa: BLE001
            need = False
        return {"key_id": k.key_id, "bits": k.bits, "direction": direction, "needs_rotation": need,
                "age_s": key_age_seconds(getattr(k, "created_at", None))}

    # ----- envoi -----
    def send_text(self, peer_id, text):
        me = self.client.user_id
        conv = conversation_id(me, peer_id)
        with self._lock:
            e = self.send_keys.get(conv)
            if e is None:
                e = self._new_send_key(conv, peer_id, False)
            elif self.km.should_rotate(e["key"]):
                e = self._new_send_key(conv, peer_id, True)
            self.last_rotated = False
            packet = self._encrypt_and_post(text, e["key"], me, peer_id, conv)
            return packet

    def _encrypt_and_post(self, text, key, me, peer_id, conv, retry=True):
        counter = storage.next_counter(self.client.username, conv, key.key_id)
        packet = self.sdk.encrypt_message(text, key, self.mode, me, peer_id, conv, counter)
        try:
            self.client.send_packet(packet)
        except ApiError as err:
            if err.code != "KEY_ROTATION_REQUIRED" or not retry:
                raise
            # ordre du SOC : nouvelle clé + nouvel échange RSA, puis on renvoie le MÊME texte
            newkey = self._new_send_key(conv, peer_id, True)["key"]
            self.last_rotated = True
            return self._encrypt_and_post(text, newkey, me, peer_id, conv, retry=False)
        return packet

    # ----- réception : tag -> anti-rejeu -> affichage (guide 7.3) -----
    def receive_key(self, data):
        conv, kid, w = data["conversation_id"], data["key_id"], data["wrapped_key_b64"]
        key = self.sdk.RSAKeyExchange.unwrap_key(self.priv, w)  # KeyExchangeError si échec
        with self._lock:
            self.recv_keys[(conv, kid)] = {"key": key, "wrapped": w}
            self._save()
        return kid

    def read(self, packet):
        e = self.recv_keys.get((packet["conversation_id"], packet["key_id"]))
        if e is None:
            raise self.sdk.UnknownKeyError(packet.get("key_id", "?"))
        text = self.sdk.decrypt_message(packet, e["key"])  # AuthTagError si falsifié
        self.guard.check(packet["conversation_id"], packet["sender_id"],
                         packet["key_id"], packet["counter"])  # ReplayError si rejeu
        return text

    def ack(self, packet):
        self.client.ack(packet["message_id"])
