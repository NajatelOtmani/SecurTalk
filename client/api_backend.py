"""Appels HTTP vers le backend (contrat 2.7). Aucune interface ici."""
from datetime import datetime, timezone
import requests
import config


class ApiError(Exception):
    def __init__(self, code, message="", status=0):
        super().__init__(f"{status} {code}: {message}")
        self.code, self.message, self.status = code, message, status


class BackendClient:
    def __init__(self, base=config.BACKEND_URL):
        self.base = base
        self.token = None
        self.user_id = None
        self.username = None
        self.expires_at = None
        self.private_pem = None  # clé privée déchiffrée, gardée en mémoire seulement
        self._s = requests.Session()

    def _request(self, method, path, **kw):
        headers = {"X-Contract-Version": config.CONTRACT_VERSION}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = self._s.request(method, self.base + path, headers=headers,
                                timeout=config.HTTP_TIMEOUT, **kw)
        except requests.RequestException:
            raise ApiError("BACKEND_UNREACHABLE", "Serveur injoignable.")
        if r.status_code >= 400:
            try:
                d = r.json()
            except ValueError:
                d = {}
            raise ApiError(d.get("error", "HTTP_ERROR"), d.get("message", ""), r.status_code)
        return r.json() if r.content else None

    def health(self):
        return self._request("GET", "/health")

    def register(self, username, password, public_key_pem):
        return self._request("POST", "/auth/register", json={
            "username": username, "password": password, "public_key_pem": public_key_pem})

    def login(self, username, password):
        d = self._request("POST", "/auth/login", json={"username": username, "password": password})
        self.token, self.user_id, self.username = d["token"], d["user_id"], username
        self.expires_at = d.get("expires_at")
        return d

    def logout(self):
        if self.token:
            try:
                self._request("POST", "/auth/logout")
            except ApiError:
                pass
        self.token = None

    def seconds_left(self):
        """Secondes avant l'expiration du jeton (None si inconnu)."""
        try:
            dt = datetime.fromisoformat(str(self.expires_at).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (dt - datetime.now(timezone.utc)).total_seconds()
        except (ValueError, TypeError):
            return None

    def public_key(self, username):
        return self._request("GET", f"/users/{username}/publickey")

    def send_packet(self, packet):
        return self._request("POST", "/messages", json=packet)

    def ack(self, message_id):
        return self._request("POST", f"/messages/{message_id}/ack")

    def exchange_key(self, conversation_id, to_user_id, key_id, wrapped_key_b64):
        return self._request("POST", "/keys/exchange", json={
            "conversation_id": conversation_id, "to_user_id": to_user_id,
            "key_id": key_id, "wrapped_key_b64": wrapped_key_b64})

    def pending_keys(self):
        return self._request("GET", "/keys/pending")

    def ws_url(self):
        return self.base.replace("http", "ws", 1) + f"/ws?token={self.token}"


BackendApi = BackendClient  # alias de compatibilité
