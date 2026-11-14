"""Événements du CLIENT vers le SOC (contrat 2.2 et 2.4). Ne bloque et ne plante JAMAIS l'application.

- source "crypto" (GCM_AUTH_FAIL, REPLAY_DETECTED...) : le client du RECEVEUR vérifie, donc c'est lui qui émet.
- source "client" (MESSAGE_BLOCKED, WARNING_SHOWN, USER_OVERRODE_WARNING).
- Métadonnées seulement : jamais de texte, jamais de clé (guide 2.9).
Mode choisi dans .env : SOC_MODE=file (défaut -> client/events.jsonl) ou http (-> SOC, 1 s max, file d'attente locale)."""
import json, os, queue, re, sys, threading, uuid
from datetime import datetime, timezone
from pathlib import Path
import requests
import config

HERE = Path(__file__).resolve().parent
SEVERITIES = ("info", "low", "medium", "high", "critical")
DEFAULT_SEVERITY = {
    "GCM_AUTH_FAIL": "high", "CMAC_AUTH_FAIL": "high", "REPLAY_DETECTED": "high", "KEY_EXCHANGE_FAIL": "high",
    "KEY_ROTATED": "info", "MESSAGE_BLOCKED": "medium", "WARNING_SHOWN": "low", "USER_OVERRODE_WARNING": "low"}
SOURCE_ENV_KEY = {"crypto": "SOC_KEY_CRYPTO", "client": "SOC_KEY_CLIENT"}
FORBIDDEN = {"message", "text", "plaintext", "content", "body", "key", "session_key",
             "private_key", "password", "token", "ciphertext"}
_B64 = re.compile(r"^[A-Za-z0-9+/=_-]{65,}$")


class PrivacyError(ValueError):
    pass


def check_privacy(obj, path="event"):
    """Même règle que le PrivacyGuard du SOC (guide 6.4) : on refuse AVANT d'envoyer."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN:
                raise PrivacyError(f"champ interdit : {path}.{k}")
            check_privacy(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            check_privacy(v, path)
    elif isinstance(obj, str) and (len(obj) > 200 or _B64.match(obj)):
        raise PrivacyError(f"valeur suspecte : {path}")


def _parse_env(path):
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return {}
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", "replace")
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


_ENV = None


def setting(name, default=""):
    global _ENV
    if _ENV is None:
        _ENV = {}
        for f in (HERE.parent / ".env", HERE / ".env"):  # racine du dépôt, puis client/
            _ENV.update(_parse_env(f))
    return os.environ.get(name) or _ENV.get(name) or default


class SocEmitter:
    def __init__(self, mode=None, url=None, base_dir=HERE, async_=True):
        self.mode = (mode or setting("SOC_MODE", "file")).lower()
        self.url = (url or setting("SOC_URL", config.SOC_URL)).rstrip("/") + "/soc/events"
        self.events_file = Path(base_dir) / "events.jsonl"
        self.pending_file = Path(base_dir) / "events_pending.jsonl"
        self._lock, self._q, self.async_ = threading.Lock(), queue.Queue(), async_
        if async_:
            threading.Thread(target=self._loop, daemon=True).start()

    def build(self, source, event_type, actor, target, details, severity):
        actor = {"user_id": None, "username": None, "ip": None, **(actor or {})}
        if not any(actor.values()):
            raise ValueError("actor vide")
        sev = severity or DEFAULT_SEVERITY.get(event_type, "info")
        if sev not in SEVERITIES:
            raise ValueError("gravité inconnue")
        return {"event_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source": source, "event_type": event_type, "severity": sev, "actor": actor,
                "target": {"user_id": None, "conversation_id": None, **(target or {})},
                "details": details or {}}

    def emit(self, source, event_type, actor=None, target=None, details=None, severity=None):
        try:
            ev = self.build(source, event_type, actor, target, details, severity)
            check_privacy({"actor": ev["actor"], "target": ev["target"], "details": ev["details"]})
        except PrivacyError as e:
            print(f"[SOC] PRIVACY_VIOLATION_BLOCKED : {e}", file=sys.stderr)
            return None
        except Exception as e:  # noqa: BLE001
            print(f"[SOC] événement ignoré : {e}", file=sys.stderr)
            return None
        self._q.put(ev) if self.async_ else self._deliver(ev)
        return ev

    def _loop(self):
        while True:
            ev = self._q.get()
            self._deliver(ev)
            self._q.task_done()

    def wait(self):
        self._q.join()

    def _deliver(self, ev):
        try:
            if self.mode == "http":
                res = self._post(ev)
                if res == "retry":
                    self._append(self.pending_file, ev)
                elif res == "ok":
                    self.flush_pending()
            else:
                self._append(self.events_file, ev)
        except Exception as e:  # noqa: BLE001
            print(f"[SOC] erreur d'émission : {e}", file=sys.stderr)

    def _append(self, path, ev):
        with self._lock, open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    def _post(self, ev):
        try:
            r = requests.post(self.url, json=ev, timeout=1, headers={
                "X-API-Key": setting(SOURCE_ENV_KEY.get(ev["source"], "")),
                "X-Contract-Version": config.CONTRACT_VERSION})
        except requests.RequestException:
            return "retry"
        if r.status_code in (200, 201, 202):
            return "ok"
        if r.status_code == 429 or r.status_code >= 500:
            return "retry"
        print(f"[SOC] événement refusé ({r.status_code}) : vérifiez les clés du .env", file=sys.stderr)
        return "drop"

    def flush_pending(self, limit=50):
        with self._lock:
            if not self.pending_file.exists():
                return
            lines = self.pending_file.read_text(encoding="utf-8").splitlines()
            self.pending_file.unlink()
        todo, rest = lines[:limit], lines[limit:]
        for i, line in enumerate(todo):
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if self._post(ev) == "retry":  # SOC toujours en panne : on garde le reste
                rest = todo[i:] + rest
                break
        for line in rest:
            with self._lock, open(self.pending_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")


_default = None


def get_emitter():
    global _default
    if _default is None:
        _default = SocEmitter()
    return _default


def emit_event(source, event_type, actor=None, target=None, details=None, severity=None):
    return get_emitter().emit(source, event_type, actor, target, details, severity)
