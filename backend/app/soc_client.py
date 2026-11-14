"""Emission des evenements vers le SOC (guide 2.2 a 2.5).

Regles respectees :
  - l'envoi ne bloque jamais et ne plante jamais l'application (thread + timeout 1 s,
    toutes les erreurs sont attrapees) ;
  - si le SOC est injoignable, l'evenement est ecrit dans events_pending.jsonl ;
  - PrivacyGuard cote emetteur : aucun champ interdit (2.9) ne part vers le SOC ;
  - mode "file" (mock du guide 4.5 bis) : tout est ecrit dans events.jsonl.
"""
import json
import logging
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import requests

from app.utils import iso, utcnow

log = logging.getLogger("securetalk.soc")

SOURCES = ("auth", "relay", "crypto", "phishing", "client")
FORBIDDEN_KEYS = {"message", "text", "plaintext", "content", "body", "key", "session_key",
                  "private_key", "password", "token", "ciphertext"}
DEFAULT_SEVERITY = {
    "REGISTER_SUCCESS": "info", "LOGIN_SUCCESS": "info", "LOGIN_FAIL": "low", "LOGOUT": "info",
    "SESSION_EXPIRED": "info", "ACCOUNT_LOCKED": "medium", "ACCOUNT_UNLOCKED": "info",
    "PACKET_ROUTED": "info", "MESSAGE_DELIVERED": "info", "PACKET_REJECTED_UNAUTH": "medium",
    "RATE_LIMIT_EXCEEDED": "medium", "HEARTBEAT": "info",
}
_B64_LONG = re.compile(r"^[A-Za-z0-9+/=_\-]{65,}$")


class PrivacyError(ValueError):
    pass


def _check_privacy(obj, chemin="event"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN_KEYS:
                raise PrivacyError(f"champ interdit : {chemin}.{k}")
            _check_privacy(v, f"{chemin}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check_privacy(v, f"{chemin}[{i}]")
    elif isinstance(obj, str):
        if len(obj) > 200 or _B64_LONG.match(obj):
            raise PrivacyError(f"valeur suspecte (trop longue / secret ?) : {chemin}")


def build_event(source, event_type, severity=None, actor=None, target=None, details=None):
    """Construit un Event conforme au contrat 2.2. Leve ValueError / PrivacyError sinon."""
    if source not in SOURCES:
        raise ValueError(f"source inconnue : {source}")
    severity = severity or DEFAULT_SEVERITY.get(event_type)
    if severity not in ("info", "low", "medium", "high", "critical"):
        raise ValueError("severity invalide")
    a = {"user_id": None, "username": None, "ip": None}
    a.update(actor or {})
    if event_type != "HEARTBEAT" and not any(a.values()):
        raise ValueError("actor : user_id, username ou ip requis")
    event = {"event_id": str(uuid.uuid4()), "timestamp": iso(utcnow()), "source": source,
             "event_type": event_type, "severity": severity, "actor": a}
    if target is not None:
        t = {"user_id": None, "conversation_id": None}
        t.update(target)
        event["target"] = t
    if details is not None:
        event["details"] = details
    _check_privacy(event)
    return event


class SocEmitter:
    def __init__(self, settings):
        self.s = settings
        self.events = []                       # mode "memory" (tests)
        self._lock = threading.Lock()
        self._down_until = 0.0                 # disjoncteur : SOC en panne -> on n'attend plus 1 s a chaque fois
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="soc-emit") \
            if settings.soc_mode == "http" else None

    # ---- API publique ----------------------------------------------------
    def emit(self, source, event_type, severity=None, actor=None, target=None, details=None):
        """Ne leve jamais d'exception. Retourne l'event (ou None s'il a ete refuse)."""
        try:
            event = build_event(source, event_type, severity, actor, target, details)
        except Exception as err:               # PrivacyError comprise : on journalise sans le contenu
            log.error("evenement %s/%s refuse : %s", source, event_type, err)
            return None
        try:
            self._dispatch(event)
        except Exception:                      # pragma: no cover - filet de securite
            log.exception("emission impossible")
        return event

    def shutdown(self):
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)

    # ---- modes -----------------------------------------------------------
    def _dispatch(self, event):
        mode = self.s.soc_mode
        if mode == "memory":
            self.events.append(event)
        elif mode == "file":
            self._append(self.s.events_file, event)
        elif mode == "http":
            self._pool.submit(self._send_http, event)
        # mode "off" : rien

    def _append(self, chemin, event):
        with self._lock:
            with open(chemin, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _post(self, event):
        cle = self.s.soc_keys.get(event["source"], "")
        if not cle:
            raise RuntimeError("cle SOC absente")
        return requests.post(self.s.soc_url, json=event, headers={"X-API-Key": cle}, timeout=1)

    def _send_http(self, event):
        try:
            if time.monotonic() < self._down_until:
                raise RuntimeError("SOC indisponible (disjoncteur)")
            r = self._post(event)
            if r.status_code == 202:
                return
            if r.status_code == 400:           # format/privacy refuse : inutile de renvoyer
                log.error("SOC a refuse l'evenement %s (400)", event["event_type"])
                return
            raise RuntimeError(f"SOC code {r.status_code}")
        except Exception:
            self._down_until = time.monotonic() + 10
            try:
                self._append(self.s.pending_file, event)
            except Exception:                  # pragma: no cover
                log.exception("ecriture events_pending impossible")

    def flush_pending(self):
        """Renvoie les evenements en attente (appele periodiquement). Retourne le nombre renvoye."""
        chemin = self.s.pending_file
        if self.s.soc_mode != "http" or not os.path.isfile(chemin):
            return 0
        with self._lock:
            tmp = chemin + ".sending"
            os.replace(chemin, tmp)
        restants, envoyes = [], 0
        with open(tmp, encoding="utf-8") as f:
            lignes = [l for l in f.read().splitlines() if l.strip()]
        for i, ligne in enumerate(lignes):
            try:
                event = json.loads(ligne)
                r = self._post(event)
                if r.status_code in (202, 400):
                    envoyes += 1
                    continue
                raise RuntimeError("SOC indisponible")
            except Exception:
                restants = lignes[i:]
                break
        if restants:
            with self._lock:
                with open(chemin, "a", encoding="utf-8") as f:
                    f.write("\n".join(restants) + "\n")
        os.remove(tmp)
        return envoyes
