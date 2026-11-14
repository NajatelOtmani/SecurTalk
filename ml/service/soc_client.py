"""Envoi des événements au SOC (guide 2.4) -- source = "phishing".

Même signature que le futur contracts/soc_emitter.py du collègue :
    emit_event(source, event_type, severity, actor, target, details)
Le jour où ce fichier existe, il suffit de changer l'import dans main.py.

RÈGLES (2.4) : ne JAMAIS bloquer ni faire planter l'application -> timeout 1 s, toutes les erreurs
attrapées ; si le SOC est injoignable, l'événement est mis de côté dans events_pending.jsonl.
RÈGLE 2.9 : jamais de texte de message ni de clé dans un événement (contrôle automatique ci-dessous).
"""
import asyncio
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("securetalk.soc")
ML_DIR = Path(__file__).resolve().parent.parent
PENDING_PATH = ML_DIR / "events_pending.jsonl"     # SOC injoignable : à renvoyer plus tard
LOCAL_PATH = ML_DIR / "events.jsonl"               # pas de clé configurée : mode "mock" (guide 4.5 bis)
TIMEOUT_SECONDS = 1.0
CONTRACT_VERSION = "1.0"
_lock = threading.Lock()

FORBIDDEN_KEYS = {"message", "text", "plaintext", "content", "body", "key", "session_key",
                  "private_key", "password", "token", "ciphertext"}          # guide 2.9
EVENT_FOR_LABEL = {"Safe": ("MESSAGE_SCANNED_SAFE", "info"),
                   "Suspicious": ("SUSPICIOUS_MESSAGE", "low"),
                   "Phishing": ("PHISHING_DETECTED", "medium")}              # guide 2.3


def _load_dotenv() -> None:
    """Lit securetalk/.env (clés API partagées avec l'équipe) sans écraser l'environnement."""
    p = ML_DIR.parent / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


def soc_url() -> str:
    return os.environ.get("SOC_URL", "http://localhost:8002/soc/events")


def api_key() -> str:
    return os.environ.get("SOC_KEY_PHISHING", "")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(source, event_type, severity, actor, target, details) -> Dict[str, Any]:
    ev = {"event_id": str(uuid.uuid4()), "timestamp": _utc_now(), "source": source,
          "event_type": event_type, "severity": severity,
          "actor": actor or {"user_id": None, "username": None, "ip": None}}
    if target is not None:
        ev["target"] = target
    if details is not None:
        ev["details"] = details
    return ev


def violates_privacy(obj: Any) -> bool:
    """Second filet (le SOC a son PrivacyGuard) : clé interdite ou texte suspect (> 200 caractères)."""
    if isinstance(obj, dict):
        return any(k.lower() in FORBIDDEN_KEYS or violates_privacy(v) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return any(violates_privacy(v) for v in obj)
    return isinstance(obj, str) and len(obj) > 200


def _append(path: Path, event: Dict[str, Any]) -> None:
    with _lock, open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def _post(event: Dict[str, Any], key: str) -> str:
    """'sent' | 'retry' (réseau, 429, 5xx : on réessaiera) | 'rejected' (4xx : inutile de réessayer)."""
    try:
        r = httpx.post(soc_url(), json=event, timeout=TIMEOUT_SECONDS,
                       headers={"X-API-Key": key, "X-Contract-Version": CONTRACT_VERSION})
    except Exception:
        return "retry"
    if r.status_code == 202:
        return "sent"
    return "retry" if (r.status_code == 429 or r.status_code >= 500) else "rejected"


def emit_event(source: str, event_type: str, severity: Optional[str] = None,
               actor: Optional[dict] = None, target: Optional[dict] = None,
               details: Optional[dict] = None) -> str:
    """Ne lève JAMAIS d'exception. Renvoie : sent | retry | rejected | local | blocked | error."""
    try:
        event = make_event(source, event_type, severity or "info", actor, target, details)
        if violates_privacy(event):
            log.error("privacy_violation_blocked event_type=%s", event_type)
            return "blocked"
        key = api_key()
        if not key:
            _append(LOCAL_PATH, event)
            return "local"
        status = _post(event, key)
        if status == "retry":
            _append(PENDING_PATH, event)
        elif status == "rejected":
            log.warning("event_rejected event_type=%s", event_type)
        return status
    except Exception as exc:
        log.error("emit_failed error=%s", type(exc).__name__)
        return "error"


def flush_pending(max_events: int = 50) -> int:
    """Renvoie les événements mis de côté. Renvoie le nombre d'événements envoyés."""
    key = api_key()
    if not key:
        return 0
    with _lock:
        if not PENDING_PATH.exists():
            return 0
        lines = [l for l in PENDING_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
        PENDING_PATH.unlink()
    sent = 0
    for i, line in enumerate(lines):
        if i >= max_events:
            _append_raw(line)
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if _post(ev, key) == "retry":
            _append(PENDING_PATH, ev)
        else:
            sent += 1
    return sent


def _append_raw(line: str) -> None:
    with _lock, open(PENDING_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ----------------------------------------------------------------------------
# Événements propres au service IA
# ----------------------------------------------------------------------------
def clean_domains(domains: List[str], limit: int = 10, max_len: int = 60) -> List[str]:
    out: List[str] = []
    for d in domains or []:
        d = re.sub(r"[\x00-\x1f\x7f\s]", "", str(d))[:max_len]
        if d and d not in out:
            out.append(d)
    return out[:limit]


def emit_scan_event(message_id: str, sender_id: str, receiver_id: str, conversation_id: str,
                    score: float, label: str, reason_codes: List[str],
                    url_domains: List[str], text_length: int) -> str:
    """Contrat 2.10 : source=phishing, actor.user_id=expéditeur, target=destinataire, jamais le texte."""
    event_type, severity = EVENT_FOR_LABEL[label]
    return emit_event(
        source="phishing", event_type=event_type, severity=severity,
        actor={"user_id": sender_id, "username": None, "ip": None},
        target={"user_id": receiver_id, "conversation_id": conversation_id},
        details={"message_id": message_id, "score": round(float(score), 4), "label": label,
                 "reason_codes": list(reason_codes), "url_domains": clean_domains(url_domains),
                 "text_length": int(text_length)})


def beat(model_version: str) -> None:
    """HEARTBEAT (2.3) : la règle R012 du SOC détecte une source silencieuse grâce à lui."""
    emit_event("phishing", "HEARTBEAT", "info",
               actor={"user_id": None, "username": None, "ip": None},
               details={"model_version": model_version})
    flush_pending()


async def heartbeat_loop(interval: float, version_fn) -> None:
    while True:
        await asyncio.to_thread(beat, version_fn())
        await asyncio.sleep(interval)
