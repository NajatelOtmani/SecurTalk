"""Configuration : variables d'environnement + fichier .env (lu a la main, sans bibliotheque).

Le lecteur de .env accepte l'UTF-8 avec BOM et l'UTF-16 (fichiers crees par PowerShell),
ce qui evite le probleme du caractere invisible \\ufeff devant la premiere cle."""
import os
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _lire_texte(chemin):
    brut = chemin.read_bytes()
    if brut.startswith((b"\xff\xfe", b"\xfe\xff")):
        return brut.decode("utf-16")
    return brut.decode("utf-8-sig")


def charger_env():
    for dossier in (BACKEND_DIR, BACKEND_DIR.parent):
        fichier = dossier / ".env"
        if not fichier.is_file():
            continue
        for ligne in _lire_texte(fichier).splitlines():
            ligne = ligne.strip().lstrip("\ufeff")
            if not ligne or ligne.startswith("#") or "=" not in ligne:
                continue
            cle, valeur = ligne.split("=", 1)
            cle, valeur = cle.strip(), valeur.strip().strip('"').strip("'")
            if cle:
                os.environ.setdefault(cle, valeur)


@dataclass
class Settings:
    database_url: str = f"sqlite:///{(BACKEND_DIR / 'securetalk_backend.db').as_posix()}"
    soc_mode: str = "file"            # "http" (vrai SOC) | "file" (mock : events.jsonl) | "memory" (tests) | "off"
    soc_url: str = "http://127.0.0.1:8002/soc/events"
    soc_keys: dict = field(default_factory=dict)       # {"auth": "...", "relay": "..."}
    events_file: str = str(BACKEND_DIR / "events.jsonl")
    pending_file: str = str(BACKEND_DIR / "events_pending.jsonl")
    internal_key: str = ""
    internal_allowed_ips: tuple = ("127.0.0.1", "::1")
    token_ttl_seconds: int = 3600
    rate_limit_per_minute: int = 30
    max_packet_bytes: int = 64 * 1024
    heartbeat_seconds: int = 60       # 0 = desactive
    fast_hash: bool = False           # Argon2 allege (tests seulement)

    @classmethod
    def from_env(cls):
        charger_env()
        e = os.environ
        s = cls()
        s.database_url = e.get("DATABASE_URL", s.database_url)
        s.soc_mode = e.get("SOC_MODE", s.soc_mode).lower()
        s.soc_url = e.get("SOC_URL", s.soc_url)
        s.soc_keys = {"auth": e.get("SOC_KEY_AUTH", ""), "relay": e.get("SOC_KEY_RELAY", "")}
        s.internal_key = e.get("INTERNAL_KEY_SOC_TO_BACKEND", "")
        ips = e.get("INTERNAL_ALLOWED_IPS")
        if ips:
            s.internal_allowed_ips = tuple(x.strip() for x in ips.split(",") if x.strip())
        s.rate_limit_per_minute = int(e.get("RATE_LIMIT_PER_MINUTE", s.rate_limit_per_minute))
        s.heartbeat_seconds = int(e.get("HEARTBEAT_SECONDS", s.heartbeat_seconds))
        return s
