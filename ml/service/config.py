"""Configuration du service IA (seuils du contrat 2.10, modifiables dans config.json)."""
import json
from pathlib import Path

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

with open(_CONFIG_PATH, encoding="utf-8") as f:
    CONFIG = json.load(f)

MODEL_VERSION: str = CONFIG["model_version"]
SAFE_BELOW: float = CONFIG["thresholds"]["safe_below"]
PHISHING_FROM: float = CONFIG["thresholds"]["phishing_from"]
MAX_TEXT_CHARS: int = CONFIG["limits"]["max_text_chars"]
MAX_URLS: int = CONFIG["limits"]["max_urls"]


def label_from_score(score: float) -> str:
    """Contrat 2.10 : Safe < 0.40 ; Suspicious 0.40-0.80 ; Phishing >= 0.80."""
    if score < SAFE_BELOW:
        return "Safe"
    if score < PHISHING_FROM:
        return "Suspicious"
    return "Phishing"
