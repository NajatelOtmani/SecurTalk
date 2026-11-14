"""Lit policy.json (décisions de sécurité écrites noir sur blanc, guide 7.2)."""
import json
from pathlib import Path

DEFAULT = {"phishing_policy": "block", "ml_unavailable": "send_with_notice"}
ALLOWED = {"phishing_policy": ("block", "warn"), "ml_unavailable": ("send_with_notice", "block")}


def load():
    try:
        data = json.loads((Path(__file__).parent / "policy.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        data = {}
    out = dict(DEFAULT)
    out.update({k: v for k, v in data.items() if k in ALLOWED and v in ALLOWED[k]})
    return out
