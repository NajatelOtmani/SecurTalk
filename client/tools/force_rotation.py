"""Simule l'ordre du SOC « forcer une rotation de clé » (route interne du backend, guide 2.8).
Usage : python tools\\force_rotation.py conv_u_xxx_u_yyy
(l'identifiant de conversation s'affiche sous le nom du contact dans le client)"""
import os, sys
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parents[2]
BACKEND = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000")


def read_key():
    if os.environ.get("INTERNAL_KEY_SOC_TO_BACKEND"):
        return os.environ["INTERNAL_KEY_SOC_TO_BACKEND"]
    for f in (ROOT / ".env", ROOT / "backend" / ".env"):
        if f.exists():
            raw = f.read_bytes()
            text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig")
            for line in text.splitlines():
                if line.strip().startswith("INTERNAL_KEY_SOC_TO_BACKEND="):
                    return line.split("=", 1)[1].strip().strip('"')
    return ""


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    key = read_key()
    if not key:
        sys.exit("INTERNAL_KEY_SOC_TO_BACKEND introuvable (fichier .env du depot ou du backend).")
    r = requests.post(f"{BACKEND}/internal/conversations/{sys.argv[1]}/force-rotation",
                      headers={"X-API-Key": key}, timeout=5)
    print(r.status_code, r.text)
