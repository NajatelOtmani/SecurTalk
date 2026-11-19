"""Vérifie que le service IA (faux OU vrai) respecte le contrat 2.10 et la liste de codes 8.2.
Usage : python tools\\check_ml_contract.py [http://127.0.0.1:8001]"""
import sys
import requests

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
CODES = {"URL_BRAND_IMITATION", "URL_HOMOGLYPH", "URL_SUSPICIOUS_TLD", "URL_IP_ADDRESS", "URL_SHORTENER",
         "URL_TOO_LONG", "TEXT_URGENCY", "TEXT_ACCOUNT_VERIFICATION", "TEXT_THREAT", "TEXT_CREDENTIAL_REQUEST",
         "TEXT_MONEY_REQUEST", "MODEL_HIGH_SCORE"}
BASE = {"message_id": "6c0e4b7a-1d2f-4e55-8f10-0a9b9c1d2e3f", "sender_id": "u_1a", "receiver_id": "u_2b",
        "conversation_id": "conv_u_1a_u_2b"}
ok_all = True


def check(name, cond, info=""):
    global ok_all
    ok_all &= bool(cond)
    print(("  OK   " if cond else "  FAIL ") + name + (f"  [{info}]" if info and not cond else ""))


def analyze(text, urls=()):
    r = requests.post(URL + "/v1/analyze", json={**BASE, "text": text, "urls": list(urls)}, timeout=5)
    return r


try:
    h = requests.get(URL + "/health", timeout=3)
    check("GET /health -> 200 avec model_version", h.status_code == 200 and "model_version" in h.json(), h.text[:80])
except requests.RequestException as e:
    sys.exit(f"Service injoignable sur {URL} : {e}")

r = analyze("Cliquez ici pour vérifier votre compte immédiatement", ["http://micros0ft-login.com/verify"])
d = r.json() if r.status_code == 200 else {}
check("/v1/analyze -> 200", r.status_code == 200, r.text[:100])
for k in ("message_id", "score", "label", "reasons", "model_version", "latency_ms"):
    check(f"champ '{k}' présent", k in d)
if d:
    s, lab = d.get("score", -1), d.get("label")
    check("score entre 0 et 1", isinstance(s, (int, float)) and 0 <= s <= 1)
    exp = "Safe" if s < 0.40 else "Suspicious" if s < 0.80 else "Phishing"
    check("label cohérent avec les seuils 0.40 / 0.80", lab == exp, f"score={s} label={lab}")
    check("message_id renvoyé identique", d.get("message_id") == BASE["message_id"])
    codes = [x.get("code") for x in d.get("reasons", [])]
    check("codes de raison dans la liste fermée (8.2)", all(c in CODES for c in codes), str(codes))
    check("chaque raison a un 'text' lisible", all(x.get("text") for x in d.get("reasons", [])))
    check("lien imitant une marque -> Phishing", lab == "Phishing", f"label={lab}")
r = analyze("Bonjour, la réunion est à 15h dans la salle B")
check("message normal -> Safe", r.status_code == 200 and r.json().get("label") == "Safe", r.text[:80])
r = analyze("Voici notre site officiel", ["https://www.microsoft.com/fr-fr"])
check("lien officiel -> pas Phishing", r.status_code == 200 and r.json().get("label") != "Phishing", r.text[:80])
for name, txt, urls in [("texte vide", "", []), ("texte très long", "a" * 6000, []),
                        ("emojis / arabe / mélange", "مرحبا 😀 bonjour hello", []), ("20+ liens", "x", ["http://a.com"] * 25)]:
    r = analyze(txt, urls)
    check(f"robustesse : {name} -> pas d'erreur 500", r.status_code < 500, f"HTTP {r.status_code}")
print("\n" + ("CONTRAT RESPECTÉ" if ok_all else "ÉCARTS DÉTECTÉS : à corriger ou à discuter avec l'autre partie"))
