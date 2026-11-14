"""FAUX service IA (jalon J3) : respecte le contrat 2.10 avec des règles simples.
Lancer : python tools\\fake_ml_service.py   (port 8001). Ne stocke et ne journalise JAMAIS le texte."""
import json, re, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

BRANDS = {"microsoft": "microsoft.com", "google": "google.com", "paypal": "paypal.com",
          "linkedin": "linkedin.com", "apple": "apple.com"}
HOMO = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e", "@": "a"})
SAFE_T, PHISH_T = 0.40, 0.80  # seuils du contrat 2.10


def host_of(u):
    return (urlparse(u if "://" in u else "http://" + u).hostname or "").lower()


def score(text, urls):
    s, reasons = 0.0, []

    def add(code, txt, w):
        nonlocal s
        s += w
        reasons.append({"code": code, "text": txt})

    t = text.lower()
    for u in urls:
        h = host_of(u)
        norm = h.translate(HOMO).replace("rn", "m")
        for brand, official in BRANDS.items():
            if brand in norm and h != official and not h.endswith("." + official):
                add("URL_BRAND_IMITATION", f"Le domaine imite {brand.capitalize()} ({h})", 0.70)
                if norm != h:
                    add("URL_HOMOGLYPH", "Caractères qui ressemblent à d'autres lettres", 0.15)
                break
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h):
            add("URL_IP_ADDRESS", "Lien avec une adresse IP à la place d'un nom", 0.40)
        if h in ("bit.ly", "tinyurl.com", "t.co"):
            add("URL_SHORTENER", "Lien raccourci qui cache la destination", 0.30)
        if h.rsplit(".", 1)[-1] in ("xyz", "top", "ru", "tk"):
            add("URL_SUSPICIOUS_TLD", "Extension de domaine souvent utilisée pour des arnaques", 0.20)
    if any(w in t for w in ("immédiatement", "immediatement", "urgent", "dans 24 h", "tout de suite")):
        add("TEXT_URGENCY", "Message demandant une action immédiate", 0.45)
    if any(w in t for w in ("vérifiez votre compte", "verifiez votre compte", "vérifier votre compte", "verify your account")):
        add("TEXT_ACCOUNT_VERIFICATION", "Demande de vérification de compte", 0.45)
    if any(w in t for w in ("suspendu", "bloqué", "suspended")):
        add("TEXT_THREAT", "Menace de suspension de compte", 0.40)
    if any(w in t for w in ("mot de passe", "password", "code de sécurité", "numéro de carte")):
        add("TEXT_CREDENTIAL_REQUEST", "Demande d'un mot de passe, code ou carte", 0.40)
    if any(w in t for w in ("virement", "cartes cadeaux", "gift card")):
        add("TEXT_MONEY_REQUEST", "Demande de virement ou de cartes cadeaux", 0.40)
    s = round(min(0.99, s) if reasons else 0.05, 2)
    label = "Safe" if s < SAFE_T else "Suspicious" if s < PHISH_T else "Phishing"
    return s, label, reasons


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # aucun log (confidentialité)
        pass

    def _j(self, code, d):
        b = json.dumps(d).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._j(200, {"status": "ok", "model_version": "fake-0.1"}) if self.path == "/health" else self._j(404, {})

    def do_POST(self):
        if self.path != "/v1/analyze":
            return self._j(404, {})
        t0 = time.time()
        try:
            d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            sc, label, reasons = score(str(d.get("text", ""))[:5000], list(d.get("urls", []))[:20])
        except (ValueError, TypeError):
            return self._j(400, {"error": "BAD_REQUEST", "message": "format invalide"})
        self._j(200, {"message_id": d.get("message_id"), "score": sc, "label": label, "reasons": reasons,
                      "model_version": "fake-0.1", "latency_ms": int((time.time() - t0) * 1000)})


if __name__ == "__main__":
    print("Faux service IA sur http://127.0.0.1:8001  (Ctrl+C pour arrêter)")
    HTTPServer(("127.0.0.1", 8001), H).serve_forever()
