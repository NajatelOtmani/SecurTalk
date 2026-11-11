"""Génère un jeu de messages style CHAT (FR / EN / AR / darija) : phishing vs normal.

  python -m training.build_dataset            ->  data/chat_dataset.csv

Données 100 % synthétiques : prénoms inventés, domaines factices, plage IP de documentation
(203.0.113.x). Aucun vrai mot de passe, aucune donnée personnelle. NE PAS visiter les liens.
Colonnes : id, text, urls, label (1 = phishing), lang, category, template_id
"""
import argparse
import csv
import random
import string
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

NAMES = {"fr": ["Sara", "Youssef", "Imane", "Omar", "Khadija", "Mehdi", "Salma", "Anas"],
         "en": ["Sara", "Youssef", "Imane", "Omar", "Khadija", "Mehdi", "Salma", "Anas"],
         "ar": ["سارة", "يوسف", "إيمان", "عمر", "خديجة", "مهدي", "سلمى"],
         "mixed": ["Sara", "Youssef", "Imane", "Omar", "Khadija", "Mehdi", "Salma"]}
PREFIX = {"fr": ["", "", "Bonjour, ", "Salut, ", "Hello, "],
          "en": ["", "", "Hi, ", "Hey, ", "Hello, "],
          "ar": ["", "", "مرحبا، ", "السلام عليكم، "],
          "mixed": ["", "", "Salam, ", "Salut, "]}
SUFFIX = ["", "", "", " 🙏", " 😊", " 👍"]          # même distribution pour les 2 classes
BRANDS = ["microsoft", "google", "paypal", "linkedin", "apple", "amazon",
          "facebook", "netflix", "dropbox", "docusign"]
LEGIT_URLS = ["https://learn.microsoft.com/fr-fr/azure/", "https://docs.google.com/document/d/abc123",
              "https://github.com/equipe/projet", "https://www.linkedin.com/in/profil",
              "https://teams.microsoft.com/l/meetup-join/xyz", "https://www.ensa.ac.ma/formation",
              "https://drive.google.com/file/d/xyz/view", "https://stackoverflow.com/questions/12345"]

# (lang, category, texte)  --  {url} = lien frauduleux, {legit_url} = lien légitime
PHISHING = [
    ("fr", "account_verification", "URGENT : votre compte {Brand} sera suspendu dans 24 h. Vérifiez votre compte ici : {url}"),
    ("fr", "account_verification", "Cliquez ici pour vérifier votre compte {Brand} : {url}"),
    ("fr", "security_alert", "Alerte sécurité : activité inhabituelle détectée. Confirmez votre identité immédiatement : {url}"),
    ("fr", "credential_request", "Envoyez-moi votre mot de passe et le code de vérification reçu par SMS, c'est pour la maintenance"),
    ("fr", "ceo_fraud", "Je suis en réunion et je ne peux pas parler. Achète {k} cartes cadeaux Amazon de 100 € et envoie-moi les codes, je te rembourse"),
    ("fr", "delivery_fee", "Votre colis est bloqué. Payez les frais de livraison de {amt} MAD : {url}"),
    ("fr", "prize", "Félicitations {n} ! Vous avez gagné un téléphone. Réclamez votre prix : {url}"),
    ("fr", "invoice", "Facture impayée n°{num}. Effectuez un virement avant ce soir pour éviter des poursuites : {url}"),
    ("fr", "password_expiry", "Votre mot de passe expire aujourd'hui. Cliquez pour le conserver : {url}"),
    ("fr", "url_only", "Document partagé avec vous : {url}"),
    ("en", "account_verification", "Your {Brand} account will be suspended. Please verify your account immediately: {url}"),
    ("en", "security_alert", "Security alert: unusual sign-in detected. Confirm your identity now: {url}"),
    ("en", "credential_request", "Please send me your password and the verification code you just received, it's for the IT audit"),
    ("en", "ceo_fraud", "I'm stuck in a meeting. Can you buy {k} gift cards and send me the codes? I'll reimburse you today"),
    ("en", "invoice", "Invoice #{num} is overdue. Make a wire transfer today to avoid legal action: {url}"),
    ("en", "prize", "Congratulations {n}, you won a prize! Claim it here: {url}"),
    ("en", "payroll", "HR notice: update your payroll information before Friday: {url}"),
    ("en", "url_only", "Shared a file with you: {url}"),
    ("ar", "account_verification", "عاجل: سيتم تعليق حسابك خلال 24 ساعة. يرجى تأكيد حسابك عبر الرابط: {url}"),
    ("ar", "security_alert", "تنبيه أمني: تم تسجيل دخول مشبوه. أكد هويتك فورا: {url}"),
    ("ar", "credential_request", "أرسل لي كلمة المرور ورمز التحقق الذي وصلك على الهاتف"),
    ("ar", "prize", "ربحت جائزة قيمة! اضغط هنا لاستلامها: {url}"),
    ("ar", "ceo_fraud", "أحتاج منك شراء بطاقات هدايا بقيمة {amt} وإرسال الأكواد لي الآن، أنا في اجتماع"),
    ("ar", "invoice", "فاتورتك غير مدفوعة. قم بتحويل مبلغ اليوم لتجنب الإجراءات القانونية: {url}"),
    ("ar", "bank", "تم إيقاف حسابك البنكي. حدّث بياناتك الآن: {url}"),
    ("mixed", "account_verification", "Compte {Brand} dyalek ghadi ytsad daba. Confirmi l'identité dyalek hna : {url}"),
    ("mixed", "credential_request", "3ajil : sift lia le code li jak f SMS w mot de passe dyalek, c'est pour la maintenance"),
    ("mixed", "prize", "Mabrouk ! rbe7ti cadeau, clicker hna : {url}"),
    ("mixed", "ceo_fraud", "Sir chri {k} cartes cadeaux Amazon w sift lia les codes, ana f réunion"),
    ("mixed", "invoice", "Facture non payée, dir virement daba bach ma tkounch poursuites : {url}"),
]
LEGIT = [
    ("fr", "meeting", "la réunion est décalée à {h}h, tu peux confirmer ta présence ?"),
    ("fr", "docs", "voici le compte rendu de la réunion d'hier : {legit_url}"),
    ("fr", "files", "peux-tu m'envoyer les slides du projet avant {h}h ?"),
    ("fr", "social", "on déjeune ensemble à {h}h ? Je réserve une table"),
    ("fr", "urgent_legit", "Urgent : le serveur de test est en panne, peux-tu regarder ?"),
    ("fr", "hard_negative", "le mot de passe du wifi invité a changé, demande-le à l'accueil"),
    ("fr", "hard_negative", "n'oublie pas de mettre à jour les informations du projet sur le drive"),
    ("fr", "hard_negative", "merci pour le virement, bien reçu !"),
    ("fr", "docs", "j'ai relu ton rapport, voici mes remarques : {legit_url}"),
    ("fr", "social", "je suis en retard, j'arrive dans {m} minutes"),
    ("en", "meeting", "the meeting moved to {h}pm, can you confirm you're coming?"),
    ("en", "files", "can you send me the slides before {h}pm?"),
    ("en", "docs", "here is the documentation we talked about: {legit_url}"),
    ("en", "urgent_legit", "Urgent: the staging server is down, can you take a look?"),
    ("en", "hard_negative", "I validated your report, everything looks good"),
    ("en", "social", "lunch at {h}? I'll book a table"),
    ("en", "hard_negative", "thanks for the payment, received on my side"),
    ("en", "social", "running late, I'll be there in {m} minutes"),
    ("ar", "meeting", "الاجتماع غدا الساعة {h}، هل يناسبك؟"),
    ("ar", "files", "هل يمكنك إرسال الملف قبل نهاية اليوم؟"),
    ("ar", "social", "شكرا {n} على المساعدة، كان العرض ممتازا"),
    ("ar", "urgent_legit", "عاجل: السيرفر متوقف، ممكن تشوف المشكل؟"),
    ("ar", "docs", "هذا رابط الوثائق: {legit_url}"),
    ("ar", "social", "سأتأخر قليلا، أصل خلال {m} دقيقة"),
    ("ar", "hard_negative", "تم تحديث معلومات المشروع على الدرايف"),
    ("mixed", "meeting", "wach nta free ghedda f {h}h bach nchoufou projet ?"),
    ("mixed", "social", "Merci bzaf {n}, kolchi mzyan"),
    ("mixed", "social", "Rani f tri9, ghadi nwsel f {m} minutes"),
    ("mixed", "files", "Sift lia les slides men ba3d ghir kheddam, merci"),
    ("mixed", "docs", "Hado les docs dyal projet : {legit_url}"),
    ("mixed", "urgent_legit", "3ajil : serveur tawa9af, chouf m3aya ?"),
]


def _token(rng, n=7):
    return "".join(rng.choices(string.ascii_letters + string.digits, k=n))


def bad_url(rng):
    """Faux lien de phishing + marque imitée (domaines factices)."""
    brand = rng.choice(BRANDS)
    kind = rng.choice(["homoglyph", "hyphen", "subdomain", "shortener", "ip", "cyrillic"])
    path = rng.choice(["verify", "login", "secure", "account/update", "confirm"])
    tld = rng.choice(["com", "net", "xyz", "top", "info"])
    if kind == "homoglyph":
        leet = next((brand.replace(a, b, 1) for a, b in (("o", "0"), ("l", "1"), ("a", "4"))
                     if a in brand), brand)
        return f"http://{leet}{rng.choice(['-login', '-secure', '-verify', ''])}.{tld}/{path}", brand
    if kind == "hyphen":
        return f"https://{brand}-{rng.choice(['support', 'secure', 'account', 'alert'])}.{tld}/{path}", brand
    if kind == "subdomain":
        return (f"https://{brand}.com.{rng.choice(['secure', 'verify', 'account'])}-{rng.randint(10, 99)}"
                f".{rng.choice(['top', 'xyz', 'click'])}/{path}"), brand
    if kind == "shortener":
        return f"https://{rng.choice(['bit.ly', 'tinyurl.com', 'cutt.ly'])}/{_token(rng)}", brand
    if kind == "ip":
        return f"http://203.0.113.{rng.randint(1, 254)}/{path}", brand      # plage de documentation
    cyr = brand.replace("o", "\u043e", 1) if "o" in brand else brand.replace("a", "\u0430", 1)
    return f"https://{cyr}.com/{path}", brand


def build_rows(seed: int = 42, per_template: int = 25):
    rng = random.Random(seed)
    rows, seen = [], set()
    specs = [(1, PHISHING), (0, LEGIT)]
    for label, templates in specs:
        for idx, (lang, cat, tpl) in enumerate(templates):
            tid = f"{'P' if label else 'L'}{idx:02d}_{lang}"
            made, attempts = 0, 0
            while made < per_template and attempts < per_template * 6:
                attempts += 1
                url, brand = bad_url(rng) if "{url}" in tpl else ("", rng.choice(BRANDS))
                legit_url = rng.choice(LEGIT_URLS)
                body = tpl.format(
                    url=url, legit_url=legit_url, Brand=brand.capitalize(),
                    n=rng.choice(NAMES[lang]), h=rng.randint(8, 18), m=rng.choice([5, 10, 15, 20]),
                    k=rng.choice([3, 5, 10]), amt=rng.choice([300, 500, 1000, 2000]),
                    num=rng.randint(1000, 9999))
                text = rng.choice(PREFIX[lang]) + body + rng.choice(SUFFIX)
                if text in seen:
                    continue
                seen.add(text)
                made += 1
                urls = [url] if url else ([legit_url] if "{legit_url}" in tpl else [])
                rows.append({"text": text, "urls": " | ".join(urls), "label": label,
                             "lang": lang, "category": cat, "template_id": tid})
    rng.shuffle(rows)
    for i, r in enumerate(rows):
        r["id"] = f"m{i:05d}"
    return rows


FIELDS = ["id", "text", "urls", "label", "lang", "category", "template_id"]


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--per-template", type=int, default=25)
    a = ap.parse_args()
    DATA_DIR.mkdir(exist_ok=True)
    rows = build_rows(a.seed, a.per_template)
    write_csv(rows, DATA_DIR / "chat_dataset.csv")
    print(f"{len(rows)} messages -> data/chat_dataset.csv "
          f"(phishing={sum(r['label'] for r in rows)}, normal={sum(1 - r['label'] for r in rows)})")
