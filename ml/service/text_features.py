"""TextAnalyzer (guide 8.1 / 8.2) : signaux de phishing dans le TEXTE d'un message.

Multilingue : français, anglais, arabe (+ quelques mots de darija en lettres latines).
Sorties : raisons (codes TEXT_* du contrat), score "règles" (0-1), features numériques pour le ML.
RÈGLE DE CONFIDENTIALITÉ : le texte n'est jamais stocké ni journalisé ici ; on ne garde que
des compteurs et des codes.
"""
from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

MAX_CHARS = 5000

WEIGHTS = {
    "TEXT_URGENCY": 0.25,
    "TEXT_ACCOUNT_VERIFICATION": 0.40,
    "TEXT_THREAT": 0.45,
    "TEXT_CREDENTIAL_REQUEST": 0.55,
    "TEXT_MONEY_REQUEST": 0.45,
}

REASON_TEXTS = {
    "TEXT_URGENCY": "Message demandant une action immédiate",
    "TEXT_ACCOUNT_VERIFICATION": "Demande de vérifier ou de confirmer un compte",
    "TEXT_THREAT": "Menace de suspension ou de blocage du compte",
    "TEXT_CREDENTIAL_REQUEST": "Demande d'un mot de passe, d'un code ou d'une carte",
    "TEXT_MONEY_REQUEST": "Demande de virement, de paiement ou de cartes cadeaux",
}

_ARABIC = re.compile(r"[\u0600-\u06FF]")


# ----------------------------------------------------------------------------
# Normalisation : minuscules, sans accents, arabe simplifié
# ----------------------------------------------------------------------------
def normalize(text: str) -> str:
    s = unicodedata.normalize("NFKD", text.lower())
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")  # accents + voyelles arabes + hamza
    s = s.replace("\u0640", "")                                    # tatweel (ـ)
    s = s.replace("ة", "ه").replace("ى", "ي")
    s = s.replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", s).strip()


def _lit(phrases: List[str], stem: bool = False) -> str:
    """Alternation regex à partir de phrases littérales (normalisées, espaces souples)."""
    parts = []
    for p in phrases:
        n = re.escape(normalize(p)).replace(r"\ ", r"\s+")
        if stem:
            n += r"\w*"
        if not _ARABIC.search(n):
            n = r"(?<!\w)" + n          # début de mot pour le latin
        parts.append(n)
    return "(?:" + "|".join(parts) + ")"


def _near(verbs: str, objs: str, gap: int = 5) -> str:
    """Un verbe suivi d'un objet à moins de `gap` mots."""
    return rf"{verbs}(?:\W+\w+){{0,{gap}}}?\W+{objs}"


# ----------------------------------------------------------------------------
# Motifs par catégorie
# ----------------------------------------------------------------------------
_URGENCY = _lit([
    "immediatement", "urgent", "urgemment", "sans delai", "au plus vite", "dans les 24 h",
    "dans les 24h", "dans 24 h", "sous 24 h", "sous 24h", "dernier avertissement",
    "dernier rappel", "avant ce soir", "tout de suite", "action requise",
    "immediately", "right away", "asap", "within 24 hours", "within 24h", "final warning",
    "last warning", "act now", "action required",
    "عاجل", "فورا", "حالا", "في اسرع وقت", "خلال 24 ساعه", "تنبيه اخير",
    "3ajil", "fawran", "b sor3a",
])

_VERIFY_VERBS = _lit(["verifi", "confirm", "valid", "mettez a jour", "mettre a jour",
                      "mise a jour", "actualis", "reactiv", "verify", "validate", "update",
                      "re-activate", "تحقق", "تاكيد", "تاكد", "اكد", "تحديث", "حدث", "فعل"],
                     stem=True)
_VERIFY_OBJS = (
    r"(?:(?:votre|vos|ton|ta|tes|your)\s+(?:\w+\s+){0,1}"
    r"(?:compte(?!\s+rendu)|identite|informations?|coordonnees|account|identity|billing|payment)"
    r"|حسابك|حسابكم|هويتك|بياناتك|معلوماتك)"
)
_ACCOUNT_VERIFICATION = _near(_VERIFY_VERBS, _VERIFY_OBJS, gap=3)

_THREAT_SUBJ = _lit(["votre compte", "votre acces", "votre carte", "your account",
                     "your access", "your card", "حسابك", "بطاقتك"])
_THREAT_STATE = _lit(["suspendu", "bloque", "ferme", "desactive", "supprime", "limite",
                      "restreint", "suspended", "blocked", "closed", "locked", "deactivated",
                      "terminated", "disabled", "restricted", "suspend", "lock", "close",
                      "معلق", "محظور", "مغلق", "موقوف"], stem=True)
_THREAT = "|".join([
    _near(_THREAT_SUBJ, _THREAT_STATE, gap=5),
    _lit(["action en justice", "poursuites judiciaires", "legal action", "will be reported",
          "سيتم تعليق", "سيتم اغلاق", "سيتم حظر", "سيتم ايقاف", "سيتم تجميد", "سيتم حذف",
          "إجراء قانوني"]),
])

_CRED_OBJS = _lit([
    "mot de passe", "mots de passe", "password", "passcode", "code de verification",
    "code de securite", "code secret", "code pin", "otp", "identifiants", "credentials",
    "login details", "numero de carte", "card number", "cvv", "carte bancaire",
    "كلمه المرور", "كلمه السر", "رمز التحقق", "كود التحقق", "رقم البطاقه", "الرقم السري",
])
_CRED_VERBS = _lit(["envoy", "donn", "communiqu", "saisi", "entr", "fourni", "partag",
                    "confirm", "renseign", "transmet", "send", "enter", "provide", "share",
                    "give", "submit", "reply with", "ارسل", "ارسال", "ادخل", "ادخال", "زود",
                    "تزويد", "شارك", "مشاركه", "اكد", "اعط"], stem=True)
_CREDENTIAL = "|".join([
    _near(_CRED_VERBS, _CRED_OBJS, gap=5),
    _lit(["votre mot de passe expire", "votre mot de passe a expire",
          "your password will expire", "your password has expired"]),
])

_MONEY_STRONG = _lit(["carte cadeau", "cartes cadeaux", "carte-cadeau", "gift card",
                      "gift cards", "western union", "bitcoin", "crypto-monnaie",
                      "بطاقات هدايا", "بطاقه هديه", "ويسترن يونيون"])
_MONEY_VERBS = _lit(["envoy", "effectu", "faites", "fais", "vir", "transf", "pay",
                     "send", "wire", "transfer", "make a", "ارسل", "حول", "ادفع"], stem=True)
_MONEY_OBJS = _lit(["virement", "paiement", "argent", "somme", "montant", "wire transfer",
                    "payment", "money", "funds", "حواله", "مبلغ", "فلوس"])
_MONEY = "|".join([_MONEY_STRONG, _near(_MONEY_VERBS, _MONEY_OBJS, gap=4)])

PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "TEXT_URGENCY": re.compile(_URGENCY),
    "TEXT_ACCOUNT_VERIFICATION": re.compile(_ACCOUNT_VERIFICATION),
    "TEXT_THREAT": re.compile(_THREAT),
    "TEXT_CREDENTIAL_REQUEST": re.compile(_CREDENTIAL),
    "TEXT_MONEY_REQUEST": re.compile(_MONEY),
}


# ----------------------------------------------------------------------------
@dataclass
class TextAnalysis:
    score: float
    reasons: List[Tuple[str, str]] = field(default_factory=list)   # (code, texte FR)
    features: Dict[str, float] = field(default_factory=dict)

    @property
    def codes(self) -> List[str]:
        return [c for c, _ in self.reasons]


class TextAnalyzer:
    def extract_features(self, text: str) -> TextAnalysis:
        raw = (text or "")[:MAX_CHARS]
        norm = normalize(raw)

        counts: Dict[str, int] = {}
        reasons: List[Tuple[str, str]] = []
        for code, pat in PATTERNS.items():
            n = len(pat.findall(norm))
            counts[code] = n
            if n:
                reasons.append((code, REASON_TEXTS[code]))

        p = 1.0
        for code, _ in reasons:
            p *= 1.0 - WEIGHTS[code]
        score = round(1.0 - p, 4)

        letters = [c for c in raw if c.isalpha()]
        features = {
            "text_length": len(raw),
            "n_words": len(raw.split()),
            "n_exclamations": raw.count("!"),
            "uppercase_ratio": (sum(c.isupper() for c in letters) / len(letters)) if letters else 0.0,
            "n_links_in_text": len(re.findall(r"https?://|www\.", raw, flags=re.I)),
            "n_urgency": counts["TEXT_URGENCY"],
            "n_account_verification": counts["TEXT_ACCOUNT_VERIFICATION"],
            "n_threat": counts["TEXT_THREAT"],
            "n_credential_request": counts["TEXT_CREDENTIAL_REQUEST"],
            "n_money_request": counts["TEXT_MONEY_REQUEST"],
        }
        return TextAnalysis(score=score, reasons=reasons, features=features)

    analyze = extract_features   # alias
