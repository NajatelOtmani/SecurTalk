"""UrlAnalyzer (guide 8.6) : analyse des liens, sans réseau, sans ouvrir les liens.

Sorties :
  - des raisons du contrat 2.10 (codes de la liste fermée 8.2) ;
  - un score de risque "règles" (0-1) ;
  - des caractéristiques numériques (features) réutilisables pour le modèle ML.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

# ----------------------------------------------------------------------------
# Listes de référence (à enrichir : ajoute les marques de ton entreprise fictive)
# marque -> domaines officiels (domaine enregistré, ex. "microsoft.com")
# ----------------------------------------------------------------------------
BRANDS: Dict[str, Set[str]] = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com",
                  "outlook.com", "office365.com", "windows.com", "azure.com",
                  "sharepoint.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googleapis.com",
               "gstatic.com", "google.fr", "google.co.ma"},
    "paypal": {"paypal.com", "paypal.me"},
    "linkedin": {"linkedin.com", "licdn.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.fr", "amazonaws.com", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "attijariwafa": {"attijariwafabank.com"},
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
              "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc"}

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
                   "link", "work", "support", "country", "gdn", "loan", "men", "icu",
                   "cyou", "buzz", "rest", "monster", "sbs"}

# suffixes à deux niveaux courants (évite une dépendance à la Public Suffix List)
SECOND_LEVEL_SUFFIXES = {"co.uk", "com.ma", "ac.ma", "org.ma", "gov.ma", "co.ma",
                         "net.ma", "com.au", "co.in", "com.br", "co.jp"}

# Caractères cyrilliques / grecs qui ressemblent à des lettres latines
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ӏ": "l", "к": "k",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "τ": "t", "κ": "k",
})
_DIGITS_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
_DIGITS_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})

# Poids pour le score "règles" (combinés en "noisy-or" : 1 - produit(1 - poids))
WEIGHTS = {
    "URL_BRAND_IMITATION": 0.85, "URL_HOMOGLYPH": 0.60, "URL_IP_ADDRESS": 0.60,
    "URL_SHORTENER": 0.40, "URL_SUSPICIOUS_TLD": 0.35, "URL_TOO_LONG": 0.30,
}


# ----------------------------------------------------------------------------
# Outils
# ----------------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    """Distance d'édition : nombre minimal d'insertions/suppressions/substitutions."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _variants(s: str) -> Set[str]:
    """Versions 'dé-obfusquées' d'un texte (0->o, 1->l ou i, rn->m, cyrillique->latin...)."""
    s = s.lower().translate(CONFUSABLES)
    out = {s, s.translate(_DIGITS_L), s.translate(_DIGITS_I)}
    for v in list(out):
        out.add(v.replace("rn", "m").replace("vv", "w"))
    return out


def _extract_host(url: str) -> Tuple[str, bool]:
    """Renvoie (hôte en minuscules, contient_arobase). Ne plante jamais."""
    s = (url or "").strip()
    if not s:
        return "", False
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", s):
        s = "http://" + s
    try:
        host = urlparse(s).hostname or ""
    except ValueError:
        return "", False
    authority = s.split("://", 1)[1].split("/", 1)[0]
    return host.rstrip("."), "@" in authority


def _to_unicode_host(host: str) -> str:
    """Décode le punycode (xn--...) pour voir les vrais caractères."""
    if "xn--" in host:
        try:
            return host.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return host
    return host


@dataclass
class HomoglyphInfo:
    non_ascii_confusable: bool   # ex. 'о' cyrillique à la place de 'o'
    digit_substitution: bool     # ex. '0' au milieu de lettres : micros0ft
    normalized: str              # domaine "nettoyé"


def detect_homoglyph(domain: str) -> HomoglyphInfo:
    d = _to_unicode_host(domain.lower())
    non_ascii = any(c in CONFUSABLES_SET for c in d)
    digit_sub = any(
        re.search(r"[a-z][0-9]+[a-z]|[a-z][0-9]+$|^[0-9]+[a-z]", label) and
        re.search(r"[a-z]", label)
        for label in d.split(".")[:-1]
    )
    return HomoglyphInfo(non_ascii, bool(digit_sub), d.translate(CONFUSABLES))


CONFUSABLES_SET = {chr(k) for k in CONFUSABLES}


@dataclass
class UrlReport:
    url: str
    host: str
    registered_domain: str
    reasons: List[Tuple[str, str]] = field(default_factory=list)  # (code, texte FR)
    features: Dict[str, float] = field(default_factory=dict)

    @property
    def codes(self) -> List[str]:
        return [c for c, _ in self.reasons]

    @property
    def score(self) -> float:
        p = 1.0
        for code in self.codes:
            p *= 1.0 - WEIGHTS[code]
        return round(1.0 - p, 4)


@dataclass
class UrlAnalysis:
    score: float
    reasons: List[Tuple[str, str]]
    domains: List[str]
    reports: List[UrlReport]


# ----------------------------------------------------------------------------
class UrlAnalyzer:
    def __init__(self, brands: Dict[str, Set[str]] | None = None):
        self.brands = brands or BRANDS

    # -- découpage du domaine ------------------------------------------------
    @staticmethod
    def _split(host: str) -> Tuple[List[str], str, str]:
        """(libellés du nom sans suffixe, suffixe, domaine enregistré)."""
        labels = [l for l in host.split(".") if l]
        if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES:
            n = 2
        else:
            n = 1
        if len(labels) <= n:
            return labels, "", host
        name_labels = labels[:-n]
        suffix = ".".join(labels[-n:])
        registered = ".".join([name_labels[-1], suffix])
        return name_labels, suffix, registered

    # -- imitation de marque -------------------------------------------------
    def _brand_hit(self, name_labels: List[str], registered: str):
        """Renvoie (marque, morceau_brut) si le domaine imite une marque sans être officiel."""
        pieces = [(tok, tok) for lab in name_labels for tok in re.split(r"-+", lab) if tok]
        for brand, official in self.brands.items():
            if registered in official:
                continue                      # c'est le vrai domaine
            for raw, _ in pieces:
                for v in _variants(_to_unicode_host(raw)):
                    if v == brand:
                        return brand, raw
                    if len(brand) >= 6 and (brand in v or levenshtein(v, brand) <= 1):
                        return brand, raw
        return None

    # -- analyse d'un lien ---------------------------------------------------
    def check_domain(self, url: str) -> UrlReport:
        host, has_at = _extract_host(url)
        host_u = _to_unicode_host(host)
        name_labels, suffix, registered = self._split(host_u)
        tld = suffix.split(".")[-1] if suffix else ""
        report = UrlReport(url=url, host=host_u, registered_domain=registered)
        if not host_u:
            report.features = self._features(url, host_u, name_labels, 0, 0, 0, 0, 0, 0, has_at)
            return report

        reasons = report.reasons
        is_ip = False
        try:
            ipaddress.ip_address(host_u.strip("[]"))
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            reasons.append(("URL_IP_ADDRESS",
                            "Le lien utilise une adresse IP au lieu d'un nom de site"))
        else:
            hg = detect_homoglyph(host_u)
            hit = self._brand_hit(name_labels, registered)
            if hit:
                brand, raw = hit
                reasons.append(("URL_BRAND_IMITATION",
                                f"Le domaine imite {brand.capitalize()} ({raw})"))
            if hg.non_ascii_confusable or (hg.digit_substitution and hit):
                reasons.append(("URL_HOMOGLYPH",
                                "Le domaine contient des caractères trompeurs "
                                "(chiffres ou lettres qui ressemblent à d'autres)"))
            if registered in SHORTENERS:
                reasons.append(("URL_SHORTENER",
                                "Lien raccourci : la vraie destination est cachée"))
            if tld in SUSPICIOUS_TLDS:
                reasons.append(("URL_SUSPICIOUS_TLD",
                                f"Extension de domaine souvent utilisée pour des arnaques (.{tld})"))
            n_sub = max(0, len(name_labels) - 1)
            if len(url) > 75 or n_sub >= 3 or host_u.count("-") >= 4:
                reasons.append(("URL_TOO_LONG",
                                "Lien anormalement long ou avec trop de sous-domaines"))

        n_sub = max(0, len(name_labels) - 1)
        c = report.codes
        report.features = self._features(
            url, host_u, name_labels, int(is_ip), int("URL_SHORTENER" in c),
            int("URL_SUSPICIOUS_TLD" in c), int("URL_BRAND_IMITATION" in c),
            int("URL_HOMOGLYPH" in c), n_sub, has_at)
        return report

    @staticmethod
    def _features(url, host, name_labels, is_ip, shortener, bad_tld,
                  brand, homoglyph, n_sub, has_at) -> Dict[str, float]:
        sld = name_labels[-1] if name_labels else ""
        return {
            "url_length": len(url), "host_length": len(host),
            "n_digits_in_domain": sum(ch.isdigit() for ch in sld),
            "n_hyphens_in_domain": host.count("-"), "n_subdomains": n_sub,
            "has_ip": is_ip, "is_shortener": shortener, "suspicious_tld": bad_tld,
            "brand_imitation": brand, "homoglyph": homoglyph,
            "has_at_symbol": int(has_at), "uses_https": int(url.strip().lower().startswith("https://")),
        }

    # -- analyse d'une liste de liens (ce que main.py appellera) -------------
    def analyze(self, urls: List[str]) -> UrlAnalysis:
        reports = [self.check_domain(u) for u in urls]
        seen, reasons = set(), []
        for r in reports:
            for code, text in r.reasons:
                if code not in seen:
                    seen.add(code)
                    reasons.append((code, text))
        score = max((r.score for r in reports), default=0.0)
        return UrlAnalysis(score=score, reasons=reasons,
                           domains=[r.host for r in reports if r.host], reports=reports)
