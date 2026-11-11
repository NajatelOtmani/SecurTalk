"""PhishingDetector (guide 8.1 / 8.4) : le chef d'orchestre.

texte  -> TextAnalyzer -> score_texte ─┐
liens  -> UrlAnalyzer  -> score_liens ─┴─> fusion -> score final -> label (seuils config.json)
                                  (modèle ML optionnel : branché à l'étape 6)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Tuple

from .config import MAX_TEXT_CHARS, MAX_URLS, PHISHING_FROM, label_from_score
from .text_features import TextAnalyzer
from .url_features import UrlAnalyzer

_URL_IN_TEXT = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)

_EMPTY_URL_FEATURES = {f"url_{k}": 0 for k in UrlAnalyzer().check_domain("").features}


class MLModelLike(Protocol):
    def predict(self, features: Dict[str, float]) -> float: ...


def extract_urls(text: str) -> List[str]:
    """Liens présents dans le texte (filet de sécurité si le client en a oublié)."""
    return [m.group(0).rstrip(".,;:!?)") for m in _URL_IN_TEXT.finditer(text or "")]


@dataclass
class Detection:
    score: float
    label: str
    reasons: List[Tuple[str, str]]
    url_domains: List[str] = field(default_factory=list)
    text_length: int = 0
    features: Dict[str, float] = field(default_factory=dict)

    @property
    def reason_codes(self) -> List[str]:
        return [c for c, _ in self.reasons]


class PhishingDetector:
    def __init__(self, text_analyzer: Optional[TextAnalyzer] = None,
                 url_analyzer: Optional[UrlAnalyzer] = None,
                 model: Optional[MLModelLike] = None):
        self.text = text_analyzer or TextAnalyzer()
        self.urls = url_analyzer or UrlAnalyzer()
        self.model = model          # None tant que le modèle n'est pas entraîné

    def analyze(self, text: str, urls: List[str]) -> Detection:
        text = (text or "")[:MAX_TEXT_CHARS]
        # liens fournis par le client + liens trouvés dans le texte, sans doublon, plafonnés
        all_urls = list(dict.fromkeys([u for u in (urls or []) if u] + extract_urls(text)))[:MAX_URLS]

        t = self.text.extract_features(text)
        u = self.urls.analyze(all_urls)

        # Fusion "noisy-or" : deux signaux indépendants se renforcent, mais jamais > 1.
        score = 1.0 - (1.0 - t.score) * (1.0 - u.score)

        features: Dict[str, float] = dict(t.features)
        worst = max(u.reports, key=lambda r: r.score, default=None)
        features.update({f"url_{k}": v for k, v in worst.features.items()} if worst else _EMPTY_URL_FEATURES)
        features["n_urls"] = len(all_urls)

        reasons = list(u.reasons) + list(t.reasons)
        if self.model is not None:                      # étape 6
            m = float(self.model.predict(features))
            score = max(score, m)
            if m >= PHISHING_FROM:
                reasons.append(("MODEL_HIGH_SCORE", "Le modèle d'analyse estime ce message très risqué"))

        score = round(min(max(score, 0.0), 1.0), 4)
        return Detection(score=score, label=label_from_score(score), reasons=reasons,
                         url_domains=u.domains, text_length=len(text), features=features)
