"""MLModel (guide 8.1) : charge le modèle entraîné et calcule une probabilité de phishing.

Deux modèles combinés (moyenne) :
  - texte  : TF-IDF sur caractères + régression logistique
  - features : Random Forest sur les features des étapes 2 et 3
ATTENTION : joblib utilise pickle. Ne charge JAMAIS un fichier .joblib venant d'une source inconnue.
"""
from pathlib import Path
from typing import Dict, List, Optional

import joblib

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "phishing_model.joblib"


class MLModel:
    def __init__(self, text_model, feature_model, feature_names: List[str],
                 version: str = "rf-lr-0.1", w_text: float = 0.5):
        self.text_model = text_model
        self.feature_model = feature_model
        self.feature_names = feature_names
        self.version = version
        self.w_text = w_text

    def predict(self, text: str, features: Dict[str, float]) -> float:
        p_text = float(self.text_model.predict_proba([text])[0][1])
        x = [[float(features.get(n, 0.0)) for n in self.feature_names]]
        p_feat = float(self.feature_model.predict_proba(x)[0][1])
        return self.w_text * p_text + (1.0 - self.w_text) * p_feat

    def save(self, path: Path = MODEL_PATH) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"text_model": self.text_model, "feature_model": self.feature_model,
                     "feature_names": self.feature_names, "version": self.version,
                     "w_text": self.w_text}, path)

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "MLModel":
        d = joblib.load(path)
        return cls(d["text_model"], d["feature_model"], d["feature_names"], d["version"], d["w_text"])


def load_if_available(path: Path = MODEL_PATH) -> Optional[MLModel]:
    """Le service doit démarrer même sans modèle (ou avec un fichier incompatible) : mode règles seules."""
    try:
        return MLModel.load(path) if Path(path).exists() else None
    except Exception:
        return None
