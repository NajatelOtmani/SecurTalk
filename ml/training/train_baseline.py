"""Étape 6 : baseline ML. Entraîne sur train.csv, évalue sur val / test / écrit-à-la-main.

  python -m training.train_baseline

Modèles : (A) TF-IDF caractères + régression logistique ; (B) Random Forest sur features.
Le jeu écrit à la main n'est JAMAIS utilisé pour entraîner : il sert uniquement à mesurer.
"""
import csv
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import Pipeline

from service.analyzer import PhishingDetector
from service.model import MLModel, MODEL_PATH
from service.text_features import normalize
from .build_dataset import DATA_DIR

RULES = PhishingDetector()                      # règles seules (sans modèle)


def load(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _urls(r):
    return [u.strip() for u in r["urls"].split("|") if u.strip()]


def featurize(rows):
    dets = [RULES.analyze(r["text"], _urls(r)) for r in rows]
    names = sorted(dets[0].features)
    X = np.array([[d.features[n] for n in names] for d in dets], dtype=float)
    return X, names, np.array([d.score for d in dets])


def fit_model(rows, seed=42, n_trees=300) -> MLModel:
    texts = [r["text"] for r in rows]
    y = [int(r["label"]) for r in rows]
    X, names, _ = featurize(rows)
    text_model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2,
                                  sublinear_tf=True, preprocessor=normalize)),
        ("lr", LogisticRegression(C=5, max_iter=2000, class_weight="balanced")),
    ]).fit(texts, y)
    rf = RandomForestClassifier(n_estimators=n_trees, min_samples_leaf=2, class_weight="balanced",
                                random_state=seed, n_jobs=-1).fit(X, y)
    return MLModel(text_model, rf, names, version="rf-lr-0.1")


def probabilities(model: MLModel, rows):
    X, _, rules = featurize(rows)
    lr = model.text_model.predict_proba([r["text"] for r in rows])[:, 1]
    rf = model.feature_model.predict_proba(X)[:, 1]
    ml = model.w_text * lr + (1 - model.w_text) * rf
    return {"règles": rules, "LR texte": lr, "RF features": rf,
            "ML (LR+RF)": ml, "HYBRIDE": np.maximum(rules, ml)}


def prf(y, p, thr):
    pred = (p >= thr).astype(int)
    a, b, c, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    return a, b, c


if __name__ == "__main__":
    train = load(DATA_DIR / "train.csv")
    model = fit_model(train)
    model.save(MODEL_PATH)
    print(f"Modèle entraîné sur {len(train)} messages -> models/phishing_model.joblib\n")

    sets = {"val": DATA_DIR / "val.csv", "test": DATA_DIR / "test.csv",
            "écrit à la main DEV": DATA_DIR / "handwritten" / "handwritten_seed.csv",
            "écrit à la main TEST FINAL": DATA_DIR / "handwritten" / "handwritten_test.csv"}
    for name, path in sets.items():
        if not Path(path).exists():
            continue
        rows = load(path)
        y = np.array([int(r["label"]) for r in rows])
        print(f"=== {name} (n={len(rows)}) ===")
        print(f"{'système':14s} {'AUC':>5s} | alerte>=0.40 (P / R / F1) | blocage>=0.80 (P / R / F1)")
        for sys_name, p in probabilities(model, rows).items():
            a1, b1, c1 = prf(y, p, 0.40)
            a2, b2, c2 = prf(y, p, 0.80)
            print(f"{sys_name:14s} {roc_auc_score(y, p):5.2f} | {a1:.2f} / {b1:.2f} / {c1:.2f}"
                  f"          | {a2:.2f} / {b2:.2f} / {c2:.2f}")
        print()

    tf = model.text_model.named_steps["tfidf"].get_feature_names_out()
    w = model.text_model.named_steps["lr"].coef_[0]
    order = np.argsort(w)
    print("Morceaux de texte qui poussent vers PHISHING :", [tf[i] for i in order[-12:][::-1]])
    print("Morceaux de texte qui poussent vers NORMAL   :", [tf[i] for i in order[:12]])
