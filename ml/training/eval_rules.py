"""Évalue le détecteur À RÈGLES (étape 4) : matrice de confusion, précision, rappel, F1.
  python -m training.eval_rules
"""
import csv
from pathlib import Path

from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from service.analyzer import PhishingDetector
from .build_dataset import DATA_DIR

D = PhishingDetector()


def load(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def evaluate(rows, threshold):
    y = [int(r["label"]) for r in rows]
    pred = [int(D.analyze(r["text"], [u.strip() for u in r["urls"].split("|") if u.strip()]).score >= threshold)
            for r in rows]
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    return confusion_matrix(y, pred, labels=[0, 1]), p, r, f


if __name__ == "__main__":
    sets = {"test (synthétique)": DATA_DIR / "test.csv",
            "écrit à la main": DATA_DIR / "handwritten" / "handwritten_seed.csv"}
    for name, path in sets.items():
        if not Path(path).exists():
            continue
        rows = load(path)
        for thr, lab in ((0.40, "alerte (>= Suspicious)"), (0.80, "blocage (>= Phishing)")):
            cm, p, r, f = evaluate(rows, thr)
            print(f"\n[{name}] n={len(rows)}  seuil {thr} -> {lab}")
            print(f"  TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}  "
                  f"précision={p:.2f} rappel={r:.2f} F1={f:.2f}")
