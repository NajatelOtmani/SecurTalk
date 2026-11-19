"""Étape 9 : règle les seuils du contrat (2.10) sur le jeu DEV, puis note UNE FOIS sur le TEST FINAL.

  python -m training.tune_thresholds            (affiche seulement ; ne modifie PAS config.json)

Règle de choix, sur le DEV uniquement :
  - phishing_from (blocage) : le plus BAS seuil dont la précision >= 0.98  -> on ne bloque presque jamais à tort
  - safe_below   (alerte)   : le plus BAS seuil dont la précision >= 0.90  -> on rattrape un maximum de phishing
Le TEST FINAL n'intervient jamais dans le choix : il sert à vérifier honnêtement le résultat.
"""
import numpy as np
from sklearn.metrics import precision_recall_fscore_support

from service.model import load_if_available
from .build_dataset import DATA_DIR
from .train_baseline import load, probabilities

GRID = np.round(np.arange(0.05, 0.96, 0.05), 2)


def prf(y, p, thr):
    pred = (p >= thr).astype(int)
    a, b, c, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    return a, b, c


def lowest_threshold(y, p, min_precision):
    for t in GRID:
        pr, rc, _ = prf(y, p, t)
        if pr >= min_precision and rc > 0:
            return float(t)
    return None


def hybrid(model, rows):
    y = np.array([int(r["label"]) for r in rows])
    return y, probabilities(model, rows)["HYBRIDE"]


if __name__ == "__main__":
    model = load_if_available()
    if model is None:
        raise SystemExit("Pas de modèle : lance d'abord  python -m training.train_baseline")
    dev = load(DATA_DIR / "handwritten" / "handwritten_seed.csv")
    test_path = DATA_DIR / "handwritten" / "handwritten_test.csv"
    y_dev, p_dev = hybrid(model, dev)

    print(f"DEV (n={len(dev)}) : seuil -> précision / rappel")
    for t in GRID[::2]:
        pr, rc, _ = prf(y_dev, p_dev, t)
        print(f"  {t:.2f} -> {pr:.2f} / {rc:.2f}")

    alert, block = lowest_threshold(y_dev, p_dev, 0.90), lowest_threshold(y_dev, p_dev, 0.98)
    print(f"\nSeuils proposés (choisis sur le DEV) : safe_below={alert}  phishing_from={block}")
    if alert is None or block is None or alert > block:
        raise SystemExit("Pas de seuil satisfaisant : il faut plus de données.")

    if test_path.exists():
        test = load(test_path)
        y_t, p_t = hybrid(model, test)
        print(f"\nTEST FINAL (n={len(test)}) -- à lire UNE fois, ne pas réajuster dessus :")
        for name, thr in (("alerte", alert), ("blocage", block), ("alerte ANCIEN 0.40", 0.40), ("blocage ANCIEN 0.80", 0.80)):
            pr, rc, f1 = prf(y_t, p_t, thr)
            print(f"  {name:20s} seuil {thr:.2f} : précision={pr:.2f} rappel={rc:.2f} F1={f1:.2f}")
    print("\nPour appliquer : modifie thresholds dans ml/config.json, puis préviens ton amie (client).")
