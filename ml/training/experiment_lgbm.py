"""EXPÉRIENCE (ne modifie rien en production) : le LightGBM proposé bat-il le modèle actuel ?

  python -m training.experiment_lgbm

Compare, sur les jeux écrits à la main (DEV 102 / TEST FINAL 35), avec 5 graines pour voir le bruit :
  1. hybride ACTUEL (règles + LR texte + RF features)
  2. LightGBM sur les features seules
  3. LightGBM sur TF-IDF réduit par SVD (50 dimensions) + features
  4. règles + LightGBM (3)
On n'adopte un nouveau modèle QUE s'il est meilleur sur le DEV ET sur le TEST, au-delà du bruit.
"""
import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import roc_auc_score

from service.text_features import normalize
from .build_dataset import DATA_DIR
from .train_baseline import featurize, fit_model, load, probabilities
from .tune_thresholds import lowest_threshold, prf

SEEDS = range(5)


def make_gbm(seed):
    try:
        from lightgbm import LGBMClassifier
        return LGBMClassifier(n_estimators=200, learning_rate=0.05, num_leaves=15, min_child_samples=10,
                              subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
                              random_state=seed, verbose=-1)
    except ImportError:                       # même famille d'algorithmes, déjà dans scikit-learn
        from sklearn.ensemble import HistGradientBoostingClassifier
        return HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, max_leaf_nodes=15, random_state=seed)


def main():
    train = load(DATA_DIR / "train.csv")
    dev = load(DATA_DIR / "handwritten" / "handwritten_seed.csv")
    test = load(DATA_DIR / "handwritten" / "handwritten_test.csv")
    y = {"dev": np.array([int(r["label"]) for r in dev]), "test": np.array([int(r["label"]) for r in test])}
    Xtr, names, rules_tr = featurize(train)
    ytr = np.array([int(r["label"]) for r in train])
    Xf = {"dev": featurize(dev), "test": featurize(test)}

    scores = {k: {"dev": [], "test": []} for k in ("actuel", "gbm_features", "gbm_svd", "regles+gbm")}
    cur = fit_model(train)
    cur_p = {k: probabilities(cur, rows)["HYBRIDE"] for k, rows in (("dev", dev), ("test", test))}
    last = {}
    for seed in SEEDS:
        tf = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, preprocessor=normalize)
        svd = TruncatedSVD(50, random_state=seed)
        Ttr = svd.fit_transform(tf.fit_transform([r["text"] for r in train]))
        g_feat = make_gbm(seed).fit(Xtr, ytr)
        g_svd = make_gbm(seed).fit(np.hstack([Ttr, Xtr]), ytr)
        for k, rows in (("dev", dev), ("test", test)):
            X, _, rules = Xf[k]
            T = svd.transform(tf.transform([r["text"] for r in rows]))
            p_feat = g_feat.predict_proba(X)[:, 1]
            p_svd = g_svd.predict_proba(np.hstack([T, X]))[:, 1]
            for name, p in (("actuel", cur_p[k]), ("gbm_features", p_feat), ("gbm_svd", p_svd),
                            ("regles+gbm", np.maximum(rules, p_svd))):
                scores[name][k].append(roc_auc_score(y[k], p))
                last[(name, k)] = p

    print(f"{'système':16s} | AUC DEV (moy ± écart, 5 graines) | AUC TEST | alerte sur TEST avec seuil réglé sur DEV (P / R)")
    for name in scores:
        d, t = np.array(scores[name]["dev"]), np.array(scores[name]["test"])
        thr = lowest_threshold(y["dev"], last[(name, "dev")], 0.90)
        pr = prf(y["test"], last[(name, "test")], thr) if thr is not None else (float("nan"),) * 3
        print(f"{name:16s} | {d.mean():.3f} ± {d.std():.3f}              | {t.mean():.3f} ± {t.std():.3f} | seuil {thr}: {pr[0]:.2f} / {pr[1]:.2f}")
    print("\nLecture : une différence plus petite que l'écart (±) est du BRUIT ; avec 35 messages de test, "
          "méfie-toi d'une AUC qui bouge de moins de ~0.03.")


if __name__ == "__main__":
    main()
