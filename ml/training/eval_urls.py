"""Mesure ton UrlAnalyzer sur de VRAIS liens publics (phishing) + de vrais domaines légitimes.

  python -m training.eval_urls --phish data/external/phishtank.csv --legit data/external/tranco.csv

--phish : CSV PhishTank (colonne "url") OU fichier texte avec un lien par ligne (ex. flux OpenPhish).
--legit : liste Tranco ("rang,domaine") OU un domaine par ligne.
Ces fichiers contiennent de VRAIS liens dangereux : ne les ouvre pas, ne les clique pas, ne les commite pas
(dossier data/external/ ignoré par Git). Les exemples affichés sont "désamorcés" (hxxp, [.]).
"""
import argparse
import csv
import random
from collections import Counter
from pathlib import Path

from service.url_features import UrlAnalyzer


def read_phish(path, n, seed=42):
    lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    if lines and "url" in lines[0].lower() and "," in lines[0]:
        urls = [r["url"] for r in csv.DictReader(lines) if r.get("url")]
    else:
        urls = [l.strip() for l in lines if l.strip()]
    random.Random(seed).shuffle(urls)
    return urls[:n]


def read_legit(path, n, seed=42):
    out = []
    for l in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        l = l.strip()
        if not l:
            continue
        out.append(l.split(",")[-1].strip())            # "rang,domaine" -> domaine
    random.Random(seed).shuffle(out)
    return ["https://" + d for d in out[:n]]


def defang(u: str) -> str:
    return u.replace("http", "hxxp").replace(".", "[.]")[:90]


def evaluate_urls(phish, legit, analyzer=None):
    A = analyzer or UrlAnalyzer()
    ps = [A.analyze([u]) for u in phish]
    ls = [A.analyze([u]) for u in legit]
    res = {"n_phish": len(ps), "n_legit": len(ls)}
    for thr in (0.40, 0.80):
        res[f"recall@{thr}"] = sum(r.score >= thr for r in ps) / max(len(ps), 1)
        res[f"false_positive_rate@{thr}"] = sum(r.score >= thr for r in ls) / max(len(ls), 1)
    res["codes_on_phish"] = Counter(c for r in ps for c, _ in r.reasons)
    res["missed"] = [defang(u) for u, r in zip(phish, ps) if r.score < 0.40][:5]
    res["false_alarms"] = [defang(u) for u, r in zip(legit, ls) if r.score >= 0.40][:5]
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", required=True)
    ap.add_argument("--legit", required=True)
    ap.add_argument("--n", type=int, default=1000)
    a = ap.parse_args()
    r = evaluate_urls(read_phish(a.phish, a.n), read_legit(a.legit, a.n))
    print(f"{r['n_phish']} liens de phishing, {r['n_legit']} domaines légitimes")
    for thr in (0.40, 0.80):
        print(f"seuil {thr}: rappel={r[f'recall@{thr}']:.2f}  fausses alertes={r[f'false_positive_rate@{thr}']:.2f}")
    print("Signaux déclenchés sur le phishing :", dict(r["codes_on_phish"]))
    print("Exemples ratés (désamorcés)       :", r["missed"])
    print("Fausses alertes (désamorcées)     :", r["false_alarms"])
