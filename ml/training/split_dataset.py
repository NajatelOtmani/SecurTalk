"""Découpe train / val / test (70/15/15) SANS fuite de données.

  python -m training.split_dataset            ->  data/train.csv, val.csv, test.csv

1) suppression des doublons (texte normalisé) ;
2) découpage par GABARIT (template_id) : un même gabarit n'apparaît que dans UN seul ensemble.
   Sinon le test contiendrait des quasi-copies du train et les scores seraient gonflés.
   (--mode random : découpage aléatoire simple, plus optimiste, à éviter pour le rapport.)
"""
import argparse
import csv
import random
import re
from collections import defaultdict
from pathlib import Path

from .build_dataset import DATA_DIR, FIELDS, write_csv


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", t.lower()).strip()


def dedupe(rows):
    seen, out = set(), []
    for r in rows:
        k = norm(r["text"])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def split_rows(rows, seed=42, mode="template", ratios=(0.70, 0.15, 0.15)):
    rng = random.Random(seed)
    rows = dedupe(rows)
    parts = {"train": [], "val": [], "test": []}
    for label in sorted({int(r["label"]) for r in rows}):          # stratifié par classe
        cls = [r for r in rows if int(r["label"]) == label]
        if mode == "random":
            rng.shuffle(cls)
            a, b = int(len(cls) * ratios[0]), int(len(cls) * (ratios[0] + ratios[1]))
            parts["train"] += cls[:a]; parts["val"] += cls[a:b]; parts["test"] += cls[b:]
            continue
        groups = defaultdict(list)
        for r in cls:
            groups[r["template_id"]].append(r)
        ids = sorted(groups)
        rng.shuffle(ids)
        total, acc = len(cls), 0
        for g in ids:
            part = "train" if acc < ratios[0] * total else "val" if acc < (ratios[0] + ratios[1]) * total else "test"
            parts[part] += groups[g]
            acc += len(groups[g])
    for p in parts.values():
        rng.shuffle(p)
    return parts


def check_no_leakage(parts, mode="template"):
    texts = {k: {norm(r["text"]) for r in v} for k, v in parts.items()}
    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        assert not texts[a] & texts[b], f"texte en commun entre {a} et {b}"
    if mode == "template":
        tids = {k: {r["template_id"] for r in v} for k, v in parts.items()}
        for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
            assert not tids[a] & tids[b], f"gabarit en commun entre {a} et {b}"
    for k, v in parts.items():
        assert {int(r["label"]) for r in v} == {0, 1}, f"{k} doit contenir les 2 classes"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--mode", choices=["template", "random"], default="template")
    a = ap.parse_args()
    with open(DATA_DIR / "chat_dataset.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    parts = split_rows(rows, a.seed, a.mode)
    check_no_leakage(parts, a.mode)
    n = sum(len(v) for v in parts.values())
    for name, p in parts.items():
        write_csv(p, DATA_DIR / f"{name}.csv")
        ph = sum(int(r["label"]) for r in p)
        print(f"{name:5s} {len(p):5d} ({len(p)/n:.0%})  phishing={ph}  normal={len(p)-ph}")
    print("OK : aucune fuite (doublons / gabarits).")
