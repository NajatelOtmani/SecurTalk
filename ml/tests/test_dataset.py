import csv
import re
from pathlib import Path

from training.build_dataset import build_rows
from training.split_dataset import check_no_leakage, split_rows

ROWS = build_rows(seed=1, per_template=10)


def test_deterministic():
    assert build_rows(seed=1, per_template=10) == ROWS


def test_both_classes_and_all_languages():
    assert {r["label"] for r in ROWS} == {0, 1}
    assert {r["lang"] for r in ROWS} == {"fr", "en", "ar", "mixed"}


def test_no_personal_data_patterns():
    for r in ROWS:
        assert "@" not in r["text"]
        assert not re.search(r"\d{9,}", r["text"])            # pas de numéros de téléphone/carte


def test_split_without_leakage_and_ratios():
    parts = split_rows(ROWS, seed=1)
    check_no_leakage(parts)
    n = sum(len(p) for p in parts.values())
    assert 0.60 <= len(parts["train"]) / n <= 0.80
    assert len(parts["val"]) > 0 and len(parts["test"]) > 0


def test_random_mode_also_has_no_text_leak():
    check_no_leakage(split_rows(ROWS, seed=1, mode="random"), mode="random")


def test_handwritten_seed_is_valid():
    p = Path(__file__).resolve().parent.parent / "data" / "handwritten" / "handwritten_seed.csv"
    rows = list(csv.DictReader(open(p, encoding="utf-8")))
    assert len(rows) >= 20 and {r["label"] for r in rows} == {"0", "1"}
