import csv
import shutil
from pathlib import Path

from training.eval_urls import evaluate_urls
from training.import_handwritten import HW_PATH, import_messages


def _copy(tmp_path):
    p = tmp_path / "hw.csv"
    shutil.copy(HW_PATH, p)
    return p


def _rows(p):
    return list(csv.DictReader(open(p, encoding="utf-8")))


def test_import_appends_with_continuing_ids(tmp_path):
    p = _copy(tmp_path)
    before = len(_rows(p))
    added, dups, errors = import_messages(
        ["# commentaire", "", "0 | fr | Salut, on mange où ce midi ?",
         "1 | en | Your mailbox is full | http://mail-upgrade.top/x | mailbox",
         "0 | ar | شكرا جزيلا"], p)
    rows = _rows(p)
    assert (added, dups, errors) == (3, 0, []) and len(rows) == before + 3
    assert rows[-1]["id"] == rows[-1]["template_id"] and rows[-2]["urls"] == "http://mail-upgrade.top/x"
    assert rows[-3]["text"] == "Salut, on mange où ce midi ?" and rows[-1]["text"] == "شكرا جزيلا"


def test_duplicates_are_skipped(tmp_path):
    p = _copy(tmp_path)
    existing = _rows(p)[0]
    added, dups, _ = import_messages([f"{existing['label']} | {existing['lang']} | {existing['text']}"], p)
    assert (added, dups) == (0, 1)


def test_errors_are_all_or_nothing(tmp_path):
    p = _copy(tmp_path)
    before = p.read_bytes()
    added, _, errors = import_messages(["0 | fr | ok message", "2 | fr | mauvais label", "1 | xx | mauvaise langue", "seulement"], p)
    assert [n for n, _ in errors] == [2, 3, 4]
    assert p.read_bytes() == before                      # rien n'a été écrit


def test_dry_run_writes_nothing(tmp_path):
    p = _copy(tmp_path)
    before = p.read_bytes()
    added, _, errors = import_messages(["0 | fr | un nouveau message"], p, dry_run=True)
    assert added == 1 and not errors and p.read_bytes() == before


def test_eval_urls_on_small_lists():
    r = evaluate_urls(["http://micros0ft-login.com/verify", "https://bit.ly/abc", "http://203.0.113.9/login"],
                      ["https://google.com", "https://github.com", "https://www.ensa.ac.ma"])
    assert r["recall@0.4"] == 1.0 and r["false_positive_rate@0.4"] == 0.0
    assert r["codes_on_phish"]["URL_SHORTENER"] == 1
    assert all("http" not in m for m in r["missed"] + r["false_alarms"])   # exemples désamorcés


def test_separate_output_file_with_prefix_and_header(tmp_path):
    out = tmp_path / "handwritten_test.csv"
    added, _, errors = import_messages(["0 | fr | premier", "1 | en | second | http://a.top/x"], out, prefix="ht")
    rows = _rows(out)
    assert (added, errors) == (2, []) and [r["id"] for r in rows] == ["ht000", "ht001"]
    assert list(rows[0]) == ["id", "text", "urls", "label", "lang", "category", "template_id"]
