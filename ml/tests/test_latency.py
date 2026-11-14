import time

from service.analyzer import PhishingDetector
from training.build_dataset import build_rows

ROWS = build_rows(seed=5, per_template=3)


def _p95(det, items):
    ts = []
    for text, urls in items:
        t = time.perf_counter()
        det.analyze(text, urls)
        ts.append(time.perf_counter() - t)
    return sorted(ts)[int(len(ts) * 0.95)]


def test_p95_latency_under_200ms_for_chat_messages():
    items = [(r["text"], [u for u in r["urls"].split(" | ") if u]) for r in ROWS]
    assert _p95(PhishingDetector(), items) < 0.2          # cible du guide 8.7


def test_max_size_message_stays_fast():
    items = [("vérifiez votre compte " * 250, ["http://micros0ft-login.com/x"] * 20)] * 5
    assert _p95(PhishingDetector(), items) < 0.2
