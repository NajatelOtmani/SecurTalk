"""Mesure la latence du détecteur (cible guide 8.7 : < 200 ms par message).
  python -m training.benchmark
"""
import csv
import statistics
import time

from service.analyzer import PhishingDetector
from service.model import load_if_available
from .build_dataset import DATA_DIR


def run(detector, rows, repeat=3):
    times = []
    for _ in range(repeat):
        for r in rows:
            urls = [u.strip() for u in r["urls"].split("|") if u.strip()]
            t = time.perf_counter()
            detector.analyze(r["text"], urls)
            times.append((time.perf_counter() - t) * 1000)
    times.sort()
    return statistics.median(times), times[int(len(times) * 0.95)], times[-1]


if __name__ == "__main__":
    rows = list(csv.DictReader(open(DATA_DIR / "test.csv", encoding="utf-8")))
    long_row = {"text": "vérifiez votre compte " * 250, "urls": "http://micros0ft-login.com/x " * 5}
    model = load_if_available()
    for name, det in (("règles seules", PhishingDetector()), ("hybride (avec modèle)", PhishingDetector(model=model))):
        if name.startswith("hybride") and model is None:
            print("hybride : aucun modèle trouvé (lance d'abord training.train_baseline)")
            continue
        p50, p95, mx = run(det, rows)
        l50, l95, lmx = run(det, [long_row], repeat=20)
        print(f"{name:24s} messages courts : médiane {p50:6.2f} ms | p95 {p95:6.2f} ms | max {mx:6.2f} ms"
              f"   | texte 5000 car. : p95 {l95:6.2f} ms   (cible < 200 ms)")
