"""Latence du détecteur (guide 8.7 : cible < 200 ms par message).  python -m training.benchmark_latency"""
import csv
import statistics
import time

from service.analyzer import PhishingDetector
from service.model import load_if_available
from .build_dataset import DATA_DIR

det = PhishingDetector(model=load_if_available())


def rows(p):
    return list(csv.DictReader(open(p, encoding="utf-8")))


def ms(text, urls):
    t = time.perf_counter()
    det.analyze(text, urls)
    return (time.perf_counter() - t) * 1000


data = rows(DATA_DIR / "test.csv") + rows(DATA_DIR / "handwritten" / "handwritten_seed.csv")
for r in data[:20]:
    ms(r["text"], [])                                          # échauffement
times = sorted(ms(r["text"], [u for u in r["urls"].split(" | ") if u]) for r in data)
worst = ms("vérifiez votre compte " * 230, [f"http://micros0ft-login{i}.com/verify" for i in range(20)])
print(f"{'avec modèle' if det.model else 'règles seules'} | {len(times)} messages")
print(f"médiane {statistics.median(times):.1f} ms | p95 {times[int(len(times) * .95)]:.1f} ms | max {times[-1]:.1f} ms")
print(f"pire cas (5000 caractères + 20 liens) : {worst:.1f} ms")
print("OBJECTIF < 200 ms :", "OK" if max(times[-1], worst) < 200 else "DÉPASSÉ")
