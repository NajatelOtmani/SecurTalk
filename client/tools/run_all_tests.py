"""Lance pytest dans chaque dossier du projet (crypto_sdk, backend, ml, soc, client) et résume."""
import subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
bad, rows = 0, []
for name in ("crypto_sdk", "backend", "ml", "soc", "client"):
    d = ROOT / name
    if not (d / "tests").exists():
        rows.append((name, "SKIP", "pas de dossier tests"))
        continue
    p = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=d, capture_output=True, text=True)
    last = [l for l in (p.stdout + p.stderr).splitlines() if l.strip()]
    summary = next((l for l in reversed(last) if " passed" in l or " failed" in l or "error" in l.lower()), last[-1] if last else "?")
    rows.append((name, "OK" if p.returncode == 0 else "FAIL", summary.strip("= ")))
    bad += p.returncode != 0
print()
for n, s, t in rows:
    print(f"  {s:<4} {n:<11} {t}")
print("\nTOUS LES TESTS AUTOMATIQUES PASSENT" if not bad else f"\n{bad} dossier(s) en échec : lancer pytest dedans pour le détail")
sys.exit(1 if bad else 0)
