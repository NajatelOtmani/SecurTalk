"""Ajoute des messages écrits à la main au jeu de test, SANS toucher au CSV à la main.

1) Écris tes messages dans un fichier texte UTF-8 (Bloc-notes), UN message par ligne :

     label | langue | texte | liens (optionnel, séparés par un espace) | catégorie (optionnel)

     0 | fr | Salut, tu peux me renvoyer le code de la salle ?
     1 | en | Your mailbox is full, upgrade now | http://mail-upgrade.top/x
     0 | ar | شكرا على المساعدة

   label : 1 = phishing, 0 = normal.   langue : fr, en, ar ou mixed.
   Les lignes vides et celles qui commencent par # sont ignorées.
   N'utilise pas le caractère | dans le texte du message.

   Jeu TEST FINAL séparé :  --out data/handwritten/handwritten_test.csv --prefix ht
2) Vérifie sans rien écrire :   python -m training.import_handwritten mon_fichier.txt --dry-run
3) Ajoute pour de bon :         python -m training.import_handwritten mon_fichier.txt

Tout ou rien : s'il y a une erreur de format, RIEN n'est ajouté et le script te dit quelle ligne corriger.
Les doublons (même texte déjà présent) sont ignorés. Les ids (hw030, hw031...) continuent tout seuls.
"""
import argparse
import csv
import re
import sys
from pathlib import Path

from .build_dataset import DATA_DIR, FIELDS
from .split_dataset import norm

HW_PATH = DATA_DIR / "handwritten" / "handwritten_seed.csv"
LANGS = {"fr", "en", "ar", "mixed"}


def parse_line(line: str):
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 3:
        raise ValueError("il faut au moins : label | langue | texte")
    label, lang, text = parts[0], parts[1].lower(), parts[2]
    urls = parts[3] if len(parts) > 3 else ""
    category = parts[4] if len(parts) > 4 and parts[4] else "handwritten"
    if label not in {"0", "1"}:
        raise ValueError("le label doit être 0 (normal) ou 1 (phishing)")
    if lang not in LANGS:
        raise ValueError(f"langue inconnue '{lang}' (fr, en, ar ou mixed)")
    if not text or len(text) > 4000:
        raise ValueError("texte vide ou trop long (max 4000 caractères)")
    url_list = urls.split()
    return {"text": text, "urls": " | ".join(url_list), "label": int(label),
            "lang": lang, "category": category}


def import_messages(lines, path: Path = HW_PATH, dry_run: bool = False, prefix: str = "hw"):
    """Renvoie (ajoutés, doublons_ignorés, erreurs[(n°ligne, message)])."""
    path = Path(path)
    existing = []
    if path.exists():
        with open(path, encoding="utf-8") as f:
            existing = list(csv.DictReader(f))
    known = {norm(r["text"]) for r in existing}
    ids = [int(m.group(1)) for r in existing if (m := re.fullmatch(prefix + r"(\d+)", r["id"]))]
    next_id = max(ids, default=-1) + 1

    new_rows, dups, errors = [], 0, []
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = parse_line(line)
        except ValueError as e:
            errors.append((n, str(e)))
            continue
        key = norm(row["text"])
        if key in known:
            dups += 1
            continue
        known.add(key)
        row["id"] = row["template_id"] = f"{prefix}{next_id:03d}"
        next_id += 1
        new_rows.append(row)

    if errors or dry_run or not new_rows:
        return len(new_rows), dups, errors
    needs_newline = path.exists() and path.stat().st_size > 0 and not path.read_bytes().endswith(b"\n")
    is_new = not path.exists() or path.stat().st_size == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        if needs_newline:
            f.write("\r\n")
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if is_new:
            w.writeheader()
        w.writerows(new_rows)
    return len(new_rows), dups, errors


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out", default=str(HW_PATH), help="CSV de destination (défaut : jeu DEV handwritten_seed.csv)")
    ap.add_argument("--prefix", default="hw", help="préfixe des ids (ex. ht pour le jeu de test final)")
    a = ap.parse_args()
    with open(a.file, encoding="utf-8-sig") as f:       # utf-8-sig : accepte le Bloc-notes Windows
        added, dups, errors = import_messages(f.read().splitlines(), Path(a.out), a.dry_run, a.prefix)
    for n, msg in errors:
        print(f"  ligne {n} : {msg}")
    if errors:
        print(f"ERREUR : {len(errors)} ligne(s) à corriger. Rien n'a été ajouté.")
        sys.exit(1)
    verb = "seraient ajoutés" if a.dry_run else "ajoutés"
    print(f"{added} message(s) {verb}, {dups} doublon(s) ignoré(s).")
