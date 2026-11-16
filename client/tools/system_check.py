"""Vérification de bout en bout avec les VRAIS composants (aucun faux, aucun mock).
Prérequis : backend (8000) et service IA (8001) lancés (demo.bat). Le SOC est vérifié s'il tourne.
Usage : python tools\\system_check.py [--stress]
Crée 2 comptes jetables 'chk_...' (le backend n'a pas de route de suppression : repartir d'une base propre avant la démo)."""
import argparse, base64, contextlib, json, os, re, secrets, statistics, subprocess, sys, tempfile, time, uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLIENT = HERE.parent
ROOT = Path(os.environ.get("SECURETALK_ROOT") or CLIENT.parent)
sys.path[:0] = [str(CLIENT), str(HERE)]
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

import requests  # noqa: E402
import api_ml, config, soc_events, storage  # noqa: E402,E401
import force_rotation  # noqa: E402
from api_backend import ApiError, BackendClient  # noqa: E402
from chat_service import ChatService, conversation_id  # noqa: E402

force_rotation.ROOT = ROOT
BACKEND = config.BACKEND_URL
R = {"OK": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}


def rec(kind, name, info=""):
    R[kind] += 1
    print(f"  {kind:<4} {name}" + (f"   [{info}]" if info else ""))


def check(name, cond, info=""):
    rec("OK" if cond else "FAIL", name, "" if cond else info)


def section(t):
    print(f"\n=== {t} ===")


# ---------------------------------------------------------------- 1. code
FAKE_RE = re.compile(r"\b(?i:fake|mock|dummy)\b|PlainCodec|k_dev|\bTODO\b|\bFIXME\b")
SKIP_DIRS = {"tests", "tools", "__pycache__", ".venv", "venv", "node_modules"}


def scan_fakes():
    hits = []
    for d in (CLIENT, ROOT / "backend" / "app", ROOT / "ml" / "service",
              ROOT / "crypto_sdk" / "securetalk_crypto", ROOT / "soc" / "app"):
        if not d.exists():
            continue
        for f in d.rglob("*.py"):
            rel = f.relative_to(ROOT) if ROOT in f.parents else f
            if SKIP_DIRS & set(rel.parts):
                continue
            for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if FAKE_RE.search(line):
                    hits.append(f"{rel}:{n}: {line.strip()[:70]}")
    return hits


def git_tracked_secrets():
    try:
        p = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, timeout=10)
    except Exception:  # noqa: BLE001
        return None
    if p.returncode != 0:
        return None
    return [f for f in p.stdout.splitlines()
            if re.search(r"(^|/)\.env$|\.pem$|\.pem\.enc$|\.db$|\.sqlite3?$", f, re.I)]


def code_hygiene():
    section("1. Code et dépôt : pas de faux dans la production, pas de secrets dans Git")
    hits = scan_fakes()
    if hits:
        rec("WARN", f"{len(hits)} mot(s) 'fake/mock/TODO...' dans le code de production (hors tests et outils)")
        for h in hits[:15]:
            print("        " + h)
    else:
        rec("OK", "aucun 'fake / mock / TODO' dans le code de production (hors tests et outils)")
    tracked = git_tracked_secrets()
    if tracked is None:
        rec("SKIP", "Git indisponible : vérifier à la main que .env, *.pem et *.db ne sont pas suivis")
    else:
        check("aucun secret suivi par Git (.env, *.pem, *.db)", not tracked, ", ".join(tracked[:5]))
    env = ROOT / ".env"
    if not env.exists():
        rec("WARN", ".env absent à la racine : copier .env.example et remplir les clés")
    else:
        vals = soc_events._parse_env(env)
        miss = [k for k in ("SOC_KEY_AUTH", "SOC_KEY_RELAY", "SOC_KEY_CRYPTO", "SOC_KEY_PHISHING",
                            "SOC_KEY_CLIENT", "INTERNAL_KEY_SOC_TO_BACKEND") if not vals.get(k)]
        rec("WARN" if miss else "OK", "clés du .env remplies" if not miss else "clés vides dans .env", ", ".join(miss))


# ---------------------------------------------------------------- 2. services
def services():
    section("2. Services lancés")
    ok = {"backend": False, "ml": False}
    try:
        h = requests.get(BACKEND + "/health", timeout=3)
        ok["backend"] = h.status_code == 200
        check("backend répond (port 8000)", ok["backend"], f"HTTP {h.status_code}")
    except requests.RequestException:
        rec("FAIL", "backend injoignable (port 8000) : lancer demo.bat")
    try:
        v = str(requests.get(config.ML_URL + "/health", timeout=3).json().get("model_version", "?"))
        ok["ml"] = True
        rec("OK", f"service IA répond (port 8001), modèle = {v}")
        check("le modèle n'est PAS le faux service", "fake" not in v.lower(),
              "le FAUX service tourne sur 8001 : stop_all.bat puis relancer ml\\")
    except (requests.RequestException, ValueError):
        rec("FAIL", "service IA injoignable (port 8001)")
    try:
        requests.get(config.SOC_URL + "/health", timeout=2).raise_for_status()
        rec("OK", "SOC répond (port 8002)")
    except requests.RequestException:
        rec("SKIP", "SOC non lancé (normal tant qu'il n'existe pas)")
    return ok


# ---------------------------------------------------------------- 3. chiffrement réel
def pump(ws, svc, want, timeout=6.0):
    """Lit le WebSocket de Bob : clés -> déballées, messages -> renvoyés."""
    got, end = [], time.time() + timeout
    while time.time() < end and len(got) < want:
        try:
            raw = ws.recv(timeout=max(0.1, end - time.time()))
        except TimeoutError:
            break
        m = json.loads(raw)
        if m.get("type") == "key":
            svc.receive_key(m if "wrapped_key_b64" in m else m.get("key", {}))
        elif m.get("type") == "message":
            got.append(m["packet"])
    return got


def read_ok(svc, pkt, text):
    try:
        return svc.read(pkt) == text
    except Exception:  # noqa: BLE001
        return False


def find_plaintext(marker):
    files = []
    for d in ("backend", "soc"):
        p = ROOT / d
        if p.exists():
            files += [f for f in p.glob("*") if re.search(r"\.(db|sqlite3?)(-wal|-shm)?$|events.*\.jsonl$|\.log$", f.name)]
    files += [f for d in ("client", "ml") for f in (ROOT / d).glob("events*.jsonl")]
    found, seen = [], []
    for f in files:
        try:
            data = f.read_bytes()
        except OSError:
            continue
        seen.append(f.name)
        if marker.encode() in data:
            found.append(str(f.relative_to(ROOT)))
    return seen, found


def e2e(stress):
    from websockets.sync.client import connect
    section("3. Échange chiffré RÉEL : 2 comptes jetables, vrai backend, vrai SDK")
    tmp = Path(tempfile.mkdtemp(prefix="stcheck_"))
    storage.user_dir = lambda u: (lambda d: (d.mkdir(parents=True, exist_ok=True), d)[1])(tmp / u)
    tag, pw = secrets.token_hex(3), secrets.token_urlsafe(12)
    U = {}
    for who in ("a", "b"):
        name = f"chk_{who}_{tag}"
        priv, pub = storage.generate_keypair()
        c = BackendClient()
        c.register(name, pw, pub)
        c.login(name, pw)
        c.private_pem = priv
        U[who] = dict(name=name, c=c, pub=pub)
    ca, cb = U["a"]["c"], U["b"]["c"]
    rec("OK", "2 comptes créés et connectés (clés RSA générées par le SDK)")
    aid, bid = ca.user_id, cb.user_id
    A, B = ChatService(ca), ChatService(cb)
    A.pubkeys[bid], B.pubkeys[aid] = U["b"]["pub"], U["a"]["pub"]
    conv = conversation_id(aid, bid)
    stack = contextlib.ExitStack()
    ws = stack.enter_context(connect(cb.ws_url(), open_timeout=5))
    rec("OK", "WebSocket de Bob connecté")
    marker = "marqueur-" + secrets.token_hex(6)
    sent = {}
    for mode in ("GCM", "CMAC"):
        A.mode, text = mode, f"Bonjour {mode} {marker}"
        pkt = A.send_text(bid, text)
        check(f"{mode} : le paquet ne contient pas le texte en clair", marker not in json.dumps(pkt))
        got = pump(ws, B, 1)
        check(f"{mode} : Bob reçoit et déchiffre exactement le texte", bool(got) and read_ok(B, got[0], text))
        if got:
            B.ack(got[0])
        sent[mode] = pkt
    # --- attaques réelles à travers le backend
    key = A.send_keys[conv]["key"]
    ctr = storage.next_counter(U["a"]["name"], conv, key.key_id)
    good = A.sdk.encrypt_message("falsification " + marker, key, "GCM", aid, bid, conv, ctr)
    bad = dict(good)
    raw = bytearray(base64.b64decode(bad["ciphertext_b64"]))
    raw[0] ^= 1
    bad["ciphertext_b64"] = base64.b64encode(bytes(raw)).decode()
    try:
        ca.send_packet(bad)
        got = pump(ws, B, 1)
        try:
            B.read(got[0])
            check("paquet falsifié rejeté par le receveur (AuthTagError)", False, "affiché !")
        except B.sdk.AuthTagError:
            rec("OK", "paquet falsifié en transit : rejeté par le receveur (AuthTagError)")
        except IndexError:
            rec("OK", "paquet falsifié : non livré (refusé par le backend)")
    except ApiError as e:
        rec("OK", "paquet falsifié : refusé par le backend", f"{e.status} {e.code}")
    try:
        ca.send_packet(sent["GCM"])
        got = pump(ws, B, 1, timeout=3)
        if got:
            try:
                B.read(got[0])
                check("rejeu d'un ancien paquet bloqué", False, "accepté deux fois !")
            except B.sdk.ReplayError:
                rec("OK", "rejeu : accepté par le backend mais bloqué par le client (ReplayError)")
        else:
            rec("OK", "rejeu : non livré")
    except ApiError as e:
        rec("OK", "rejeu : doublon refusé par le backend", f"{e.status} {e.code}")
    forged = dict(good, sender_id=bid, message_id=str(uuid.uuid4()))
    try:
        ca.send_packet(forged)
        check("usurpation de sender_id refusée", False, "paquet accepté !")
    except ApiError as e:
        check("usurpation de sender_id refusée (403)", e.status == 403, f"HTTP {e.status} {e.code}")
    # --- accès non autorisés
    pk = dict(good, message_id=str(uuid.uuid4()))
    r = requests.post(BACKEND + "/messages", json=pk, timeout=5)
    check("envoi sans jeton -> 401", r.status_code == 401, f"HTTP {r.status_code}")
    r = requests.post(BACKEND + "/messages", json=pk, timeout=5,
                      headers={"Authorization": "Bearer " + secrets.token_urlsafe(32)})
    check("envoi avec un faux jeton -> 401", r.status_code == 401, f"HTTP {r.status_code}")
    r = requests.get(BACKEND + f"/users/{U['a']['name']}/publickey", timeout=5)
    check("clé publique sans jeton -> 401", r.status_code == 401, f"HTTP {r.status_code}")
    r = requests.post(BACKEND + f"/internal/accounts/{aid}/lock", timeout=5)
    check("ordre interne sans clé -> refusé (401/403)", r.status_code in (401, 403), f"HTTP {r.status_code}")
    big = dict(good, message_id=str(uuid.uuid4()), ciphertext_b64="A" * 80000)
    r = requests.post(BACKEND + "/messages", json=big, timeout=10, headers={"Authorization": "Bearer " + ca.token})
    check("paquet de plus de 64 Ko -> 413", r.status_code == 413, f"HTTP {r.status_code}")
    r1 = requests.post(BACKEND + "/auth/login", timeout=5, json={"username": "inconnu_" + tag, "password": "x" * 12})
    r2 = requests.post(BACKEND + "/auth/login", timeout=5, json={"username": U["a"]["name"], "password": "mauvais-mot-de-passe"})
    same = r1.status_code == r2.status_code == 401 and r1.json().get("error") == r2.json().get("error")
    check("même erreur pour « utilisateur inconnu » et « mauvais mot de passe »", same, f"{r1.status_code}/{r2.status_code}")
    return dict(stack=stack, A=A, B=B, ws=ws, ca=ca, cb=cb, U=U, aid=aid, bid=bid, conv=conv, marker=marker, pw=pw, tmp=tmp)


def confidentiality_and_events(ctx):
    section("3b. Confidentialité : le texte n'est nulle part côté serveur, événements corrects")
    seen, found = find_plaintext(ctx["marker"])
    if not seen:
        rec("WARN", "aucun fichier serveur trouvé à inspecter (base, événements) : vérifier ROOT")
    else:
        check(f"texte en clair introuvable dans {len(seen)} fichiers ({', '.join(sorted(set(seen))[:4])}...)", not found,
              "TROUVÉ dans " + ", ".join(found))
    ev = ROOT / "backend" / "events.jsonl"
    if not ev.exists():
        rec("SKIP", "backend\\events.jsonl absent (mode http : à vérifier au SOC)")
        return
    mine, bad = set(), 0
    for line in ev.read_text(encoding="utf-8", errors="replace").splitlines():
        if ctx["aid"] in line or ctx["bid"] in line or ctx["U"]["a"]["name"] in line:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            mine.add(e.get("event_type"))
            try:
                soc_events.check_privacy({k: e.get(k) for k in ("actor", "target", "details")})
            except soc_events.PrivacyError:
                bad += 1
    want = {"REGISTER_SUCCESS", "LOGIN_SUCCESS", "LOGIN_FAIL", "PACKET_ROUTED", "MESSAGE_DELIVERED", "PACKET_REJECTED_UNAUTH"}
    check("le backend a émis tous les événements attendus", want <= mine, "manquants : " + ", ".join(sorted(want - mine)))
    check("aucun événement du backend ne contient de champ interdit", bad == 0, f"{bad} événement(s)")


# ---------------------------------------------------------------- 4. IA
BATTERY = [
    ("Bonjour, la réunion est à 15h en salle B", "Safe"),
    ("Peux-tu m'envoyer le rapport avant midi ?", "Safe"),
    ("Voici le dossier partagé de l'équipe", "Safe", "https://drive.google.com/drive/folders/abc123"),
    ("Réunion Teams mise à jour", "Safe", "https://www.microsoft.com/fr-fr/microsoft-teams"),
    ("Votre compte sera suspendu. Vérifiez-le maintenant", "Phishing", "http://micros0ft-login.com/verify"),
    ("allez check :support-security@google-security-update.com", "NotSafe"),
    ("URGENT : virement de 5000 euros à faire immédiatement, envoyez-moi vos codes", "NotSafe"),
    ("Réinitialisez votre mot de passe sur http://192.168.4.7/login", "NotSafe"),
    ("Cliquez ici pour gagner une carte cadeau : bit.ly/3xYz", "NotSafe"),
    ("envoi moi ton mots de passe paypal", "NotSafe"),
    ("c'est urgent, appelle-moi dès que tu peux", "Safe"),
]


def ml_checks():
    section("4. Service IA réel : verdicts sur des cas types (aide à améliorer le modèle)")
    good, lat = 0, []
    t0 = time.time()
    api_ml.analyze(str(uuid.uuid4()), "u_chk_a", "u_chk_b", "conv_u_chk_a_u_chk_b", "chauffe", [])
    first = time.time() - t0
    for case in BATTERY:
        text, expect = case[0], case[1]
        if len(case) > 2:
            text += " " + case[2]
        try:
            t0 = time.time()
            d = api_ml.analyze(str(uuid.uuid4()), "u_chk_a", "u_chk_b", "conv_u_chk_a_u_chk_b", text, api_ml.extract_urls(text))
            lat.append(time.time() - t0)
        except api_ml.MlUnavailable:
            rec("FAIL", "le service IA ne répond pas comme le contrat 2.10 l'exige")
            return
        label = d["label"]
        okc = label == expect or (expect == "NotSafe" and label != "Safe")
        good += okc
        codes = ",".join(x.get("code", "?") for x in d.get("reasons", []))
        rec("OK" if okc else "WARN", f"{expect:<8} attendu -> {label:<10} {float(d['score']):.2f}  « {text[:48]} »", codes if not okc else "")
    print(f"        {good}/{len(BATTERY)} verdicts conformes. Les WARN sont des pistes d'amélioration du modèle (faux positif ou phishing raté).")
    check("réponse en moins de 2 s (délai du client)", max(lat + [first]) < config.ML_TIMEOUT, f"max {max(lat + [first]):.2f}s")
    med = statistics.median(lat)
    msg = f"latence : 1er appel {first * 1000:.0f} ms, médiane {med * 1000:.0f} ms, max {max(lat) * 1000:.0f} ms (cible du guide : moins de 200 ms)"
    rec("OK" if med < 0.2 else "WARN", msg)
    if first > 3 * max(med, 0.05):
        print("        le 1er appel est bien plus lent : charger et « chauffer » le modèle au démarrage du service (guide 8.7)")
    marker = "marqueurml-" + secrets.token_hex(6)
    api_ml.analyze(str(uuid.uuid4()), "u_chk_a", "u_chk_b", "conv_u_chk_a_u_chk_b", "Voici " + marker, [])
    time.sleep(0.5)
    evs = list((ROOT / "ml").glob("events*.jsonl"))
    if not evs:
        rec("SKIP", "ml\\events.jsonl absent (mode http : vérifier au SOC que le texte n'apparaît pas)")
    else:
        check("le service IA n'écrit pas le texte analysé dans ses événements", all(marker.encode() not in f.read_bytes() for f in evs),
              "TEXTE TROUVÉ dans ml\\events*.jsonl")


# ---------------------------------------------------------------- 5. ordres du SOC
def internal_checks(ctx):
    section("5. Ordres du SOC vers le backend : rotation forcée (T8) et verrouillage")
    key = force_rotation.read_key()
    if not key:
        rec("SKIP", "INTERNAL_KEY_SOC_TO_BACKEND vide dans .env : le remplir, relancer le backend, puis relancer ce test")
        return
    hdr, A, B, ws = {"X-API-Key": key}, ctx["A"], ctx["B"], ctx["ws"]
    old = A.key_info(ctx["bid"])[0]
    r = requests.post(f"{BACKEND}/internal/conversations/{ctx['conv']}/force-rotation", headers=hdr, timeout=5)
    check("ordre de rotation accepté par le backend", r.status_code in (200, 202, 204), f"HTTP {r.status_code} {r.text[:80]}")
    text = "après rotation " + ctx["marker"]
    try:
        A.send_text(ctx["bid"], text)
        check("le client a géré le 409 tout seul (nouvelle clé, nouvel échange RSA, renvoi)", A.last_rotated)
        check("le key_id a changé", A.key_info(ctx["bid"])[0] != old)
        got = pump(ws, B, 1)
        check("Bob déchiffre le message envoyé après rotation", bool(got) and read_ok(B, got[0], text))
    except ApiError as e:
        rec("FAIL", "envoi après rotation forcée", f"{e.status} {e.code}")
    url = f"{BACKEND}/internal/accounts/{ctx['bid']}/lock"
    r1 = requests.post(url, headers=hdr, timeout=5)
    r2 = requests.post(url, headers=hdr, timeout=5)
    check("verrouillage accepté, et idempotent (2 fois sans erreur)", r1.status_code < 300 and r2.status_code < 300,
          f"{r1.status_code}/{r2.status_code}")
    try:
        BackendClient().login(ctx["U"]["b"]["name"], ctx["pw"])
        check("compte verrouillé : connexion refusée même avec le bon mot de passe", False, "connexion acceptée !")
    except ApiError as e:
        check("compte verrouillé : connexion refusée (403 ACCOUNT_LOCKED)", e.status == 403, f"{e.status} {e.code}")
    r = requests.post(f"{BACKEND}/internal/accounts/{ctx['bid']}/unlock", headers=hdr, timeout=5)
    check("déverrouillage accepté", r.status_code < 300, f"HTTP {r.status_code}")
    try:
        BackendClient().login(ctx["U"]["b"]["name"], ctx["pw"])
        rec("OK", "après déverrouillage, la connexion fonctionne de nouveau")
    except ApiError as e:
        rec("FAIL", "connexion après déverrouillage", f"{e.status} {e.code}")


def stress(ctx):
    section("6. Limitation de débit (30 paquets par minute)")
    n = 0
    try:
        for n in range(1, 46):
            ctx["A"].send_text(ctx["bid"], f"rafale {n}")
        rec("FAIL", "45 envois rapides acceptés : pas de limitation de débit")
    except ApiError as e:
        check(f"limitation déclenchée au paquet n°{n} (429)", e.status == 429, f"{e.status} {e.code}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stress", action="store_true", help="teste aussi la limitation de débit")
    args = ap.parse_args()
    print(f"Vérification du système réel : backend {BACKEND}, IA {config.ML_URL}, SOC {config.SOC_URL}")
    code_hygiene()
    ok = services()
    ctx = None
    if ok["backend"]:
        try:
            ctx = e2e(args.stress)
            confidentiality_and_events(ctx)
        except Exception as e:  # noqa: BLE001
            rec("FAIL", "erreur inattendue pendant l'échange chiffré", f"{type(e).__name__}: {e}")
    if ok["ml"]:
        try:
            ml_checks()
        except Exception as e:  # noqa: BLE001
            rec("FAIL", "erreur inattendue pendant les tests IA", f"{type(e).__name__}: {e}")
    if ctx:
        for fn in (internal_checks, stress) if args.stress else (internal_checks,):
            try:
                fn(ctx)
            except Exception as e:  # noqa: BLE001
                rec("FAIL", f"erreur inattendue : {fn.__name__}", f"{type(e).__name__}: {e}")
        try:
            ctx["stack"].close()
        except Exception:  # noqa: BLE001
            pass
    print(f"\n=== RÉSULTAT : {R['OK']} OK, {R['FAIL']} FAIL, {R['WARN']} WARN, {R['SKIP']} SKIP ===")
    if ctx:
        print(f"Comptes de test créés : {ctx['U']['a']['name']} et {ctx['U']['b']['name']} (à supprimer avec la base avant la démo).")
    print("FAIL = à corriger ; WARN = à examiner ; SKIP = pas encore testable (SOC absent, clé vide...).")
    sys.exit(1 if R["FAIL"] else 0)


if __name__ == "__main__":
    main()
