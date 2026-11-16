# SecureTalk AI : client de chat (dossier `client/`)

Application de bureau (Python + PySide6) : connexion, chat chiffré de bout en bout, analyse anti-phishing avant envoi,
panneau de sécurité en temps réel, événements envoyés au Mini-SOC. Elle suit le **guide d'équipe** (sections 2, 7 et 9).

## 1. Prérequis et installation (une fois)

Depuis la racine du dépôt (`securetalk/`) : double-cliquer sur `setup.bat`, ou à la main :

```
python -m pip install -e crypto_sdk
python -m pip install -r backend\requirements.txt
python -m pip install -r client\requirements.txt
```

## 2. Lancer

**Tout d'un coup** : `demo.bat` (libère les ports 8000/8001, lance le backend, le service IA, puis Alice et Bob).
`stop_all.bat` libère les ports 8000, 8001 et 8002.

**À la main** (4 terminaux, dans cet ordre) :

| Terminal | Commande | Port |
|---|---|---|
| SOC (quand il existe) | `cd soc` puis `python -m uvicorn app.main:app --port 8002` | 8002 |
| Service IA | `cd ml` puis `python -m uvicorn service.main:app --host 127.0.0.1 --port 8001` | 8001 |
| Backend | `cd backend` puis `python -m uvicorn app.main:app --port 8000` | 8000 |
| Client | `cd client` puis `python app.py --profile alice` (et `--profile bob`) | n/a |

Sans le vrai service IA : `python tools\fake_ml_service.py` (faux service conforme au contrat 2.10).

## 3. Utiliser

1. **Créer un compte** (nom de 3 à 32 caractères `a-z 0-9 _`, mot de passe de 10 caractères minimum). Une paire RSA est générée ;
   la clé privée est **chiffrée avec le mot de passe** et reste sur la machine (`~/.securetalk/<nom>/private.pem.enc`).
2. Ajouter un contact : taper son nom dans « Ajouter un contact » puis Entrée.
3. Écrire. Le sélecteur de droite choisit **AES-GCM** ou **AES-CBC + CMAC**. « Renouveler la clé » force une rotation.
4. Pour répondre à un expéditeur affiché `u_xxxx`, l'ajouter d'abord par son nom (le paquet ne contient que l'identifiant).

## 4. Architecture

```
client/
├── app.py              point d'entrée (--profile), boucle connexion / session expirée
├── config.py           URLs et délais (ports du guide)
├── policy.json         décisions de sécurité (voir 6)    policy.py : lecture validée
├── api_backend.py      HTTP vers le backend (contrat 2.7)
├── api_ml.py           POST /v1/analyze, délai 2 s, extraction des liens (contrat 2.10)
├── soc_events.py       événements vers le SOC (contrat 2.2), délai 1 s, file d'attente locale
├── storage.py          clé privée chiffrée, compteurs, clés de session enveloppées
├── chat_service.py     LOGIQUE du chat, sans interface : clés, chiffrement, réception
├── ui/                 theme, login_window, main_window, widgets, worker, ws_thread
├── tools/              fake_ml_service.py, check_ml_contract.py, force_rotation.py
└── tests/              44 tests (pytest)
```

L'interface est séparée de la logique : `chat_service.py` se teste sans fenêtre (guide 7.1).

## 5. Parcours d'un message

**Envoi** : extraction des liens, analyse IA (2 s max), puis selon le verdict : Safe, on continue ; Suspicious, avertissement avec « Annuler » ou
« Envoyer quand même » ; Phishing, bloqué (politique `block`). Ensuite : clé de session (créée et envoyée en RSA-OAEP si absente),
`encrypt_message` avec un compteur sauvegardé sur disque, `POST /messages`. Sur **409 KEY_ROTATION_REQUIRED** : nouvelle clé, nouvel échange RSA,
renvoi du même texte.

**Réception** (WebSocket `/ws`) : clé reçue puis déballée avec la clé privée ; message : **tag, puis anti-rejeu, puis affichage**, accusé de réception
(`/ack`). Un paquet falsifié ou rejoué est ignoré et signalé au SOC. Le message est aussi analysé par l'IA (badge et bandeau si suspect).

## 6. Décisions de sécurité

| Décision | Choix | Pourquoi |
|---|---|---|
| Message Phishing | `block` (`policy.json`) | un phishing ne doit pas partir ; `warn` disponible |
| IA injoignable | `send_with_notice` (ou `block`) | la messagerie ne s'arrête pas ; le message porte le badge « Non analysé » |
| Clé privée | chiffrée AES-GCM, clé dérivée du mot de passe (scrypt) | un vol de fichier ne donne pas la clé ; migration automatique des anciens fichiers |
| Clés de session sur disque | uniquement enveloppées en RSA | aucune clé en clair sur le disque |
| Liens | texte simple, jamais ouverts | pas de clic involontaire sur un phishing |
| Événements | métadonnées seulement, filtre avant envoi | le SOC ne voit ni texte ni clé (guide 2.9) |
| SOC en panne | délai 1 s, envoi en arrière-plan, `events_pending.jsonl` | le chat ne dépend jamais du SOC |
| Session | jeton de 1 h, avertissement à 5 min, retour à la connexion | pas de session fantôme |

## 7. Configuration

- `.env` à la racine du dépôt (jamais dans Git) : `SOC_MODE=file` (défaut, écrit `client/events.jsonl`) ou `http` (envoi au SOC) ;
  `SOC_URL`, `SOC_KEY_CRYPTO`, `SOC_KEY_CLIENT`, `INTERNAL_KEY_SOC_TO_BACKEND` (pour `tools/force_rotation.py`).
- `policy.json` : `phishing_policy` = `block` ou `warn` ; `ml_unavailable` = `send_with_notice` ou `block`. Une valeur invalide revient au défaut.

## 8. Événements émis au SOC

| Source | Événement | Quand |
|---|---|---|
| crypto | `GCM_AUTH_FAIL`, `CMAC_AUTH_FAIL` | tag invalide à la réception |
| crypto | `REPLAY_DETECTED` | compteur déjà vu ou trop ancien |
| crypto | `KEY_EXCHANGE_FAIL` | clé reçue impossible à ouvrir |
| crypto | `KEY_ROTATED` | rotation (`manual` ou `soc_order`) |
| client | `WARNING_SHOWN`, `MESSAGE_BLOCKED`, `USER_OVERRODE_WARNING` | modal phishing ; IA indisponible (`reason: ml_unavailable`) |

## 9. Tests

```
cd client
python -m pytest          # 44 tests, sans ouvrir de fenêtre
python tools\check_ml_contract.py     # vérifie le service IA (faux ou vrai) contre le contrat 2.10
python tools\force_rotation.py conv_u_xxx_u_yyy   # simule l'ordre du SOC (test T8)
```
Pour tout vérifier d'un coup : `check_all.bat` (racine du dépôt). Voir `GUIDE_TEST_COMPLET.md` (comment savoir que tout est réel et bien lié),
`TESTS_INTEGRATION.md` (T1 à T12) et `CHECKLIST_ET_RAPPORT.md`.

## 10. Limites connues (à citer dans le rapport)

- Code cryptographique du SDK écrit à la main : base pédagogique, à auditer avant tout usage réel.
- Le service IA lit le texte en clair (compromis du guide 2.9) : il doit rester local et ne rien stocker.
- Le garde anti-rejeu est en mémoire : un redémarrage du client l'oublie.
- L'historique des messages n'est pas conservé (volontaire : aucun texte en clair sur le disque).
- Un mot de passe perdu rend la clé privée locale irrécupérable : il faut recréer un compte.
- Le jeton WebSocket passe dans l'URL (contrat du guide) : il peut apparaître dans des journaux d'accès.
- SQLite et un seul serveur : pas de haute disponibilité.

## 11. Dépannage

| Symptôme | Cause et solution |
|---|---|
| `Errno 10048` au lancement d'un serveur | port déjà pris (souvent l'ancien faux service IA) : `stop_all.bat` |
| « 'pip' n'est pas reconnu » | utiliser `python -m pip ...` |
| « Serveur injoignable » à la connexion | backend non lancé (port 8000) |
| « SDK crypto absent » | `python -m pip install -e crypto_sdk` |
| « Protection IA : Indisponible » | service IA arrêté ; les messages partent avec le badge « Non analysé » |
| « Protection IA : fake-0.1 » | le faux service répond encore : le remplacer par `ml/` |
| « Mot de passe incorrect pour la clé privée » | le mot de passe ne déchiffre pas la clé de cet appareil |
| Tag invalide alors que rien n'a changé | les deux côtés ne construisent pas l'AAD pareil (guide 9.6) |
