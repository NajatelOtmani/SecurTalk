# Guide de test complet : comment savoir que tout marche vraiment

## 1. Les trois niveaux de preuve

| Niveau | Outil | Ce que ça prouve | Faux composants ? |
|---|---|---|---|
| A. Tests automatiques | `python -m pytest` dans chaque dossier (ou `tools\run_all_tests.py`) | la logique est correcte, rapide, détecte les régressions | **oui, volontairement** (un faux backend isole le test) |
| B. Vérification réelle | `python tools\system_check.py` | tout est branché pour de vrai : vrai backend, vrai SDK, vrai modèle IA, vraies attaques | **non** |
| C. Scénarios à l'écran | l'application elle-même (section 4) | l'interface est bien liée au reste | **non** |

Les faux des tests n'existent **pas** dans l'application : le niveau B le vérifie (section 3, preuve n°1).

## 2. Tout lancer en 2 étapes

1. Double-clic sur `demo.bat` (backend, IA, 2 clients). Attendre que les fenêtres se stabilisent.
2. Double-clic sur `check_all.bat` : lance les tests de tous les dossiers, puis la vérification du système réel.
   Pour tester aussi la limitation de débit : `cd client` puis `python tools\system_check.py --stress`.

Lecture du résultat : **OK** = vérifié ; **FAIL** = à corriger ; **WARN** = à examiner (souvent une piste d'amélioration) ;
**SKIP** = pas encore testable (SOC absent, clé vide dans `.env`...).

| FAIL fréquent | Cause probable | Action |
|---|---|---|
| backend ou IA injoignable | service non lancé | `demo.bat` |
| « le modèle n'est PAS le faux service » | le faux service occupe le port 8001 | `stop_all.bat` puis relancer `ml\` |
| usurpation, 401, 413 : mauvais code HTTP | le backend ne suit pas le contrat | corriger **le guide d'abord**, puis le code |
| texte en clair TROUVÉ côté serveur | fuite : **grave** | chercher quel composant écrit le texte (logs, base, événements) |
| ordre interne refusé | clé `.env` vide ou backend non relancé | remplir `INTERNAL_KEY_SOC_TO_BACKEND`, relancer le backend |
| pas de limitation de débit (avec `--stress`) | limite absente ou trop haute | vérifier `relay.py` (30 paquets par minute) |

## 3. Comment savoir qu'il n'y a ni faux ni simulation (6 preuves)

1. **Le code de production est propre** : `system_check` section 1 cherche `fake`, `mock`, `dummy`, `TODO` dans `client/`, `backend/app`, `ml/service`,
   `crypto_sdk` et `soc/app` (tests et outils exclus).
2. **Le modèle est le vrai** : le panneau affiche « Protection IA : rf-lr-0.1 » (jamais `fake-0.1`), et la vérification échoue sinon.
3. **Mêmes modules que l'interface** : `system_check` utilise `BackendClient`, `ChatService` et `api_ml`, exactement le code que la fenêtre appelle.
   Ce qui marche dans l'outil marche dans l'interface ; seule la partie graphique diffère, couverte par `test_ui_flows` et la section 4.
4. **Le serveur ne voit rien** : un texte unique (`marqueur-...`) est envoyé, puis cherché dans la base, les journaux et les fichiers d'événements. Il ne doit apparaître nulle part.
5. **Les événements viennent d'actions réelles** : `Get-Content backend\events.jsonl -Tail 10 -Wait` pendant que tu utilises l'application.
6. **Aucun faux processus ne tourne** :
   ```
   Get-NetTCPConnection -LocalPort 8000,8001,8002 -State Listen | Select-Object LocalPort, OwningProcess
   Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Select-Object ProcessId, CommandLine
   ```
   Aucune ligne de commande ne doit contenir `fake_ml_service`.

## 4. Scénarios à l'écran (10 minutes)

| Action dans l'application | Preuve à l'écran | Preuve hors de l'application |
|---|---|---|
| Créer Alice et Bob | panneau « Backend : Connecté », événement `LOGIN_SUCCESS` | `REGISTER_SUCCESS` et `LOGIN_SUCCESS` dans `backend\events.jsonl` |
| Alice écrit à Bob | bulle « Livré » chez Alice, message chez Bob, « Âge de la clé » | `PACKET_ROUTED` puis `MESSAGE_DELIVERED` ; voir la base ci-dessous |
| Lien `micros0ft-login.com` | modal rouge avec les raisons du modèle, rien n'est envoyé | `ml\events.jsonl` : `PHISHING_DETECTED` sans texte ; `client\events.jsonl` : `MESSAGE_BLOCKED` |
| Arrêter le service IA | « Protection IA : Indisponible », message avec badge « Non analysé » | `WARNING_SHOWN` avec `reason: ml_unavailable` |
| Arrêter puis relancer le backend | « Injoignable », « Reconnexion… », puis retour au vert **sans relancer le client** | n/a |
| Forcer une rotation (`tools\force_rotation.py conv_...`) | prochain envoi réussi, notification « clé renouvelée », nouveau `Key ID` | `KEY_ROTATED` avec `reason: soc_order` |
| Fermer puis rouvrir Bob | Bob lit les nouveaux messages sans nouvel échange de clé | `~\.securetalk\bob\private.pem.enc` illisible dans le Bloc-notes |
| 5 mauvais mots de passe sur Alice | message d'erreur toujours identique | 5 `LOGIN_FAIL` dans `backend\events.jsonl` |

Voir ce que le serveur stocke vraiment (tu dois voir du texte chiffré en base64, jamais ton message) :
```
python -c "import sqlite3;c=sqlite3.connect('backend/securetalk_backend.db');print(c.execute('select * from messages order by rowid desc limit 1').fetchall())"
```

## 5. Quand le Mini-SOC sera prêt

1. Remplir toutes les clés de `.env` : `python -c "import secrets; print(secrets.token_urlsafe(32))"` pour chacune.
2. Passer `SOC_MODE=http` dans `.env` (backend, client et IA lisent le même réglage), puis relancer les services.
3. Ordre de démarrage : **SOC, IA, backend, clients**.
4. Chaque source doit avoir sa clé : `auth` et `relay` (backend), `crypto` et `client` (client), `phishing` (IA). Une clé ne peut envoyer que sa propre source.
5. Les règles qui dépendent du client : R004, R005, R010 (événements `crypto` : acteur = expéditeur du paquet, cible = receveur), R007 (événements `phishing` avec `target.user_id`),
   R011 (`USER_OVERRODE_WARNING`), R012 (`HEARTBEAT`). Si une règle ne se déclenche pas, comparer d'abord l'événement reçu au contrat 2.2.
6. Tests à jouer ensemble : T5, T6, T7 (avec le simulateur d'attaques), T10 (SOC arrêté : `events_pending.jsonl` se remplit puis se vide), T11 (événement avec `details.text` refusé), T12 (5 minutes de trafic normal sans fausse alerte).
7. Une fois le SOC en ligne, étendre `system_check.py` : vérifier via l'API du SOC (`GET /soc/events`) que les événements créés par la vérification sont arrivés.

## 6. Améliorer le ML sans casser l'intégration

1. Modifier le modèle ou les règles dans `ml/`.
2. `python -m pytest` dans `ml\`, puis `python tools\check_ml_contract.py` (le contrat doit rester respecté).
3. `python tools\system_check.py` : la section 4 rejoue des cas types. Les **WARN** sont ton travail (phishing raté ou faux positif).
   Ajoute tes propres cas dans la liste `BATTERY` de `tools/system_check.py`, surtout des messages de chat réalistes.
4. Garder : champs de réponse, seuils 0,40 / 0,80, liste fermée de codes de raison (un nouveau code s'ajoute **d'abord** au guide 8.2), latence sous 200 ms,
   aucun texte écrit nulle part. Changer `model_version` et mettre à jour `model_card.md`.
5. Surveiller en priorité les **faux positifs** sur des messages légitimes : un message normal bloqué rend l'application inutilisable.
   Les jeux de données publics sont des courriels longs ; évaluer séparément sur des messages courts de style chat.

## 7. Limites de cette vérification (à connaître)

- Elle prouve l'intégration et des propriétés de sécurité de base, **pas l'absence de faille** : le SDK cryptographique reste à auditer avant tout usage réel.
- Elle crée deux comptes `chk_...` à chaque lancement (le backend n'a pas de route de suppression) : repartir d'une base propre avant la démo
  (`stop_all.bat`, supprimer `backend\securetalk_backend.db`).
- Certains codes attendus (413, 403, 409) viennent du contrat. Un FAIL peut montrer un écart de contrat plutôt qu'un bug : lire le message,
  décider avec ton amie qui corrige, et **mettre le guide à jour avant le code**.
- Elle ne teste pas l'apparence de l'interface.
