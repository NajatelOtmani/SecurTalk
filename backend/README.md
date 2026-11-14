# backend/ : SecureTalk AI (port 8000)

Authentification, relais de paquets chiffres (sans les lire), echange de cles, commandes du SOC.

## Installer et lancer (depuis le dossier backend/)
    py -m pip install -r requirements.txt
    py -m pip install -e ../crypto_sdk        (seulement pour les tests)
    py -m pytest                              (50 tests)
    py -m uvicorn app.main:app --port 8000

Documentation interactive : http://127.0.0.1:8000/docs

## Configuration (.env a la racine du depot, voir .env.example)
- `INTERNAL_KEY_SOC_TO_BACKEND` : cle des commandes /internal (obligatoire pour que le SOC puisse agir).
- `SOC_KEY_AUTH`, `SOC_KEY_RELAY` : cles d'envoi des evenements.
- `SOC_MODE=file` (defaut) : evenements ecrits dans `events.jsonl` (mock du SOC, guide 4.5 bis).
  `SOC_MODE=http` : envoi a http://127.0.0.1:8002/soc/events (timeout 1 s, sinon `events_pending.jsonl`).
- Optionnel : `RATE_LIMIT_PER_MINUTE` (30), `HEARTBEAT_SECONDS` (60), `INTERNAL_ALLOWED_IPS` (127.0.0.1,::1).

## Routes
| Route | Role |
|---|---|
| POST /auth/register, /auth/login, /auth/logout | comptes et sessions (1 h) |
| GET /users/{username}/publickey | cle publique RSA (alias /public-key) |
| POST /keys/exchange, GET /keys/pending | cles de session enveloppees en RSA-OAEP |
| POST /messages, POST /messages/{id}/ack | relais d'un paquet (contrat 2.6) |
| GET /conversations/{id}/status | rotation_required ? |
| WS /ws?token=... | pousse {type:"message"} et {type:"key"} |
| POST /internal/accounts/{id}/lock, /unlock, /force-rotation-all | commandes du SOC |
| POST /internal/conversations/{id}/force-rotation | commande du SOC |

## Regles de securite appliquees
Argon2 ; jeton = 32 octets aleatoires, seul le hash est stocke ; erreurs identiques (inconnu / mauvais mot de passe) ;
sender_id verifie contre le jeton ; paquet max 64 Ko ; 30 paquets/min/utilisateur ; aucun texte ni cle dans les
evenements (PrivacyGuard cote emetteur) ; /internal protege par cle + liste d'IP ; aucune cle privee connue du backend.

## Limites connues
SQLite et un seul serveur ; le jeton du WebSocket passe dans l'URL (contrat du guide) donc il peut apparaitre
dans les logs d'acces ; limitation de debit en memoire (remise a zero au redemarrage).
