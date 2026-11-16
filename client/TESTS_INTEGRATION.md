# Tests d'intégration T1 à T12 (guide 9.4)

Légende : **Client** = prêt à tester avec le client ; **SOC** = demande le Mini-SOC (ou son simulateur) ; **Auto** = déjà couvert par `pytest`.
Avant chaque série : `demo.bat`, puis vérifier dans les deux clients « Backend : Connecté », « WebSocket : Actif », « Protection IA : (nom du modèle) ».

| N° | Test | Comment faire | Résultat attendu | Statut |
|---|---|---|---|---|
| T1 | Alice s'inscrit puis se connecte | Client : « Créer un compte » | `REGISTER_SUCCESS` et `LOGIN_SUCCESS` dans `backend\events.jsonl` (ou au SOC en mode http) | Client |
| T2 | Alice envoie « Bonjour » à Bob | Alice ajoute `bob`, écrit | Bob le lit ; `MESSAGE_SCANNED_SAFE` (IA), `PACKET_ROUTED`, `MESSAGE_DELIVERED` (backend) | Client |
| T3 | Le backend n'a jamais le texte | voir la commande ci-dessous | « aucun résultat » | Client |
| T4 | Lien `micros0ft-login.com` | Alice écrit `Voir http://micros0ft-login.com/verify` | modal rouge, rien n'est envoyé ; `PHISHING_DETECTED` (IA) + `MESSAGE_BLOCKED` (client) | Client |
| T5 | 5 mauvais mots de passe | 5 connexions ratées sur Alice | 5 `LOGIN_FAIL` au backend ; alerte R001 et verrouillage par le SOC ; 6e connexion refusée (403) | SOC pour R001 ; le verrouillage manuel est décrit ci-dessous |
| T6 | Paquet modifié en route | simulateur `attacks.py tag_tamper` | Bob n'affiche rien ; `GCM_AUTH_FAIL` ; alerte R004 | Auto (client) ; SOC pour l'alerte |
| T7 | Paquet rejoué | simulateur `attacks.py replay` | `REPLAY_DETECTED` ; alerte R005 ; rotation forcée | Auto (client) ; SOC pour l'alerte |
| T8 | Le SOC ordonne une rotation | `python tools\force_rotation.py conv_...` (voir ci-dessous) | prochain envoi : 409, nouvelle clé, message livré, notification | Client |
| T9 | Service IA arrêté | fermer le terminal de l'IA, écrire un message | le message part avec « Non analysé » ; rien ne plante | Client, Auto |
| T10 | SOC arrêté | `.env` : `SOC_MODE=http`, ne pas lancer le SOC, discuter | le chat marche ; `events_pending.jsonl` se remplit (client et backend) ; renvoi au retour du SOC | Client |
| T11 | Événement contenant du texte | envoyer un événement avec `details.text` | refus 400 par le PrivacyGuard du SOC | SOC ; côté client, refus avant envoi (Auto) |
| T12 | Trafic normal 5 min | simulateur `attacks.py normal_traffic --minutes 5` | aucune fausse alerte | SOC |

## Commandes utiles (PowerShell, depuis la racine du dépôt)

**T3 : chercher le texte en clair** (remplacer `Bonjour` par ce que tu as écrit) :
```
python -c "for f in ('backend/securetalk_backend.db','backend/events.jsonl','client/events.jsonl'): print(f, 'TROUVE' if b'Bonjour' in open(f,'rb').read() else 'aucun résultat (OK)')"
```

**T8 : forcer la rotation.** L'identifiant de conversation s'affiche sous le nom du contact dans le client (le copier avec la souris).
`INTERNAL_KEY_SOC_TO_BACKEND` doit être rempli dans le `.env` et le backend relancé.
```
cd client
python tools\force_rotation.py conv_u_xxxxxxxx_u_yyyyyyyy
```
Attendu : `200`. Puis Alice envoie un message : notification « clé renouvelée » et nouveau `Key ID`.

**T5 : verrouiller un compte à la main** (ce que fera le playbook du SOC). `u_xxxxxxxx` = identifiant d'Alice (visible dans `conv_...`) :
```
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/internal/accounts/u_xxxxxxxx/lock -Headers @{"X-API-Key"="COLLE_LA_CLE_ICI"}
```
Ensuite, la connexion d'Alice est refusée même avec le bon mot de passe (« Compte verrouillé »). Pour déverrouiller : même URL avec `/unlock`.

**T10 : vérifier la file d'attente.** Après quelques messages sans SOC :
```
Get-Content client\events_pending.jsonl | Measure-Object -Line
```

## Ordre conseillé pour la démo (guide 10.1)

1. T2 (message normal, montrer les événements) ; 2. T3 (le serveur ne voit rien) ; 3. T4 (phishing bloqué, raisons affichées) ;
4. T5 (force brute et verrouillage, avec le SOC) ; 5. T6 et T7 (falsification et rejeu, rotation forcée) ; 6. T9 et T10 (pannes).
Prévoir des comptes de démo, une base propre (`stop_all.bat`, supprimer `backend\securetalk_backend.db` et `%USERPROFILE%\.securetalk`) et une vidéo de secours.
