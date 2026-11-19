# Checklist finale (guide, section 11) et texte pour le rapport

## A. Checklist « client »

Légende : ✔ vérifié par un test automatique (`pytest`, 44 tests) ; 👁 vérifié à l'écran avec le vrai backend, le vrai SDK et le vrai service IA ; ◻ à valider en réel (voir `TESTS_INTEGRATION.md`).

| Exigence du guide | État | Preuve ou à faire |
|---|---|---|
| Inscription, connexion | ✔ 👁 | `test_api_backend`, écran |
| Envoi et réception chiffrés | ✔ 👁 | `test_chat_service`, captures Alice et Bob |
| Échange de clés RSA, rotation | ✔ 👁 | `test_chat_service`, bouton « Renouveler la clé » |
| Rotation sur 409 (ordre du SOC) | ✔ ◻ | test automatique ; T8 réel avec `force_rotation.py` |
| Appel `/v1/analyze`, délai 2 s, repli | ✔ 👁 | `test_api_ml`, `test_ui_flows` ; IA arrêtée vue à l'écran |
| Avertissements clairs avec les raisons | 👁 | modal rouge avec le vrai modèle |
| Événements client et crypto conformes à 2.2 | ✔ | `test_soc_events`, `test_ui_flows` ; ◻ en mode `http` avec le vrai SOC |
| Clé privée uniquement en local, chiffrée | ✔ | `test_storage_session` |
| Aucun texte ni clé dans les logs et événements | ✔ | filtre de confidentialité testé ; ◻ T3 sur la vraie base |
| Aucun lien ouvert automatiquement | ✔ | bulles en texte simple |
| Cas du guide 7.6 : Safe, Suspicious (confirmé et annulé), Phishing, IA en panne, 409, falsifié, rejoué | ✔ | `test_ui_flows`, `test_chat_service` |
| Session expirée | ✔ | `test_storage_session` (calcul de l'expiration) ; ◻ à voir à l'écran |
| Reconnexion automatique du WebSocket | ✔ 👁 | `test_ws_thread`, états vus sur capture |
| Tests T2, T4, T9 | ◻ | à jouer ensemble (`TESTS_INTEGRATION.md`) |

## B. Intégration avec la partie IA

- `python tools\check_ml_contract.py` : **contrat respecté** avec le service de `ml/` (modèle `rf-lr-0.1`).
- À ne pas oublier : le service IA envoie lui-même `MESSAGE_SCANNED_SAFE`, `SUSPICIOUS_MESSAGE` et `PHISHING_DETECTED` ; le client n'envoie pas ces trois-là.

## C. Ce qui reste (hors client)

SOC complet (collecte, règles R001 à R013, playbooks, dashboard, simulateur d'attaques), puis T5, T6, T7, T11, T12 et T10 avec le vrai SOC.

---

## D. Texte prêt à adapter pour le rapport (chapitre « Client »)

**Rôle.** Le client est l'application de bureau (Python, PySide6) utilisée par chaque employé. C'est la seule partie qui voit les messages en clair :
elle chiffre avant l'envoi, vérifie à la réception, et demande l'avis de l'IA avant d'envoyer.

**Choix techniques.** Python partout pour importer directement le SDK cryptographique ; PySide6 plutôt que Tkinter pour une interface professionnelle ;
interface séparée de la logique (`chat_service.py` testable sans fenêtre) ; appels réseau dans des threads pour que la fenêtre ne se fige jamais.

**Sécurité du client.**
1. Chiffrement de bout en bout : le backend ne reçoit que des paquets chiffrés et authentifiés (AES-GCM ou AES-CBC + CMAC, AAD liant expéditeur, compteur et clé).
2. Ordre à la réception : tag, anti-rejeu, puis affichage ; un paquet falsifié ou rejoué n'est jamais affiché.
3. Clés de session envoyées en RSA-OAEP ; sur disque, uniquement sous forme enveloppée.
4. Clé privée RSA chiffrée avec le mot de passe (AES-GCM, scrypt), gardée en mémoire seulement pendant la session.
5. Anti-phishing : analyse avant envoi, politique `block`, repli explicite si l'IA est arrêtée, badge « Non analysé ».
6. Confidentialité vers le SOC : métadonnées seulement, filtre avant envoi ; un SOC en panne ne bloque jamais le chat.
7. Réaction au SOC : sur ordre de rotation (409), nouvelle clé et renvoi automatique, sans action de l'utilisateur.

**Tests.** 44 tests automatiques (formats, chiffrement, falsification, rejeu, rotation, politique de repli, événements, stockage, reconnexion),
un vérificateur de contrat pour le service IA, et les tests d'intégration T1 à T12.

**Limites honnêtes.** Voir `README.md` section 10 (cryptographie pédagogique, IA qui lit le texte en clair, anti-rejeu en mémoire,
pas d'historique conservé, mot de passe perdu = clé perdue, SQLite sans haute disponibilité).

## E. Questions probables du jury (partie client)

- **Le serveur peut-il lire les messages ?** Non : il ne reçoit que du texte chiffré et ne connaît aucune clé ; la clé de session voyage enveloppée avec la clé publique du destinataire.
- **Pourquoi l'IA lit-elle le texte en clair ?** Pour l'analyser, elle doit le lire : elle tourne en local, ne stocke rien, et ne renvoie au SOC que score, label et codes de raison. C'est un compromis assumé.
- **Que se passe-t-il si l'IA tombe ?** Politique de repli écrite dans `policy.json` : envoi avec avertissement et badge « Non analysé », ou refus selon le choix.
- **Que se passe-t-il si le SOC tombe ?** Rien pour l'utilisateur : délai de 1 s, envoi en arrière-plan, événements gardés dans un fichier et renvoyés plus tard.
- **Comment réagit le client à un ordre du SOC ?** Le backend répond 409 ; le client crée une nouvelle clé, refait l'échange RSA et renvoie le message.
- **Que fait-on contre un paquet falsifié ou rejoué ?** Le tag est vérifié avant tout ; le compteur est comparé au dernier vu et mis à jour seulement après un tag valide ; les deux cas émettent un événement au SOC.
- **Où est la clé privée ?** Sur la machine de l'utilisateur, chiffrée par son mot de passe ; jamais envoyée au backend ni au SOC.
