# Model card : service anti-phishing SecureTalk AI (bloc 3)

**Version :** `rf-lr-0.1` (règles + modèle ML ; mode `rules-0.1` si le fichier modèle est absent)
**Rôle :** classer un message de chat (texte + liens) en Safe / Suspicious / Phishing avant son envoi. Contrat : guide 2.10, `POST /v1/analyze`.

## Utilisation prévue
Aide à la décision pour l'utilisateur (avertissement ou blocage selon `policy.json` du client). Projet pédagogique : **pas un outil de sécurité de production.**

## Fonctionnement
1. `UrlAnalyzer` : imitation de marque, homoglyphes, IP, raccourcisseurs, TLD suspects, liens longs.
2. `TextAnalyzer` : urgence, vérification de compte, menace, demande d'identifiants, demande d'argent (FR/EN/AR).
3. Règles fusionnées (noisy-or) -> score règles.
4. Modèle ML : TF-IDF caractères + régression logistique **et** Random Forest sur les features des règles (moyenne).
5. Score final = `max(règles, modèle)` : le modèle ne peut qu'ajouter de la détection.

## Seuils (`config.json`)
Safe < 0.35 ; Suspicious de 0.35 à 0.60 ; Phishing >= 0.60.
Choisis sur le jeu **DEV** (102 messages écrits à la main) : alerte = plus bas seuil de précision >= 0.90 ; blocage = plus bas seuil de précision >= 0.98. Vérifiés **une seule fois** sur le TEST FINAL (35 messages, jamais utilisés pour régler). Les valeurs du guide (0.40 / 0.80) ont été abandonnées : au seuil 0.80, le rappel de blocage n'était que de 0.12 sur le test final (script : `python -m training.tune_thresholds`).

## Données
| Jeu | Contenu | Usage |
|---|---|---|
| `chat_dataset.csv` | 1353 messages **synthétiques** (gabarits FR/EN/AR/darija), seed 42 | entraînement / validation / test (70/15/15 par gabarit, sans fuite) |
| `handwritten_seed.csv` | 102 messages écrits à la main (jeu **DEV**) | réglage des seuils, jamais d'entraînement |
| `handwritten_test.csv` | 35 messages écrits à la main (jeu **TEST FINAL**) | note finale, lu une seule fois |
Aucune donnée personnelle ; prénoms inventés, domaines factices, IP de documentation 203.0.113.0/24.

## Résultats (seuils retenus : alerte 0.35, blocage 0.60 ; précision / rappel / F1)
| Jeu | Système | AUC | Alerte >= 0.35 | Blocage >= 0.60 |
|---|---|---|---|---|
| DEV écrit à la main (n=102) | Règles seules | 0.92 | 0.98 / 0.86 / 0.92 | 1.00 / 0.35 / 0.52 |
| DEV écrit à la main (n=102) | Hybride (règles + ML) | 0.98 | 0.93 / 0.98 / 0.95 | 1.00 / 0.71 / 0.83 |
| TEST FINAL écrit à la main (n=35) | Règles seules | 0.96 | 1.00 / 0.88 / 0.94 | 1.00 / 0.29 / 0.45 |
| TEST FINAL écrit à la main (n=35) | Hybride (règles + ML) | 0.99 | 0.94 / 1.00 / 0.97 | 1.00 / 0.71 / 0.83 |
| Test synthétique (n=175) | Règles seules | 0.99 | 1.00 / 0.98 / 0.99 | 1.00 / 0.91 / 0.95 |
| Test synthétique (n=175) | Hybride (règles + ML) | 1.00 | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.00 |

Anciens seuils (0.40 / 0.80) sur le TEST FINAL, hybride : alerte 0.94 / 0.88 / 0.91 ; blocage 1.00 / 0.12 / 0.21.
**Lecture prudente :** le test final n'a que 35 messages (17 phishings) : un message change le rappel d'environ 6 points. Les scores sur le jeu synthétique sont optimistes (voir limites).

## Limites connues
- Données d'entraînement synthétiques et proches des règles : les scores synthétiques sont optimistes. Le jeu écrit à la main est la seule mesure réaliste.
- Seulement 35 messages de test final et 102 de réglage : intervalles d'incertitude larges.
- Le modèle texte seul apprend surtout le style des gabarits (AUC 0.81 en validation) ; le Random Forest réutilise les signaux des règles, donc n'est pas une preuve indépendante.
- Les probabilités du modèle sont basses (non calibrées) sur des formulations nouvelles : le seuil de blocage a dû être abaissé à 0.60, et seuls ~70 % des phishings du test sont bloqués ; les autres restent « Suspicious » (avertissement).
- Seuil d'alerte abaissé à 0.35 : un lien à extension suspecte (.top, .xyz...) suffit à lui seul (score règles 0.35) à passer le message en « Suspicious ».
- Phishing sans lien imitant une marque (ex. `site-pirate.com/login.php`) mal détecté par les règles de liens.
- Darija en lettres latines : couverture minimale. Arabe : règles de base.
- Faux positifs possibles sur des demandes légitimes (ex. « peux-tu me donner le mot de passe du wifi »).

## Confidentialité
Le texte n'est ni stocké ni journalisé. Le SOC ne reçoit que : score, label, codes de raison, domaines des liens, longueur du texte (guide 2.9). Le service doit tourner en local / réseau de confiance.

## Reproduire
```
python -m training.build_dataset && python -m training.split_dataset
python -m training.train_baseline        # crée models/phishing_model.joblib (non versionné)
python -m training.benchmark_latency
```
Ne charger que des fichiers `.joblib` produits par soi-même (pickle).
