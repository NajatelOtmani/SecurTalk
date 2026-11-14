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
Safe < 0.40 ; Suspicious 0.40 à 0.80 ; Phishing >= 0.80. Valeurs du guide, **pas encore réglées** : réglage prévu sur le jeu « dev » écrit à la main, une fois agrandi.

## Données
| Jeu | Contenu | Usage |
|---|---|---|
| `chat_dataset.csv` | 1353 messages **synthétiques** (gabarits FR/EN/AR/darija), seed 42 | entraînement / validation / test (70/15/15 par gabarit, sans fuite) |
| `handwritten_seed.csv` | 30 messages écrits à la main (à agrandir à 150+) | mesure uniquement, jamais d'entraînement |
Aucune donnée personnelle ; prénoms inventés, domaines factices, IP de documentation 203.0.113.0/24.

## Résultats (seuil alerte 0.40 ; précision / rappel / F1)
| Jeu | Règles seules | Hybride (règles + ML) |
|---|---|---|
| Test synthétique (n=175) | 1.00 / 0.98 / 0.99 | 1.00 / 1.00 / 1.00 |
| **Écrit à la main (n=30)** | 1.00 / 0.53 / 0.70 | **0.94 / 1.00 / 0.97** |

Seuil blocage 0.80 : rappel 0.99 sur le test synthétique mais **0.20 sur le jeu écrit à la main**.
**À refaire après agrandissement du jeu écrit à la main (n=30 : un message = 3 points).**

## Limites connues
- Données d'entraînement synthétiques et proches des règles : les scores synthétiques sont optimistes. Le jeu écrit à la main est la seule mesure réaliste.
- Seulement 30 messages de mesure : intervalle d'incertitude large.
- Le modèle texte seul apprend surtout le style des gabarits (AUC 0.81 en validation) ; le Random Forest réutilise les signaux des règles, donc n'est pas une preuve indépendante.
- Peu de blocage (>= 0.80) sur des formulations nouvelles : la plupart des phishings restent « Suspicious ».
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
