# Données du service anti-phishing (guide 8.3)

| Fichier | Contenu | Versionné ? |
|---|---|---|
| `chat_dataset.csv` | Jeu SYNTHÉTIQUE généré par `training/build_dataset.py` (seed 42) | non (régénérable) |
| `train.csv` / `val.csv` / `test.csv` | Découpage 70/15/15 par gabarit, sans doublon ni fuite | non (régénérable) |
| `handwritten/handwritten_seed.csv` | Messages écrits à la main, formulations indépendantes des gabarits : **jeu de test "style chat" du rapport** | **oui** |

Régénérer : `python -m training.build_dataset` puis `python -m training.split_dataset`.

## Règles
- Aucune donnée personnelle, aucun vrai mot de passe. Prénoms inventés, domaines factices,
  IP de la plage de documentation `203.0.113.0/24`. **Ne jamais visiter les liens.**
- Le jeu synthétique est construit à partir des mêmes idées que les règles (urgence, menace,
  marque imitée...) : les scores obtenus dessus sont OPTIMISTES. Le jeu écrit à la main est la
  mesure réaliste. À agrandir (objectif : 150+ messages, relus par ton amie).
- Jeux publics à ajouter pour l'entraînement (vérifier licence, date, qualité, citer dans le rapport) :
  PhishTank / OpenPhish (URL), UCI "Phishing Websites", collections d'e-mails de phishing.
  Attention : surtout des e-mails longs, pas des messages de chat.
- Colonnes : `id, text, urls (séparées par " | "), label (1=phishing), lang, category, template_id`.
