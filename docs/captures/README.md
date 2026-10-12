# Captures d'écran pour le rapport

Preuves à garder au fil de l'eau. Une capture = un fichier PNG dans ce dossier.

## Démo de détection (secret en dur)

| Fichier | Ce qu'on doit voir | Où le trouver |
|---|---|---|
| `demo-01-push-bloque.png` | Le terminal avec `GITHUB PUSH PROTECTION` | Terminal, pendant `faille.sh bloque` |
| `demo-02-pipeline-rouge.png` | La PR avec Gitleaks et Trivy en rouge, merge bloqué | Page de la PR, après `faille.sh rouge` |
| `demo-03-run-rouge.png` | Le détail du run en échec | [run 38322342740](https://github.com/securestack-team/clinic-booking/actions/runs/38322342740) |
| `demo-04-alerte-security.png` | L'alerte sur `api/appsettings.json`, ligne 4 | Security → Code scanning (filtre `is:closed` après la correction) |
| `demo-05-gitleaks-historique.png` | Trivy vert mais Gitleaks rouge après une simple suppression | [run 38322821765](https://github.com/securestack-team/clinic-booking/actions/runs/38322821765) |
| `demo-06-correction.png` | Le diff de la correction : plus de clé dans le fichier | Onglet « Files changed » de la PR |
| `demo-07-pipeline-verte.png` | Tous les checks verts | [run 38322924524](https://github.com/securestack-team/clinic-booking/actions/runs/38322924524) |

Les captures 03, 05 et 07 peuvent être faites à tout moment à partir des liens de la
répétition. Les captures 01, 02, 04 et 06 se font pendant une démo : l'état rouge de la PR
disparaît après la correction.

## Remédiation automatique (plus tard)

| Fichier | Ce qu'on doit voir |
|---|---|
| `autofix-01-pr-du-bot.png` | Une PR `autofix/...` avec le label `ai-autofix` |
| `autofix-02-diff.png` | Le diff : seulement la version du paquet et le lockfile |
| `autofix-03-pipeline.png` | La pipeline verte sur la PR du bot, en attente d'approbation |
| `autofix-04-synthese.png` | Le commentaire de synthèse sur la PR d'origine |
