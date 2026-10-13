# Travail réalisé les 12 et 13 octobre 2026 : compte rendu détaillé

Ce document raconte **tout ce qui a été fait** sur deux modules du projet, dans l'ordre, avec
les résultats, les vérifications, les problèmes rencontrés et ce qui reste à faire.

- Module **AI Security Agent + threat model** (responsable : Mohammed EL OMRI)
- Module **Auto-remediation + tests de sécurité** (responsable : Abdedaym CHAKRA), dont la
  **démo de détection** de la semaine

> Rien n'est encore mergé dans `main`. Tout est dans cinq Pull Requests ouvertes, pipeline
> verte, en attente d'une approbation. Les liens vers les fichiers de ce document pointent
> donc vers les branches.

## Sommaire

1. [Vue d'ensemble](#1-vue-densemble)
2. [Journal : ce qui a été fait, dans l'ordre](#2-journal--ce-qui-a-été-fait-dans-lordre)
3. [Livrable A : le threat model v1](#3-livrable-a--le-threat-model-v1)
4. [Livrable B : l'agent IA de sécurité](#4-livrable-b--lagent-ia-de-sécurité)
5. [Livrable C : la démo de détection](#5-livrable-c--la-démo-de-détection)
6. [Livrable D : la remédiation automatique v1](#6-livrable-d--la-remédiation-automatique-v1)
7. [Livrable E : la remédiation automatique v2](#7-livrable-e--la-remédiation-automatique-v2)
8. [Inventaire des fichiers](#8-inventaire-des-fichiers)
9. [Toutes les vérifications faites](#9-toutes-les-vérifications-faites)
10. [Ce que le travail a fait découvrir](#10-ce-que-le-travail-a-fait-découvrir)
11. [Problèmes rencontrés et solutions](#11-problèmes-rencontrés-et-solutions)
12. [Ce qui n'a pas pu être vérifié](#12-ce-qui-na-pas-pu-être-vérifié)
13. [Ce qui reste à faire, et par qui](#13-ce-qui-reste-à-faire-et-par-qui)
14. [Règles du projet : ce qui a été respecté, points d'attention](#14-règles-du-projet--ce-qui-a-été-respecté-points-dattention)
15. [Tout relancer soi-même](#15-tout-relancer-soi-même)
16. [Pour la présentation du mercredi 14 octobre](#16-pour-la-présentation-du-mercredi-14-octobre)
17. [Index des documents](#17-index-des-documents)

---

## 1. Vue d'ensemble

### Les cinq Pull Requests

| PR | Branche | Contenu | Pipeline |
|---|---|---|---|
| [#6](https://github.com/securestack-team/clinic-booking/pull/6) | `docs/threat-model-v1` | Threat model v1 + diagramme en image | Verte |
| [#7](https://github.com/securestack-team/clinic-booking/pull/7) | `feature/ai-security-agent` | Agent IA de triage + compte rendu du module | Verte |
| [#8](https://github.com/securestack-team/clinic-booking/pull/8) | `docs/demo-detection` | Guide de la démo, script, 3 captures | Verte |
| [#9](https://github.com/securestack-team/clinic-booking/pull/9) | `feature/auto-remediation` | Remédiation v1 (paquets vulnérables) | Verte |
| [#10](https://github.com/securestack-team/clinic-booking/pull/10) | `feature/auto-remediation-v2` (empilée sur #9) | Remédiation v2 (patch proposé par LLM) + compte rendu du module | Verte |

À part : la [PR #5](https://github.com/securestack-team/clinic-booking/pull/5) a servi à la
répétition de la démo. Elle est **fermée sans merge** et sa branche est supprimée.

### En chiffres

| | |
|---|---|
| Commits | 13, répartis sur 5 branches |
| Code de l'agent IA | 13 fichiers Python, 1 261 lignes |
| Tests de l'agent IA | 79 tests |
| Code de la remédiation (v1 + v2) | 14 fichiers Python, 1 716 lignes |
| Tests de la remédiation | 65 tests |
| Dépendances externes ajoutées | 0 (bibliothèque standard de Python uniquement) |
| Runs de pipeline pour la répétition de la démo | 3 (rouge, encore rouge, vert) |
| Menaces dans le threat model | 10, sur 13 composants et 14 flux |
| Fichiers d'un autre module modifiés | 0 |

### État de chaque demande

| Demande | État |
|---|---|
| Threat model v1 (STRIDE, 6 à 10 menaces) | Fait |
| Agent IA : SARIF → déduplication → Risk Score → commentaire + `triage.json` | Fait, LLM simulé dans les tests |
| Test d'un appel réel au LLM | **Non fait** : pas de clé |
| Démo de détection : faille → rouge → correction → vert | Répétée pour de vrai sur GitHub |
| Captures d'écran de la démo | 3 sur 7 |
| Remédiation v1 : mise à jour d'un paquet vulnérable | Fait, vérifié avec les vrais `npm` et `dotnet` |
| Remédiation v2 : patch LLM | Fait, LLM simulé, compilation vérifiée avec le vrai `dotnet build` |
| Jobs dans la pipeline | **Non fait** : module CI/CD, jobs prêts à copier |
| Tests de sécurité xUnit (403, 401, 429, 400) | **Bloqué** : pas encore d'API |
| Branche `vulnerable-demo` | **Bloqué** : prévue en semaine 7 |

---

## 2. Journal : ce qui a été fait, dans l'ordre

### Étape 1 : lecture et état des lieux

1. Lecture de `contexte-mercredi-14-oct.md` (le plan de la semaine) et de `AGENTS.md` (le
   contexte complet du projet).
2. Lecture de tous les fichiers du repo : `README.md`, `.gitignore`,
   `.pre-commit-config.yaml`, `.github/dependabot.yml`, le modèle de PR, `ci.yml` et
   `security.yml`.
3. État de GitHub : une seule branche (`main`), 4 PR Dependabot fermées, pipeline verte sur
   `main`, un ruleset actif sur `main`.
4. Téléchargement des **vrais rapports SARIF** du dernier run de `main` (Gitleaks, Trivy,
   CodeQL) pour voir leur forme exacte avant d'écrire le moindre code.

### Étape 2 : threat model v1

5. Rédaction de `docs/threat-model-v1.md` : actifs, 13 composants, diagramme de flux, 14 flux,
   10 menaces STRIDE, couverture, état actuel, liste pour la v2.
6. Commit sur la branche `docs/threat-model-v1`.

### Étape 3 : agent IA

7. Tentative d'appel à GitHub Models : le service répond « OK » à tout. Vérification dans la
   documentation : **il a été arrêté le 30 juillet 2026**. L'agent est donc écrit pour Gemini.
8. Vérification des noms de modèles Gemini dans la documentation Google.
9. Écriture de l'agent, module par module : `sarif.py`, `dedupe.py`, `scoring.py`,
   `redact.py`, `schema.py`, `llm.py`, `recommend.py`, `net.py`, `report.py`, `github.py`,
   `cli.py`.
10. Production de vrais rapports Gitleaks et Trivy à partir d'un faux secret, dans un dossier
    temporaire **hors du repo**, pour vérifier le format réel des findings.
11. Écriture de 4 rapports SARIF d'exemple et de 79 tests.
12. Corrections trouvées par les tests (voir section 11).
13. Exécution de l'agent sur les vrais rapports de `main` et sur les rapports du faux secret.
14. Scan Gitleaks et Trivy des nouveaux fichiers, puis 2 commits sur
    `feature/ai-security-agent`.
15. Rédaction de `security/agent/README.md` (mode d'emploi) et de
    `docs/README-module-mohammed.md` (compte rendu du module).

### Étape 4 : démo de détection

16. Vérification locale d'un point clé : Gitleaks scanne **toutes** les branches par défaut.
17. Création de la branche `demo/faille` avec une fausse paire de clés AWS →
    **push refusé** par la push protection.
18. Nouveau push avec l'identifiant seul → accepté. Ouverture de la PR #5 →
    **pipeline rouge**.
19. Récupération des preuves : logs Gitleaks et Trivy, 2 alertes dans l'onglet Security.
20. Suppression de la clé dans un nouveau commit → Trivy vert, **Gitleaks encore rouge**.
21. Réécriture de l'historique de la branche → **pipeline verte**.
22. Commentaire de synthèse sur la PR #5, fermeture sans merge, suppression de la branche.
23. Écriture de `docs/demo/faille.sh` (rejoue chaque étape), testé sur un dépôt Git local.
24. Rédaction de `docs/demo/README.md` (guide) et `docs/captures/README.md` (liste des
    captures).

### Étape 5 : remédiation v1

25. Écriture de `security/remediation` : `triage_input.py`, `versions.py`, `guardrails.py`,
    `fixers.py`, `gitops.py`, `github.py`, `report.py`, `cli.py`.
26. Écriture de 46 tests, dont des tests de bout en bout avec de **vrais dépôts Git**
    temporaires.
27. Désactivation temporaire de 6 garde-fous, un par un, pour vérifier qu'un test échoue à
    chaque fois.
28. Essai avec le **vrai `npm`** (`lodash` 4.17.20 → 4.17.21) puis le **vrai `dotnet`**
    (`Newtonsoft.Json` 12.0.1 → 13.0.1).
29. Rédaction de `security/remediation/README.md` et de `docs/README-module-abdedaym.md`.

### Étape 6 : Pull Requests

30. Les PR #6 et #7 avaient été ouvertes entre-temps ; la description de la #7 a été remplie.
31. Ouverture des PR #8 et #9. Les quatre pipelines sont vertes.

### Étape 7 : remédiation v2

32. Écriture de `codefix.py`, `llm.py` et `redact.py` ; le chemin commun (worktree, commit,
    push, PR) est partagé avec la v1.
33. Écriture de 19 tests de plus (65 au total), puis désactivation temporaire de 5 contrôles
    de la v2 pour vérifier que les tests les détectent.
34. Essai avec le **vrai `dotnet build`** sur un projet ASP.NET temporaire : un patch qui ne
    compile pas ne donne pas de PR, un patch correct en donne une.
35. Ouverture de la PR #10, empilée sur la #9. Pipeline verte.

### Étape 8 : vérifications visuelles et captures

36. Rendu du diagramme du threat model avec la vraie bibliothèque **Mermaid 11** dans un
    navigateur sans interface : le diagramme est correct. Export en PNG, ajouté à la PR #6.
37. Captures d'écran des trois runs de la répétition (pages publiques), ajoutées à la PR #8.
38. Mise à jour des deux comptes rendus de module, puis rédaction de ce document.

---

## 3. Livrable A : le threat model v1

Fichier : `docs/threat-model-v1.md` (PR #6). C'est le livrable demandé pour mercredi.

### Contenu

| Section | Contenu |
|---|---|
| 1. Ce qu'on protège | 5 actifs : données des patients, tokens, secrets, pipeline, code de `main` |
| 2. Composants | 13 composants (C1 à C13), chacun avec sa zone de confiance |
| 3. Diagramme de flux de données | Diagramme Mermaid, 3 frontières de confiance : Internet, Azure, GitHub |
| 4. Flux de données | 14 flux (F1 à F14) avec la protection prévue |
| 5. Menaces | 10 menaces au format demandé |
| 6. Où en est-on aujourd'hui | Ce que la pipeline détecte déjà |
| 7. À traiter dans la v2 | 6 points repoussés |

Le diagramme existe aussi en image : `docs/threat-model-v1-dfd.png`, pour les slides.

### Les 10 menaces

| ID | Menace | STRIDE | Catégorie OWASP | Contrôle prévu | Outil qui la détecte |
|---|---|---|---|---|---|
| T1 | Lire ou annuler le rendez-vous d'un autre patient | Elevation of Privilege | API1:2023 BOLA, A01:2025 | Vérifier le propriétaire à chaque endpoint | Tests xUnit (403), ZAP |
| T2 | Secret commité dans le repo public | Information Disclosure | A02:2025, A04:2025 | user-secrets, Key Vault, OIDC | Gitleaks, push protection, Trivy |
| T3 | Se faire passer pour un utilisateur | Spoofing | API2:2023, A07:2025 | Identity, token court, signature vérifiée | Tests xUnit (401), ZAP, CodeQL |
| T4 | Injection SQL (`FromSqlRaw` concaténé) | Tampering | A05:2025 | Requêtes paramétrées, DTOs | CodeQL, Semgrep, ZAP |
| T5 | Patient qui appelle un endpoint admin, ou s'attribue un rôle | Elevation of Privilege | API5:2023, API3:2023 | `[Authorize]` + rôles, DTOs sans `role` | Tests xUnit (403), Semgrep, ZAP |
| T6 | Inonder l'API, réserver tous les créneaux | Denial of Service | API4:2023, API6:2023 | Rate limiting, pagination, limits K8s | Tests xUnit (429), Grafana, Checkov |
| T7 | Dépendance vulnérable ou action GitHub compromise | Tampering | A03:2025 | Dependabot, actions épinglées par SHA | Trivy, Dependabot, npm audit, CodeQL |
| T8 | Action sensible non tracée | Repudiation | A09:2025 | Logs Serilog structurés, alertes | Prometheus + Grafana |
| T9 | Token volé sur le client (AsyncStorage, localStorage, HTTP) | Information Disclosure | M9:2024, M5:2024 | expo-secure-store, token en mémoire, HTTPS | MobSF, Semgrep, ZAP |
| T10 | Prompt injection contre l'agent IA | Tampering | LLM01, LLM05, LLM02 (2025) | Contenu non fiable, sortie validée, gate indépendante | Tests de l'agent, quality gate, revue humaine |

Les 6 catégories STRIDE et les 4 référentiels OWASP demandés sont couverts.

### Choix faits

- **10 menaces**, le maximum demandé. Les autres sont notées pour la v2.
- **Mermaid** plutôt qu'une image seule : le diagramme se modifie dans une PR comme du code.
- **T10 vise notre propre agent IA** : ses contrôles sont ceux codés et testés dans l'agent.
- **Hypothèse** : prise de rendez-vous en clinique, rôles patient / médecin / admin.

---

## 4. Livrable B : l'agent IA de sécurité

Dossier : `security/agent` (PR #7). Détail complet dans `docs/README-module-mohammed.md`.

### À quoi il sert

Les scanners trouvent, mais ne trient pas. L'agent retire les doublons, classe par risque et
dit quoi faire. Il publie un commentaire sur la PR et écrit `reports/triage.json`, lu ensuite
par la remédiation. **Il conseille, il ne bloque pas.**

### Le parcours d'un finding

```
 reports/*.sarif  →  NORMALISER  →  DÉDUPLIQUER  →  MASQUER  →  TRIAGE LLM  →  RISK SCORE  →  SORTIES
                     sarif.py       dedupe.py       redact.py   llm.py         scoring.py     report.py, github.py
```

### Ce que fait chaque fichier

| Fichier | Lignes | Rôle |
|---|---|---|
| `cli.py` | 136 | Ligne de commande ; enchaîne les étapes |
| `sarif.py` | 235 | Lit les SARIF ; ramène chaque finding à : outil, règle, sévérité, CWE, fichier, ligne, message |
| `dedupe.py` | 82 | Fusionne les findings qui désignent le même problème ; donne un identifiant stable |
| `redact.py` | 65 | Remplace tout ce qui ressemble à un secret par `[MASQUÉ]` |
| `llm.py` | 250 | Appelle Gemini ; valide sa réponse ; repli si le LLM ne répond pas |
| `scoring.py` | 88 | Calcule le Risk Score |
| `recommend.py` | 40 | Recommandations par défaut, sans LLM |
| `report.py` | 175 | Construit `triage.json` et le commentaire Markdown |
| `github.py` | 68 | Publie ou met à jour le commentaire de la PR |
| `schema.py` | 72 | Petit validateur JSON Schema |
| `net.py` | 42 | Client HTTP : HTTPS obligatoire, redirections refusées |

### Normalisation : les règles

| Sujet | Règle |
|---|---|
| Sévérité | 1) secret → toujours `critical` · 2) niveau écrit par Trivy dans ses tags · 3) score CVSS · 4) niveau SARIF |
| Catégorie | `secret` (Gitleaks, tag Trivy, CWE-798/259/321) · `dependency` (CVE, GHSA) · `config` (Trivy, Checkov) · `code` (le reste) |
| CodeQL | Ses règles sont dans `tool.extensions`, pas dans `tool.driver` : constaté sur un vrai rapport |
| Trivy | Le message « Clé: valeur » donne le paquet, la version installée et la version corrigée |
| Secrets | Le message du scanner n'est jamais gardé : seuls la règle, le fichier et la ligne sortent |
| Rapport cassé | Ignoré et signalé, sans faire planter l'agent |

### Déduplication : les clés

| Catégorie | Deux findings sont identiques s'ils ont… |
|---|---|
| Secret | le même fichier et la même ligne |
| Dépendance | la même CVE, le même paquet et le même fichier |
| Code, configuration | le même fichier, la même ligne et la même CWE |

Sur les rapports d'exemple : **9 findings bruts → 6**.

### Risk Score

**Risk Score = Sévérité × Exposition × Confiance** (de 0 à 10)

| Facteur | Calcul |
|---|---|
| Sévérité (0 à 10) | Score CVSS du scanner ; sinon critical 9.5, high 8.0, medium 5.5, low 2.0, info 0.5 |
| Exposition (0 à 1) | `api/` 1.0 · `web/`, `mobile/`, `infra/`, `.github/` 0.9 · autre 0.7 · `security/` 0.6 · tests 0.4 · `docs/` 0.2. Avec le LLM : × (0.5 + 0.5 × exploitabilité) |
| Confiance (0 à 1) | 1 − probabilité de faux positif ; jamais sous 0.5 ; jamais sous 0.8 si deux outils sont d'accord. Sans LLM : 1.0 |

| Exemple | Calcul | Score |
|---|---|---|
| Secret en dur | toujours | 9.5 |
| Injection SQL dans `api/`, CVSS 8.8, sans LLM | 8.8 × 1.0 × 1.0 | 8.8 |
| La même avec LLM (faux positif 10 %, exploitabilité 80 %) | 8.8 × 0.9 × 0.9 | 7.1 |
| La même dans `api/tests/` | 8.8 × 0.4 × 1.0 | 3.5 |

Garde-fous : le LLM peut seulement **baisser** un score, au plus d'un facteur 4 ; il ne peut
supprimer aucun finding ; un secret vaut toujours 9.5 ; la quality gate n'utilise pas ce score.

### Le LLM

- **Gemini**, modèle `gemini-3.5-flash-lite` par défaut. La clé va dans le secret
  `GEMINI_API_KEY`.
- Envoyé : identifiant, outils, règle, sévérité, CWE, fichier, ligne, message masqué, et 3
  lignes de code avant et après, masquées. **Jamais un finding de type secret.**
- Reçu : probabilité de faux positif, exploitabilité, justification, recommandation, en JSON
  validé par `schemas/llm-response.schema.json`, élément par élément.
- Limites : 45 findings au plus, par lots de 15.
- **Si le LLM ne répond pas** : une seconde tentative, puis l'agent continue avec les
  sévérités brutes. Il sort toujours en code 0.

### Sécurité de l'agent

| Menace | Contrôle | Test |
|---|---|---|
| Un secret part chez le LLM | Findings `secret` exclus + masquage | `test_un_secret_n_est_jamais_envoye` |
| Prompt injection | Score borné, aucun finding supprimé, gate indépendante | `test_prompt_injection_reussie_score_borne_et_finding_conserve` |
| Réponse du LLM invalide | Schéma JSON, rien n'est exécuté | `test_evaluations_invalides_ecartees_une_par_une` |
| HTML, lien ou mention dans le commentaire | Échappement par `md()` | `test_contenu_non_fiable_neutralise` |
| Chemin `../../` dans un SARIF | Chemin vérifié, liens symboliques compris | `test_chemin_hors_du_repo_refuse` |
| Fuite de la clé d'API | En-tête HTTP, erreurs courtes | `test_erreurs_converties_sans_fuite_de_la_cle` |
| Injection de commande dans les logs Actions | Logs sur une ligne, préfixés | `test_les_logs_ne_peuvent_pas_injecter_de_commande_actions` |

### Les sorties

- **Commentaire de PR** : tableau trié par Risk Score, avec sévérité brute, outils, estimation
  de faux positif et recommandation. Mis à jour à chaque exécution au lieu d'être dupliqué.
- **`reports/triage.json`** : la liste complète, au format `schemas/triage.schema.json`.
  Chaque finding a un `id` stable, sa `category`, et pour une dépendance le paquet et la
  version corrigée.

---

## 5. Livrable C : la démo de détection

Dossier : `docs/demo` (PR #8). C'est le point le plus important de mercredi.

### La répétition, faite pour de vrai

Avec une **fausse clé au format AWS**, fabriquée pour l'occasion, dans `api/appsettings.json`.

| # | Action | Résultat | Preuve |
|---|---|---|---|
| 1 | Push d'une fausse **paire** de clés | **Refusé** par la push protection | Sortie du terminal dans `docs/demo/README.md` |
| 2 | Push de l'identifiant seul + PR #5 | Pipeline **rouge** en 52 s | [run 38322342740](https://github.com/securestack-team/clinic-booking/actions/runs/38322342740), `demo-03-run-rouge.png` |
| 3 | Onglet Security | Alertes Gitleaks `aws-access-token` et Trivy `aws-access-key-id` (critique), ligne 4 | [alerte 1](https://github.com/securestack-team/clinic-booking/security/code-scanning/1), [alerte 2](https://github.com/securestack-team/clinic-booking/security/code-scanning/2) |
| 4 | Clé retirée dans un nouveau commit | Trivy vert, **Gitleaks encore rouge** | [run 38322821765](https://github.com/securestack-team/clinic-booking/actions/runs/38322821765), `demo-05-gitleaks-historique.png` |
| 5 | Historique de la branche réécrit | Pipeline **verte** en 59 s | [run 38322924524](https://github.com/securestack-team/clinic-booking/actions/runs/38322924524), `demo-07-pipeline-verte.png` |
| 6 | Nettoyage | PR fermée sans merge, branche supprimée, alertes passées à « fixed » | PR #5 |

### Ce qui a été préparé pour le direct

- `docs/demo/README.md` : liste de vérification, les 5 étapes avec ce qu'on voit et ce qu'on
  dit, le plan B, la variante injection SQL.
- `docs/demo/faille.sh` : une commande par étape (`bloque`, `rouge`, `suppression`, `vert`,
  `nettoyer`). La fausse clé y est assemblée en deux morceaux pour que Gitleaks ne la voie pas
  dans le script lui-même.
- `docs/captures/` : 3 captures faites, et la liste des 4 qui restent.

---

## 6. Livrable D : la remédiation automatique v1

Dossier : `security/remediation` (PR #9). Détail complet dans
`docs/README-module-abdedaym.md`.

### Ce qu'elle fait

Elle lit `reports/triage.json`. Pour chaque **paquet vulnérable** NuGet ou npm :

```
 CHOISIR  →  PLANIFIER  →  APPLIQUER  →  CONTRÔLER  →  VÉRIFIER  →  branche autofix/<id> → commit → push → PR (label ai-autofix)
```

**Elle ne merge jamais**, et ne crée rien sans l'option `--apply`.

### Les correctifs

| Cas | Modification | Commande |
|---|---|---|
| NuGet, paquet dans le `.csproj` | `Version="..."` de la ligne du paquet | `dotnet restore --force-evaluate` |
| NuGet, versions centralisées | `Version="..."` dans `Directory.Packages.props` | `dotnet restore --force-evaluate` |
| npm, paquet dans `package.json` | aucune à la main | `npm install paquet@version --package-lock-only --ignore-scripts` |

- Plusieurs CVE sur le même paquet → **une seule PR**, vers la version qui les corrige toutes.
- Plusieurs versions corrigées proposées → la plus petite, de préférence dans la même version
  majeure, jamais une préversion.
- Le lockfile est régénéré par l'outil officiel, jamais édité à la main.
- Dépendance transitive, version en plage ou en variable, outil absent → pas de PR, un
  commentaire avec la raison.

### Ce que fait chaque fichier

Les nombres de lignes sont ceux de la branche `feature/auto-remediation-v2`.

| Fichier | Lignes | Rôle |
|---|---|---|
| `cli.py` | 225 | Ligne de commande ; partie commune à tous les correctifs |
| `triage_input.py` | 181 | Lit `triage.json` ; choisit les findings ; regroupe par paquet |
| `versions.py` | 51 | Compare les versions ; choisit la version corrigée |
| `fixers.py` | 270 | Planifie, applique et vérifie une mise à jour de paquet |
| `guardrails.py` | 75 | Toutes les règles de sécurité |
| `gitops.py` | 98 | Worktree, commit, push |
| `github.py` | 81 | PR, label, commentaire. **Aucune fonction de merge** |
| `report.py` | 261 | Texte des PR, synthèse, rapport JSON |
| `net.py` | 42 | Client HTTP |

### Les garde-fous

| Garde-fou | Test |
|---|---|
| Jamais de merge ni d'approbation | `test_jamais_de_merge_ni_d_approbation` |
| Nombre maximum de PR (3 par défaut, 10 au plus) | `test_nombre_maximum_de_pr` |
| Rien dans `.github/` ni `infra/` ; fichiers de dépendances seulement | `test_l_outil_modifie_un_fichier_interdit` |
| Pas de PR pour un correctif non validé, un commentaire | `test_correctif_non_valide_pas_de_pr_mais_un_commentaire` |
| Pas de doublon ; respect d'une PR fermée par un humain | `test_pas_de_doublon` |
| Pas de boucle sur une branche `autofix/` | `test_ne_se_corrige_pas_elle_meme` |
| Entrée non fiable validée ; commandes sans shell | `test_valeurs_dangereuses_ecartees` |
| `dotnet` et `npm` ne voient pas les tokens | `test_l_outil_ne_voit_pas_les_secrets_de_l_environnement` |
| Dossier de travail intact (worktree temporaire) | vérifié dans chaque test de bout en bout |
| Simulation par défaut | `test_simulation_par_defaut_ne_cree_rien` |

---

## 7. Livrable E : la remédiation automatique v2

Même dossier, PR #10. Elle ne s'active que si `GEMINI_API_KEY` existe.

### Les trois cas

| Cas | CWE | Correction demandée au LLM |
|---|---|---|
| Injection SQL | CWE-89 | Remplacer la requête concaténée par une requête paramétrée |
| Autorisation manquante | CWE-862, CWE-285, CWE-306 | Ajouter `[Authorize]` sur l'endpoint |
| Secret en dur dans le code | CWE-798, CWE-259, CWE-321 | Lire la valeur depuis la configuration |

Seulement pour un fichier `.cs` dans `api/`.

### Le principe : le LLM propose, la remédiation contrôle

Le LLM reçoit 12 lignes avant et après la ligne signalée, numérotées, secrets masqués. Pour un
secret en dur, **toutes les chaînes de caractères de l'extrait sont effacées**. Il répond par
un seul remplacement de lignes, en JSON.

| # | Contrôle | Ce qui est refusé |
|---|---|---|
| 1 | Forme | JSON inattendu ; patch hors de l'extrait, qui ne couvre pas la ligne signalée, ou de plus de 12 lignes |
| 2 | Contenu | `[MASQUÉ]` recopié ; valeur qui ressemble à un secret ; aucun changement ; SQL encore concaténé ; `[Authorize]` absent ou `[AllowAnonymous]` ajouté ; valeur en dur gardée |
| 3 | Périmètre | Tout fichier modifié autre que celui du finding |
| 4 | Compilation | `dotnet build` en échec |

Un contrôle échoue → pas de PR, un commentaire avec la raison. Tous passent → une PR marquée
« écrit par un LLM, à relire ligne par ligne ».

| Fichier | Lignes | Rôle |
|---|---|---|
| `codefix.py` | 233 | Choisit les findings, prépare l'extrait, contrôle et applique le patch, lance la compilation |
| `llm.py` | 122 | Demande le patch à Gemini ; valide la forme de la réponse |
| `redact.py` | 67 | Masque les secrets avant l'envoi |

**Limite assumée** : ces contrôles réduisent le risque, ils ne prouvent pas que le patch est
bon. D'où la pipeline complète et la relecture humaine, toujours obligatoires.

---

## 8. Inventaire des fichiers

### PR #6, `docs/threat-model-v1`

| Fichier | Contenu |
|---|---|
| `docs/threat-model-v1.md` | Le threat model |
| `docs/threat-model-v1-dfd.png` | Le diagramme de flux en image |

### PR #7, `feature/ai-security-agent`

| Fichier | Contenu |
|---|---|
| `security/agent/README.md` | Mode d'emploi, formule, job à ajouter à la pipeline |
| `security/agent/triage/*.py` | 13 fichiers, le code de l'agent |
| `security/agent/schemas/llm-response.schema.json` | Forme obligatoire de la réponse du LLM |
| `security/agent/schemas/triage.schema.json` | Format de `reports/triage.json` |
| `security/agent/tests/fixtures/*.sarif` | 4 rapports d'exemple : CodeQL, Semgrep, Trivy, Gitleaks |
| `security/agent/tests/test_*.py` | 6 fichiers, 79 tests |
| `docs/README-module-mohammed.md` | Compte rendu détaillé du module |

### PR #8, `docs/demo-detection`

| Fichier | Contenu |
|---|---|
| `docs/demo/README.md` | Guide de la démo + résultat de la répétition |
| `docs/demo/faille.sh` | Script qui rejoue chaque étape |
| `docs/captures/README.md` | Liste des captures |
| `docs/captures/demo-03-run-rouge.png` | Run en échec |
| `docs/captures/demo-05-gitleaks-historique.png` | Trivy vert, Gitleaks rouge |
| `docs/captures/demo-07-pipeline-verte.png` | Run réussi |

### PR #9 et #10, `feature/auto-remediation` puis `-v2`

| Fichier | Contenu |
|---|---|
| `security/remediation/README.md` | Mode d'emploi, garde-fous, job à ajouter à la pipeline |
| `security/remediation/remediation/*.py` | 11 fichiers en v1, 14 avec la v2 |
| `security/remediation/tests/test_units.py` | 28 tests |
| `security/remediation/tests/test_cli.py` | 18 tests de bout en bout (v1) |
| `security/remediation/tests/test_codefix.py` | 19 tests (v2) |
| `docs/README-module-abdedaym.md` | Compte rendu détaillé du module |

---

## 9. Toutes les vérifications faites

### Tests automatiques

| Module | Tests | Durée | Réseau |
|---|---|---|---|
| Agent IA | 79 | moins d'une seconde | aucun appel (un garde-fou fait échouer tout test qui essaierait) |
| Remédiation | 65 | environ 5 secondes | aucun appel |

### Vérifications avec de vrais outils

| Quoi | Comment | Résultat |
|---|---|---|
| L'agent sur les vrais rapports de `main` | Rapports du run 38300923207 | 3 rapports lus, 0 finding, commentaire « Aucun finding » |
| L'agent sur un vrai secret détecté | Vrais Gitleaks et Trivy sur un faux secret, hors du repo | 2 findings bruts fusionnés en 1, score 9.5 |
| La remédiation avec le vrai `npm` | `lodash` 4.17.20 → 4.17.21 | `package.json` et `package-lock.json` à jour, branche poussée, rien d'autre modifié |
| La remédiation avec le vrai `dotnet` | `Newtonsoft.Json` 12.0.1 → 13.0.1 (SDK 8) | `.csproj` et `packages.lock.json` à jour, nouvelle empreinte |
| La v2 avec le vrai `dotnet build` | Projet ASP.NET temporaire | Patch sans le bon espace de noms : erreur CS0246, pas de PR. Patch correct : PR d'une ligne |
| Git | Vrais dépôts temporaires dans les tests | Branche, commit et fichiers modifiés vérifiés sur le remote |
| Le script de démo | Dépôt Git local | Les 5 étapes donnent l'état attendu |
| Le diagramme | Bibliothèque Mermaid 11 dans un navigateur | Rendu correct, exporté en PNG |

### Vérifications sur GitHub

| Quoi | Résultat |
|---|---|
| La démo complète | PR #5 : push refusé, rouge, encore rouge, vert |
| La pipeline sur les 5 PR | 10 checks réussis sur chacune (`Build & Test (.NET)` est ignoré tant qu'il n'y a pas d'API) |
| Les secrets | Gitleaks et Trivy ne trouvent rien dans les 5 branches |

### Les tests détectent-ils vraiment un garde-fou retiré ?

Onze contrôles ont été désactivés temporairement, un par un. À chaque fois, au moins un test a
échoué.

| Module | Contrôles désactivés |
|---|---|
| Remédiation v1 | Contrôle des fichiers modifiés · vérification du correctif · anti-boucle · limite de PR · validation du nom de paquet · respect d'une PR fermée |
| Remédiation v2 | Contrôle du patch · compilation · contrôle du fichier modifié · effacement des chaînes · masquage de l'extrait |

---

## 10. Ce que le travail a fait découvrir

| # | Découverte | Conséquence |
|---|---|---|
| 1 | **GitHub Models a été arrêté le 30 juillet 2026.** Son API répond « OK » à tout | Il ne reste que Gemini. `AGENTS.md` cite encore GitHub Models : à corriger |
| 2 | **La push protection bloque la paire de clés AWS, pas l'identifiant seul** | La démo se fait en deux temps |
| 3 | **Supprimer un secret dans un nouveau commit ne suffit pas** : Gitleaks lit l'historique | Il faut révoquer, puis réécrire l'historique de la branche |
| 4 | **Gitleaks scanne toutes les branches du repo** (6 commits scannés pour une PR d'un commit) | Une branche avec un secret met les PR de tout le monde au rouge |
| 5 | **Une PR créée avec le `GITHUB_TOKEN` du workflow ne déclenche pas la pipeline** | La remédiation a besoin d'un token de GitHub App ou d'un PAT (`AUTOFIX_TOKEN`) |
| 6 | **`ubuntu-latest` passe à Ubuntu 26 le 19 octobre 2026** (annoncé dans chaque run) | À surveiller par le module CI/CD |
| 7 | Seuls deux comptes apparaissaient comme collaborateurs du repo le 12 octobre | Les autres membres doivent avoir accès pour approuver |
| 8 | Deux scanners voient le même secret (Gitleaks et Trivy) | C'est exactement ce que l'agent déduplique |
| 9 | Un patch d'une seule zone ne peut pas ajouter de `using` en haut du fichier | Le LLM doit écrire le nom complet du type, sinon le patch ne compile pas |
| 10 | Python recolle les morceaux d'un faux secret dans ses fichiers compilés (`.pyc`) | `__pycache__` doit rester ignoré par Git, sinon Gitleaks réagit |

---

## 11. Problèmes rencontrés et solutions

| Problème | Solution |
|---|---|
| Réseau très lent : impossible de télécharger les images Docker des scanners et la base de vulnérabilités de Trivy | Formats Gitleaks et secret Trivy vérifiés avec les outils locaux ; les exemples « vulnérabilité » et « configuration » de Trivy suivent le format documenté |
| L'outil de rendu Mermaid en ligne de commande ne s'installait pas | Rendu fait plus tard avec la bibliothèque Mermaid dans un navigateur sans interface |
| Un secret en dur vu par CodeQL obtenait 9.8 au lieu de 9.5 | Score d'un secret fixé à 9.5, comme documenté |
| Un test de l'agent faisait un **vrai appel réseau** | Client HTTP rendu remplaçable ; garde-fou ajouté : tout appel réseau fait échouer les tests |
| Un test attendait 2 vraies secondes | Pause rendue remplaçable |
| Les messages Trivy étaient illisibles dans le commentaire | Message reconstruit : paquet, version, description courte |
| Projet déjà à jour mais lockfile en retard : la remédiation concluait à tort « dépendance transitive » | Cas reconnu : seul le lockfile est régénéré |
| npm transformait une version exacte en plage (`^`) | Le style d'origine est conservé (`--save-exact`) |
| La v2 refusait `[Microsoft.AspNetCore.Authorization.Authorize]` | Le nom complet est accepté ; les `using` du fichier sont donnés au LLM |
| La raison d'un échec de compilation était vide | Les numéros d'erreur du compilateur (CS0246…) sont ajoutés, sans le code cité |
| Une commande `gh` de modification de PR échouait | Passage par l'API REST de GitHub |
| L'aperçu du diagramme sur GitHub ne s'affichait pas dans les captures automatiques | Même le README officiel de Mermaid ne s'y affiche pas depuis ce réseau : image PNG ajoutée en secours |

---

## 12. Ce qui n'a pas pu être vérifié

| Point | Pourquoi | Comment le vérifier |
|---|---|---|
| L'appel réel à Gemini (agent et v2) | Aucune clé | `python3 -m triage --check-llm` avec `GEMINI_API_KEY` |
| Les noms de modèles `gemini-3.5-flash-lite` et `gemini-3.8-flash` | Lus dans la documentation, pas essayés | Premier appel réel ; sinon `--model` ou `AUTOFIX_LLM_MODEL` |
| La qualité des patchs du vrai LLM | Ni clé, ni code d'API | Branche `vulnerable-demo`, semaine 7 |
| La publication réelle d'un commentaire par l'agent | API GitHub simulée ; pas de job | Ajouter le job, ouvrir une PR |
| La création réelle d'une PR par la remédiation | API GitHub simulée ; pas de job | Ajouter le job, ouvrir une PR avec un paquet vulnérable |
| `dotnet` avec .NET 10 | Vérifié avec le SDK 8 | Premier run du job |
| Le format réel d'un finding CodeQL, Semgrep, ou d'une vulnérabilité Trivy | Exemples écrits d'après le format documenté | Premier vrai commentaire de l'agent |
| L'aperçu du diagramme sur GitHub | Réseau trop lent pour l'observer | Ouvrir la PR #6 dans un navigateur |
| Le script `faille.sh` contre GitHub | Testé sur un dépôt local ; sur GitHub les étapes ont été faites à la main | Répétition de mercredi matin |
| La variante `FromSqlRaw` de la démo | Pas de code C# dans `/api` | Après le squelette de l'API |
| Python 3.12 du runner | Tout a été lancé en Python 3.13 | Premier run d'un job Python |

---

## 13. Ce qui reste à faire, et par qui

| # | Tâche | Qui |
|---|---|---|
| 1 | Approuver les PR #6, #7, #8, #9, puis #10 | Un autre membre de l'équipe pour chacune |
| 2 | Relire le code et cocher « Code généré par IA relu, compris et testé » dans les PR | La personne qui pousse |
| 3 | Faire les 4 captures restantes : push bloqué, PR rouge, alerte Security, diff de la correction | Abdedaym |
| 4 | Répéter la démo mercredi matin avec `faille.sh` | Abdedaym + Ali |
| 5 | Créer la clé Gemini et le secret `GEMINI_API_KEY` | Mohammed + Ali |
| 6 | Créer le token du bot et le secret `AUTOFIX_TOKEN` | Ali |
| 7 | Ajouter les jobs `ai-triage` et `auto-remediation` dans `security.yml` (prêts dans les deux README) | Ali cette semaine, puis Hajar |
| 8 | Ajouter `python` aux langages CodeQL | Hajar |
| 9 | Décider si Gitleaks doit se limiter à l'historique de la PR | Hajar |
| 10 | Vérifier la pipeline après le passage à Ubuntu 26 (19 octobre) | Hajar |
| 11 | Corriger `AGENTS.md` : GitHub Models n'existe plus | Ali |
| 12 | Donner accès au repo à tous les membres | Ali |
| 13 | Squelette de l'API, authentification, endpoints | Freddy |
| 14 | Tests de sécurité xUnit : 403, 401, 429, 400 (plan dans `docs/README-module-abdedaym.md`) | Abdedaym + Freddy |
| 15 | Essayer la v2 avec le vrai LLM, ajuster le prompt | Abdedaym |
| 16 | Branche `vulnerable-demo` | Abdedaym + Freddy |
| 17 | Threat model v2, diagramme dans OWASP Threat Dragon | Mohammed + équipe |

Ordre de merge conseillé : #6 et #8 d'abord (utiles mercredi), puis #7, #9 et #10.

---

## 14. Règles du projet : ce qui a été respecté, points d'attention

| Règle | Situation |
|---|---|
| Tout passe par une PR vers `main` | Oui : aucun push sur `main` |
| Branches `feature/`, `fix/`, `ci/`, `infra/`, `docs/` | Oui, sauf `demo/faille`, nom imposé par le contexte de la semaine |
| Conventional Commits | Oui : `feat:`, `docs:`, `chore:`, `fix:` |
| Pas de force-push | Respecté sur `main`. Utilisé sur la branche de démo : c'est la seule façon de retirer un secret de l'historique |
| Aucun secret dans le repo | Oui : les faux secrets des tests et du script sont assemblés à l'exécution. Le faux secret de la démo n'a existé que sur une branche supprimée |
| Chaque scanner produit un SARIF | Non concerné : aucun workflow modifié |
| Ne jamais envoyer de secret à un LLM | Oui, et testé automatiquement dans les deux modules |
| Rester dans son périmètre | `.github/workflows`, `/api`, `/infra`, `/web`, `/mobile` et le `README.md` racine n'ont pas été touchés |
| Petites PR | 5 PR séparées ; la v2 est empilée sur la v1 pour que chaque diff reste lisible |
| Code généré par IA relu, compris et testé | La case est **décochée** dans les PR : elle se coche après relecture |
| « À ne pas faire avant mercredi » : agent IA et remédiation | Ils sont faits en avance, dans des PR séparées. Seules #6 et #8 servent mercredi |

---

## 15. Tout relancer soi-même

```bash
# Tests de l'agent IA (branche feature/ai-security-agent)
cd security/agent
python3 -m unittest
python3 -m triage --input tests/fixtures --output /tmp/triage      # essai sans LLM
cat /tmp/triage/triage.md

# Tests de la remédiation (branche feature/auto-remediation-v2)
cd security/remediation
python3 -m unittest
python3 -m remediation --triage /tmp/triage/triage.json --repo-root ../.. --output /tmp/remediation   # simulation

# Avec une clé Gemini (jamais dans le repo)
export GEMINI_API_KEY=...
cd security/agent && python3 -m triage --check-llm

# La démo de détection (branche docs/demo-detection)
cp docs/demo/faille.sh /tmp/faille.sh
/tmp/faille.sh bloque        # push refusé
/tmp/faille.sh rouge         # PR ouverte, pipeline rouge
/tmp/faille.sh vert          # pipeline verte
/tmp/faille.sh nettoyer      # à faire tout de suite après
```

---

## 16. Pour la présentation du mercredi 14 octobre

| Point à montrer | Ce que ce travail apporte |
|---|---|
| 3. Le threat model v1 | PR #6 : le tableau des 10 menaces et le diagramme (image prête pour une slide) |
| 7. La démo en direct | PR #8 : le guide, le script, et les captures en plan B |
| 6. Une pipeline qui tourne sur chaque PR | Les 5 PR ouvertes le montrent : 10 checks verts sur chacune |
| 4. Le repo protégé | La PR #5 montre la push protection et le blocage du merge en action |

Trois phrases utiles pendant la démo :

1. « GitHub refuse le push : le secret n'arrive même pas sur le serveur. »
2. « S'il passe quand même, deux outils le détectent, le merge est bloqué et une alerte est
   créée. »
3. « Supprimer le secret ne suffit pas : il reste dans l'historique. On le révoque. »

L'agent IA et la remédiation ne sont pas à présenter mercredi : ils sont prêts pour la suite.

---

## 17. Index des documents

| Document | Branche | Pour quoi faire |
|---|---|---|
| `docs/README.md` | `docs/work-summary` | Ce compte rendu global |
| `docs/threat-model-v1.md` | `docs/threat-model-v1` | Le threat model |
| `docs/README-module-mohammed.md` | `feature/ai-security-agent` | Tout sur l'agent IA et le threat model, questions de soutenance |
| `security/agent/README.md` | `feature/ai-security-agent` | Mode d'emploi de l'agent, job de pipeline |
| `docs/demo/README.md` | `docs/demo-detection` | Guide de la démo en direct |
| `docs/captures/README.md` | `docs/demo-detection` | Liste des captures |
| `docs/README-module-abdedaym.md` | `feature/auto-remediation-v2` | Tout sur la démo et la remédiation, plan des tests de sécurité, questions de soutenance |
| `security/remediation/README.md` | `feature/auto-remediation-v2` | Mode d'emploi de la remédiation, job de pipeline |
