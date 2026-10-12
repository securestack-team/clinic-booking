# Module « AI Security Agent + threat model » : tout ce qui a été fait

Ce document explique en détail le travail réalisé pour le module de **Mohammed EL OMRI** :
le **threat model v1** et l'**agent IA de triage**. Il sert à comprendre le code, à le
présenter, et à savoir ce qu'il reste à faire.

> État au 12 octobre 2026. Le travail est sur deux branches, en attente de Pull Request.

## Sommaire

1. [Résumé](#1-résumé)
2. [Où se trouve le travail](#2-où-se-trouve-le-travail)
3. [Partie 1 : le threat model v1](#3-partie-1--le-threat-model-v1)
4. [Partie 2 : l'agent IA de sécurité](#4-partie-2--lagent-ia-de-sécurité)
5. [Les tests](#5-les-tests)
6. [Ce qui est demandé dans AGENTS.md et où c'est fait](#6-ce-qui-est-demandé-dans-agentsmd-et-où-cest-fait)
7. [Ce qui n'a pas pu être vérifié](#7-ce-qui-na-pas-pu-être-vérifié)
8. [Ce qu'il reste à faire, et par qui](#8-ce-quil-reste-à-faire-et-par-qui)
9. [Questions probables à la soutenance](#9-questions-probables-à-la-soutenance)
10. [Preuves à garder pour le rapport](#10-preuves-à-garder-pour-le-rapport)

---

## 1. Résumé

| Livrable | État | Où |
|---|---|---|
| Threat model v1 (STRIDE, 10 menaces) | Fait | `docs/threat-model-v1.md` |
| Agent IA : lecture et normalisation des SARIF | Fait, testé | `security/agent/triage/sarif.py` |
| Agent IA : déduplication | Fait, testé | `security/agent/triage/dedupe.py` |
| Agent IA : masquage des secrets | Fait, testé | `security/agent/triage/redact.py` |
| Agent IA : triage LLM (Gemini) | Fait, testé avec un LLM simulé | `security/agent/triage/llm.py` |
| Agent IA : Risk Score 0 à 10 | Fait, testé | `security/agent/triage/scoring.py` |
| Agent IA : commentaire de PR + `triage.json` | Fait, testé avec une API simulée | `security/agent/triage/report.py`, `github.py` |
| Appel réel à Gemini | **Pas encore testé** (pas de clé) | voir section 7 |
| Job dans la pipeline | **Pas fait** (module CI/CD) | voir section 8 |
| Threat model dans OWASP Threat Dragon | **Pas fait** (prévu pour la v2) | voir section 8 |

En chiffres : 13 fichiers Python pour l'agent (environ 1 260 lignes), 79 tests automatiques,
2 schémas JSON, 4 rapports SARIF d'exemple, aucune dépendance externe.

## 2. Où se trouve le travail

| Branche | Commits | Contenu |
|---|---|---|
| `docs/threat-model-v1` | `2bc19e0` | `docs/threat-model-v1.md` |
| `feature/ai-security-agent` | `1fdace7`, `cc10a00` | Tout le dossier `security/agent` + ce document |

Les deux branches partent de `main`. Rien n'a été poussé directement sur `main` : il faut ouvrir
une Pull Request par branche, avec une approbation chacune.

Aucun fichier d'un autre module n'a été modifié : ni `.github/workflows`, ni `/api`, ni
`/infra`, ni le `README.md` de la racine.

```
docs/
  threat-model-v1.md            le threat model (branche docs/threat-model-v1)
  README-module-mohammed.md     ce document
security/agent/
  README.md                     mode d'emploi court de l'agent
  triage/                       le code de l'agent
    cli.py                      ligne de commande, enchaîne les étapes
    sarif.py                    lit les SARIF, normalise les findings
    dedupe.py                   fusionne les doublons
    redact.py                   masque les secrets
    llm.py                      triage par Gemini
    scoring.py                  Risk Score
    recommend.py                recommandations par défaut (sans LLM)
    report.py                   triage.json + commentaire Markdown
    github.py                   publie le commentaire sur la PR
    net.py                      petit client HTTP
    schema.py                   validateur JSON Schema
  schemas/
    llm-response.schema.json    forme obligatoire de la réponse du LLM
    triage.schema.json          forme de reports/triage.json
  tests/                        79 tests + 4 rapports SARIF d'exemple
```

---

## 3. Partie 1 : le threat model v1

Fichier : `docs/threat-model-v1.md`. C'est le livrable demandé pour la présentation du
mercredi 14 octobre.

### Ce qu'il contient

| Section | Contenu |
|---|---|
| 1. Ce qu'on protège | 5 actifs : données des patients, tokens, secrets, pipeline, code de `main` |
| 2. Composants | 13 composants (C1 à C13) avec leur zone de confiance |
| 3. Diagramme de flux de données | Diagramme Mermaid avec 3 frontières de confiance : Internet, Azure, GitHub |
| 4. Flux de données | 14 flux (F1 à F14) avec la protection prévue pour chacun |
| 5. Menaces STRIDE | 10 menaces, au format demandé |
| 6. Où en est-on aujourd'hui | Quelles menaces la pipeline détecte déjà |
| 7. À traiter dans la v2 | 6 points repoussés |

### La méthode

1. Lister les composants et les ranger par **zone de confiance**.
2. Tracer les flux entre eux. Chaque flux qui **traverse une frontière** est un point d'attaque.
3. Pour chaque flux, se poser les 6 questions STRIDE (Spoofing, Tampering, Repudiation,
   Information Disclosure, Denial of Service, Elevation of Privilege).
4. Pour chaque menace retenue : catégorie OWASP → contrôle prévu → outil de la pipeline qui la
   détecte. C'est le lien avec le reste du projet : **chaque menace a un outil en face**.

### Les 10 menaces

| ID | Menace | STRIDE | OWASP | Outil qui la détecte |
|---|---|---|---|---|
| T1 | Lire le rendez-vous d'un autre patient | Elevation of Privilege | API1:2023 BOLA | Tests xUnit (403), ZAP |
| T2 | Secret commité dans le repo public | Information Disclosure | A02:2025, A04:2025 | Gitleaks, push protection, Trivy |
| T3 | Se faire passer pour un utilisateur | Spoofing | API2:2023, A07:2025 | Tests xUnit (401), ZAP, CodeQL |
| T4 | Injection SQL | Tampering | A05:2025 | CodeQL, Semgrep, ZAP |
| T5 | Patient qui appelle un endpoint admin | Elevation of Privilege | API5:2023, API3:2023 | Tests xUnit (403), Semgrep, ZAP |
| T6 | Inonder l'API | Denial of Service | API4:2023, API6:2023 | Tests xUnit (429), Grafana, Checkov |
| T7 | Dépendance ou action GitHub compromise | Tampering | A03:2025 | Trivy, Dependabot, npm audit, CodeQL |
| T8 | Action sensible non tracée | Repudiation | A09:2025 | Alertes Prometheus + Grafana |
| T9 | Token volé sur le client | Information Disclosure | M9:2024, M5:2024 | MobSF, Semgrep, ZAP |
| T10 | Prompt injection contre l'agent IA | Tampering | LLM01, LLM05, LLM02 (2025) | Tests de l'agent, quality gate, revue humaine |

Les 6 catégories STRIDE et les 4 référentiels OWASP demandés (Top 10:2025, API, Mobile, LLM)
sont tous couverts au moins une fois.

### Choix faits

- **10 menaces, pas plus** : c'est le maximum demandé pour la v1. Les menaces écartées sont
  listées dans la section « v2 » du threat model pour ne pas les oublier.
- **Diagramme en Mermaid** plutôt qu'une image : il se modifie dans une PR comme du code et
  GitHub l'affiche directement. La version OWASP Threat Dragon est prévue pour la v2.
- **Hypothèse sur l'application** : prise de rendez-vous en clinique, rôles patient / médecin /
  admin. Si l'équipe change d'idée, seuls les exemples de T1 et T5 changent.
- **T10 concerne notre propre agent IA** : le threat model couvre aussi la pipeline, pas
  seulement l'application. Les contrôles de T10 sont exactement ceux codés dans l'agent.

---

## 4. Partie 2 : l'agent IA de sécurité

### 4.1 À quoi il sert

La pipeline lance plusieurs scanners. Sur une PR avec des problèmes, on obtient beaucoup de
résultats, en double, sans ordre de priorité. L'agent répond à trois questions :

1. **Qu'est-ce qui est en double ?** → déduplication.
2. **Qu'est-ce qui est le plus urgent ?** → Risk Score de 0 à 10.
3. **Qu'est-ce que je dois faire ?** → une recommandation par finding.

Il publie la réponse en commentaire sur la PR et dans `reports/triage.json`, que la remédiation
automatique (module d'Abdedaym) lira ensuite.

### 4.2 Le parcours d'un finding

```
 reports/*.sarif          (CodeQL, Semgrep, Trivy, Gitleaks, plus tard Checkov et ZAP)
        │
        ▼
 1. NORMALISER   sarif.py     → outil, règle, sévérité, CWE, fichier, ligne, message
        │
        ▼
 2. DÉDUPLIQUER  dedupe.py    → un seul finding par problème, avec la liste des outils
        │
        ▼
 3. MASQUER      redact.py    → les secrets sont retirés ; les findings « secret » sont mis de côté
        │
        ▼
 4. TRIAGE LLM   llm.py       → faux positif ? exploitable ? que faire ?   (optionnel)
        │
        ▼
 5. RISK SCORE   scoring.py   → Sévérité × Exposition × Confiance
        │
        ▼
 6. SORTIES      report.py    → reports/triage.json, reports/triage.md
                 github.py    → commentaire sur la Pull Request
```

`cli.py` enchaîne ces étapes dans cet ordre. C'est le meilleur fichier pour commencer à lire le
code.

### 4.3 Étape 1 : normaliser (`sarif.py`)

Chaque scanner écrit du SARIF 2.1.0, mais pas de la même façon. L'agent ramène tout à 7 champs.

| Champ | D'où il vient |
|---|---|
| Outil | `runs[].tool.driver.name` |
| Règle | `results[].ruleId` (ou `rule.id`, ou `ruleIndex`) |
| Sévérité | Voir le tableau suivant |
| CWE | Les tags de la règle : `external/cwe/cwe-089` (CodeQL), `CWE-89: ...` (Semgrep) |
| Fichier | `locations[0].physicalLocation.artifactLocation.uri`, rendu relatif au repo |
| Ligne | `locations[0].physicalLocation.region.startLine` |
| Message | `message.text`, nettoyé et masqué |

La sévérité est choisie dans cet ordre :

| Priorité | Source | Exemple |
|---|---|---|
| 1 | Le finding est un secret | toujours `critical` |
| 2 | Niveau écrit dans les tags (Trivy) | `HIGH` → `high` |
| 3 | Score CVSS `security-severity` | ≥ 9 critical · ≥ 7 high · ≥ 4 medium · > 0 low |
| 4 | Niveau SARIF | `error` → high · `warning` → medium · `note` → low |

Chaque finding reçoit aussi une **catégorie** :

| Catégorie | Quand |
|---|---|
| `secret` | Outil Gitleaks, tag `secret` (Trivy), ou CWE-798 / CWE-259 / CWE-321 (secret en dur vu par CodeQL ou Semgrep) |
| `dependency` | Tag `vulnerability` (Trivy) ou règle qui commence par `CVE-` / `GHSA-` |
| `config` | Tag `misconfiguration` (Trivy), ou outil Checkov / Hadolint |
| `code` | Tout le reste (SAST) |

Points particuliers :

- **CodeQL range ses règles dans `tool.extensions`**, pas dans `tool.driver` comme les autres.
  Cela a été constaté sur un vrai rapport de la pipeline.
- **Trivy écrit ses messages en lignes `Clé: valeur`.** L'agent en tire le paquet, la version
  installée et la **version corrigée** : c'est ce dont la remédiation v1 a besoin.
- **Le message d'un scanner de secrets n'est jamais gardé.** Il est remplacé par
  « Secret détecté (règle X) ». Seuls la règle, le fichier et la ligne sortent de l'agent.
- Les findings marqués comme supprimés dans le SARIF (`suppressions`) sont ignorés.
- Un rapport illisible ne fait pas planter l'agent : il est ignoré et signalé dans le
  commentaire.

### 4.4 Étape 2 : dédupliquer (`dedupe.py`)

Deux findings sont fusionnés quand ils ont la même **clé** :

| Catégorie | Clé | Exemple |
|---|---|---|
| Secret | fichier + ligne | Gitleaks et Trivy trouvent la même clé AWS |
| Dépendance | CVE + paquet + fichier | La même CVE signalée deux fois |
| Code, configuration | fichier + ligne + CWE | CodeQL et Semgrep sur la même injection SQL |
| Code sans CWE | fichier + ligne + outil + règle | Seulement les doublons exacts |

Le finding fusionné garde la sévérité la plus haute, la liste de tous les outils et le nombre
de signalements. Son **identifiant** est un hachage de la clé (12 caractères) : il reste le
même d'une exécution à l'autre, ce qui permet de nommer une branche `autofix/<id>`.

Sur les rapports d'exemple : **9 findings bruts → 6 après déduplication**.

### 4.5 Étape 3 : masquer les secrets (`redact.py`)

Règle du projet : ne jamais envoyer de secret à un LLM. Deux protections :

1. Les findings de catégorie `secret` ne sont **jamais envoyés**. Le code lève même une erreur
   si on essaie.
2. Tout le reste (messages, extraits de code) passe par `redact()`, qui remplace par
   `[MASQUÉ]` :

| Ce qui est masqué | Exemple |
|---|---|
| Clés privées PEM | `-----BEGIN PRIVATE KEY-----...` |
| Clés AWS | `AKIA...` |
| Tokens GitHub | `ghp_...`, `github_pat_...` |
| Clés Google / Gemini | `AIza...` |
| Tokens Slack | `xoxb-...` |
| JWT | `eyJ....eyJ....xxx` |
| En-tête `Authorization` | `Bearer ...` |
| Identifiants dans une URL | `postgres://user:motdepasse@hôte` |
| Affectations | `Password=...`, `"ApiKey": "..."`, `jwtSecret = "..."` |
| Longues chaînes aléatoires | hachés hexadécimaux, base64 à forte entropie |

Le dernier cas utilise l'**entropie de Shannon** : une chaîne de 32 caractères ou plus qui
ressemble à du hasard est masquée, alors qu'un chemin de fichier ou un nom de classe ne l'est
pas. On préfère masquer trop que pas assez.

Le masquage est aussi appliqué aux messages affichés dans le commentaire de la PR, car le repo
est public.

### 4.6 Étape 4 : triage par le LLM (`llm.py`)

**Ce qui est envoyé** pour chaque finding : identifiant, outils, règle, catégorie, sévérité,
CWE, fichier, ligne, message masqué, et pour le code les 3 lignes avant et après, masquées.

**Ce qui est demandé** au LLM, en JSON :

| Champ | Signification |
|---|---|
| `false_positive_probability` | 0 à 1 : probabilité que ce soit une fausse alerte |
| `exploitability` | 0 à 1 : facilité d'exploitation par un attaquant externe |
| `rationale` | Une phrase de justification |
| `recommendation` | Une action concrète pour corriger |

**Le modèle** : Gemini, par l'API REST `generateContent`, modèle `gemini-3.5-flash-lite` par
défaut (modifiable avec `--model` ou `AGENT_LLM_MODEL`). GitHub Models, l'autre option
envisagée, a été arrêté le 30 juillet 2026.

**Les limites** : 45 findings au maximum (les plus graves d'abord), par lots de 15, donc 3
appels au plus par exécution. Messages tronqués à 500 caractères, lignes de code à 200.

**La validation de la réponse** :

1. La réponse doit être du JSON de la forme `{"findings": [...]}`. Sinon elle est rejetée.
2. Chaque élément est validé **séparément** par `schemas/llm-response.schema.json` : bons
   types, nombres entre 0 et 1, textes de 400 caractères au plus, aucun champ en trop.
3. Un élément invalide est ignoré, les autres sont gardés.
4. Un identifiant que l'agent n'a pas envoyé est ignoré.
5. Les textes du LLM sont remis sur une ligne et repassent par `redact()`.

Rien de ce que le LLM renvoie n'est exécuté.

**Si le LLM ne répond pas** (pas de clé, erreur réseau, réponse invalide) : une seconde
tentative, puis l'agent continue avec les **sévérités brutes** et les recommandations par
défaut de `recommend.py`. Le commentaire l'indique clairement.

### 4.7 Étape 5 : le Risk Score (`scoring.py`)

**Risk Score = Sévérité × Exposition × Confiance**

| Facteur | Plage | Calcul |
|---|---|---|
| Sévérité | 0 à 10 | Score CVSS du scanner. Sinon : critical 9.5 · high 8.0 · medium 5.5 · low 2.0 · info 0.5 |
| Exposition | 0 à 1 | Emplacement du code (tableau suivant). Avec le LLM : × (0.5 + 0.5 × exploitabilité) |
| Confiance | 0 à 1 | 1 − probabilité de faux positif. Jamais sous 0.5. Jamais sous 0.8 si deux outils sont d'accord. Sans LLM : 1.0 |

| Emplacement | Exposition | Pourquoi |
|---|---|---|
| `api/` | 1.0 | Joignable depuis Internet, données des patients |
| `web/`, `mobile/` | 0.9 | S'exécute chez l'utilisateur |
| `infra/`, `.github/` | 0.9 | Configuration de la production, accès au déploiement |
| Autre | 0.7 | Valeur par défaut |
| `security/` | 0.6 | Outils internes, exécutés seulement dans la pipeline |
| Tests | 0.4 | Ne part jamais en production |
| `docs/` | 0.2 | Documentation |
| Secret (n'importe où) | 1.0 | Le repo est public : le secret est exposé |

Niveaux : 🔴 critique ≥ 9 · 🟠 élevé ≥ 7 · 🟡 moyen ≥ 4 · 🟢 faible < 4.

Exemples calculés :

| Cas | Calcul | Score |
|---|---|---|
| Secret en dur | toujours | **9.5** |
| Injection SQL dans `api/`, CVSS 8.8, sans LLM | 8.8 × 1.0 × 1.0 | **8.8** |
| La même, LLM : faux positif 10 %, exploitabilité 80 % | 8.8 × (1.0 × 0.9) × 0.9 | **7.1** |
| La même, dans `api/tests/`, sans LLM | 8.8 × 0.4 × 1.0 | **3.5** |
| XSS dans `web/`, niveau medium, sans LLM | 5.5 × 0.9 × 1.0 | **5.0** |

**Les garde-fous**, à retenir pour la soutenance :

- Le LLM peut seulement **baisser** un score, au maximum d'un facteur 4. Il ne peut pas le
  monter.
- Le LLM ne peut **supprimer** aucun finding.
- Un secret vaut **toujours 9.5** : le LLM n'intervient pas.
- La **quality gate n'utilise pas ce score**. Elle utilise les sévérités brutes des scanners.
  Tromper le LLM ne débloque donc jamais un merge.

### 4.8 Étape 6 : les sorties

**Le commentaire sur la PR** (`report.py`, `github.py`). Extrait raccourci du résultat obtenu
sur les rapports d'exemple, sans LLM :

> **6 finding(s)** après déduplication (9 bruts) · Risk Score maximum : **9.5/10** ·
> 🔴 critique : 2 · 🟠 élevé : 3 · 🟡 moyen : 1
>
> | Risk Score | Sévérité scanner | Finding | Emplacement | Outil(s) | Faux positif | Recommandation |
> |---|---|---|---|---|---|---|
> | 🔴 **9.5** | critique | **aws-access-key-id, aws-access-token** · 3 signalements fusionnés | api/appsettings.json:3 | Trivy, gitleaks | non envoyé au LLM | Révoquer ce secret tout de suite… |
> | 🟠 **8.8** | élevé | **cs/sql-injection** (CWE-89) · 2 signalements fusionnés | api/Controllers/AppointmentsController.cs:42 | CodeQL, Semgrep OSS | non évalué | Remplacer la requête concaténée par une requête paramétrée… |
> | 🟠 **7.5** | élevé | **CVE-2024-21907** | api/packages.lock.json:5 | Trivy | non évalué | Mettre à jour Newtonsoft.Json vers la version 13.0.1. |

- Le commentaire commence par un marqueur invisible. À la prochaine exécution, l'agent **met
  à jour** son commentaire au lieu d'en ajouter un.
- Il n'affiche que les 25 findings les plus prioritaires ; le reste est dans `triage.json`.
- Quand le LLM dit « faux positif » à 50 % ou plus sur une faille grave, la ligne porte la
  mention « à confirmer par un humain ».
- Le même contenu est écrit dans le résumé du job GitHub Actions.

**Tout texte affiché vient d'un scanner ou du LLM, donc peut-être d'un attaquant.** Avant
affichage, la fonction `md()` échappe le Markdown et le HTML, retire les liens et empêche les
mentions `@compte`.

**`reports/triage.json`** : la liste complète, triée du score le plus haut au plus bas. Son
format est fixé par `schemas/triage.schema.json`. C'est le **contrat avec la remédiation
automatique**. Champs utiles pour elle :

| Champ | Usage |
|---|---|
| `id` | Nom de la branche `autofix/<id>` |
| `category` | `dependency` → remédiation v1 ; `code` → remédiation v2 |
| `package.name`, `package.fixed_version` | Le paquet à mettre à jour et vers quelle version |
| `file`, `line`, `cwe`, `rules` | Où et quoi corriger |
| `risk_score` | Par quoi commencer |
| `severity` | La sévérité brute du scanner |

### 4.9 Utilisation

```bash
cd security/agent

python3 -m unittest                                              # les 79 tests
python3 -m triage --input tests/fixtures --output /tmp/triage    # essai sans LLM

export GEMINI_API_KEY=...                                        # jamais dans le repo
python3 -m triage --check-llm                                    # teste la clé et le modèle
python3 -m triage --input ../../reports --output ../../reports --source-root ../.. --comment
```

L'agent sort toujours en code 0 quand il a pu travailler, même si le LLM ou le commentaire
échouent : il conseille, il ne bloque pas. Le détail des options est dans
`security/agent/README.md`.

### 4.10 Les choix techniques et leurs raisons

| Choix | Raison |
|---|---|
| Python, bibliothèque standard uniquement | Rien à installer sur le runner, aucune dépendance à surveiller : pas de risque de chaîne d'approvisionnement ajouté par l'agent |
| Gemini | GitHub Models n'existe plus depuis le 30 juillet 2026 |
| Clé d'API dans un en-tête HTTP | Une URL finit souvent dans des logs |
| Redirections HTTP refusées | Une redirection renverrait la clé vers un autre serveur |
| Le LLM ne peut que baisser un score | Limite l'effet d'une prompt injection |
| Score séparé de la quality gate | L'IA ne peut jamais débloquer un merge |
| Validateur JSON Schema maison (72 lignes) | Évite une dépendance pour quelques mots-clés |
| Agent toujours en code 0 | Une panne du LLM ne doit pas bloquer l'équipe |
| Identifiant stable par finding | La remédiation peut retrouver le même finding d'une exécution à l'autre |
| Tests sans réseau | Un garde-fou fait échouer tout test qui tenterait un vrai appel |

### 4.11 Sécurité de l'agent lui-même

L'agent traite du contenu non fiable (le code de la PR) et parle à un service externe. Voici
les menaces prises en compte :

| Menace | Référence | Contrôle | Test |
|---|---|---|---|
| Un secret part chez le LLM | LLM02:2025 | Findings `secret` exclus + `redact()` | `test_un_secret_n_est_jamais_envoye`, `test_message_et_code_sont_masques` |
| Un texte dans la PR manipule le LLM | LLM01:2025 | Score borné, aucun finding supprimé, gate indépendante | `test_prompt_injection_reussie_score_borne_et_finding_conserve` |
| Le LLM renvoie n'importe quoi | LLM05:2025 | Validation par schéma, rien n'est exécuté | `test_evaluations_invalides_ecartees_une_par_une` |
| Le commentaire sert à injecter du HTML, un lien, une mention | LLM05:2025 | Échappement par `md()` | `test_contenu_non_fiable_neutralise` |
| L'agent a trop de droits | LLM06:2025 | Lecture des rapports + commentaire, token `pull-requests: write` seulement | (configuration du job) |
| Trop d'appels au LLM | LLM10:2025 | 45 findings, 3 appels au plus | `test_lots_et_plafond` |
| Un SARIF fait lire un fichier hors du repo (`../../`) | CWE-22 | Chemin vérifié, liens symboliques compris | `test_chemin_hors_du_repo_refuse` |
| La clé d'API fuit dans une URL ou un log | CWE-532 | En-tête, messages d'erreur courts | `test_erreurs_converties_sans_fuite_de_la_cle` |
| Un texte injecte une commande dans les logs Actions | CWE-117 | Logs sur une ligne, préfixés | `test_les_logs_ne_peuvent_pas_injecter_de_commande_actions` |
| L'agent modifie le commentaire d'un humain | n/a | Ne met à jour que le commentaire d'un bot | `test_ne_modifie_pas_le_commentaire_d_un_humain` |

---

## 5. Les tests

79 tests, lancés avec `python3 -m unittest` depuis `security/agent`. Ils durent moins d'une
seconde et ne font aucun appel réseau.

| Fichier | Tests | Ce qui est vérifié |
|---|---|---|
| `test_sarif.py` | 12 | Lecture de chaque format, sévérités, catégories, chemins, rapports cassés |
| `test_dedupe_scoring.py` | 14 | Fusions attendues, identifiants stables, formule, garde-fous du score |
| `test_redact.py` | 9 | Chaque type de secret est masqué, le code normal reste lisible |
| `test_llm.py` | 19 | Ce qui est envoyé, validation de la réponse, repli, prompt injection, appel Gemini |
| `test_report.py` | 10 | `triage.json` conforme au schéma, commentaire, échappement |
| `test_cli.py` | 15 | Exécution complète, LLM en panne, commentaire de PR, logs |

Les rapports d'exemple dans `tests/fixtures` contiennent volontairement : la même injection
SQL vue par CodeQL et Semgrep, le même secret vu par Gitleaks (2 commits) et Trivy, un secret
en dur vu par CodeQL, une CVE avec version corrigée, un Dockerfile en root, et un message
Semgrep piégé (instruction injectée, `<img>`, lien, mention).

Les faux secrets utilisés par les tests sont **fabriqués à l'exécution** par concaténation.
Écrits en un seul morceau, ils feraient échouer Gitleaks et la push protection sur notre propre
repo.

**Vérifications faites en plus des tests :**

- L'agent a été lancé sur les **vrais rapports SARIF** du dernier run de `main` (Gitleaks,
  Trivy, CodeQL) : 3 rapports lus, 0 finding, commentaire « Aucun finding ».
- Il a été lancé sur de vrais rapports Gitleaks et Trivy produits à partir d'un faux secret,
  dans un dossier temporaire hors du repo : 2 findings bruts, fusionnés en 1, score 9.5.
- Gitleaks ne trouve aucun secret dans les commits des deux branches.

---

## 6. Ce qui est demandé dans AGENTS.md et où c'est fait

| Demande | Fait ? | Où |
|---|---|---|
| Threat model STRIDE, v1 maintenant | Oui | `docs/threat-model-v1.md` |
| Chaque menace : catégorie OWASP → contrôle → outil | Oui | Section 5 du threat model |
| Référentiels Top 10:2025, API, Mobile, LLM | Oui | Tableau « Couverture » |
| Réalisé avec OWASP Threat Dragon | Non, v2 | Section 8 |
| Entrée : tous les SARIF de la pipeline | Oui | `sarif.load_reports` |
| Normaliser : outil, règle, sévérité, CWE, fichier, ligne, message | Oui | `sarif.py` |
| Dédupliquer | Oui | `dedupe.py` |
| Probabilité de faux positif, exploitabilité | Oui | `llm.py` |
| Risk Score 0–10, formule documentée (sévérité × exposition × confiance) | Oui | `scoring.py` |
| Recommandation | Oui | `llm.py`, `recommend.py` |
| Commentaire Markdown sur la PR | Oui | `report.py`, `github.py` |
| `reports/triage.json` pour la remédiation | Oui | `report.py`, `schemas/triage.schema.json` |
| Si le LLM ne répond pas, continuer avec les sévérités brutes | Oui | `llm.triage`, `cli.py` |
| Masquer les secrets | Oui | `redact.py` |
| Ne jamais envoyer un finding Gitleaks | Oui | `llm.build_item`, `llm.triage` |
| Contenu analysé traité comme non fiable | Oui | Prompt + score borné + `md()` |
| Sortie JSON validée par un schéma | Oui | `schema.py`, `llm-response.schema.json` |
| Ne jamais exécuter ce que le LLM renvoie | Oui | Aucune exécution dans le code |
| Token avec permissions minimales | À faire dans le job | Section 8 |
| LLM : GitHub Models ou Gemini | Gemini | GitHub Models n'existe plus |
| Tester un appel au LLM choisi | Non | Pas de clé : `--check-llm` est prêt |
| Commentaire trié par Risk Score, avec une recommandation chacun | Oui | `report.sort_findings` |

---

## 7. Ce qui n'a pas pu être vérifié

Ces points sont à contrôler avant de dire que le module est terminé.

| Point | Pourquoi | Comment le vérifier |
|---|---|---|
| L'appel réel à Gemini | Aucune clé disponible | `python3 -m triage --check-llm` avec `GEMINI_API_KEY` |
| Le nom du modèle `gemini-3.5-flash-lite` | Lu dans la documentation Google, pas essayé | Même commande ; sinon changer avec `--model` |
| Le rendu du diagramme Mermaid | Pas d'outil de rendu disponible au moment de l'écrire | Ouvrir `docs/threat-model-v1.md` sur GitHub |
| La publication réelle du commentaire sur une PR | Testée avec une API GitHub simulée | Ajouter le job, ouvrir une PR |
| Les formats réels des findings CodeQL, Semgrep et des vulnérabilités / configurations Trivy | Les exemples suivent le format documenté des outils | Regarder le premier vrai commentaire de l'agent |
| La version de Python du runner | Testé en Python 3.13 ; le code vise Python 3.10 et plus | Premier run du job |

Vérifié sur de vrais rapports : les findings Gitleaks, les secrets Trivy et l'emplacement des
règles CodeQL.

---

## 8. Ce qu'il reste à faire, et par qui

| # | Tâche | Qui | Bloque quoi |
|---|---|---|---|
| 1 | Ouvrir les 2 Pull Requests et les faire approuver | Abdedaym ou Mohammed + 1 relecteur | Tout le reste |
| 2 | Relire et comprendre le code de l'agent | Mohammed | La soutenance |
| 3 | Créer une clé sur Google AI Studio | Mohammed | Le triage LLM |
| 4 | Ajouter le secret `GEMINI_API_KEY` au repo | Ali (admin) | Le triage LLM |
| 5 | Ajouter le job `ai-triage` dans `security.yml` (prêt dans `security/agent/README.md`) | Ali cette semaine, puis Hajar | L'agent ne tourne pas sur les PR |
| 6 | Ajouter `python` aux langages CodeQL | Hajar | Le scan du code de l'agent |
| 7 | Corriger `AGENTS.md` : GitHub Models n'existe plus | Ali | Rien, mais évite une confusion |
| 8 | Confirmer l'idée de l'application | Toute l'équipe | Les exemples T1 et T5 |
| 9 | Brancher la remédiation sur `triage.json` | Abdedaym | La remédiation automatique |
| 10 | Refaire le diagramme dans OWASP Threat Dragon, export PNG | Mohammed | Le threat model v2 |
| 11 | Threat model v2 (6 points listés dans la v1) | Mohammed + équipe | Le rapport |
| 12 | Ajuster les poids d'exposition sur de vrais findings | Mohammed | La qualité du score |

**Rappel du planning :** le fichier de contexte de la semaine dit de ne pas présenter l'agent
IA avant mercredi. Seule la PR du threat model est attendue pour le 14 octobre. La PR de
l'agent peut être relue ensuite.

---

## 9. Questions probables à la soutenance

**Pourquoi un agent IA en plus des scanners ?**
Les scanners trouvent, mais ne trient pas. L'agent retire les doublons, classe par risque et
dit quoi faire. Sur les rapports d'exemple : 9 findings bruts deviennent 6, classés.

**Comment est calculé le Risk Score ?**
Sévérité × Exposition × Confiance. La sévérité vient du scanner (CVSS), l'exposition de
l'emplacement du code et de l'exploitabilité, la confiance de la probabilité de faux positif.

**Et si le LLM se trompe ou se fait manipuler ?**
Trois protections. Il ne peut que baisser un score, au plus d'un facteur 4. Il ne peut
supprimer aucun finding. Et la quality gate ne regarde pas son avis : elle utilise les
sévérités brutes. Une prompt injection réussie change l'ordre d'un commentaire, rien d'autre.

**Est-ce que vous envoyez des secrets au LLM ?**
Non. Les findings de type secret ne sont jamais envoyés, et tout le reste passe par un
masquage. C'est testé automatiquement.

**Et si le LLM est en panne ?**
L'agent continue avec les sévérités brutes et des recommandations par défaut. La pipeline
n'est jamais bloquée par le LLM.

**Pourquoi Gemini ?**
Les deux options étaient GitHub Models et Gemini. GitHub Models a été arrêté le 30 juillet
2026.

**Pourquoi aucune bibliothèque externe ?**
Un outil de sécurité avec des dépendances ajoute lui-même un risque de chaîne
d'approvisionnement. La bibliothèque standard de Python suffit ici.

**Comment savez-vous que ça marche ?**
79 tests automatiques, dont des cas d'attaque, plus une exécution sur les vrais rapports de la
pipeline.

**Quel est le lien avec le threat model ?**
La menace T10 du threat model est la prompt injection contre l'agent. Les contrôles écrits
dans le threat model sont ceux qui sont codés et testés dans l'agent.

---

## 10. Preuves à garder pour le rapport

- Capture du threat model affiché sur GitHub (tableau des menaces + diagramme).
- Capture des 79 tests qui passent.
- Capture du premier commentaire de l'agent sur une vraie PR, **avec** et **sans** LLM.
- Capture d'une PR avec un texte de prompt injection : le finding reste affiché, la quality
  gate reste rouge.
- Le fichier `reports/triage.json` d'une exécution (artefact du job).
- Le temps d'exécution du job de l'agent, pour la section « impact performance ».
