# Module « Auto-remediation + tests de sécurité » : tout ce qui a été fait

Ce document explique en détail le travail réalisé pour le module d'**Abdedaym CHAKRA** : la
**démo de détection**, la **remédiation automatique**, et ce qui reste bloqué (tests de
sécurité, branche `vulnerable-demo`). Il sert à comprendre le code, à le présenter, et à
savoir ce qu'il reste à faire.

> État au 13 octobre 2026.

## Sommaire

1. [Résumé](#1-résumé)
2. [Où se trouve le travail](#2-où-se-trouve-le-travail)
3. [Partie 1 : la démo de détection](#3-partie-1--la-démo-de-détection)
4. [Partie 2 : la remédiation automatique](#4-partie-2--la-remédiation-automatique)
5. [Partie 3 : les tests de sécurité (bloqué)](#5-partie-3--les-tests-de-sécurité-bloqué)
6. [Partie 4 : la branche vulnerable-demo (bloqué)](#6-partie-4--la-branche-vulnerable-demo-bloqué)
7. [Les tests de la remédiation](#7-les-tests-de-la-remédiation)
8. [Ce qui est demandé et où c'est fait](#8-ce-qui-est-demandé-et-où-cest-fait)
9. [Ce qui n'a pas pu être vérifié](#9-ce-qui-na-pas-pu-être-vérifié)
10. [Ce qu'il reste à faire, et par qui](#10-ce-quil-reste-à-faire-et-par-qui)
11. [Questions probables à la soutenance](#11-questions-probables-à-la-soutenance)
12. [Preuves à garder pour le rapport](#12-preuves-à-garder-pour-le-rapport)

---

## 1. Résumé

| Livrable | État | Où |
|---|---|---|
| Démo de détection : répétition complète sur GitHub | **Fait** : bloqué → rouge → vert | [PR #5](https://github.com/securestack-team/clinic-booking/pull/5) (fermée sans merge) |
| Guide et script pour la démo en direct | Fait, script testé sur un dépôt local | `docs/demo/` |
| Captures d'écran | **À faire à la main** | `docs/captures/README.md` donne la liste |
| Remédiation v1 : mise à jour d'un paquet vulnérable (NuGet, npm) | Fait, testé | `security/remediation/` |
| Branche `autofix/<id>` → commit → PR avec le label `ai-autofix` | Fait ; Git testé pour de vrai, API GitHub simulée | `cli.py`, `gitops.py`, `github.py` |
| Garde-fous (pas de merge, max de PR, dossiers interdits…) | Fait, chacun a son test | `guardrails.py` |
| Remédiation v2 : patch de code proposé par un LLM, contrôlé puis compilé | Fait, testé avec un LLM simulé | `codefix.py`, `llm.py` |
| Job dans la pipeline | **Pas fait** (module CI/CD) | Job prêt dans `security/remediation/README.md` |
| Tests de sécurité xUnit (403, 401, 429, 400) | **Bloqué** : pas encore d'API | Section 5 |
| Branche `vulnerable-demo` | **Bloqué** : prévue en semaine 7 | Section 6 |

En chiffres : 14 fichiers Python pour la remédiation (environ 1 700 lignes), 65 tests
automatiques, 3 runs de pipeline pour la répétition de la démo, 4 Pull Requests ouvertes.

## 2. Où se trouve le travail

| Branche | Pull Request | Contenu |
|---|---|---|
| `docs/demo-detection` | [#8](https://github.com/securestack-team/clinic-booking/pull/8) | Guide de la démo, script, captures |
| `feature/auto-remediation` | [#9](https://github.com/securestack-team/clinic-booking/pull/9) | Remédiation v1 (paquets vulnérables) |
| `feature/auto-remediation-v2` | [#10](https://github.com/securestack-team/clinic-booking/pull/10), empilée sur #9 | Remédiation v2 (patch LLM) + ce document à jour |

Les Pull Requests sont ouvertes et leur pipeline est verte. Il leur manque **une approbation**
chacune. Ordre de merge : #9 avant #10. La branche `demo/faille` de la répétition a été
supprimée après usage.

Aucun fichier d'un autre module n'a été modifié : ni `.github/workflows`, ni `/api`, ni
`/infra`, ni `security/agent`.

```
docs/
  demo/README.md                guide de la démo en direct + résultat de la répétition
  demo/faille.sh                script qui rejoue chaque étape de la démo
  captures/README.md            liste des captures d'écran à faire
  README-module-abdedaym.md     ce document
security/remediation/
  README.md                     mode d'emploi court
  remediation/
    cli.py                      ligne de commande, enchaîne les étapes
    triage_input.py             lit triage.json, choisit les findings à corriger
    versions.py                 compare les versions, choisit la version corrigée
    fixers.py                   v1 : planifie, applique et vérifie une mise à jour de paquet
    codefix.py                  v2 : prépare l'extrait, contrôle et applique le patch du LLM
    llm.py                      v2 : demande du patch à Gemini
    redact.py                   v2 : masque les secrets avant l'envoi au LLM
    guardrails.py               toutes les règles de sécurité
    gitops.py                   branche, commit, push (dans un worktree)
    github.py                   PR, label, commentaire
    report.py                   texte de la PR, synthèse, rapport JSON
    net.py                      petit client HTTP
  tests/                        65 tests
```

---

## 3. Partie 1 : la démo de détection

C'est la tâche de la semaine : montrer mercredi qu'une faille poussée dans une PR est bloquée
par la pipeline.

### Ce qui a été fait

Une répétition complète sur le vrai repo, avec une **fausse clé au format AWS** dans
`api/appsettings.json`. La clé a été fabriquée pour l'occasion : elle ne donne accès à rien.

| # | Action | Résultat | Preuve |
|---|---|---|---|
| 1 | Push d'une fausse **paire** de clés (identifiant + clé secrète) | **Refusé** par la push protection de GitHub | Sortie du terminal dans `docs/demo/README.md` |
| 2 | Push de l'identifiant seul + ouverture de la PR #5 | Pipeline **rouge** en 52 s : `Gitleaks (secrets)` et `Trivy (dependencies & config)` en échec | [run 38322342740](https://github.com/securestack-team/clinic-booking/actions/runs/38322342740) |
| 3 | Onglet Security | 2 alertes : Gitleaks `aws-access-token`, Trivy `aws-access-key-id` (critique), `api/appsettings.json` ligne 4 | [alerte 1](https://github.com/securestack-team/clinic-booking/security/code-scanning/1), [alerte 2](https://github.com/securestack-team/clinic-booking/security/code-scanning/2) |
| 4 | Clé retirée dans un nouveau commit | Trivy vert, **Gitleaks encore rouge** | [run 38322821765](https://github.com/securestack-team/clinic-booking/actions/runs/38322821765) |
| 5 | Historique de la branche réécrit | Pipeline **verte** en 59 s | [run 38322924524](https://github.com/securestack-team/clinic-booking/actions/runs/38322924524) |
| 6 | Nettoyage | PR fermée sans merge, branche supprimée, alertes passées à « fixed » | PR #5 |

### Ce que la répétition a appris

1. **La push protection bloque la paire, pas l'identifiant seul.** D'où une démo en deux
   temps : la paire pour montrer le push refusé, l'identifiant seul pour atteindre la pipeline.
2. **Supprimer un secret dans un nouveau commit ne suffit pas.** Gitleaks lit tout
   l'historique. La vraie correction : révoquer le secret, puis le retirer de l'historique.
   C'est un bon message pour la présentation.
3. **Gitleaks scanne toutes les branches du repo.** Le job a scanné 6 commits alors que la PR
   n'en contenait qu'un : il lit aussi les autres branches. Conséquence : tant qu'une branche
   contient un secret, **les PR de tous les membres passent au rouge**. À signaler à Hajar
   (voir section 10) et à retenir pour mercredi : nettoyer la branche de démo tout de suite.
4. **Deux outils voient le même secret** (Gitleaks et Trivy). C'est exactement le cas que
   l'agent IA déduplique.

### Pour la démo en direct

Tout est dans `docs/demo/README.md` : la liste de vérification, les 5 commandes, ce qu'on voit
et ce qu'on dit à chaque étape, et le plan B.

```bash
cp docs/demo/faille.sh /tmp/faille.sh   # le script change de branche : on le lance hors du repo
/tmp/faille.sh bloque        # push refusé par la push protection
/tmp/faille.sh rouge         # PR ouverte, pipeline rouge
/tmp/faille.sh suppression   # facultatif : Gitleaks reste rouge
/tmp/faille.sh vert          # pipeline verte
/tmp/faille.sh nettoyer      # ferme la PR, supprime la branche
```

Le script a été testé étape par étape sur un dépôt Git local. Sur GitHub, les mêmes opérations
ont été faites à la main pendant la répétition.

### Points d'attention

- La branche s'appelle `demo/faille` parce que le contexte de la semaine le demande. Ce
  préfixe n'est pas dans la liste habituelle (`feature/`, `fix/`, `ci/`, `infra/`, `docs/`).
- L'étape « vert » utilise `git push --force` sur la branche de démo. La règle « pas de
  force-push » protège `main` ; sur une branche de travail, c'est la seule façon de retirer un
  secret de l'historique.
- La variante « injection SQL avec `FromSqlRaw` » n'a pas pu être testée : il n'y a pas encore
  de code C# dans `/api`.

---

## 4. Partie 2 : la remédiation automatique

### 4.1 À quoi elle sert

L'agent IA dit quoi corriger et dans quel ordre. La remédiation va un pas plus loin : pour les
cas simples, elle **prépare le correctif** et ouvre une Pull Request. Un humain n'a plus qu'à
relire et approuver.

Règle absolue : **elle ne merge jamais**.

### 4.2 Le parcours d'un correctif

```
 reports/triage.json            (produit par l'agent IA)
        │
        ▼
 1. CHOISIR      triage_input.py  → paquets vulnérables NuGet / npm ; le reste est écarté avec une raison
        │
        ▼
 2. PLANIFIER    fixers.py        → quel fichier changer ? quelle commande lancer ? (rien n'est écrit)
        │
        ▼
 3. APPLIQUER    fixers.py        → dans une copie de travail séparée : modifier, régénérer le lockfile
        │
        ▼
 4. CONTRÔLER    guardrails.py    → les fichiers RÉELLEMENT modifiés sont-ils tous autorisés ?
        │
        ▼
 5. VÉRIFIER     fixers.py        → la version vulnérable a-t-elle disparu du fichier signalé ?
        │
        ├── non ──► pas de PR, un commentaire qui explique pourquoi
        ▼
 6. PUBLIER      gitops.py        → branche autofix/<id>, commit, push
                 github.py        → Pull Request + label ai-autofix
        │
        ▼
 La pipeline se relance sur la PR du bot. Un humain relit et approuve.
```

`cli.py` enchaîne ces étapes : c'est le meilleur fichier pour commencer à lire le code.

### 4.3 Étape 1 : choisir (`triage_input.py`)

L'entrée est `reports/triage.json`. Pour chaque finding :

| Finding | Décision |
|---|---|
| Catégorie `dependency`, fichier `packages.lock.json`, `Directory.Packages.props` ou `package-lock.json` | **Candidat** |
| Injection SQL, autorisation manquante ou secret en dur, dans un fichier `.cs` de `api/` | **Candidat pour la v2** (si la clé du LLM existe), voir 4.9 |
| Secret trouvé par Gitleaks ou Trivy | Écarté : « un secret ne se corrige pas par une PR, il faut le révoquer » |
| Autre finding de code, ou de configuration | Écarté : cas non géré |
| Autre type de fichier (`requirements.txt`, `go.mod`…) | Écarté : non géré en v1 |
| Pas de version corrigée | Écarté : rien à proposer |
| Fichier dans `.github/` ou `infra/` | Écarté : dossier interdit |
| Identifiant, chemin, nom de paquet ou version suspects | Écarté : entrée refusée |

Deux règles en plus :

- **Plusieurs CVE sur le même paquet = un seul correctif**, vers la version qui les corrige
  toutes. Sinon deux PR modifieraient la même ligne.
- Les candidats sont traités **du Risk Score le plus haut au plus bas**. Avec la limite de PR,
  ce sont donc les plus urgents qui passent.

Le choix de la version (`versions.py`) : Trivy donne parfois plusieurs versions corrigées
(« 2.3.1, 3.0.1 »). On prend la plus petite qui dépasse la version installée, de préférence
dans la **même version majeure**, et jamais une préversion. Si la version majeure change, la
PR porte un avertissement.

### 4.4 Étapes 2 et 3 : planifier puis appliquer (`fixers.py`)

| Cas | Ce qui est modifié | Commande lancée ensuite |
|---|---|---|
| NuGet, paquet dans le `.csproj` | `Version="..."` de la ligne `PackageReference` | `dotnet restore --force-evaluate` |
| NuGet, versions centralisées | `Version="..."` dans `Directory.Packages.props` | `dotnet restore --force-evaluate` |
| npm, paquet dans `package.json` | rien à la main | `npm install paquet@version --package-lock-only --ignore-scripts` |

Détails importants :

- Le `.csproj` est modifié par **remplacement ciblé** : seule la valeur de `Version` de la
  bonne ligne change, le reste du fichier garde sa mise en forme.
- **Le lockfile est régénéré par l'outil officiel**, jamais édité à la main : il contient des
  empreintes (hachés) que seul l'outil sait calculer. Sans cela, Trivy verrait encore
  l'ancienne version et la PR du bot resterait rouge.
- `--package-lock-only` : npm ne télécharge et n'installe rien. `--ignore-scripts` : aucun
  script d'installation d'un paquet ne s'exécute dans la pipeline.
- Si le projet épingle une version exacte (`"4.17.20"` sans `^`), ce style est conservé.
- `dotnet` et `npm` sont lancés **sans les tokens** de l'environnement : un fichier de projet
  venu d'une PR peut faire exécuter du code pendant une restauration.

Cas où la remédiation **refuse** de proposer un correctif (`CannotFix`) :

| Cas | Raison affichée |
|---|---|
| Le paquet n'est pas référencé directement | Dépendance transitive : mettre à jour le paquet parent |
| La version est une plage ou une variable MSBuild | Trop risqué à modifier automatiquement |
| `dotnet` ou `npm` absent ou en échec | L'outil n'a pas pu régénérer le lockfile |
| Le fichier pointe hors du repo (lien symbolique) | Chemin refusé |

### 4.5 Étapes 4 et 5 : contrôler et vérifier

C'est ce qui répond à la demande « commenter au lieu de proposer un patch non validé ».

1. **Contrôle des fichiers.** Après le correctif, `git status` donne la liste des fichiers
   réellement modifiés. Si un seul n'est pas un fichier de dépendances autorisé, ou se trouve
   dans `.github/` ou `infra/`, tout est abandonné. On contrôle le résultat réel, pas ce qui
   était prévu : un outil peut toucher un fichier inattendu.
2. **Vérification du correctif.** Le fichier signalé par le scanner est relu. Toutes les
   occurrences du paquet doivent être à la version corrigée ou au-dessus. Sinon : pas de PR.

Dans les deux cas d'échec, rien n'est poussé et la raison apparaît dans le commentaire de
synthèse.

### 4.6 Étape 6 : publier (`gitops.py`, `github.py`)

- Chaque correctif est préparé dans un **worktree Git** : une copie de travail temporaire. Le
  dossier courant n'est jamais modifié, même si le correctif échoue à mi-chemin.
- Branche : `autofix/<id>`, où `<id>` est l'identifiant stable du finding dans le triage.
- Commit : `fix: bump <paquet> from <a> to <b>` (Conventional Commits), auteur
  `github-actions[bot]`.
- Push **sans** `--force` : si la branche existe déjà, rien n'est écrasé.
- Pull Request vers la branche analysée, avec le label `ai-autofix`. Son texte contient la
  CVE, le Risk Score, le fichier signalé et une liste de vérifications pour le relecteur.
- Un **commentaire de synthèse** sur la PR d'origine, mis à jour à chaque exécution. Exemple :

> | Résultat | Correctif | Vulnérabilité(s) | Détail |
> |---|---|---|---|
> | ✅ PR ouverte | `Newtonsoft.Json` 12.0.1 → 13.0.1 | CVE-2024-21907 | #12 (branche `autofix/a90dea08ce76`) ⚠️ version majeure |
> | ✅ PR ouverte | Patch LLM : use a parameterized query, `api/Controllers/AppointmentsController.cs`, ligne 17 | CWE-89 | #13 (branche `autofix/c0de00000001`) |
> | 💬 Pas de correctif sûr | Patch LLM : add missing authorization, `api/Controllers/AppointmentsController.cs`, ligne 22 | CWE-862 | le projet ne compile pas avec le patch (dotnet build, code 1, CS0246) |
> | ⏭️ Ignoré | `lodash` 4.17.20 → 4.17.21 | CVE-2021-23337 | limite de 3 PR par exécution atteinte |

Le résultat complet est aussi écrit dans `reports/remediation.json`.

### 4.7 Les garde-fous

| Garde-fou | Comment | Test |
|---|---|---|
| Jamais de merge automatique | Aucune fonction de merge ou d'approbation n'existe dans le code | `test_jamais_de_merge_ni_d_approbation` |
| Nombre maximum de PR | 3 par exécution, 10 au plus | `test_nombre_maximum_de_pr` |
| Ne jamais modifier `.github/workflows` ni `/infra` | Refus à l'entrée et contrôle des fichiers modifiés | `test_l_outil_modifie_un_fichier_interdit` |
| Commenter au lieu d'un patch non validé | Vérification après correctif | `test_correctif_non_valide_pas_de_pr_mais_un_commentaire` |
| Pas de doublon | Rien si une PR est déjà ouverte ou si la branche existe | `test_pas_de_doublon`, `test_branche_de_correctif_deja_presente` |
| Respect d'un refus humain | Rien si la PR de ce correctif a été fermée sans merge | `test_pas_de_doublon` |
| Pas de boucle | Ne tourne pas sur une branche `autofix/` | `test_ne_se_corrige_pas_elle_meme` |
| Entrée non fiable | Identifiant, chemin, paquet, version validés par expression régulière | `test_valeurs_dangereuses_ecartees`, `test_entree_malveillante_aucune_commande` |
| Pas de fuite de token vers les outils | Environnement nettoyé avant `dotnet` / `npm` | `test_l_outil_ne_voit_pas_les_secrets_de_l_environnement` |
| Pas de fichier hors du repo | Chemins résolus, liens symboliques compris | `test_lien_symbolique_hors_du_repo_refuse` |
| Pas de branche orpheline | Si la PR ne peut pas être créée, la branche est retirée | `test_pr_non_creee_la_branche_est_retiree` |
| Rien sans le demander | Simulation par défaut, `--apply` obligatoire | `test_simulation_par_defaut_ne_cree_rien` |

Pourquoi « entrée non fiable » ? `triage.json` est construit à partir des rapports de scan,
donc à partir du code de la PR. Un attaquant pourrait écrire dans un lockfile un nom de paquet
comme `lodash --registry=http://serveur-pirate`. Sans validation, ce texte finirait dans une
commande `npm`. Ici il est refusé avant, et les commandes sont de toute façon lancées sans
shell.

### 4.8 Les choix techniques et leurs raisons

| Choix | Raison |
|---|---|
| Python, bibliothèque standard uniquement | Comme l'agent IA : rien à installer, aucune dépendance à surveiller |
| Lockfile régénéré par `dotnet` / `npm` | Seule façon d'obtenir un lockfile valide, donc une pipeline verte sur la PR du bot |
| Worktree Git temporaire | Le dossier de travail reste intact ; pas de nettoyage dangereux |
| Simulation par défaut | Un outil qui pousse des branches ne doit rien faire par accident |
| Vérifier les fichiers réellement modifiés | On ne fait pas confiance à l'outil lancé |
| Un seul correctif par paquet | Évite deux PR en conflit |
| Pas de `--force` au push | Ne jamais écraser le travail de quelqu'un |
| La remédiation valide elle-même son entrée | Elle ne dépend pas du code de l'agent, seulement du format de `triage.json` |

### 4.9 La v2 : un patch de code proposé par un LLM

La v1 est déterministe : elle change un numéro de version. La v2 traite trois cas où il faut
modifier du **code C#** dans `api/` :

| Cas | CWE | Correction demandée au LLM |
|---|---|---|
| Injection SQL | CWE-89 | Remplacer la requête concaténée par une requête paramétrée |
| Autorisation manquante | CWE-862, CWE-285, CWE-306 | Ajouter `[Authorize]` sur l'endpoint |
| Secret en dur | CWE-798, CWE-259, CWE-321 | Lire la valeur depuis la configuration |

Elle ne s'active que si la clé `GEMINI_API_KEY` existe. Sinon, seule la v1 tourne.

**Ce qui est envoyé au LLM** (`codefix.build_prompt`) : le nom du fichier, la CWE, la ligne, la
correction demandée, les `using` du fichier, et 12 lignes avant et après la ligne signalée,
numérotées. Tout passe par le masquage des secrets. Pour un secret en dur, **toutes les chaînes
de caractères de l'extrait sont effacées** : la valeur ne quitte jamais la pipeline.

**Ce que le LLM renvoie** : un seul remplacement de lignes, en JSON
(`start_line`, `end_line`, `replacement`, `explanation`).

**Le principe : le LLM propose, la remédiation contrôle.** Un patch ne devient une PR que s'il
passe les quatre contrôles. Sinon : pas de PR, un commentaire avec la raison.

| # | Contrôle | Ce qui est refusé |
|---|---|---|
| 1 | Forme | Réponse qui n'est pas le JSON attendu ; patch hors de l'extrait, qui ne couvre pas la ligne signalée, ou de plus de 12 lignes |
| 2 | Contenu | `[MASQUÉ]` recopié, valeur qui ressemble à un secret, patch qui ne change rien. Puis un contrôle par cas : SQL encore concaténé, `[Authorize]` absent ou `[AllowAnonymous]` ajouté, valeur en dur gardée |
| 3 | Périmètre | Tout fichier modifié autre que celui du finding |
| 4 | Compilation | `dotnet build` en échec sur le projet |

La PR ouverte porte un avertissement visible : « ce patch a été écrit par un LLM, à relire
ligne par ligne ». Pour un secret en dur, elle rappelle que le secret reste dans l'historique
et doit être révoqué.

**Limites à connaître :**

- Les contrôles réduisent le risque, ils ne prouvent pas que le patch est bon. Un LLM
  manipulé par un commentaire dans le code pourrait proposer un patch qui compile mais fait
  autre chose. D'où la pipeline complète et la relecture humaine, toujours obligatoires.
- Le patch ne peut pas ajouter de `using` en haut du fichier. Le LLM doit écrire le nom
  complet d'un type absent (`[Microsoft.AspNetCore.Authorization.Authorize]`), sinon le patch
  ne compile pas et il n'y a pas de PR. Ce cas a été rencontré pendant les essais.
- Les correctifs v1 passent avant les patchs v2, et la limite de PR par exécution est commune.

### 4.10 Lien avec l'agent IA

La remédiation utilise ces champs de `triage.json` :

| Champ | Usage |
|---|---|
| `id` | Nom de la branche `autofix/<id>` |
| `category` | `dependency` → v1 ; `code` et `secret` avec une CWE gérée → v2 |
| `file` | Fichier de dépendances signalé |
| `package.name`, `installed_version`, `fixed_version`, `advisory` | Quoi mettre à jour, vers quoi, pour quelle CVE |
| `line`, `cwe` | v2 : où se trouve la faille et de quel type elle est |
| `risk_score` | Ordre de traitement |
| `rules`, `recommendation` | Texte du commentaire pour les findings non corrigés |

L'agent est sur la branche `feature/ai-security-agent`, pas encore mergée. Les deux modules ne
partagent aucun code : seul le format du fichier les relie.

---

## 5. Partie 3 : les tests de sécurité (bloqué)

**Pas faits**, et impossibles à faire pour l'instant : ils testent des endpoints de l'API, et
`/api` est encore vide. Ils se font avec Freddy, une fois l'authentification et les premiers
endpoints en place (phase 2).

Voici le plan, pour démarrer vite le moment venu. Les routes sont des exemples : elles
dépendront de l'API de Freddy.

| Test | Requête | Résultat attendu | Menace du threat model |
|---|---|---|---|
| Ressource d'un autre utilisateur | Patient A lit le rendez-vous du patient B | **403** | T1 (BOLA) |
| Endpoint réservé | Un patient appelle un endpoint admin | **403** | T5 |
| Sans token | Requête sans en-tête `Authorization` | **401** | T3 |
| Token expiré | JWT dont la date d'expiration est passée | **401** | T3 |
| Token falsifié | JWT signé avec une autre clé | **401** | T3 |
| Trop de requêtes | Dépasser la limite sur le login | **429** | T6 |
| Entrée invalide | Date de rendez-vous absente ou mal formée | **400** | T4 |
| Champ en trop | Envoyer `role: admin` à l'inscription | Rôle ignoré | T5 |

Outils : xUnit + `WebApplicationFactory`, dans `/api/tests`. Ces tests tourneront dans
`ci.yml` avec les autres : un test de sécurité qui échoue bloque le merge.

Ce dont il faut convenir avec Freddy : comment créer deux utilisateurs de test et obtenir
leurs tokens, la base utilisée pendant les tests, et la limite de requêtes configurée.

## 6. Partie 4 : la branche `vulnerable-demo` (bloqué)

Prévue en semaine 7, avec Freddy. Elle a besoin de l'application, de l'agent et de la
remédiation dans la pipeline. Rien n'a été fait.

| Faille volontaire | Outil qui doit la détecter | Correctif attendu |
|---|---|---|
| Secret en dur | Gitleaks, Trivy, push protection | Révocation (pas de PR automatique) |
| `FromSqlRaw` concaténé | CodeQL, Semgrep | **Remédiation v2 : prête, à essayer avec le vrai LLM** |
| Paquet vulnérable | Trivy | **Remédiation v1 : déjà prête** |
| Endpoint BOLA | Tests xUnit, ZAP | Correction à la main |
| Token mobile dans AsyncStorage | MobSF, Semgrep | Correction à la main |

La démo de détection de cette semaine est la première ligne de ce tableau, déjà répétée.

---

## 7. Les tests de la remédiation

65 tests, lancés avec `python3 -m unittest` depuis `security/remediation`. Ils durent environ
5 secondes et ne font aucun appel réseau.

| Fichier | Tests | Ce qui est vérifié |
|---|---|---|
| `test_units.py` | 28 | Versions, garde-fous, choix des findings, planification, application, vérification |
| `test_cli.py` | 18 | Exécution complète de la v1 : simulation, PR NuGet, PR npm, chaque garde-fou, entrées invalides |
| `test_codefix.py` | 19 | v2 : choix des findings, extrait envoyé et secrets masqués, 15 patchs piégés refusés, compilation en échec, PR ouverte |

Comment ils fonctionnent :

- **Git est réel.** Chaque test crée un vrai dépôt temporaire avec un vrai remote local, puis
  vérifie ce qui a été poussé : la branche, le commit, la liste exacte des fichiers modifiés.
- **`dotnet` et `npm` sont simulés** par un faux outil qui fait ce que ferait le vrai sur le
  lockfile. On peut ainsi le faire échouer ou tricher exprès (modifier un workflow).
- **L'API GitHub est simulée** : les appels sont enregistrés et vérifiés.
- **Le LLM est simulé** : on lui fait répondre de bons patchs, des patchs piégés, du texte
  libre ou une panne.

**Vérifications faites en plus :**

- Avec le **vrai `npm`** : `lodash` 4.17.20 → 4.17.21, `package.json` et `package-lock.json`
  mis à jour, branche poussée, rien d'autre modifié.
- Avec le **vrai `dotnet`** (SDK 8, projet `net8.0`) : `Newtonsoft.Json` 12.0.1 → 13.0.1,
  `.csproj` et `packages.lock.json` mis à jour, avec la nouvelle empreinte.
- Avec le **vrai `dotnet build`** (v2, projet ASP.NET temporaire) : un patch `[Authorize]` sans
  le bon espace de noms ne compile pas (erreur CS0246) et ne donne **pas** de PR ; le même
  patch avec le nom complet de l'attribut compile et donne une PR d'une seule ligne.
- **Les tests détectent bien un garde-fou retiré** : onze contrôles ont été désactivés
  temporairement, un par un (pour la v1 : contrôle des fichiers modifiés, vérification du
  correctif, anti-boucle, limite de PR, validation du nom de paquet, respect d'une PR fermée ;
  pour la v2 : contrôle du patch, compilation, contrôle du fichier modifié, effacement des
  chaînes, masquage de l'extrait). À chaque fois, au moins un test a échoué.
- Gitleaks et Trivy ne trouvent aucun secret dans les fichiers des deux branches.

---

## 8. Ce qui est demandé et où c'est fait

### Contexte de la semaine (démo de détection)

| Demande | Fait ? | Où |
|---|---|---|
| Branche `demo/faille` avec un faux secret de test | Oui | Répétition, PR #5 |
| Requête `FromSqlRaw` concaténée | Non | Pas de code C# dans `/api` |
| Ouvrir la PR, vérifier la pipeline rouge et l'alerte Security | Oui | Runs et alertes de la section 3 |
| Capturer le blocage par la push protection | Sortie du terminal gardée ; capture d'écran à faire | `docs/demo/README.md` |
| Corriger dans la même PR → pipeline verte | Oui | Run 38322924524 |
| Captures d'écran de chaque étape | **Non** | Liste dans `docs/captures/README.md` |

### AGENTS.md (remédiation)

| Demande | Fait ? | Où |
|---|---|---|
| Entrée : `reports/triage.json` | Oui | `triage_input.py` |
| v1 : mise à jour d'un paquet vulnérable vers la version corrigée | Oui (NuGet, npm) | `fixers.py`, `versions.py` |
| v2 : patch LLM pour des findings simples (SQL concaténé, `[Authorize]` manquant, secret en dur) | Oui, avec un LLM simulé | `codefix.py`, `llm.py` |
| Branche `autofix/<id>` → commit → PR via l'API GitHub | Oui | `gitops.py`, `github.py` |
| Label `ai-autofix` | Oui, créé s'il n'existe pas | `github.add_label` |
| La pipeline se relance | Dépend du token | Section 9 |
| Jamais de merge automatique | Oui | `github.py` n'a pas de fonction de merge |
| Nombre maximum de PR par exécution | Oui | `--max-prs`, `guardrails.py` |
| Ne jamais modifier `.github/workflows` ni `/infra` | Oui | `guardrails.py` |
| Commenter au lieu de proposer un patch non validé | Oui | `fixers.verify`, synthèse |
| Tests de sécurité xUnit (403, 401, 429, 400) | Non, bloqué | Section 5 |
| Branche `vulnerable-demo` | Non, semaine 7 | Section 6 |

---

## 9. Ce qui n'a pas pu être vérifié

| Point | Pourquoi | Comment le vérifier |
|---|---|---|
| La création réelle d'une PR par la remédiation | L'API GitHub est simulée dans les tests ; le job n'existe pas | Ajouter le job, ouvrir une PR avec un paquet vulnérable |
| Une vraie réponse de Gemini pour un patch (v2) | Pas de clé : le LLM est simulé | Créer `GEMINI_API_KEY`, lancer sur un vrai finding |
| La qualité des patchs du LLM sur le vrai code de l'API | Il n'y a pas encore d'API | Branche `vulnerable-demo`, semaine 7 |
| Le nom du modèle `gemini-3.8-flash` | Lu dans la documentation Google, pas essayé | Premier appel réel ; sinon `AUTOFIX_LLM_MODEL` |
| La relance de la pipeline sur la PR du bot | Elle dépend du token utilisé | Voir ci-dessous |
| `dotnet restore` avec .NET 10 | Vérifié avec le SDK 8 seulement | Premier run du job |
| Le format réel du message Trivy pour une vulnérabilité NuGet | L'agent s'appuie sur le format documenté | Premier vrai finding |
| La démo `FromSqlRaw` | Pas d'API | Après le squelette de Freddy |
| Le script `faille.sh` contre GitHub | Testé sur un dépôt local ; sur GitHub les étapes ont été faites à la main | Une répétition mercredi matin |
| La branche du hook pre-commit dans le script | Le hook n'était pas installé sur la machine | Installer `pre-commit` et relancer |

**Le point du token.** Une PR créée avec le `GITHUB_TOKEN` du workflow **ne déclenche pas la
pipeline** : GitHub l'empêche pour éviter les boucles. Pour respecter « la pipeline se
relance », il faut un token de GitHub App ou un PAT dans un secret `AUTOFIX_TOKEN`. Le code le
gère déjà (il le prend en priorité), mais le secret doit être créé par Ali.

---

## 10. Ce qu'il reste à faire, et par qui

| # | Tâche | Qui | Bloque quoi |
|---|---|---|---|
| 1 | Faire les captures d'écran de la démo | Abdedaym | Le plan B de mercredi, le rapport |
| 2 | Faire approuver les Pull Requests #8, #9 puis #10 | 1 relecteur de l'équipe | Tout le reste |
| 3 | Relire et comprendre le code de la remédiation | Abdedaym | La soutenance |
| 4 | Répéter la démo mercredi matin avec `faille.sh` | Abdedaym + Ali | La démo en direct |
| 5 | Merger l'agent IA (`feature/ai-security-agent`) | Mohammed | `triage.json` n'existe pas sans lui |
| 6 | Créer le token du bot et le secret `AUTOFIX_TOKEN` | Ali (propriétaire de l'organisation) | La relance de la pipeline sur les PR du bot |
| 6 bis | Créer la clé Gemini et le secret `GEMINI_API_KEY` | Mohammed + Ali | La v2 (et le triage LLM de l'agent) |
| 7 | Ajouter le job `auto-remediation` dans `security.yml` | Ali cette semaine, puis Hajar | La remédiation ne tourne pas |
| 8 | Limiter Gitleaks à l'historique de la PR (`--log-opts`) ou accepter le comportement actuel | Hajar | Une branche avec un secret met toutes les PR au rouge |
| 9 | Squelette de l'API, puis authentification et endpoints | Freddy | Tests de sécurité, démo `FromSqlRaw` |
| 10 | Écrire les tests de sécurité xUnit | Abdedaym + Freddy | Pratique Tier 1 « Automated Security Testing » |
| 11 | Essayer la v2 avec le vrai LLM sur de vraies failles, ajuster le prompt | Abdedaym | A besoin du code de l'API et de la clé Gemini |
| 12 | Branche `vulnerable-demo` | Abdedaym + Freddy | Semaine 7 |

**Ce qui manque à la v2.** Le mécanisme est écrit et testé, mais avec un LLM simulé. Tant
qu'il n'y a ni clé Gemini ni code d'API, on ne sait pas si les patchs du vrai LLM seront bons
du premier coup. Les contrôles garantissent seulement qu'un mauvais patch ne devient pas une
PR.

**Rappel du planning.** Le contexte de la semaine dit de ne pas présenter la remédiation avant
mercredi. Pour le 14 octobre, seule la PR #8 (`docs/demo-detection`) est utile.

---

## 11. Questions probables à la soutenance

**Que fait la remédiation, concrètement ?**
Elle lit le triage de l'agent IA. Pour un paquet vulnérable, elle change la version, régénère
le lockfile, vérifie que la version vulnérable a disparu, puis ouvre une PR avec le label
`ai-autofix`.

**Est-ce qu'elle peut merger toute seule ?**
Non. Le code ne contient aucune fonction de merge ni d'approbation, et un test le vérifie. La
PR repasse par toute la pipeline et attend une approbation humaine.

**Et si le correctif est mauvais ?**
Trois filets : la vérification avant le commit (sinon pas de PR, un commentaire), la pipeline
complète sur la PR du bot (build, tests, scans), et la relecture humaine.

**Qu'est-ce qui l'empêche de modifier la pipeline ou l'infrastructure ?**
Tout fichier dans `.github/` ou `infra/` est refusé, et seuls les fichiers de dépendances sont
autorisés. Le contrôle porte sur les fichiers réellement modifiés, pas sur ce qui était prévu.

**Vous laissez un LLM écrire du code dans le repo ?**
Il propose, il ne décide pas. Son patch est limité à quelques lignes d'un seul fichier, il est
contrôlé, il doit compiler, et il arrive dans une PR marquée « écrit par un LLM » qui repasse
par toute la pipeline et attend une approbation humaine. Si un contrôle échoue, il n'y a pas
de PR.

**Et si le LLM se fait manipuler par un commentaire dans le code ?**
Le risque existe et il est écrit dans le threat model (T10). Les contrôles limitent ce qu'un
patch peut faire, mais ne prouvent pas qu'il est bon : c'est pour cela qu'il n'y a jamais de
merge automatique.

**Pourquoi ne pas simplement utiliser Dependabot ?**
Les deux se complètent. Dependabot surveille `main` et propose des mises à jour au fil du
temps. La remédiation agit **sur la PR en cours**, avant le merge, et dans l'ordre du Risk
Score calculé par l'agent. Et sa v2 corrige du code, ce que Dependabot ne fait pas.

**Pourquoi un secret n'est-il pas corrigé automatiquement ?**
Parce que le retirer du code ne suffit pas, comme l'a montré la démo : il reste dans
l'historique et doit être révoqué. C'est une action humaine.

**Que se passe-t-il si quelqu'un ferme la PR du bot ?**
La remédiation ne la rouvre pas : elle respecte la décision.

**L'entrée vient du code de la PR : est-ce dangereux ?**
C'est pour cela que chaque valeur est validée avant usage et que les commandes sont lancées
sans shell. Un nom de paquet piégé est écarté avant d'atteindre `npm`.

**Qu'avez-vous appris avec la démo ?**
Que la push protection bloque la paire de clés mais pas l'identifiant seul, que supprimer un
secret ne suffit pas, et que Gitleaks scanne toutes les branches.

---

## 12. Preuves à garder pour le rapport

Déjà disponibles :

- La [PR #5](https://github.com/securestack-team/clinic-booking/pull/5) et son tableau de
  résultat.
- Les 3 runs : [rouge](https://github.com/securestack-team/clinic-booking/actions/runs/38322342740),
  [Gitleaks encore rouge](https://github.com/securestack-team/clinic-booking/actions/runs/38322821765),
  [vert](https://github.com/securestack-team/clinic-booking/actions/runs/38322924524).
- Les alertes 1 à 3 de l'onglet Security (état « fixed »).
- La sortie du terminal du push refusé.

À produire :

- Les captures d'écran listées dans `docs/captures/README.md`.
- Une capture des 65 tests qui passent.
- La première PR `autofix/...` ouverte par le bot, son diff, et la pipeline verte dessus.
- Le commentaire de synthèse de la remédiation sur une vraie PR.
- Le temps d'exécution du job, pour la section « impact performance ».
