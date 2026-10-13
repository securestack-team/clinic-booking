# Remédiation automatique

La remédiation lit `reports/triage.json` (produit par l'agent IA) et ouvre une **Pull Request de
correctif** pour ce qu'elle sait corriger :

- **v1** : un paquet vulnérable (NuGet, npm) → mise à jour vers la version corrigée ;
- **v2** : une injection SQL, un `[Authorize]` manquant ou un secret en dur dans le code C# de
  l'API → patch proposé par un LLM, contrôlé puis compilé.

```
reports/triage.json ─► choisir ─► planifier ─► appliquer ─► vérifier ─► branche autofix/<id>
                       (paquets                (dotnet /    (version               │
                        vulnérables)            npm)         vulnérable            ▼
                                                             disparue ?)    commit ─► push ─► PR
                                                                                  label ai-autofix
```

**Elle ne merge jamais.** Une PR de correctif repasse par toute la pipeline et attend une
approbation humaine.

Python 3.10+ et bibliothèque standard uniquement. Git est requis ; `dotnet` et `npm` seulement
pour les correctifs correspondants.

## Utilisation

```bash
cd security/remediation

python3 -m unittest                                           # les tests

# Simulation (par défaut) : dit ce qui serait corrigé, ne crée rien
python3 -m remediation --triage ../../reports/triage.json --repo-root ../.. --output /tmp/remediation

# Réel : crée les branches et les PR
export GITHUB_REPOSITORY=securestack-team/clinic-booking
export GITHUB_TOKEN=...            # jamais dans le repo
python3 -m remediation --triage ../../reports/triage.json --repo-root ../.. --base ma-branche --apply
```

| Option | Rôle |
|---|---|
| `--triage` | Fichier produit par l'agent IA (défaut : `reports/triage.json`) |
| `--output` | Dossier où écrire `remediation.json` et `remediation.md` (défaut : `reports`) |
| `--repo-root` | Racine du repo Git (défaut : dossier courant) |
| `--base` | Branche à corriger (défaut : la branche de la PR en cours) |
| `--max-prs` | Nombre maximum de PR par exécution (défaut : 3, plafond : 10) |
| `--apply` | Crée réellement les branches et les PR. Sans cette option : simulation |
| `--no-llm` | v1 seulement : ne demande aucun patch de code au LLM |

| Variable | Rôle |
|---|---|
| `AUTOFIX_TOKEN` | Token du bot (GitHub App ou PAT). Utilisé en priorité |
| `GITHUB_TOKEN` | Utilisé si `AUTOFIX_TOKEN` est absent |
| `GITHUB_REPOSITORY` | `organisation/repo` |
| `AUTOFIX_GIT_NAME`, `AUTOFIX_GIT_EMAIL` | Auteur des commits (défaut : `github-actions[bot]`) |
| `GEMINI_API_KEY` | Active la v2. Sans cette clé, seule la v1 tourne |
| `AUTOFIX_LLM_MODEL` | Modèle Gemini pour les patchs (défaut : `gemini-3.8-flash`) |

## Ce qui est corrigé (v1)

| Cas | Fichier signalé par le scanner | Correctif |
|---|---|---|
| NuGet, paquet référencé dans le projet | `packages.lock.json` | `Version="..."` dans le `.csproj`, puis `dotnet restore --force-evaluate` |
| NuGet, versions centralisées | `packages.lock.json` ou `Directory.Packages.props` | `Version="..."` dans le `.props` |
| npm, paquet dans `package.json` | `package-lock.json` | `npm install paquet@version --package-lock-only --ignore-scripts` |

Ce qui n'est **pas** corrigé, avec un commentaire qui explique pourquoi :

- les dépendances transitives (le paquet n'est pas référencé directement) ;
- un paquet sans version corrigée ;
- une version écrite comme une plage ou une variable MSBuild ;
- les secrets trouvés par Gitleaks ou Trivy (il faut les révoquer) et la configuration ;
- tout fichier dans `.github/` ou `infra/`.

Plusieurs CVE sur le même paquet donnent **une seule PR**, vers la version qui les corrige
toutes. Si Trivy propose plusieurs versions corrigées, on prend la plus petite, de préférence
dans la même version majeure.

## Ce qui est corrigé (v2) : patch proposé par un LLM

| Cas | CWE | Ce que le LLM doit faire |
|---|---|---|
| Injection SQL | CWE-89 | Remplacer la requête concaténée par une requête paramétrée |
| Autorisation manquante | CWE-862, CWE-285, CWE-306 | Ajouter `[Authorize]` sur l'endpoint |
| Secret en dur dans le code | CWE-798, CWE-259, CWE-321 | Lire la valeur depuis la configuration |

Seulement pour un fichier `.cs` dans `api/`, et seulement si `GEMINI_API_KEY` existe.

Le LLM reçoit 12 lignes avant et après la ligne signalée, numérotées, **secrets masqués**. Pour
un secret en dur, toutes les chaînes de caractères de l'extrait sont effacées avant l'envoi. Il
répond par un seul remplacement de lignes, en JSON.

Le LLM propose, la remédiation contrôle. Un patch ne devient une PR que s'il passe **tous** les
contrôles ; sinon, pas de PR, un commentaire avec la raison :

| Contrôle | Détail |
|---|---|
| Forme | JSON exact ; un seul remplacement, de 12 lignes au plus, qui couvre la ligne signalée |
| Contenu | Pas de `[MASQUÉ]` recopié, pas de valeur qui ressemble à un secret, un vrai changement |
| Cas par cas | SQL : plus de concaténation dans `FromSqlRaw` · autorisation : `[Authorize]` présent, pas de `[AllowAnonymous]` · secret : la valeur en dur a disparu |
| Périmètre | Un seul fichier modifié : celui du finding |
| Compilation | `dotnet build` doit réussir sur le projet |

La PR porte un avertissement : le patch a été écrit par un LLM et doit être relu ligne par
ligne. Pour un secret en dur, elle rappelle qu'il reste dans l'historique et doit être révoqué.

Ces contrôles réduisent le risque, ils ne prouvent pas que le patch est bon. Un LLM manipulé
par un commentaire dans le code pourrait proposer un patch qui compile mais fait autre chose :
c'est pour cela que la pipeline complète et la relecture humaine restent obligatoires.

Les correctifs v1 passent avant les patchs v2, et la limite de PR par exécution est commune.

## Les garde-fous

| Garde-fou | Comment |
|---|---|
| Jamais de merge | Le code ne contient aucun appel de merge ni d'approbation |
| Nombre maximum de PR | 3 par exécution par défaut, 10 au plus |
| Pas de pipeline ni d'infrastructure | Tout fichier dans `.github/` ou `infra/` est refusé |
| Fichiers de dépendances seulement | `.csproj`, `.props`, `packages.lock.json`, `package.json`, `package-lock.json` |
| Contrôle après coup | La liste des fichiers **réellement modifiés** est vérifiée avant le commit |
| Pas de patch non validé | Le fichier signalé est relu : si la version vulnérable y est encore, pas de PR, un commentaire |
| Pas de doublon | Rien si la branche ou une PR existe déjà |
| Respect d'un refus | Rien si une PR de ce correctif a été fermée sans merge |
| Pas de boucle | La remédiation ne tourne pas sur une branche `autofix/` |
| Entrée non fiable | Identifiant, chemin, nom de paquet et version validés par expression régulière |
| Pas de shell | `git`, `dotnet` et `npm` sont lancés avec une liste d'arguments |
| Secrets à l'abri | `dotnet` et `npm` sont lancés sans les tokens de l'environnement |
| Dossier de travail intact | Chaque correctif est préparé dans un worktree Git temporaire |
| Simulation par défaut | Il faut `--apply` pour créer quoi que ce soit |

## Les sorties

- Une PR par correctif : branche `autofix/<id>`, titre `fix: bump <paquet> from <a> to <b>`,
  label `ai-autofix`, avec la CVE, le Risk Score et une liste de vérifications.
- Un commentaire de synthèse sur la PR analysée, mis à jour à chaque exécution.
- `reports/remediation.json` et `reports/remediation.md`.

## Intégration dans la pipeline

Job à ajouter dans `.github/workflows/security.yml` (module CI/CD), après le job `ai-triage` :

```yaml
  auto-remediation:
    name: Auto-remediation
    needs: ai-triage
    # Pas sur une PR du bot (pas de boucle) ni sur un fork (pas de secrets)
    if: >-
      always() && github.event_name == 'pull_request'
      && !startsWith(github.head_ref, 'autofix/')
      && github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          token: ${{ secrets.AUTOFIX_TOKEN || github.token }}
      - uses: actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0
        with:
          dotnet-version: 10.0.x
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: triage
          path: reports
      - name: Tests de la remédiation
        working-directory: security/remediation
        run: python3 -m unittest
      - name: Remédiation
        env:
          GITHUB_TOKEN: ${{ github.token }}
          AUTOFIX_TOKEN: ${{ secrets.AUTOFIX_TOKEN }}
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }} # optionnel : active la v2
          PYTHONPATH: security/remediation
        run: python3 -m remediation --triage reports/triage.json --output reports --apply
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: remediation
          path: |
            reports/remediation.json
            reports/remediation.md
```

### Le token : point important

Une PR créée avec le `GITHUB_TOKEN` du workflow **ne déclenche pas la pipeline** : GitHub
bloque cela pour éviter les boucles. Pour que « la pipeline se relance » sur la PR du bot, il
faut un autre token dans le secret `AUTOFIX_TOKEN` :

- de préférence une **GitHub App** installée sur le repo (droits : Contents et Pull requests en
  écriture) ;
- sinon un PAT « fine-grained » limité à ce repo, avec les mêmes droits.

Sans `AUTOFIX_TOKEN`, la remédiation fonctionne quand même, mais il faut relancer la pipeline à
la main sur la PR du bot, et activer dans les réglages du repo « Allow GitHub Actions to create
and approve pull requests ».

## Limites connues

- Jamais exécutée dans GitHub Actions : le job n'existe pas encore. La création réelle d'une
  PR est testée avec une API GitHub simulée.
- `dotnet restore` évalue le fichier de projet de la PR, qui peut contenir du code. Les tokens
  sont retirés de l'environnement de l'outil, mais le job ne doit tourner que sur les PR des
  membres de l'équipe (condition `if` ci-dessus).
- La v2 n'a jamais reçu de vraie réponse de Gemini (pas de clé) : le LLM est simulé dans les
  tests. La qualité réelle de ses patchs sur le code de l'API reste à mesurer.
- Un patch v2 ne peut pas ajouter de directive `using` en haut du fichier : le LLM doit écrire
  le nom complet d'un type absent, sinon le patch ne compile pas et il n'y a pas de PR.
- `dotnet build` prouve que le patch compile, pas qu'il est correct.
