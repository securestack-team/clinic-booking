# Remédiation automatique

La remédiation lit `reports/triage.json` (produit par l'agent IA) et ouvre une **Pull Request de
correctif** pour chaque paquet vulnérable qu'elle sait corriger.

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

| Variable | Rôle |
|---|---|
| `AUTOFIX_TOKEN` | Token du bot (GitHub App ou PAT). Utilisé en priorité |
| `GITHUB_TOKEN` | Utilisé si `AUTOFIX_TOKEN` est absent |
| `GITHUB_REPOSITORY` | `organisation/repo` |
| `AUTOFIX_GIT_NAME`, `AUTOFIX_GIT_EMAIL` | Auteur des commits (défaut : `github-actions[bot]`) |

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
- les secrets (il faut les révoquer), le code et la configuration (prévu en v2) ;
- tout fichier dans `.github/` ou `infra/`.

Plusieurs CVE sur le même paquet donnent **une seule PR**, vers la version qui les corrige
toutes. Si Trivy propose plusieurs versions corrigées, on prend la plus petite, de préférence
dans la même version majeure.

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
- La v2 (patch proposé par LLM pour une injection SQL, un `[Authorize]` manquant, un secret en
  dur) n'est pas faite : elle a besoin du code de l'API et d'une clé pour le LLM.
