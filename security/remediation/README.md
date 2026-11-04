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

Python 3.10+ et bibliothèque standard uniquement. Git est requis. En CI, Docker exécute
`dotnet` et `npm` dans des conteneurs isolés ; les outils n'ont pas à être installés sur l'hôte.

## Utilisation

```bash
cd security/remediation

python3 -m unittest                                           # les tests

# Simulation (par défaut) : dit ce qui serait corrigé, ne crée rien
python3 -m remediation --triage ../../reports/triage.json --repo-root ../.. --output /tmp/remediation

# Réel : crée les branches et les PR
export GITHUB_REPOSITORY=securestack-team/clinic-booking
export GITHUB_TOKEN=...            # jamais dans le repo
python3 -m remediation --triage ../../reports/triage.json --repo-root ../.. --base ma-branche --apply --sandbox-tools
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
| `--sandbox-tools` | Obligatoire dans le job CI : exécute les outils dans Docker, sans identifiants du runner ; aucun repli sur l'hôte |

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

Le job se trouve dans [security.yml](../../.github/workflows/security.yml).
Il conserve le code du bot au commit de base approuvé et traite `pr-source/` comme
le dépôt à corriger. Les tests du nouveau code de la PR tournent séparément dans
`remediation-tests`, avec `contents: read`, sans secrets ni credentials persistés.

Le job privilégié attend le succès du triage et des tests de remédiation. Il refuse
les forks et les branches `autofix/`. La publication utilise `--sandbox-tools` :

- `dotnet` et `npm` sont lancés dans des conteneurs sans les variables ou fichiers
  d'identification du runner, sans `.git`, sans socket Docker ni espace PID de l'hôte ;
- seule une copie du dépôt de travail est montée, avec un utilisateur non-root sur
  les runners Ubuntu, rootfs en lecture seule, capabilities retirées et ressources limitées ;
- seuls les changements de dépendances autorisés reviennent après validation complète ;
  liens, fichiers spéciaux, suppressions et modifications hors périmètre sont refusés ;
- les caches/builds sont jetables ; le réseau du conteneur reste nécessaire pour les
  paquets publics, mais aucun secret de feed privé ne lui est transmis ;
- Docker absent, timeout ou échec de contrôle : pas de PR et jamais de build sur l'hôte.

Le bot peut toujours utiliser Gemini sur l'hôte pour préparer un patch, puis compiler
ce patch dans le conteneur. Les secrets Gemini et GitHub ne sont pas transmis au build.
Cela ne prouve pas qu'un patch est correct : scans et revue humaine restent nécessaires.

**Première intégration :** tant que `sandbox.py` n'existe pas dans le commit de base
approuvé, le job émet une notice et ne publie aucun correctif. Il ne récupère jamais ce
module depuis la PR pour l'exécuter avec des secrets. Les tests du module proposé
peuvent quand même passer dans le job en lecture seule. Après la fusion, une nouvelle
PR basée sur cette version de `main` peut utiliser le bot isolé.

### Vérifier l'isolation

```bash
cd security/remediation
python3 -m unittest
# Test Docker réel avec une image de sonde locale construite depuis Alpine :
RUN_SANDBOX_DOCKER_TESTS=1 python3 -m unittest tests.test_sandbox.DockerBoundaryTest -v
```

Le test Docker utilise uniquement de faux marqueurs et vérifie qu'un processus de
build ne voit ni les credentials du runner, ni `.git`, ni le socket Docker ; il vérifie
également le retour d'un lockfile. Les tests unitaires couvrent le refus des fichiers
hors périmètre/liens et l'absence de PR lorsqu'un outil isolé échoue.

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

- La création de PR est couverte avec une API simulée ; la preuve d'une vraie PR du bot
  et de la relance de ses checks reste à garder après l'intégration du job.
- `--sandbox-tools` est requis dans la CI privilégiée. Sans cette option, les outils sont
  lancés sur l'hôte : ce mode local historique ne convient pas à des projets non fiables
  lorsqu'un token ou un autre secret est accessible sur la machine.
- Docker et les images officielles SDK .NET / Node doivent être disponibles. Les caches
  de paquets ne sont pas partagés avec l'hôte et un dépôt contenant des liens est refusé.
- La v2 n'a jamais reçu de vraie réponse de Gemini (pas de clé) : le LLM est simulé dans les
  tests. La qualité réelle de ses patchs sur le code de l'API reste à mesurer.
- Un patch v2 ne peut pas ajouter de directive `using` en haut du fichier : le LLM doit écrire
  le nom complet d'un type absent, sinon le patch ne compile pas et il n'y a pas de PR.
- `dotnet build` prouve que le patch compile, pas qu'il est correct.
