# Contexte complet du projet : pipeline DevSecOps augmentée par IA

> **Comment utiliser ce fichier :** colle-le au début de ta conversation avec ton assistant IA
> (Claude, ChatGPT…) ou mets-le dans un fichier `CLAUDE.md` / `AGENTS.md` dans ton dossier de
> travail. Lis aussi la section de ton rôle (partie 3).
> Pour les tâches de cette semaine, utilise en plus `contexte-mercredi-14-oct.md`.

---

## 1. Le projet

Projet académique d'une équipe de 5 personnes. Objectif : concevoir une **pipeline DevSecOps
augmentée par IA** pour une application **ASP.NET Core** (API + site web React + application
mobile React Native), déployée sur **Microsoft Azure**.

La note porte sur la **pipeline** (11 pratiques DevSecOps « Tier 1 » obligatoires,
automatisation, preuves), **pas** sur le nombre de fonctionnalités. L'application sert de
support : elle doit être simple mais réelle.

Chaque contrôle de sécurité doit être démontré ainsi :

**Pratique → Outil → Intégration dans la pipeline → Détection → Résultat → Action corrective**

### Le principe (shift-left)

L'application est construite **petit à petit**, fonctionnalité par fonctionnalité, via des Pull
Requests. La pipeline existe **dès le premier jour** et vérifie chaque ajout de code. On
n'attend pas d'avoir une application finie pour la scanner.

### Cycle d'une fonctionnalité

1. Branche `feature/...` → commits. Le hook **Gitleaks pre-commit** bloque les secrets en local.
2. Pull Request vers `main` → la pipeline démarre automatiquement :
   - build
   - tests, dont les tests de sécurité
   - SAST : CodeQL, Semgrep
   - secrets : Gitleaks
   - dépendances : Trivy, npm audit, `dotnet list package --vulnerable`
   - image Docker : Trivy
   - IaC : Checkov
3. **Agent IA** : lit tous les rapports SARIF, déduplique, calcule un Risk Score et commente la PR.
4. **Remédiation automatique** : ouvre une PR de correctif, jamais mergée sans humain.
5. **Quality gate** : la pipeline échoue s'il y a une vulnérabilité High/Critical ou un secret.
6. **Revue humaine** (1 approbation) → merge dans `main`.
7. **Déploiement automatique** : image → Azure Container Registry → AKS (staging) → **DAST**
   (OWASP ZAP attaque l'API déployée) → production.
8. **Monitoring** : Prometheus + Grafana + alertes.

Exemple : Freddy pousse par erreur un mot de passe → Gitleaks le détecte → pipeline rouge →
l'agent IA commente « Critique 9.5/10 : secret en dur » → le bot ouvre une PR qui déplace le
secret dans Key Vault → revue → merge → pipeline verte → déploiement.

---

## 2. Stack, équipe, organisation

### Stack

| Couche | Choix |
|---|---|
| Code & CI/CD | GitHub (organisation, repo **public**) + GitHub Actions (runners `ubuntu-latest`) |
| API | ASP.NET Core Web API (.NET 10 LTS), EF Core, PostgreSQL, ASP.NET Identity + JWT, Swagger |
| Web | React + Vite + TypeScript |
| Mobile | React Native (Expo) + expo-secure-store |
| Cloud | Azure (Azure for Students) : AKS, ACR, Azure Database for PostgreSQL, Key Vault |
| IaC | Terraform (scanné par Checkov) + manifests Kubernetes |
| Rapports de sécurité | SARIF 2.1.0 |
| LLM de l'agent IA | GitHub Models ou Gemini (à décider) |

Pourquoi un repo public : CodeQL, le secret scanning et la push protection sont gratuits, et
les minutes GitHub Actions sont illimitées sur les runners standards. Un repo privé
consommerait le quota de minutes.

### Équipe et modules

| Membre | Module(s) |
|---|---|
| **Ali** (DRISSI) | Cloud & Kubernetes + site web React. Propriétaire de l'organisation GitHub. |
| **Hajar** (ELASRI) | Security Engine & CI/CD (workflows, scanners, quality gate, SARIF) |
| **Mohammed** (EL OMRI) | AI Security Agent (triage, Risk Score) + pilote du threat model |
| **Abdedaym** (CHAKRA) | Auto-remediation (PR de correctifs) + tests de sécurité avec Freddy |
| **Freddy** | API ASP.NET Core + application mobile React Native |

### Structure du repo

```
/api                    API ASP.NET Core
/api/tests              tests xUnit (dont tests de sécurité)
/web                    React + Vite + TypeScript
/mobile                 React Native (Expo)
/infra/terraform        infrastructure Azure
/infra/k8s              manifests Kubernetes
/security/agent         agent IA (Mohammed)
/security/remediation   remédiation automatique (Abdedaym)
/docs                   threat model, architecture, rapport, captures
/.github/workflows      pipelines GitHub Actions
```

### Règles non négociables

- **Tout passe par une Pull Request** vers `main` : 1 approbation minimum, checks obligatoires,
  pas de push direct, pas de force-push.
- **Branches :** `feature/...`, `fix/...`, `ci/...`, `infra/...`, `docs/...`
- **Commits** au format Conventional Commits : `feat:`, `fix:`, `ci:`, `infra:`, `docs:`,
  `test:`, `chore:`
- **Petites PR**, une fonctionnalité ou un changement à la fois.
- **Aucun secret dans le repo** (mots de passe, clés, chaînes de connexion) :
  - en local : `dotnet user-secrets` ou fichier `.env` (dans `.gitignore`)
  - sur Azure : Key Vault
  - GitHub → Azure via **OIDC**, sans aucune clé Azure stockée dans GitHub
- **Quality gate :** la pipeline échoue sur toute vulnérabilité High/Critical ou tout secret.
- **SARIF :** chaque scanner produit un fichier SARIF, uploadé dans l'onglet Security et en
  artefact (`reports/<outil>.sarif`).
- **Runners :** `ubuntu-latest` uniquement. Les « larger runners » sont payants même sur un
  repo public.
- **Règles IA :**
  - ne jamais envoyer de secret ou de token réel à un LLM ;
  - tout code généré par IA est relu, compris et testé par la personne qui le pousse ;
  - chacun doit pouvoir expliquer son code à la soutenance.
- **Code réutilisé** depuis un repo public : uniquement avec une licence compatible (MIT,
  Apache…) et cité dans le README et le rapport. On ne copie pas un projet entier.
- **Garder des preuves au fil de l'eau** pour le rapport : captures de pipeline rouge/verte,
  commentaires de l'agent IA, PR de correctif.

### Les 11 pratiques Tier 1 (obligatoires)

| Pratique | Outils | Responsable |
|---|---|---|
| SAST | CodeQL, Semgrep, Roslyn analyzers, eslint-plugin-security | Hajar |
| DAST | OWASP ZAP (API scan via OpenAPI) sur le staging Azure | Hajar + Ali |
| Automated Security Testing | xUnit : BOLA (403), auth (401), rate limit (429) | Freddy + Abdedaym |
| Vulnerability Scanning | Dependabot, Trivy, `dotnet list package --vulnerable`, npm audit, MobSF | Hajar + Ali |
| Continuous Monitoring | Prometheus + Grafana, logs Serilog, alertes | Ali |
| Continuous Integration | GitHub Actions : build → test → scans → gate | Hajar |
| Threat Modeling | STRIDE avec OWASP Threat Dragon | Mohammed + équipe |
| Shift-Left Security | Gitleaks pre-commit, push protection, scans à chaque PR | Hajar |
| Collaboration | GitHub Projects + Issues | Tout le monde |
| Continuous Deployment | Image → ACR → AKS si gates OK, auth OIDC | Ali |
| Code Review | PR + approbations + CODEOWNERS, revue des patchs IA | Tout le monde |

Bonus Tier 2 si le temps le permet : Secrets Management (Key Vault + CSI driver), IaC scanning,
SBOM (CycloneDX), signature d'image (Cosign), Environment Hardening.

### Phases et planning (10 semaines, à ajuster selon la date de soutenance)

| Phase | Contenu | Semaines |
|---|---|---|
| 0. Cadrage | Idée de l'app, architecture, threat model v1, répartition | S1 |
| 1. Fondations | Repo sécurisé, squelette API, première pipeline | S1–S2 |
| 2. Application | Auth JWT, fonctionnalités, web, mobile, tests de sécurité | S2–S4 |
| 3. Cloud | Docker, Terraform, AKS, déploiement continu, DAST | S3–S5 |
| 4. IA | Agent de triage + remédiation automatique | S4–S7 |
| 5. Monitoring | Prometheus, Grafana, alertes | S6 |
| 6. Démo | Branche `vulnerable-demo`, flux complet de bout en bout | S7 |
| 7. Bonus Tier 2 | Key Vault CSI, SBOM, Cosign | S8 |
| 8. Rapport + soutenance | Preuves, rapport, slides, répétition, vidéo de secours | S9–S10 |

Dépendances :
- La phase 1 doit être finie avant tout le reste.
- L'IA (phase 4) a besoin des rapports SARIF de la pipeline.
- La démo (phase 6) a besoin de tout.

### Décisions encore ouvertes

- Idée de l'application. Proposition : prise de rendez-vous en clinique, avec les rôles
  patient / médecin / admin.
- LLM de l'agent IA : GitHub Models ou Gemini.
- Nom de l'organisation GitHub.
- Date de la soutenance.

---

## 3. Contexte par rôle

### Ali (DRISSI) : Cloud & Kubernetes + site web React + propriétaire de l'organisation GitHub

**Cloud & Kubernetes**
- Azure for Students + **alerte de budget** dès le premier jour. Arrêter le cluster AKS quand on
  ne travaille pas dessus.
- Terraform (`/infra/terraform`) :
  - resource group, ACR, AKS, Key Vault ;
  - PostgreSQL Flexible Server, non publique ;
  - state dans un storage account Azure, jamais commité.
- GitHub → Azure par **OIDC** (federated credential).
- Dockerfiles durcis : multi-stage, image minimale, utilisateur non-root, aucun secret.
  docker-compose pour le local. Hadolint.
- Manifests K8s durcis (`/infra/k8s`) :
  - `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, drop ALL ;
  - requests/limits, probes sur `/health` ;
  - NetworkPolicies, Ingress HTTPS.
- Déploiement continu vers staging, seulement si la quality gate passe. Fournir l'URL de
  staging à Hajar pour ZAP.
- Monitoring : Prometheus + Grafana (Helm), alertes sur les pics de 401/403/429 et sur les pods
  en erreur.
- Bonus : Key Vault + CSI driver.
- Après la soutenance : `terraform destroy`.

**Site web React (`/web`)**
- React + Vite + TypeScript.
- Écrans : login + écrans principaux.
- Sécurité :
  - access token en mémoire, pas dans le localStorage ;
  - pas de `dangerouslySetInnerHTML` ;
  - Content-Security-Policy ;
  - eslint-plugin-security ;
  - seulement des valeurs publiques dans les variables `VITE_*`.
- Le contrat d'API vient de Freddy (Swagger) : se mettre d'accord avec lui sur le refresh token.

**Interfaces**
- Hajar : jobs de build d'image, de scan et de déploiement ; Checkov ; ZAP.
- Freddy : `/health`, configuration, CORS.

**Terminé quand :** un merge sur `main` déploie automatiquement sur AKS via OIDC,
l'infrastructure est 100 % Terraform et passe Checkov, et le monitoring affiche des métriques.

### Hajar (ELASRI) : Security Engine & CI/CD

- Reprend et fait évoluer le repo et les workflows créés en semaine 1. Ali reste propriétaire de
  l'organisation ; Hajar doit être admin du repo.
- Maintenir le ruleset sur `main`, CODEOWNERS, Dependabot (nuget, npm, github-actions, docker,
  terraform), secret scanning, push protection.
- Hook Gitleaks pre-commit (`.pre-commit-config.yaml`) + documentation pour l'équipe.
- Workflows :
  - `ci.yml` : build + tests ;
  - `security.yml` : CodeQL (C# + JS/TS), Semgrep, Gitleaks, Trivy fs,
    `dotnet list package --vulnerable`, npm audit ;
  - ensuite : scan Trivy de l'image, Checkov, OWASP ZAP sur le staging (avec Ali), MobSF sur
    l'APK (avec Freddy), jobs de l'agent IA et de la remédiation.
- Upload SARIF (onglet Security + artefacts `reports/<outil>.sarif`).
- Quality gate. Mesure du temps de chaque job (section « impact performance » du rapport).
- Sécurité des workflows :
  - bloc `permissions:` minimal ;
  - actions tierces épinglées par SHA ;
  - jamais de `pull_request_target` avec checkout du code de la PR ;
  - aucun secret en clair ;
  - cache NuGet/npm.

**Interfaces**
- Mohammed : noms et emplacement des SARIF.
- Ali : staging, IaC, déploiement.
- Freddy : commandes de build/test, APK.
- Abdedaym : les PR du bot repassent par toute la pipeline.

**Terminé quand :** chaque PR déclenche build, tests et tous les scans, les résultats
apparaissent dans l'onglet Security, et une faille grave bloque le merge.

### Mohammed (EL OMRI) : AI Security Agent + threat model

**Threat model**
- STRIDE avec OWASP Threat Dragon : v1 maintenant, v2 avant le rapport.
- Chaque menace : catégorie OWASP (Top 10:2025, API Top 10, Mobile Top 10, LLM Top 10) →
  contrôle → outil qui la détecte.

**Agent (`/security/agent`)**
- Entrée : tous les SARIF de la pipeline.
- Normaliser : outil, règle, sévérité, CWE, fichier, ligne, message.
- Dédupliquer.
- Triage LLM :
  - probabilité de faux positif, exploitabilité ;
  - Risk Score 0–10 avec une formule documentée (sévérité × exposition × confiance) ;
  - recommandation.
- Sorties :
  - commentaire Markdown sur la PR ;
  - `reports/triage.json` pour Abdedaym.
- Si le LLM ne répond pas, l'agent continue avec les sévérités brutes.

**Sécurité du LLM**
- Masquer les secrets ; ne jamais envoyer un finding Gitleaks.
- Contenu analysé traité comme non fiable (prompt injection).
- Sortie JSON validée par un schéma ; ne jamais exécuter ce que le LLM renvoie.
- Token avec permissions minimales.

**LLM**
- GitHub Models : `GITHUB_TOKEN` + permission `models: read`.
- Ou Gemini : clé dans les secrets GitHub.

**Terminé quand :** sur chaque PR, un commentaire clair liste les findings dédupliqués, triés par
Risk Score, avec une recommandation pour chacun.

### Abdedaym (CHAKRA) : Auto-remediation + tests de sécurité

**Remédiation (`/security/remediation`)**
- Entrée : `reports/triage.json`.
- v1 : mise à jour d'un paquet vulnérable vers la version corrigée.
- v2 : patch LLM pour des findings simples (SQL concaténé → paramétré, `[Authorize]` manquant,
  secret en dur → configuration).
- Pour chaque correctif : branche `autofix/<id>` → commit → PR via l'API GitHub (label
  `ai-autofix`) → la pipeline se relance.
- **Jamais de merge automatique.**
- Garde-fous :
  - nombre maximum de PR par exécution ;
  - ne jamais modifier `.github/workflows` ni `/infra` ;
  - commenter au lieu de proposer un patch non validé.

**Tests de sécurité (avec Freddy, `/api/tests`)**
- xUnit + WebApplicationFactory :
  - ressource d'un autre utilisateur → 403 ;
  - sans token / token expiré → 401 ;
  - trop de requêtes → 429 ;
  - entrée invalide → 400.

**Branche `vulnerable-demo` (avec Freddy, S7)**
- Failles volontaires :
  - secret en dur ;
  - `FromSqlRaw` concaténé ;
  - paquet vulnérable ;
  - endpoint BOLA ;
  - token mobile en AsyncStorage.
- Vérifier que chacune est détectée, scorée et corrigée.

**Terminé quand :** un finding simple produit automatiquement une PR de correctif qui passe la
pipeline et attend une validation humaine.

### Freddy : API ASP.NET Core + application mobile

**API (`/api`)**
- .NET 10 LTS, EF Core + Npgsql, Swagger.
- Identity + JWT : access token court + refresh token.
- Autorisation :
  - `[Authorize]` + politiques par rôle ;
  - **vérifier systématiquement que l'utilisateur ne touche qu'à SES données** (contre le
    BOLA).
- DTOs + validation ; jamais d'entités EF exposées directement.
- Jamais de SQL concaténé.
- Rate limiting, CORS limité au site web, HTTPS + HSTS, ProblemDetails sans stack trace,
  Swagger seulement en développement.
- Serilog sans données sensibles, endpoint `/health`.
- Configuration : `dotnet user-secrets` en local, variables d'environnement / Key Vault sur
  Azure.
- Analyzers Roslyn (`AnalysisLevel` latest-recommended).
- Tests xUnit dans `/api/tests`.

**Mobile (`/mobile`)**
- Expo.
- Tokens dans expo-secure-store, jamais AsyncStorage.
- HTTPS uniquement, aucun secret dans l'app.
- Build APK dans Actions pour MobSF.

**Terminé quand :** l'API et l'app mobile couvrent les fonctionnalités prévues, les endpoints
sont protégés et testés, et aucune vulnérabilité High/Critical n'est ouverte.

---

## 4. Consignes pour l'assistant IA

- Réponds en français, explique simplement et donne des étapes concrètes.
- Respecte les règles de la partie 2 ; signale-moi si une demande les enfreint.
- Reste dans mon périmètre. Si une tâche touche le module d'un autre membre, dis-moi à qui en
  parler au lieu de le faire à sa place.
- Propose des changements petits, testables, adaptés à une PR.
- Pour chaque fonctionnalité, pense sécurité :
  - quelle menace ?
  - quel contrôle ?
  - quel outil la détecte dans la pipeline ?
  - quelle preuve garder pour le rapport ?
