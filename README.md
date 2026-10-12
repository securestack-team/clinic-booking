# Pipeline DevSecOps augmentée par IA

Projet académique : une pipeline DevSecOps augmentée par IA pour une application ASP.NET Core
(API + site web React + application mobile React Native), déployée sur Microsoft Azure.

La sécurité est en place **avant** l'application : chaque Pull Request passe par une pipeline
qui compile, teste et scanne le code (shift-left).

## Équipe

| Membre | Module |
|---|---|
| Ali DRISSI | Cloud & Kubernetes + site web React |
| Hajar ELASRI | Security Engine & CI/CD |
| Mohammed EL OMRI | AI Security Agent + threat model |
| Abdedaym CHAKRA | Auto-remediation + tests de sécurité |
| Freddy | API ASP.NET Core + application mobile |

## Stack

ASP.NET Core (.NET 10) · EF Core · PostgreSQL · React + Vite · React Native (Expo) ·
GitHub Actions · Azure (AKS, ACR, Key Vault) · Terraform

## Structure

```
api/                    API ASP.NET Core (+ api/tests)
web/                    site web React
mobile/                 application React Native
infra/terraform/        infrastructure Azure
infra/k8s/              manifests Kubernetes
security/agent/         agent IA de triage
security/remediation/   remédiation automatique
docs/                   architecture, threat model, rapport
.github/workflows/      pipelines CI et sécurité
```

## Pipeline actuelle

| Workflow | Contrôles |
|---|---|
| `ci.yml` | Build + tests .NET, paquets NuGet vulnérables |
| `security.yml` | Gitleaks (secrets), Trivy (dépendances, configuration, secrets), CodeQL (SAST) |

Les résultats apparaissent dans l'onglet **Security** du repo. Une vulnérabilité High/Critical
ou un secret fait échouer la pipeline et bloque le merge.

## Contribuer

1. Installer le hook anti-secrets (une fois) :
   ```bash
   brew install pre-commit   # ou : pip install pre-commit
   pre-commit install
   ```
2. Créer une branche : `feature/...`, `fix/...`, `ci/...`, `infra/...`, `docs/...`
3. Commits au format Conventional Commits (`feat:`, `fix:`, `ci:`…).
4. Ouvrir une Pull Request vers `main` : la pipeline doit être verte et 1 approbation est
   requise. Pas de push direct sur `main`.
5. Aucun secret dans le code : `dotnet user-secrets` ou `.env` en local, Key Vault sur Azure.

Le contexte complet du projet (pour les humains et les assistants IA) est dans
[`AGENTS.md`](AGENTS.md).
