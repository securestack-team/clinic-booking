# Branche `vulnerable-demo` — Documentation de la démonstration DevSecOps

> **Cette branche ne doit jamais être mergée dans `main`.**
> Elle est exclusivement destinée à la démonstration académique de la pipeline DevSecOps.

## Objectif

Prouver que la pipeline DevSecOps détecte, analyse et priorise des vulnérabilités réelles
dans le code. Chaque vulnérabilité est introduite volontairement, isolée dans des fichiers
ou des espaces dédiés, et documentée ici avec le chemin de détection complet.

---

## Tableau récapitulatif

| # | Vulnérabilité | Fichier | Outil de détection | CWE / Advisory | Risk Score estimé | Action corrective |
|---|---|---|---|---|---|---|
| 1 | Secret en dur | `api/src/ClinicBooking.Api/appsettings.Demo.json` | Gitleaks | CWE-798 | 9.5 (critique) | Révoquer, déplacer dans Key Vault |
| 2 | Injection SQL (`FromSqlRaw`) | `api/src/ClinicBooking.Api/Controllers/DemoController.cs` | CodeQL / Semgrep | CWE-89 | ≥ 7.1 (élevé) | Requête paramétrée (`FromSqlInterpolated`) |
| 3 | Dépendance vulnérable | `api/src/ClinicBooking.Api/ClinicBooking.Api.csproj` | Trivy / dotnet audit | CVE-2024-21907 | ≥ 7.0 (élevé) | Mise à jour vers `Newtonsoft.Json ≥ 13.0.1` |
| 4 | BOLA | `api/src/ClinicBooking.Api/Controllers/DemoController.cs` | Test xUnit + CodeQL | CWE-639 | ≥ 7.0 (élevé) | Vérifier `appointment.PatientId == userId` |
| 5 | Conteneur en root | `api/Dockerfile` | Hadolint (DL3002) / Trivy config | — | ≥ 5.5 (moyen) | Revenir à `USER $APP_UID` |

---

## Vulnérabilité 1 — Secret en dur

**Fichier :** `api/src/ClinicBooking.Api/appsettings.Demo.json`

**Valeur introduite :** `FAKE_DEMO_API_KEY_1a2b3c4d5e6f7890abcdef1234567890`

Il s'agit d'une **fausse clé entièrement fictive**, jamais utilisée. Sa forme générique
(chaîne hexadécimale de 32 caractères après le préfixe `FAKE_DEMO_API_KEY_`) est délibérément
choisie pour être reconnue par Gitleaks (motif `generic-api-key`).

**Chemin de détection :**
1. Gitleaks analyse l'historique Git complet (`--fetch-depth: 0`).
2. Il produit un rapport `reports/gitleaks.sarif` uploadé dans l'onglet Security.
3. L'agent IA lit ce rapport, catégorise le finding comme `secret`, lui attribue un
   Risk Score de **9.5** (le repo est public — le secret est donc exposé), et ne l'envoie
   **jamais** au LLM (protège contre LLM02 : fuite de données sensibles).
4. Le commentaire de la PR mentionne le finding mais **n'affiche pas** la valeur du secret.
5. La quality gate bloque le merge (`exit-code 1` sur Gitleaks, sévérité `critical`).

**Correction :** révoquer la clé, la retirer du fichier, la placer dans `dotnet user-secrets`
en local et dans Azure Key Vault en production.

**Preuve attendue :** capture `docs/captures/demo-final-gitleaks.png`

---

## Vulnérabilité 2 — Injection SQL (`FromSqlRaw` concaténé)

**Fichier :** `api/src/ClinicBooking.Api/Controllers/DemoController.cs`, endpoint `GET /api/demo/search`

**Code vulnérable :**
```csharp
var sql = "SELECT * FROM \"Appointments\" WHERE \"PatientId\" LIKE '%" + name + "%'";
var results = await db.Appointments.FromSqlRaw(sql).ToListAsync();
```

La valeur de `name` vient directement du paramètre HTTP et est concaténée dans la chaîne SQL.
Un attaquant peut injecter `'; DROP TABLE --` ou extraire des données d'autres tables.

**Chemin de détection :**
1. CodeQL (règle `cs/sql-injection`) suit le flux de données : paramètre HTTP → `FromSqlRaw`.
2. Semgrep (règle `csharp.dotnet.security.sqli.sql-injection`) détecte le même pattern.
3. Les deux findings sont dédupliqués par l'agent (même fichier, même ligne, même CWE-89).
4. Le finding fusionné reçoit un Risk Score élevé (CVSS 8.8 × exposition API 1.0).
5. Gemini analyse le flux et confirme l'exploitabilité.

**Correction :** utiliser `FromSqlInterpolated` ou LINQ pur :
```csharp
// Correct :
var results = await db.Appointments
    .Where(a => EF.Functions.Like(a.PatientId, $"%{name}%"))
    .ToListAsync();
```

**Preuve attendue :** capture `docs/captures/demo-final-sqli.png`

---

## Vulnérabilité 3 — Dépendance vulnérable (`Newtonsoft.Json 12.0.1`)

**Fichier :** `api/src/ClinicBooking.Api/ClinicBooking.Api.csproj`

**Dépendance introduite :** `Newtonsoft.Json 12.0.1`

Cette version est affectée par des CVE critiques, notamment une vulnérabilité de déni de service
(DoS) par données malformées (CVE-2024-21907 / GHSA-5crp-9r3c-p9vr).

**Chemin de détection :**
1. Trivy scanne le répertoire avec `--scanners vuln` et détecte le paquet dans le fichier de
   verrou NuGet (`packages.lock.json` ou `.csproj`).
2. `dotnet list package --vulnerable --include-transitive` détecte aussi la vulnérabilité dans
   le job `ci.yml` et fait échouer le build.
3. L'agent IA lit le SARIF Trivy, catégorise en `dependency`, génère une entrée `package`
   complète dans `triage.json` (name, installed\_version, fixed\_version, advisory).
4. Le bot de remédiation (Abdedaym) lit cette entrée et ouvre une PR `autofix/<id>` qui met
   à jour la version.

**Correction :** mettre à jour vers `Newtonsoft.Json >= 13.0.1`.

**Preuve attendue :** capture `docs/captures/demo-final-trivy.png`

---

## Vulnérabilité 4 — BOLA (Broken Object Level Authorization)

**Fichier :** `api/src/ClinicBooking.Api/Controllers/DemoController.cs`, endpoint `GET /api/demo/appointments/{id}`

**Code vulnérable :**
```csharp
var appointment = await db.Appointments.FindAsync(id);
if (appointment is null) return NotFound();
// Aucune vérification que appointment.PatientId == userId courant !
return Ok(appointment);
```

Tout utilisateur authentifié peut accéder au rendez-vous d'un autre en connaissant son GUID.

**Chemin de détection :**
1. Test xUnit `BolaTests.OtherPatient_CanAccessAnotherPatientAppointment_DemoBola` :
   - Crée un rendez-vous pour le patient A.
   - Envoie la requête avec le JWT du patient B.
   - **Reçoit 200** (au lieu de 403 attendu) → le test **échoue intentionnellement**.
2. L'échec du test apparaît dans la pipeline CI et constitue la preuve de la faille.
3. CodeQL peut détecter l'absence de contrôle d'autorisation sur la ressource.

**Correction :**
```csharp
var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
if (appointment.PatientId != userId) return Forbid();
```

**Preuve attendue :** capture `docs/captures/demo-final-bola.png`

---

## Vulnérabilité 5 — Conteneur exécuté en tant que root

**Fichier :** `api/Dockerfile`

**Configuration introduite :**
```dockerfile
USER root
```

L'image de production d'origine utilisait `USER $APP_UID` (non-root) sur une image "chiseled".
Cette ligne a été remplacée par `USER root` pour la démonstration.

**Risques :** si un attaquant compromet l'application, il obtient les privilèges root dans le
conteneur, facilitant les escalades vers le nœud Kubernetes et les autres pods.

**Chemin de détection :**
1. Hadolint (règle `DL3002`) détecte `USER root` et émet un avertissement dans le rapport SARIF.
2. Trivy (`--scanners misconfig`) peut aussi détecter la configuration dans le manifeste K8s
   si `runAsNonRoot: false` s'y retrouve.
3. L'agent IA lit le rapport Hadolint, catégorise en `config`, calcule un Risk Score.

**Correction :** revenir à `USER $APP_UID` et utiliser l'image "chiseled" (non-root par défaut).

**Preuve attendue :** capture `docs/captures/demo-final-docker.png`

---

## Flux complet agent IA

```
Pipeline GitHub Actions
  ├─ gitleaks     → reports/gitleaks.sarif    ┐
  ├─ codeql       → reports/codeql-*.sarif    │
  ├─ semgrep      → reports/semgrep.sarif     ├─► Agent IA (ai-triage)
  ├─ trivy        → reports/trivy.sarif       │     ├─ sarif.py    : normalise
  ├─ hadolint     → reports/hadolint.sarif    ┘     ├─ dedupe.py   : fusionne
  └─ checkov      → reports/checkov.sarif           ├─ redact.py   : masque les secrets
                                                     ├─ llm.py     : triage Gemini
                                                     ├─ scoring.py : Risk Score
                                                     └─ report.py  : commentaire PR
                                                              ↓
                                                    reports/triage.json
                                                              ↓
                                                    Remédiation (Abdedaym)
                                                    branche autofix/<id>
```

### Déduplication

Deux findings sont fusionnés quand ils partagent la même clé :
- **secret** : même fichier + même ligne (Gitleaks et Trivy sur le même secret).
- **dépendance** : même CVE + même paquet + même fichier (Trivy et Dependabot).
- **code** : même fichier + même ligne + même CWE (CodeQL et Semgrep sur le même `FromSqlRaw`).

Le finding fusionné conserve la **sévérité la plus haute** et liste tous les outils.

### Calcul du Risk Score

```
Risk Score = Sévérité × Exposition × Confiance
```

| Facteur | Source |
|---|---|
| Sévérité (0–10) | Score CVSS du scanner ; sinon critical=9.5, high=8.0, medium=5.5, low=2.0 |
| Exposition (0–1) | Localisation : `api/` → 1.0, `web/` → 0.9, tests → 0.4 |
| Confiance (0–1) | 1 − probabilité de faux positif estimée par Gemini (jamais < 0.5) |

Règle absolue : un **secret vaut toujours 9.5**, le LLM n'intervient pas.

### Masquage des secrets

Avant tout envoi à Gemini, `redact.py` remplace par `[MASQUÉ]` :
- Clés PEM, tokens AWS, GitHub, Google (clés `AIza...`), Slack, JWT.
- Toute affectation contenant `password`, `api_key`, `secret`, `token`…
- Chaînes aléatoires de plus de 32 caractères avec une entropie élevée (> 4,3 bits/car).

Les findings de catégorie `secret` (Gitleaks, CWE-798) sont **exclus** de l'envoi au LLM.
Seuls la règle, le fichier et la ligne apparaissent dans le commentaire PR.

---

## Captures à produire après l'exécution de la pipeline

| Fichier | Contenu attendu |
|---|---|
| `docs/captures/demo-final-gitleaks.png` | Rapport Gitleaks — finding `generic-api-key` |
| `docs/captures/demo-final-sqli.png` | CodeQL ou Semgrep — `cs/sql-injection` sur DemoController.cs |
| `docs/captures/demo-final-trivy.png` | Trivy — `Newtonsoft.Json 12.0.1` / CVE-2024-21907 |
| `docs/captures/demo-final-bola.png` | Échec du test `BolaTests` dans la pipeline CI |
| `docs/captures/demo-final-docker.png` | Hadolint — `DL3002` sur `USER root` |
| `docs/captures/demo-final-agent-comment.png` | Commentaire de l'agent IA sur la PR draft |
| `docs/captures/demo-final-risk-score.png` | Tableau des Risk Scores dans le commentaire |
| `docs/captures/demo-final-pipeline.png` | Pipeline rouge (quality gate déclenchée) |

Les captures doivent être prises depuis l'interface GitHub (onglet Security, PR, Actions).
Ne pas créer de fausses captures.
