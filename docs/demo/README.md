# Démo de détection : faille → pipeline rouge → correction → pipeline verte

Guide de la démonstration en direct du mercredi 14 octobre, et résultat de la répétition.

L'idée : on pousse volontairement un **faux secret**, on montre que chaque barrière le voit,
puis on corrige.

| Barrière | Quand | Ce qu'elle fait |
|---|---|---|
| Hook Gitleaks pre-commit | Sur le poste du développeur | Bloque le commit |
| Push protection de GitHub | Au moment du `git push` | Refuse le push |
| Gitleaks + Trivy dans la pipeline | Sur la Pull Request | Pipeline rouge, merge bloqué, alerte dans l'onglet Security |

## 1. Résultat de la répétition (12 octobre)

Faite sur la [PR #5](https://github.com/securestack-team/clinic-booking/pull/5), fermée sans
merge. Tout s'est passé comme prévu.

| # | Action | Résultat | Preuve |
|---|---|---|---|
| 1 | Push d'une fausse **paire** de clés AWS | **Refusé** par la push protection | Sortie du terminal ci-dessous |
| 2 | Push de la fausse clé seule + ouverture de la PR | Pipeline **rouge** en 52 s : Gitleaks et Trivy échouent | [run 38322342740](https://github.com/securestack-team/clinic-booking/actions/runs/38322342740) |
| 3 | Alertes | 2 alertes dans l'onglet Security : Gitleaks `aws-access-token` et Trivy `aws-access-key-id` (critique), sur `api/appsettings.json:4` | [alerte 1](https://github.com/securestack-team/clinic-booking/security/code-scanning/1), [alerte 2](https://github.com/securestack-team/clinic-booking/security/code-scanning/2) |
| 4 | Clé retirée dans un nouveau commit | Trivy vert, **Gitleaks encore rouge** | [run 38322821765](https://github.com/securestack-team/clinic-booking/actions/runs/38322821765) |
| 5 | Historique de la branche réécrit | Pipeline **verte** en 59 s | [run 38322924524](https://github.com/securestack-team/clinic-booking/actions/runs/38322924524) |

Extrait de la sortie du terminal à l'étape 1 (liens de contournement retirés) :

```
remote: error: GH013: Repository rule violations found for refs/heads/demo/faille.
remote:
remote: - GITHUB PUSH PROTECTION
remote:     Resolve the following violations before pushing again
remote:
remote:     - Push cannot contain secrets
remote:
remote:       —— Amazon AWS Access Key ID ——————————————————————————
remote:        locations:
remote:          - commit: c79004024e159dc83cbece7d4d346ebd6a9b5d3a
remote:            path: api/appsettings.json:4
remote:
remote:       —— Amazon AWS Secret Access Key ——————————————————————
remote:        locations:
remote:          - commit: c79004024e159dc83cbece7d4d346ebd6a9b5d3a
remote:            path: api/appsettings.json:5
remote:
 ! [remote rejected] demo/faille -> demo/faille (push declined due to repository rule violations)
error: failed to push some refs to 'github.com:securestack-team/clinic-booking.git'
```

### Ce que la répétition a appris

- **La push protection bloque la paire** (identifiant + clé secrète), **pas l'identifiant
  seul**. C'est pour cela que la démo se fait en deux temps : la paire pour montrer le blocage
  du push, l'identifiant seul pour atteindre la pipeline.
- **Supprimer un secret dans un nouveau commit ne suffit pas.** Gitleaks lit tout
  l'historique : la clé y est encore. Dans la vraie vie, il faut **révoquer** le secret, puis
  le retirer de l'historique.
- **Gitleaks scanne toutes les branches du repo**, pas seulement celle de la PR. Tant que la
  branche de démo contient le secret, **les PR des autres membres passent au rouge**. Il faut
  donc faire l'étape « vert » ou « nettoyer » tout de suite après la démo.

## 2. Avant la démo

- [ ] `ci.yml` et `security.yml` sont verts sur `main`.
- [ ] `gh auth status` fonctionne (le script ouvre la PR avec `gh`).
- [ ] Aucune modification en attente : `git status` est propre.
- [ ] La branche `demo/faille` n'existe pas déjà : `git ls-remote --heads origin demo/faille`
      ne renvoie rien.
- [ ] Le script est copié **hors du repo** (il change de branche pendant la démo) :
      `cp docs/demo/faille.sh /tmp/faille.sh`
- [ ] Trois onglets ouverts : les Pull Requests, l'onglet Actions, l'onglet Security → Code
      scanning.
- [ ] Les captures de la répétition sont prêtes, au cas où le réseau lâche.

## 3. Déroulé en direct (environ 5 minutes)

Chaque étape est une commande. Entre deux étapes, la pipeline met environ 1 minute.

### Étape 1 : le push est refusé

```bash
/tmp/faille.sh bloque
```

- **Ce qu'on voit :** `GITHUB PUSH PROTECTION … Push cannot contain secrets`.
- **Ce qu'on dit :** « Un développeur colle une clé d'accès dans la configuration. GitHub
  refuse le push : le secret n'arrive même pas sur le serveur. »
- Si le hook pre-commit est installé, il bloque encore plus tôt, dès le commit : le script le
  signale puis continue.

### Étape 2 : la pipeline devient rouge

```bash
/tmp/faille.sh rouge
```

- **Ce qu'on voit :** la PR s'ouvre ; après 1 minute, `Gitleaks (secrets)` et
  `Trivy (dependencies & config)` sont rouges et le bouton de merge est bloqué. Dans
  Security → Code scanning, deux alertes pointent `api/appsettings.json`, ligne 4.
- **Ce qu'on dit :** « Si un secret passe quand même, la pipeline le détecte avec deux outils
  différents, bloque le merge et crée une alerte. »

### Étape 3 (facultative) : supprimer ne suffit pas

```bash
/tmp/faille.sh suppression
```

- **Ce qu'on voit :** Trivy passe au vert, Gitleaks reste rouge.
- **Ce qu'on dit :** « Le fichier est propre, mais la clé est toujours dans l'historique Git.
  Un secret poussé doit être considéré comme compromis : on le révoque. »

### Étape 4 : la correction, la pipeline redevient verte

```bash
/tmp/faille.sh vert
```

- **Ce qu'on voit :** après 1 minute, tous les checks sont verts.
- **Ce qu'on dit :** « La clé est sortie du code et de l'historique. Elle sera lue depuis
  `dotnet user-secrets` en local et depuis Key Vault sur Azure. »

### Étape 5 : nettoyer

```bash
/tmp/faille.sh nettoyer
```

Ferme la PR sans la merger et supprime la branche. **À faire tout de suite après la démo.**

> Pourquoi un `push --force` à l'étape 4 ? La règle « pas de force-push » protège `main`. Sur
> une branche de travail, réécrire l'historique est la seule façon de retirer un secret.

## 4. Plan B

- Le réseau ou GitHub ne répond pas : montrer les captures de `docs/captures/` et les liens de
  la répétition (section 1).
- Le push de l'étape 1 passe au lieu d'être refusé : enchaîner directement sur l'étape 2, la
  pipeline bloquera.
- La PR existe déjà : `/tmp/faille.sh nettoyer`, puis recommencer.

## 5. Variante : injection SQL (quand l'API existera)

Le contexte de la semaine propose aussi une requête `FromSqlRaw` concaténée avec une entrée
utilisateur. Elle n'a **pas pu être testée** : il n'y a pas encore de code C# dans `/api`.
Une fois le squelette de l'API mergé :

```csharp
// Faille volontaire : entrée utilisateur concaténée dans la requête
var rows = db.Appointments.FromSqlRaw("SELECT * FROM Appointments WHERE PatientName = '" + name + "'");

// Correction : requête paramétrée
var rows = db.Appointments.FromSqlInterpolated($"SELECT * FROM Appointments WHERE PatientName = {name}");
```

Outil attendu : CodeQL C# (règle `cs/sql-injection`). Ici la correction se fait par un commit
normal, sans réécrire l'historique.

## 6. Captures à garder

Liste et noms de fichiers dans [`docs/captures/README.md`](../captures/README.md).
