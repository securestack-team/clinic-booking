# API Clinic Booking — API de Freddy

Solution ASP.NET Core .NET 10, EF Core avec PostgreSQL et tests d'intégration xUnit.

## Compiler et tester

Depuis `clinic-booking/api`, avec le SDK .NET 10 installé :

```bash
dotnet restore
dotnet build --no-restore --configuration Release
dotnet test --no-build --configuration Release --verbosity normal
```

La base de données est configurée avec `ConnectionStrings:Default`. En local, elle
doit être enregistrée avec les user-secrets :

```bash
dotnet user-secrets init --project src/ClinicBooking.Api
dotnet user-secrets set "ConnectionStrings:Default" "Host=localhost;Database=clinic_booking;Username=...;Password=..." --project src/ClinicBooking.Api
```

En conteneur, utilisez la variable d'environnement
`ConnectionStrings__Default`. La chaîne de connexion n'est jamais stockée dans
`appsettings.json`.

La clé JWT et ses paramètres sont également fournis par configuration, jamais
dans le dépôt :

```bash
dotnet user-secrets set "Jwt:Key" "<clé aléatoire d'au moins 32 octets>" --project src/ClinicBooking.Api
dotnet user-secrets set "Jwt:Issuer" "ClinicBooking.Api" --project src/ClinicBooking.Api
dotnet user-secrets set "Jwt:Audience" "ClinicBooking.Clients" --project src/ClinicBooking.Api
```

En conteneur, utilisez `Jwt__Key`, `Jwt__Issuer` et `Jwt__Audience`.

Pour créer ou appliquer les migrations :

```bash
dotnet ef database update --project src/ClinicBooking.Api
```

Ces commandes sont celles du workflow CI existant. La solution `ClinicBooking.slnx`
inclut l'API dans `src/ClinicBooking.Api` et les tests dans `tests/ClinicBooking.Api.Tests`.

Vérification locale du 13 octobre 2026 : build Release sans erreur ni avertissement,
5 tests réussis. Le rapport de cette exécution se trouve dans
`tests/ClinicBooking.Api.Tests/TestResults/api-skeleton.trx` (ignoré par Git).

## Lancer la démonstration

Depuis `clinic-booking/api` :

```bash
dotnet run --project src/ClinicBooking.Api --launch-profile http
```

| URL | Résultat attendu |
|---|---|
| http://localhost:5080/health | HTTP 200, texte `Healthy` |
| http://localhost:5080/api/ping | HTTP 200, JSON `{"message":"pong"}` |
| http://localhost:5080/swagger | Interface interactive en développement |

Le profil local utilise HTTP sur localhost pour cette démonstration sans données
sensibles. Le déploiement Azure devra servir HTTPS avec Ali. `AllowedHosts` limite
les noms d'hôte à localhost et 127.0.0.1 ; Ali devra configurer cette valeur par
variable d'environnement pour le nom d'hôte du déploiement.

## Sécurité et preuves

- Swagger est enregistré et exposé uniquement en développement : les tests
  vérifient le document et l'interface en développement, puis leur absence en production.
- `/health` indique la disponibilité du processus, sans détails internes.
- `/api/ping` retourne une réponse fixe, sans entrée utilisateur ni donnée patient.
- Le modèle `Appointment` stocke le patient, le médecin, la date et le statut ;
  ses migrations sont versionnées dans `src/ClinicBooking.Api/Migrations`.
- `POST /api/auth/register` crée un compte Patient et retourne un access token
  court ; `POST /api/auth/login` authentifie un compte existant.
- Les erreurs utilisent ProblemDetails ; HSTS est activé hors développement.
- `appsettings.json` contient uniquement les niveaux de logs et les hôtes autorisés.
- Les analyseurs Roslyn sont activés avec `latest-recommended`.

Garder une capture du résultat des tests, des deux endpoints et de Swagger,
puis de la PR et de ses checks CI/Security. Les tests prouvent le contrat HTTP et
le contrôle d'exposition de Swagger ; CodeQL et Gitleaks sont exécutés par le
workflow de sécurité existant. La démonstration d'une faille rouge → verte reste
à coordonner avec Abdedaym et Ali.

## Soumettre la PR

Depuis la racine du dépôt, après avoir relu et compris le code :

```bash
git add api
git commit -m "feat: add PostgreSQL and JWT authentication"
git push -u origin feature/postgresql-jwt-auth
```

Ouvrir une PR vers `main`, faire valider par un membre de l'équipe et vérifier
que les workflows CI et Security sont verts avant le merge.

## Vérifier PostgreSQL, les migrations et le login (docker-compose)

Depuis la racine du repo :

```bash
cp .env.example .env    # puis remplacer POSTGRES_PASSWORD et JWT_KEY (openssl rand -base64 48)
docker compose up -d --build
curl -s -H 'Content-Type: application/json' \
  -d '{"email":"patient1@example.com","password":"Str0ng!Passw0rd"}' \
  http://localhost:8080/api/auth/register
curl -s -H 'Content-Type: application/json' \
  -d '{"email":"patient1@example.com","password":"Str0ng!Passw0rd"}' \
  http://localhost:8080/api/auth/login
docker compose down
```

Les migrations sont appliquées au démarrage (`Database__MigrateOnStartup=true`, seulement dans
compose). Résultats attendus (vérifiés le 3 novembre 2026) :

| Requête | Statut |
|---|---|
| Inscription | 200 + token |
| Mot de passe faible | 400 |
| Mauvais mot de passe | 401 |
| Login | 200, token avec le rôle `Patient` |

Les mêmes cas sont couverts automatiquement par `tests/ClinicBooking.Api.Tests/Security/AuthTests.cs`
(base EF Core en mémoire).
