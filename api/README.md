# API Clinic Booking — squelette de Freddy

Solution ASP.NET Core .NET 10 et tests d'intégration xUnit pour la présentation du
14 octobre 2026. Aucun secret ni accès à une base de données n'est nécessaire.

## Compiler et tester

Depuis `clinic-booking/api`, avec le SDK .NET 10 installé :

```bash
dotnet restore
dotnet build --no-restore --configuration Release
dotnet test --no-build --configuration Release --verbosity normal
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
git commit -m "feat: add API skeleton with integration tests"
git push -u origin feature/api-skeleton
```

Ouvrir une PR vers `main`, faire valider par un membre de l'équipe et vérifier
que les workflows CI et Security sont verts avant le merge.
