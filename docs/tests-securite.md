# Tests de sécurité de l'API : plan

| | |
|---|---|
| **Pratique** | Automated Security Testing (Tier 1) |
| **Responsables** | Abdedaym CHAKRA, avec Freddy (API) |
| **Où** | `api/tests/ClinicBooking.Api.Tests/Security/` (xUnit + `WebApplicationFactory`) |
| **Quand ils tournent** | À chaque Pull Request, dans le job « Build & Test (.NET) » de `ci.yml` |

Le principe : chaque menace du threat model qui touche l'API a **au moins un test** qui
échoue si le contrôle disparaît. Un test rouge bloque la PR, comme un scanner.

---

## 1. Déjà en place

Ces tests ne dépendent pas du login. Ils protègent ce qui existe déjà dans le squelette.

| Test | Ce qu'il vérifie | Menace |
|---|---|---|
| `Swagger_InProduction_IsNotExposed` (Freddy) | Swagger renvoie 404 en production | API8:2023 Security Misconfiguration |
| `UnknownHost_IsRejected` | Un en-tête `Host` inconnu renvoie **400** | Host header falsifié |
| `AllowedHost_IsServed` | `localhost` et `127.0.0.1` sont servis (le test précédent ne passe pas « par hasard ») | — |
| `AllowedHosts_FromConfiguration_IsApplied` | `AllowedHosts` venant de la configuration est bien appliqué (nécessaire sur Azure) | API8:2023 |
| `UnhandledError_InProduction_ReturnsProblemDetailsWithoutInternals` | Une exception renvoie un ProblemDetails 500 **sans** message interne, nom d'exception ni pile d'appels | A10:2025 Mishandling of Exceptional Conditions |
| `UnknownRoute_Returns404WithoutBody` | Une route inconnue renvoie 404 sans contenu | A02:2025 Security Misconfiguration |
| `Https_InProduction_SendsHsts` | L'en-tête `Strict-Transport-Security` est envoyé en HTTPS hors développement | A04:2025 Cryptographic Failures |
| `CrossOriginRequest_FromUnknownSite_IsNotAllowed` | Un site inconnu n'obtient jamais `Access-Control-Allow-Origin` (requête simple et pré-requête) | A02:2025 |

## 2. À écrire dès que le login JWT existe

Les numéros T renvoient au threat model (`docs/threat-model-v1.md`).

### 401 : authentification

| Test | Requête | Attendu | Menace |
|---|---|---|---|
| Sans token | `GET /api/appointments` sans en-tête `Authorization` | 401 | T3 |
| Token signé avec une autre clé | JWT valide en apparence, signé avec une clé aléatoire | 401 | T11 |
| Token expiré | JWT signé avec la bonne clé, `exp` dans le passé (au-delà du `ClockSkew`) | 401 | T11 |
| `alg: none` | JWT non signé | 401 | T11 |
| Mauvais émetteur / audience | `iss` ou `aud` différents de la configuration | 401 | T11 |
| Refresh token réutilisé | Le même refresh token utilisé deux fois | 401 la seconde fois | T12 |
| Énumération | Login avec un email inconnu, puis avec un mauvais mot de passe | Même code (401), même corps | T14 |

### 403 : autorisation

| Test | Requête | Attendu | Menace |
|---|---|---|---|
| BOLA en lecture | Patient A lit `GET /api/appointments/{id du rendez-vous de B}` | 403 (ou 404, à décider avec Freddy) | T1 |
| BOLA en écriture | Patient A annule ou modifie le rendez-vous de B | 403 / 404, et le rendez-vous de B n'a pas changé | T1 |
| BFLA | Un patient appelle un endpoint réservé au médecin ou à l'admin | 403 | T5 |
| Rôle à l'inscription | `POST /api/auth/register` avec `"role": "Admin"` | Compte créé avec le rôle **Patient** | T13 |

### 400 : entrées invalides

| Test | Requête | Attendu | Menace |
|---|---|---|---|
| Email invalide | `register` avec `email = "pas-un-email"` | 400 ProblemDetails | — |
| Mot de passe faible | `register` avec `"123"` | 400 | T15 |
| Champ manquant | `POST /api/appointments` sans date | 400 | — |
| Date passée | Rendez-vous dans le passé | 400 | — |
| Identifiant mal formé | `GET /api/appointments/abc` | 400 ou 404, jamais 500 | A10:2025 |

### 429 : limitation de débit (quand Freddy ajoute le rate limiting)

| Test | Requête | Attendu | Menace |
|---|---|---|---|
| Force brute | N+1 tentatives de login en moins d'une minute | 429 à partir de la N+1ᵉ | T3, T6 |

## 3. Ce dont j'ai besoin de Freddy

Pour écrire ces tests sans deviner :

1. **Les routes exactes** : login, register, refresh, rendez-vous (lecture, création,
   annulation), endpoints réservés au médecin et à l'admin.
2. **Le format des corps** : champs de `register` et `login`, nom du champ qui contient
   l'access token et le refresh token dans la réponse.
3. **Les noms de rôles** (`Patient`, `Doctor`, `Admin` ?).
4. **Les clés de configuration JWT** (par exemple `Jwt:Issuer`, `Jwt:Audience`,
   `Jwt:SigningKey`) et la durée de vie du token. Les tests les remplacent par des valeurs de
   test **générées à l'exécution** : aucune clé n'est écrite dans le repo.
5. **La base en test** : EF Core InMemory, SQLite en mémoire, ou PostgreSQL via
   Testcontainers (Docker est disponible sur `ubuntu-latest`).
6. **Comment créer un utilisateur de test** : via `register`, ou un seed réservé aux tests.
7. **BOLA : 403 ou 404 ?** 404 ne révèle pas que le rendez-vous existe ; 403 est ce que
   demande la consigne. Il faut choisir une règle et l'appliquer partout.

## 4. Comment ce sera construit

- Une fabrique `SecurityApiFactory` (dérivée de `WebApplicationFactory<Program>`) qui
  remplace la base par une base de test et la configuration JWT par une clé aléatoire.
- Un utilitaire `TestTokens` qui fabrique des tokens valides, expirés, mal signés ou sans
  signature, avec la même bibliothèque que l'API.
- Deux utilisateurs de test (patient A, patient B) et un médecin, créés au début de chaque
  classe de tests.
- Les tests restent rapides (pas de vrai réseau) pour tourner à chaque PR.

## 5. Preuves pour le rapport

- La sortie de `dotnet test` dans le job « Build & Test (.NET) » (nombre de tests de sécurité).
- Une capture d'une PR où un test de sécurité échoue (par exemple `[Authorize]` retiré
  volontairement sur une branche de démonstration), puis la même PR verte après correction.
