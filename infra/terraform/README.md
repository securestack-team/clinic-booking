# Infrastructure Azure (Terraform)

Pour l'instant : un resource group et un Azure Container Registry. AKS et PostgreSQL
viendront ensuite.

| Fichier | Rôle |
|---|---|
| `versions.tf` | Version de Terraform, provider `azurerm` 5.10.x, backend distant |
| `variables.tf` | `project`, `environment` (staging / prod), `location`, `tags` |
| `main.tf` | Resource group + registre d'images (sans compte admin) |
| `outputs.tf` | Nom du resource group, adresse du registre |
| `.terraform.lock.hcl` | Versions exactes des providers (commité, comme un lockfile) |

## Vérifier sans rien créer sur Azure

```bash
terraform fmt -check
terraform init -backend=false
terraform validate
```

## Sécurité

- **Aucun secret** dans ces fichiers.
  - Le state est stocké dans un storage account Azure (`backend.hcl`, non commité, voir
    `backend.hcl.example`).
  - La pipeline se connecte à Azure par OIDC.
- **Registre sans compte admin** : AKS y accédera par identité managée (rôle `AcrPull`).
- **Checkov** : 0 échec. Les 8 contrôles ignorés concernent des fonctions réservées au SKU
  Premium (Private Link, géo-réplication, quarantaine, signature…). Chaque raison est écrite
  à côté de la ressource (`#checkov:skip`). Le scan des images est assuré par Trivy dans la
  pipeline.
