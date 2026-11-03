terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.10.0"
    }
  }

  # State distant dans un storage account Azure (jamais commité).
  # terraform init -backend-config=backend.hcl   (voir backend.hcl.example)
  backend "azurerm" {}
}

provider "azurerm" {
  features {}
  # Abonnement lu depuis ARM_SUBSCRIPTION_ID ; en CI, connexion OIDC (aucun secret stocké).
}
