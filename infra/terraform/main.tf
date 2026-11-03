locals {
  name = "${var.project}-${var.environment}"
  tags = merge({
    project     = var.project
    environment = var.environment
    managed_by  = "terraform"
  }, var.tags)
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

# Registre des images Docker de l'API. AKS y accédera par identité managée (AcrPull) :
# pas de compte admin, donc aucun mot de passe de registre à stocker.
resource "azurerm_container_registry" "main" {
  #checkov:skip=CKV_AZURE_139:L'accès privé (Private Link) exige le SKU Premium, hors budget Azure for Students
  #checkov:skip=CKV_AZURE_163:Le scan des images est fait par Trivy dans la pipeline avant le push
  #checkov:skip=CKV_AZURE_164:La signature d'images (trust policy) exige le SKU Premium ; Cosign prévu en bonus
  #checkov:skip=CKV_AZURE_165:La géo-réplication exige le SKU Premium, inutile pour un projet académique
  #checkov:skip=CKV_AZURE_166:La quarantaine exige le SKU Premium ; Trivy bloque déjà les images vulnérables
  #checkov:skip=CKV_AZURE_167:La politique de rétention exige le SKU Premium
  #checkov:skip=CKV_AZURE_233:La redondance de zone exige le SKU Premium
  #checkov:skip=CKV_AZURE_237:Les data endpoints dédiés exigent le SKU Premium
  name                = replace("acr${local.name}", "-", "")
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}
