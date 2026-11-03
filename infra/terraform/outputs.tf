output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "acr_login_server" {
  description = "Adresse du registre, utilisée par la pipeline pour pousser l'image."
  value       = azurerm_container_registry.main.login_server
}
