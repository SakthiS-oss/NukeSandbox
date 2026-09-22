output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "location" {
  value = azurerm_resource_group.main.location
}

output "acr_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "acr_name" {
  value = azurerm_container_registry.main.name
}

output "container_app_fqdn" {
  value = azurerm_container_app.api.ingress[0].fqdn
}

output "container_app_name" {
  value = azurerm_container_app.api.name
}

output "sandbox_job_name" {
  value = azurerm_container_app_job.sandbox.name
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "github_client_id" {
  value       = azurerm_user_assigned_identity.github.client_id
  description = "Set this as the GitHub Actions secret AZURE_CLIENT_ID for OIDC login."
}

output "azure_tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "azure_subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}
