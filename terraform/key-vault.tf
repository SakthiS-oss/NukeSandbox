resource "azurerm_key_vault" "main" {
  name                       = "kv${replace(local.prefix, "-", "")}${local.suffix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  rbac_authorization_enabled = true
  tags                       = local.tags
}

resource "azurerm_role_assignment" "terraform_kv_officer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "api_kv_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.api.principal_id
}

# Placeholder values only. Set the real secrets with Azure CLI after apply so
# they never enter Terraform state. See docs/azure.md.
resource "azurerm_key_vault_secret" "google_api_key" {
  name         = "google-api-key"
  value        = "REPLACE_ME"
  key_vault_id = azurerm_key_vault.main.id

  lifecycle {
    ignore_changes = [value]
  }

  depends_on = [azurerm_role_assignment.terraform_kv_officer]
}

resource "azurerm_key_vault_secret" "api_key_hashes" {
  name         = "api-key-hashes"
  value        = "{}"
  key_vault_id = azurerm_key_vault.main.id

  lifecycle {
    ignore_changes = [value]
  }

  depends_on = [azurerm_role_assignment.terraform_kv_officer]
}
