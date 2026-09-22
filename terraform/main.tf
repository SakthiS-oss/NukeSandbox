resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  prefix = var.name_prefix
  suffix = random_string.suffix.result
  tags = {
    app         = "nukesandbox"
    environment = "azure"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.prefix}-${local.suffix}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.prefix}-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 7
  tags                = local.tags
}

resource "azurerm_container_registry" "main" {
  name                = "${replace(local.prefix, "-", "")}${local.suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}

resource "azurerm_container_app_environment" "main" {
  name                       = "cae-${local.prefix}-${local.suffix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  tags                       = local.tags
}

resource "azurerm_user_assigned_identity" "api" {
  name                = "id-${local.prefix}-api"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "github" {
  name                = "id-${local.prefix}-github"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}
