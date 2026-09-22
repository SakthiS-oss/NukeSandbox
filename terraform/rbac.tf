resource "azurerm_role_assignment" "api_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.api.principal_id
}

resource "azurerm_role_assignment" "github_acr_push" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPush"
  principal_id         = azurerm_user_assigned_identity.github.principal_id
}

resource "azurerm_role_definition" "github_deployer" {
  name        = "${local.prefix}-github-deployer-${local.suffix}"
  scope       = azurerm_resource_group.main.id
  description = "Update the API Container App image. Cannot read Key Vault or start sandbox jobs."

  permissions {
    actions = [
      "Microsoft.App/containerApps/read",
      "Microsoft.App/containerApps/write",
    ]
    not_actions = []
  }

  assignable_scopes = [azurerm_resource_group.main.id]
}

resource "azurerm_role_assignment" "github_container_app" {
  scope              = azurerm_container_app.api.id
  role_definition_id = azurerm_role_definition.github_deployer.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.github.principal_id
}

resource "azurerm_role_definition" "sandbox_runner" {
  name        = "${local.prefix}-sandbox-runner-${local.suffix}"
  scope       = azurerm_resource_group.main.id
  description = "Start and read only the disposable sandbox job."

  permissions {
    actions = [
      "Microsoft.App/jobs/read",
      "Microsoft.App/jobs/start/action",
      "Microsoft.App/jobs/stop/action",
      "Microsoft.App/jobs/executions/read",
    ]
    not_actions = []
  }

  assignable_scopes = [azurerm_resource_group.main.id]
}

resource "azurerm_role_assignment" "api_sandbox_runner" {
  scope              = azurerm_container_app_job.sandbox.id
  role_definition_id = azurerm_role_definition.sandbox_runner.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.api.principal_id
}

resource "azurerm_role_assignment" "api_environment_reader" {
  scope                = azurerm_container_app_environment.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.api.principal_id
}
