resource "azurerm_container_app" "api" {
  name                         = "nukesandbox-api"
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.api.id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.api.id
  }

  secret {
    name                = "google-api-key"
    key_vault_secret_id = azurerm_key_vault_secret.google_api_key.versionless_id
    identity            = azurerm_user_assigned_identity.api.id
  }

  secret {
    name                = "api-key-hashes"
    key_vault_secret_id = azurerm_key_vault_secret.api_key_hashes.versionless_id
    identity            = azurerm_user_assigned_identity.api.id
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = "api"
      image  = var.api_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "SANDBOX_EXECUTION_MODE"
        value = "azure"
      }

      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.api.client_id
      }

      env {
        name  = "AZURE_SUBSCRIPTION_ID"
        value = data.azurerm_client_config.current.subscription_id
      }

      env {
        name  = "AZURE_RESOURCE_GROUP"
        value = azurerm_resource_group.main.name
      }

      env {
        name  = "AZURE_SANDBOX_JOB_NAME"
        value = azurerm_container_app_job.sandbox.name
      }

      env {
        name  = "AZURE_CONTAINER_APP_ENVIRONMENT_ID"
        value = azurerm_container_app_environment.main.id
      }

      env {
        name  = "API_AUTH_REQUIRED"
        value = "true"
      }

      env {
        name        = "GOOGLE_API_KEY"
        secret_name = "google-api-key"
      }

      env {
        name        = "API_KEY_HASHES"
        secret_name = "api-key-hashes"
      }

      liveness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/health"
      }

      readiness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/ready"
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].container[0].image,
    ]
  }
}

resource "azurerm_container_app_job" "sandbox" {
  name                         = "nukesandbox-sandbox"
  location                     = azurerm_resource_group.main.location
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  replica_timeout_in_seconds   = 15
  replica_retry_limit          = 0
  tags                         = local.tags

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      name    = "curl"
      image   = var.sandbox_image
      cpu     = 0.25
      memory  = "0.5Gi"
      command = ["curl"]
      args    = ["--version"]
    }
  }
}
