variable "location" {
  type        = string
  default     = "eastus"
  description = "Azure region for the Container Apps environment, ACR, and Key Vault."
}

variable "name_prefix" {
  type        = string
  default     = "nukesandbox"
  description = "Prefix for Azure resource names. ACR and Key Vault append a random suffix for global uniqueness."
}

variable "github_repository" {
  type        = string
  default     = "SakthiS-oss/NukeSandbox"
  description = "GitHub owner/name used for OIDC federated credentials."
}

variable "google_api_key" {
  type        = string
  sensitive   = true
  description = "Gemini API key stored in Key Vault and injected into the Container App. Never commit this value."
}

variable "api_key_hashes" {
  type        = string
  sensitive   = true
  default     = "{}"
  description = "JSON map of identity to SHA-256 API-key digest, stored in Key Vault as API_KEY_HASHES."
}

variable "api_image" {
  type        = string
  default     = "mcr.microsoft.com/k8se/quickstart:latest"
  description = "Initial Container App image. CI replaces this with a digest-pinned ACR image after the first build."
}

variable "sandbox_image" {
  type        = string
  default     = "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"
  description = "Digest-pinned curl image used by the disposable Container Apps Job."
}

variable "min_replicas" {
  type    = number
  default = 1
}

variable "max_replicas" {
  type    = number
  default = 3
}
