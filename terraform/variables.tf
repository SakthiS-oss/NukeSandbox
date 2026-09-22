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
  type        = number
  default     = 0
  description = "API scale-to-zero default keeps the Consumption plan idle-cost at zero."
}

variable "max_replicas" {
  type        = number
  default     = 1
  description = "Cap replicas at one to avoid surprise Consumption scale-out."
}
