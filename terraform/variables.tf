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
  default     = "curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93"
  description = "Upstream curl image imported into this registry. The job pulls the ACR copy of this digest, not Docker Hub."
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
