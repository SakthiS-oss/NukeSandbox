variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}

variable "kubeconfig_context" {
  type    = string
  default = null
}

variable "namespace" {
  type    = string
  default = "nukesandbox"
}
