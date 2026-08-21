resource "kubernetes_namespace_v1" "nukesandbox" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of"          = "nukesandbox"
      "pod-security.kubernetes.io/enforce" = "restricted"
    }
  }
}

resource "kubernetes_service_account_v1" "api" {
  metadata {
    name      = "nukesandbox-api"
    namespace = kubernetes_namespace_v1.nukesandbox.metadata[0].name
  }
}

resource "kubernetes_role_v1" "sandbox_runner" {
  metadata {
    name      = "sandbox-runner"
    namespace = kubernetes_namespace_v1.nukesandbox.metadata[0].name
  }

  rule {
    api_groups = [""]
    resources  = ["pods"]
    verbs      = ["create", "get", "delete"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods/log"]
    verbs      = ["get"]
  }
}

resource "kubernetes_role_binding_v1" "sandbox_runner" {
  metadata {
    name      = "sandbox-runner"
    namespace = kubernetes_namespace_v1.nukesandbox.metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.sandbox_runner.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account_v1.api.metadata[0].name
    namespace = kubernetes_namespace_v1.nukesandbox.metadata[0].name
  }
}

resource "kubernetes_resource_quota_v1" "sandbox" {
  metadata {
    name      = "sandbox-limits"
    namespace = kubernetes_namespace_v1.nukesandbox.metadata[0].name
  }

  spec {
    hard = {
      "pods"            = "20"
      "requests.cpu"    = "2"
      "requests.memory" = "2Gi"
      "limits.cpu"      = "4"
      "limits.memory"   = "4Gi"
    }
  }
}
