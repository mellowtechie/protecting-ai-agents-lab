resource "cloudflare_zero_trust_access_service_token" "agent_access" {
  account_id = var.account_id
  name       = "${var.resource_prefix}-access"
  duration   = "8760h"
  enabled    = true
  lifecycle { create_before_destroy = true }
}

resource "cloudflare_zero_trust_access_service_token" "agent_enrollment" {
  account_id = var.account_id
  name       = "${var.resource_prefix}-enrollment"
  duration   = "8760h"
  enabled    = true
  lifecycle { create_before_destroy = true }
}

resource "cloudflare_zero_trust_access_policy" "agent_service_auth" {
  account_id = var.account_id
  name       = "${var.resource_prefix}-service-auth"
  decision   = "non_identity"
  include = [{
    service_token = { token_id = cloudflare_zero_trust_access_service_token.agent_access.id }
  }]
  require = [{
    common_name = { common_name = "demo-agent" }
  }]
}

resource "cloudflare_zero_trust_access_policy" "agent_enrollment" {
  account_id = var.account_id
  name       = "${var.resource_prefix}-enrollment"
  decision   = "non_identity"
  include = [{
    service_token = { token_id = cloudflare_zero_trust_access_service_token.agent_enrollment.id }
  }]
}

resource "cloudflare_zero_trust_access_application" "private_api" {
  account_id                = var.account_id
  name                      = "${var.resource_prefix}-private-api"
  type                      = "self_hosted"
  domain                    = var.api_hostname
  session_duration          = "1h"
  app_launcher_visible      = false
  service_auth_401_redirect = false
  destinations = [{
    type = "public"
    uri  = var.api_hostname
  }]
  policies = [{
    id         = cloudflare_zero_trust_access_policy.agent_service_auth.id
    precedence = 1
  }]
}

resource "cloudflare_zero_trust_access_mtls_certificate" "demo_ca" {
  account_id           = var.account_id
  name                 = "${var.resource_prefix}-ca"
  certificate          = sensitive(file("${path.module}/../pki/.secrets/root-ca.crt"))
  associated_hostnames = [var.api_hostname]
}
