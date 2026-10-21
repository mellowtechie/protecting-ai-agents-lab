resource "cloudflare_zero_trust_access_policy" "guide_operator" {
  account_id = var.account_id
  name       = "${var.resource_prefix}-guide-operator"
  decision   = "allow"
  include = [{
    email = { email = var.guide_allowed_email }
  }]
}

resource "cloudflare_zero_trust_access_application" "guide" {
  account_id           = var.account_id
  name                 = "${var.resource_prefix}-guide"
  type                 = "self_hosted"
  domain               = var.guide_hostname
  session_duration     = "8h"
  app_launcher_visible = false
  destinations = [{
    type = "public"
    uri  = var.guide_hostname
  }]
  policies = [{
    id         = cloudflare_zero_trust_access_policy.guide_operator.id
    precedence = 1
  }]
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "guide" {
  account_id = var.account_id
  name       = "${var.resource_prefix}-guide"
  config_src = "cloudflare"
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "guide" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.guide.id
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "guide" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.guide.id
  source     = "cloudflare"
  config = {
    ingress = [
      {
        hostname = var.guide_hostname
        service  = "http://127.0.0.1:8765"
      },
      {
        service = "http_status:404"
      }
    ]
  }
}

resource "cloudflare_dns_record" "guide" {
  zone_id = var.zone_id
  name    = var.guide_hostname
  content = "${cloudflare_zero_trust_tunnel_cloudflared.guide.id}.cfargotunnel.com"
  type    = "CNAME"
  ttl     = 1
  proxied = true
  comment = "${var.resource_prefix} Access-protected guide"
}
