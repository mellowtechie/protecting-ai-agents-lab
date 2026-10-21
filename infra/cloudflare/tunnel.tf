resource "cloudflare_zero_trust_tunnel_cloudflared" "private_api" {
  account_id = var.account_id
  name       = "${var.resource_prefix}-private-api"
  config_src = "cloudflare"
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "private_api" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.private_api.id
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "private_api" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.private_api.id
  source     = "cloudflare"
  config = {
    ingress = [
      {
        hostname = var.api_hostname
        service  = "http://127.0.0.1:8000"
      },
      {
        service = "http_status:404"
      }
    ]
  }
}

resource "cloudflare_dns_record" "private_api" {
  zone_id = var.zone_id
  name    = var.api_hostname
  content = "${cloudflare_zero_trust_tunnel_cloudflared.private_api.id}.cfargotunnel.com"
  type    = "CNAME"
  ttl     = 1
  proxied = true
  comment = "${var.resource_prefix} private API tunnel"
}
