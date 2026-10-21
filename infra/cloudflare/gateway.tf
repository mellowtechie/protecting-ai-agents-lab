resource "cloudflare_zero_trust_gateway_policy" "api_do_not_inspect" {
  account_id  = var.account_id
  name        = "${var.resource_prefix}-api-do-not-inspect"
  description = "Preserve end-to-end mTLS for the demo agent private API"
  action      = "off"
  enabled     = true
  filters     = ["http"]
  precedence  = var.do_not_inspect_precedence
  traffic     = "http.conn.hostname == \"${var.api_hostname}\""
}

resource "cloudflare_zero_trust_dlp_custom_profile" "agent_sensitive_data" {
  account_id          = var.account_id
  name                = "${var.resource_prefix} sensitive data"
  description         = "Synthetic protected marker used only by the demo agent"
  allowed_match_count = 0
}

resource "cloudflare_zero_trust_dlp_custom_entry" "protected_marker" {
  account_id  = var.account_id
  profile_id  = cloudflare_zero_trust_dlp_custom_profile.agent_sensitive_data.id
  name        = "${var.resource_prefix} protected marker"
  description = "Matches the synthetic ACME demo marker"
  enabled     = true
  pattern = {
    regex = "ACME-SECRET-[0-9]{8}"
  }
}

resource "cloudflare_zero_trust_gateway_policy" "saas_dlp_block" {
  account_id  = var.account_id
  name        = "${var.resource_prefix}-saas-dlp-block"
  description = "Block synthetic protected marker sent to the controlled mock SaaS"
  action      = "block"
  enabled     = true
  filters     = ["http"]
  precedence  = var.dlp_block_precedence
  traffic     = "http.request.host == \"${var.saas_hostname}\" and http.request.method == \"POST\" and any(dlp.profiles[*] in {\"${cloudflare_zero_trust_dlp_custom_profile.agent_sensitive_data.id}\"})"
  rule_settings = {
    block_reason = "Synthetic demo data blocked by DLP"
    payload_log  = { enabled = false }
  }
  depends_on = [cloudflare_zero_trust_dlp_custom_entry.protected_marker]
}
