resource "local_sensitive_file" "access_env" {
  filename             = "${path.module}/.secrets/access.env"
  file_permission      = "0600"
  directory_permission = "0700"
  content              = <<-EOT
    CF_ACCESS_CLIENT_ID=${cloudflare_zero_trust_access_service_token.agent_access.client_id}
    CF_ACCESS_CLIENT_SECRET=${cloudflare_zero_trust_access_service_token.agent_access.client_secret}
    CONTROLLED_ENDPOINT_TOKEN=${var.controlled_endpoint_token}
    CLOUDFLARE_ACCOUNT_ID=${var.account_id}
    DEMO_AGENT_API_URL=https://${var.api_hostname}/inventory
    DEMO_AGENT_SAAS_URL=https://${var.saas_hostname}/ingest
  EOT
}

resource "local_sensitive_file" "worker_env" {
  filename             = "${path.module}/.secrets/worker.env"
  file_permission      = "0600"
  directory_permission = "0700"
  content              = <<-EOT
    CONTROLLED_ENDPOINT_TOKEN=${var.controlled_endpoint_token}
    CLOUDFLARE_ACCOUNT_ID=${var.account_id}
  EOT
}

resource "local_sensitive_file" "tunnel_env" {
  filename             = "${path.module}/.secrets/tunnel.env"
  file_permission      = "0600"
  directory_permission = "0700"
  content              = "TUNNEL_TOKEN=${data.cloudflare_zero_trust_tunnel_cloudflared_token.private_api.token}\n"
}

resource "local_sensitive_file" "guide_tunnel_env" {
  filename             = "${path.module}/.secrets/live-guide.env"
  file_permission      = "0600"
  directory_permission = "0700"
  content              = "TUNNEL_TOKEN=${data.cloudflare_zero_trust_tunnel_cloudflared_token.guide.token}\n"
}

resource "local_sensitive_file" "warp_mdm" {
  filename             = "${path.module}/.secrets/mdm.xml"
  file_permission      = "0600"
  directory_permission = "0700"
  content              = <<-EOT
    <dict>
      <key>auth_client_id</key>
      <string>${cloudflare_zero_trust_access_service_token.agent_enrollment.client_id}</string>
      <key>auth_client_secret</key>
      <string>${cloudflare_zero_trust_access_service_token.agent_enrollment.client_secret}</string>
      <key>auto_connect</key>
      <integer>1</integer>
      <key>onboarding</key>
      <false/>
      <key>organization</key>
      <string>${var.team_name}</string>
      <key>service_mode</key>
      <string>warp</string>
    </dict>
  EOT
}
