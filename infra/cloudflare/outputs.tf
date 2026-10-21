output "access_audience" {
  value = cloudflare_zero_trust_access_application.private_api.aud
}

output "enrollment_policy_id" {
  value = cloudflare_zero_trust_access_policy.agent_enrollment.id
}

output "access_team_domain" {
  value = "https://${var.team_name}.cloudflareaccess.com"
}

output "tunnel_name" {
  value = cloudflare_zero_trust_tunnel_cloudflared.private_api.name
}

output "api_hostname" {
  value = var.api_hostname
}

output "saas_hostname" {
  value = var.saas_hostname
}

output "guide_hostname" {
  value = var.guide_hostname
}

output "guide_tunnel_env_path" {
  value = local_sensitive_file.guide_tunnel_env.filename
}

output "dlp_profile_name" {
  value = cloudflare_zero_trust_dlp_custom_profile.agent_sensitive_data.name
}

output "access_env_path" {
  value = local_sensitive_file.access_env.filename
}

output "tunnel_env_path" {
  value = local_sensitive_file.tunnel_env.filename
}
