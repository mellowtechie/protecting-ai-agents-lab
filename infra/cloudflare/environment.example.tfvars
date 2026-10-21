account_id                = "00000000000000000000000000000000"
zone_id                   = "00000000000000000000000000000000"
controlled_endpoint_token = "ce_replace_with_43_url_safe_random_characters_here"
zone_name                 = "example.com"
team_name                 = "your-zero-trust-team"
api_hostname              = "agent-api.example.com"
saas_hostname             = "agent-saas.example.com"
guide_hostname            = "agent-guide.example.com"
guide_allowed_email       = "operator@example.com"
resource_prefix           = "demo-agent"

# Replace both invalid sentinels with distinct positive values selected from a fresh preflight.
do_not_inspect_precedence = -1
dlp_block_precedence      = -2
