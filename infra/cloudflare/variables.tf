variable "account_id" {
  type      = string
  sensitive = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "account_id must be a 32-character lowercase hexadecimal ID."
  }
}

variable "zone_id" {
  type      = string
  sensitive = true
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a 32-character lowercase hexadecimal ID."
  }
}

variable "controlled_endpoint_token" {
  type      = string
  sensitive = true
  validation {
    condition     = can(regex("^ce_[A-Za-z0-9_-]{43}$", var.controlled_endpoint_token))
    error_message = "controlled_endpoint_token must be a ce_ prefix followed by 43 URL-safe characters."
  }
}

variable "zone_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9.-]+\\.[a-z]{2,}$", var.zone_name))
    error_message = "zone_name must be a DNS zone name."
  }
}

variable "team_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.team_name))
    error_message = "team_name must be the Zero Trust organization label without a hostname suffix."
  }
}

variable "api_hostname" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9.-]+\\.[a-z]{2,}$", var.api_hostname))
    error_message = "api_hostname must be a DNS hostname."
  }
}

variable "saas_hostname" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9.-]+\\.[a-z]{2,}$", var.saas_hostname))
    error_message = "saas_hostname must be a DNS hostname."
  }
}

variable "guide_hostname" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9.-]+\\.[a-z]{2,}$", var.guide_hostname))
    error_message = "guide_hostname must be a DNS hostname."
  }
}

variable "guide_allowed_email" {
  type = string
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.guide_allowed_email))
    error_message = "guide_allowed_email must be an email address."
  }
}

variable "resource_prefix" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.resource_prefix))
    error_message = "resource_prefix must be 3 to 31 lowercase letters, digits, or hyphens."
  }
}

check "hostnames_in_zone" {
  assert {
    condition = (
      endswith(var.api_hostname, ".${var.zone_name}") &&
      endswith(var.saas_hostname, ".${var.zone_name}") &&
      endswith(var.guide_hostname, ".${var.zone_name}") &&
      length(distinct([var.api_hostname, var.saas_hostname, var.guide_hostname])) == 3
    )
    error_message = "The three hostnames must be distinct subdomains of zone_name."
  }
}

variable "do_not_inspect_precedence" {
  type = number
  validation {
    condition     = var.do_not_inspect_precedence > 0
    error_message = "do_not_inspect_precedence must be positive."
  }
}

variable "dlp_block_precedence" {
  type = number
  validation {
    condition     = var.dlp_block_precedence > 0
    error_message = "dlp_block_precedence must be positive."
  }
}

check "distinct_precedences" {
  assert {
    condition     = var.do_not_inspect_precedence != var.dlp_block_precedence
    error_message = "Gateway policy precedence values must be distinct."
  }
}
