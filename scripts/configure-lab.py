#!/usr/bin/env python3
"""Create ignored lab configuration and a fresh controlled-endpoint token."""

import argparse
import json
import os
import re
import secrets
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("account-id", "zone-id", "zone-name", "team-name", "api-hostname", "saas-hostname", "guide-hostname", "guide-allowed-email"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--resource-prefix", default="demo-agent")
    parser.add_argument("--do-not-inspect-precedence", type=int, required=True)
    parser.add_argument("--dlp-block-precedence", type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{32}", args.account_id) or not re.fullmatch(r"[0-9a-f]{32}", args.zone_id):
        parser.error("account and zone IDs must be 32 lowercase hexadecimal characters")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", args.zone_name):
        parser.error("zone name must be a DNS name")
    hosts = (args.api_hostname, args.saas_hostname, args.guide_hostname)
    if len(set(hosts)) != 3 or any(not host.endswith("." + args.zone_name) for host in hosts):
        parser.error("hostnames must be distinct subdomains of the zone")
    if not re.fullmatch(r"[a-z0-9-]+", args.team_name):
        parser.error("team name must be a Zero Trust organization label")
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,30}", args.resource_prefix):
        parser.error("resource prefix must be 3 to 31 lowercase letters, digits, or hyphens")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", args.guide_allowed_email):
        parser.error("guide operator must be an email address")
    if args.do_not_inspect_precedence <= 0 or args.dlp_block_precedence <= 0 or args.do_not_inspect_precedence == args.dlp_block_precedence:
        parser.error("Gateway precedences must be distinct positive values")

    root = Path(__file__).resolve().parents[1]
    secrets_dir = root / "infra" / "cloudflare" / ".secrets"
    tfvars = root / "infra" / "cloudflare" / "environment.auto.tfvars"
    token_path = secrets_dir / "controlled-endpoint-token"
    worker_config = root / "demo" / "mock-saas" / "wrangler.deploy.jsonc"
    if any(path.exists() or path.is_symlink() for path in (tfvars, token_path, worker_config)):
        parser.error("configuration already exists; preserve it and edit the ignored files deliberately")
    secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if secrets_dir.is_symlink() or (secrets_dir.stat().st_mode & 0o077):
        parser.error("secrets directory must be private and must not be a symlink")
    token = "ce_" + secrets.token_urlsafe(32)
    values = {
        "account_id": args.account_id,
        "zone_id": args.zone_id,
        "controlled_endpoint_token": token,
        "zone_name": args.zone_name,
        "team_name": args.team_name,
        "api_hostname": args.api_hostname,
        "saas_hostname": args.saas_hostname,
        "guide_hostname": args.guide_hostname,
        "guide_allowed_email": args.guide_allowed_email,
        "resource_prefix": args.resource_prefix,
        "do_not_inspect_precedence": args.do_not_inspect_precedence,
        "dlp_block_precedence": args.dlp_block_precedence,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for path, content in (
        (tfvars, "".join(f"{key} = {json.dumps(value)}\n" for key, value in values.items())),
        (token_path, token + "\n"),
    ):
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w") as file:
            file.write(content)
    worker = json.loads((root / "demo" / "mock-saas" / "wrangler.jsonc").read_text())
    worker["name"] = f"{args.resource_prefix}-mock-saas"
    worker["routes"] = [{"pattern": args.saas_hostname, "custom_domain": True}]
    worker_config.write_text(json.dumps(worker, indent=2) + "\n")
    print("Created ignored Terraform configuration, Worker configuration, and controlled-endpoint token.")


if __name__ == "__main__":
    main()
