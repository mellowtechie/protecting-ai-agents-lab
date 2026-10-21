# AI assistant instructions for this lab

Read `README.md` before making changes or deploying. This repository is a reusable synthetic lab. Use the requester's own Cloudflare account, zone, hosts, and credentials; never copy values from another installation.

## Build and verification order

1. Run the component tests from `README.md`. For the agent alone, `docker build --target test -t protecting-ai-agents-test -f Dockerfile.agent .` and `docker run --rm protecting-ai-agents-test` are also supported.
2. Run `python3 scripts/configure-lab.py` with the operator's supplied account and host values. Check for existing DNS records, Gateway precedence collisions, Access policies, and product entitlements before applying Terraform.
3. Review `terraform plan` with a human before `apply`. Account-level One Client enrollment, Gateway root trust, TLS inspection, and management-network exclusions require the account administrator's decisions.
4. Use either the native agent service or the optional Docker guide on the enrolled Ubuntu host. Both serve port 8765 on loopback; never start both at once. The Docker path does not replace One Client, Cloudflare Tunnel, Access, or the private API guest.
5. Run the six CLI modes and inspect Access, Gateway, and controlled Worker evidence in a bounded UTC window. A CLI status or 302 redirect alone is not proof of DLP non-delivery.

Never print, commit, or paste `.secrets/`, `.env`, Terraform state/plans, private keys, service tokens, Tunnel tokens, raw request bodies, or customer data into generated output. Keep the browser guide protected by Cloudflare Access before making its Tunnel reachable.
