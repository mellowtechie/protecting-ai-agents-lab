# Protecting AI agents lab

Deploy a synthetic agent workload that demonstrates two Cloudflare One boundaries: Access protects a private API using a service token and client certificate; Gateway inspects the agent's outbound traffic and DLP blocks a protected marker before it reaches a controlled Worker. The six fixed commands are `identity`, `no-auth`, `token-only`, `authorized`, `send-safe`, and `send-raw`.

This repository contains the agent, private API, controlled Worker, certificate issuer, Cloudflare Terraform, guest installers, Access-protected browser guide, and component tests. It contains no credentials, Terraform state, live customer data, or resources from the original presentation lab.

## Requirements

- A Cloudflare account with Zero Trust, Access, Gateway HTTP filtering and TLS inspection, DLP custom profiles, Workers, and a DNS zone you control. Check product entitlements and billing before creating resources.
- An existing Zero Trust organization and enrollment configuration. The operator must be allowed to attach a new enrollment policy and install the account's Gateway root certificate on the agent VM.
- Two reachable Linux guests: Ubuntu 24.04 amd64 for the agent and Debian 13 amd64 for the private API. They can run on Proxmox or another hypervisor. SSH/console management is required; the origin API and guide listen only on loopback.
- Python 3.12, Node.js 22, npm, Terraform 1.8 or newer, `step` CLI, and OpenSSL on the operator machine. The guests install their own runtime dependencies.
- A scoped Cloudflare API token for the resources in `infra/cloudflare/`, and Wrangler authorization for the same account. Use a protected shell/session for credentials.

## 1. Preflight

Choose three unused subdomains in one zone: private API, controlled endpoint, and guide. Choose a unique `resource_prefix` and two unused positive Gateway policy precedences. Confirm that existing Gateway rules will not shadow the lab rules, and that TLS inspection is enabled for the controlled endpoint. The private API gets an exact-host Do Not Inspect rule so its client certificate reaches Access. Keep this demo separate from production application hostnames and policies.

Clone this repository to the operator machine. Generate local configuration with `scripts/configure-lab.py`:

```sh
python3 scripts/configure-lab.py \
  --account-id YOUR_32_HEX_ACCOUNT_ID \
  --zone-id YOUR_32_HEX_ZONE_ID \
  --zone-name example.com \
  --team-name your-zero-trust-team \
  --api-hostname agent-api.example.com \
  --saas-hostname agent-saas.example.com \
  --guide-hostname agent-guide.example.com \
  --guide-allowed-email operator@example.com \
  --do-not-inspect-precedence 110 \
  --dlp-block-precedence 120
```

The command creates ignored `infra/cloudflare/environment.auto.tfvars`, a private controlled-endpoint token, and ignored `demo/mock-saas/wrangler.deploy.jsonc`. It refuses to replace an existing configuration. Read [the example variables](infra/cloudflare/environment.example.tfvars) for each field. Keep `infra/cloudflare/.secrets/` and `infra/pki/.secrets/` off Git and restrict the repository checkout to your operator account.

## 2. Issue the demo certificate and deploy Cloudflare configuration

Run the one-time PKI issuer before Terraform. It creates a disposable CA and client certificate; the CA private key stays on the operator machine.

```sh
bash infra/pki/issue-fixtures.sh
```

Set a restrictive shell umask and authenticate the Cloudflare provider without writing the API token into the repository. Review the Terraform plan before applying it:

```sh
umask 077
terraform -chdir=infra/cloudflare init
terraform -chdir=infra/cloudflare validate
terraform -chdir=infra/cloudflare plan -out=.secrets/apply.tfplan
terraform -chdir=infra/cloudflare apply .secrets/apply.tfplan
```

Terraform creates Access policies and apps, both Tunnels and DNS records, a DLP profile and Gateway rules, and ignored guest environment files. It also creates a service token for headless One Client enrollment. State and saved plans contain credentials: keep them private and use an encrypted remote backend if sharing operation. Do not commit them. This lab does not modify the existing WARP enrollment application or global Gateway TLS settings; complete those account-level steps below.

## 3. Install the private API guest

Stage a checkout on the Debian 13 origin guest, then run `sudo bash scripts/install-origin.sh`. The installer creates a restricted service user, installs the API and `cloudflared`, and registers systemd units. It does not start the Tunnel.

On the operator machine, get the runtime values from Terraform and create an ignored file using a restrictive umask:

```sh
umask 077
team_domain=$(terraform -chdir=infra/cloudflare output -raw access_team_domain)
audience=$(terraform -chdir=infra/cloudflare output -raw access_audience)
printf 'ACCESS_TEAM_DOMAIN=%s\nACCESS_AUDIENCE=%s\n' "$team_domain" "$audience" > infra/cloudflare/.secrets/runtime.env
```

Transfer `runtime.env` to `/etc/demo-private-api/runtime.env` and `infra/cloudflare/.secrets/tunnel.env` to `/etc/cloudflared/tunnel.env` using your protected management channel. Both guest files must be root-owned mode `0600`. Start the API first, require `/readyz` to return 200, then start the Tunnel:

```sh
sudo systemctl enable --now demo-private-api.service
curl -fsS http://127.0.0.1:8000/readyz
sudo systemctl enable --now demo-cloudflared.service
```

## 4. Install the controlled Worker

Run `npm ci` in `demo/mock-saas`, then `npm run check`. Set `CLOUDFLARE_ACCOUNT_ID` to the account chosen above and authenticate Wrangler for that account. The generated deployment config binds the Worker custom domain. Check for an existing DNS record or Worker route before deploying.

From `demo/mock-saas`, provide the ignored token through stdin, then deploy the same configuration:

```sh
npm exec -- wrangler secret put CONTROLLED_ENDPOINT_TOKEN --config wrangler.deploy.jsonc < ../../infra/cloudflare/.secrets/controlled-endpoint-token
npm exec -- wrangler deploy --config wrangler.deploy.jsonc
```

The secret command itself creates a Worker version; inspect the selected account and route before running it. A successful safe POST returns only the synthetic payload it received. It logs request metadata, not payload contents.

## 5. Enroll and install the agent guest

Stage a checkout on the Ubuntu 24.04 agent VM and run `sudo bash scripts/install-agent.sh`. Transfer ignored `.secrets/access.env` to `/etc/demo-agent/access.env`, owner `demo-agent:demo-agent`, mode `0600`. Transfer the issued `demo-agent.crt` and `demo-agent.key` to `/etc/demo-agent/pki/`, owner `demo-agent:demo-agent`, mode `0600`. Transfer ignored `.secrets/live-guide.env` to `/etc/cloudflared/live-guide.env`, root-owned mode `0600`.

Attach the Terraform `enrollment_policy_id` output to your existing One Client device enrollment application without removing existing enrollment policies. Install `.secrets/mdm.xml` on the agent as `/var/lib/cloudflare-warp/mdm.xml`, root-owned mode `0600`, then run `warp-cli mdm refresh`. Install your account's Gateway root certificate into the OS trust store and run `update-ca-certificates`. Connect the One Client and verify `warp-cli status` reports a healthy Traffic and DNS connection. Apply any management-network exclusion needed to keep SSH available. The account-wide device profile and TLS-inspection settings are intentionally left under your administrator's control.

Start the guide process only after the Access application exists. Enable its Tunnel, then immediately confirm that an unauthenticated request to the guide hostname redirects to Access. Stop the Tunnel if the guide is reachable without authentication:

```sh
sudo systemctl enable --now demo-agent-web.service
curl -fsS http://127.0.0.1:8765/health
sudo systemctl enable --now demo-agent-guide-tunnel.service
curl -I https://agent-guide.example.com/
```

The guide's `/run` endpoint triggers real synthetic traffic, so keep its exact hostname protected by the Terraform Access policy and give guide access only to the intended operator email. The agent process and guide bind to loopback; never expose port 8765 directly.

## 6. Verify the lab

On the agent guest, run each command as the dedicated user:

```sh
sudo -u demo-agent demo-agent identity
sudo -u demo-agent demo-agent no-auth
sudo -u demo-agent demo-agent token-only
sudo -u demo-agent demo-agent authorized
sudo -u demo-agent demo-agent send-safe
sudo -u demo-agent demo-agent send-raw
```

Expected HTTP results are no request, 403, 403, 200, 200, and a Gateway block (403 or 302 to Cloudflare's block authority). Open the Access-protected guide and confirm its six buttons return sanitized, timestamped results. Match Access and Gateway logs to each run's UTC window. For the safe send, require a controlled Worker acceptance event. For the protected send, require a DLP block and no accepted Worker event in a bounded window. The CLI status alone does not prove non-receipt.

Run component tests before changing the lab:

```sh
PYTHONPATH=demo/agent python3 -m pytest demo/agent/tests
PYTHONPATH=demo/private-api python3 -m pytest demo/private-api/tests
npm --prefix demo/mock-saas test
```

## Cleanup and limits

Review `terraform -chdir=infra/cloudflare plan -destroy` before removing the lab. Delete the Worker custom domain and secret through Wrangler, then apply a reviewed Terraform destroy plan. Remove guest files and certificates through your normal VM retirement process. Preserve evidence and any needed Terraform state before cleanup.

This is a deterministic demonstration, not an LLM or prompt-injection workload. Access machine-authentication decisions may need Access analytics beyond the dashboard's standard authentication log view. Gateway DLP policy and device behavior depend on the account's entitlements and pre-existing policy order. The installers and Terraform are reproducible, but this repository has not been exercised against a fresh third-party Cloudflare account; complete the preflight and live verification before using its results in a presentation.

## License

MIT. See [LICENSE](LICENSE).
