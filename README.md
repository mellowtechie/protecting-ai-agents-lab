# Protecting AI agents lab

Deploy a synthetic agent workload that demonstrates two Cloudflare One boundaries: Access protects a private API using a service token and client certificate; Gateway inspects the agent's outbound traffic and DLP blocks a protected marker before it reaches a controlled Worker. The six fixed commands are `identity`, `no-auth`, `token-only`, `authorized`, `send-safe`, and `send-raw`.

This repository contains the agent, private API, controlled Worker, certificate issuer, Cloudflare Terraform, guest installers, Access-protected browser guide, and component tests. The agent and guide can run as a native systemd service or in the optional Docker image on the enrolled agent host. It contains no credentials, Terraform state, live customer data, or resources from the original presentation lab.

The setup below is the human runbook. AI assistants should also read [AGENTS.md](AGENTS.md); it identifies the steps that require an account administrator's judgment. The [browser guide](docs/demo-command-guide.html) is included in this repo and displays your configured hostnames, a link to your account's request logs, and buttons for the same six CLI modes. It is served by the agent host after deployment, not by GitHub Pages.

## Requirements

- A Cloudflare account with Zero Trust, Access, Gateway HTTP filtering and TLS inspection, DLP custom profiles, Workers, and a DNS zone you control. Check product entitlements and billing before creating resources.
- An existing Zero Trust organization and enrollment configuration. The operator must be allowed to attach a new enrollment policy and install the account's Gateway root certificate on the agent VM.
- Two reachable Linux guests: Ubuntu 24.04 amd64 for the agent and Debian 13 amd64 for the private API. They can run on Proxmox or another hypervisor. SSH/console management is required; the origin API and guide listen only on loopback.
- Python 3.12, Node.js 22, npm, Terraform 1.8 or newer, `step` CLI, and OpenSSL on the operator machine. The guests install their own runtime dependencies.
- A scoped Cloudflare API token for the resources in `infra/cloudflare/`, and Wrangler authorization for the same account. Use a protected shell/session for credentials.
- Docker Engine with the Compose plugin only if you choose the optional container path. One Client still runs on the Ubuntu host; Docker does not emulate Access, Gateway, DLP, or Tunnel.

## What's included and what to run

| Part | Source | Verification |
| --- | --- | --- |
| Agent CLI and browser guide | `demo/agent/`, `docs/demo-command-guide.html` | Agent pytest suite, six live modes, local `/health` |
| Private API | `demo/private-api/` | API pytest suite, local `/readyz` |
| Controlled Worker | `demo/mock-saas/` | `npm run check`, safe acceptance and protected non-acceptance evidence |
| Cloudflare resources | `infra/cloudflare/` | `terraform validate`, reviewed plan, Access and Gateway logs |
| Guest setup and certificate issuer | `scripts/`, `infra/pki/`, `infra/proxmox/systemd/` | Certificate verification, systemd and One Client status |

Before creating resources, run the local tests. Python 3.12 or newer and Node.js 22 or newer are required. Use virtual environments so the two Python dependency sets do not modify the system interpreter:

```sh
python3 -m venv .venv
.venv/bin/pip install -r demo/agent/requirements.txt -r demo/private-api/requirements.txt
PYTHONPATH=demo/agent .venv/bin/python -m pytest -q demo/agent/tests
PYTHONPATH=demo/private-api .venv/bin/python -m pytest -q demo/private-api/tests
npm --prefix demo/mock-saas ci
npm --prefix demo/mock-saas run check
```

With Docker Engine running, the agent CLI and guide tests can instead run in an isolated image:

```sh
docker build --target test -t protecting-ai-agents-test -f Dockerfile.agent .
docker run --rm protecting-ai-agents-test
```

The repository's [Verify lab workflow](.github/workflows/verify.yml) runs the agent, API, and Worker tests, builds and smoke tests the guide image, and validates Terraform with a temporary CI certificate. It does not deploy Cloudflare resources or replace the live checks in section 6.

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

Transfer `runtime.env` to `/etc/demo-private-api/runtime.env` and `infra/cloudflare/.secrets/tunnel.env` to `/etc/cloudflared/tunnel.env` using your protected management channel. Both guest files must be root-owned mode `0600`. For example, set `ORIGIN_SSH` to the guest's SSH destination, stage the files in a private directory, and install them on the guest:

```sh
export ORIGIN_SSH='your-user@origin-guest'
ssh "$ORIGIN_SSH" 'install -d -m 0700 ~/lab-secrets'
scp infra/cloudflare/.secrets/runtime.env infra/cloudflare/.secrets/tunnel.env "$ORIGIN_SSH:lab-secrets/"
ssh "$ORIGIN_SSH" 'sudo install -o root -g root -m 0600 ~/lab-secrets/runtime.env /etc/demo-private-api/runtime.env && sudo install -o root -g root -m 0600 ~/lab-secrets/tunnel.env /etc/cloudflared/tunnel.env'
```

Start the API first, require `/readyz` to return 200, then start the Tunnel on the origin guest:

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

Stage a checkout on the Ubuntu 24.04 agent VM and run `sudo bash scripts/install-agent.sh`. The installer installs current `ca-certificates` from the guest's configured Ubuntu repositories. Transfer ignored `.secrets/access.env` to `/etc/demo-agent/access.env`, owner `demo-agent:demo-agent`, mode `0600`. Transfer the issued `demo-agent.crt` and `demo-agent.key` to `/etc/demo-agent/pki/`, owner `demo-agent:demo-agent`, mode `0600`. Transfer ignored `.secrets/live-guide.env` to `/etc/cloudflared/live-guide.env`, root-owned mode `0600`.

For example, set `AGENT_SSH` to the agent guest's SSH destination, then stage and install those four files:

```sh
export AGENT_SSH='your-user@agent-guest'
ssh "$AGENT_SSH" 'install -d -m 0700 ~/lab-secrets'
scp infra/cloudflare/.secrets/access.env infra/cloudflare/.secrets/live-guide.env infra/pki/.secrets/demo-agent.crt infra/pki/.secrets/demo-agent.key "$AGENT_SSH:lab-secrets/"
ssh "$AGENT_SSH" 'sudo install -o demo-agent -g demo-agent -m 0600 ~/lab-secrets/access.env /etc/demo-agent/access.env && sudo install -o demo-agent -g demo-agent -m 0600 ~/lab-secrets/demo-agent.crt /etc/demo-agent/pki/demo-agent.crt && sudo install -o demo-agent -g demo-agent -m 0600 ~/lab-secrets/demo-agent.key /etc/demo-agent/pki/demo-agent.key && sudo install -o root -g root -m 0600 ~/lab-secrets/live-guide.env /etc/cloudflared/live-guide.env'
```

Attach the Terraform `enrollment_policy_id` output to your existing One Client device enrollment application without removing existing enrollment policies. Copy `infra/cloudflare/.secrets/mdm.xml` to the agent guest and install it as `/var/lib/cloudflare-warp/mdm.xml`, root-owned mode `0600`. Run `warp-cli mdm refresh`. Download your account's Gateway root certificate through your Zero Trust administrator's approved process, copy it to `/usr/local/share/ca-certificates/` with a `.crt` extension, and run `sudo update-ca-certificates`. Verify the certificate source before trusting it. Connect the One Client and verify `warp-cli status` reports a healthy Traffic and DNS connection. Apply any management-network exclusion needed to keep SSH available. The account-wide device profile and TLS-inspection settings are intentionally left under your administrator's control.

```sh
scp infra/cloudflare/.secrets/mdm.xml "$AGENT_SSH:lab-secrets/"
ssh "$AGENT_SSH" 'sudo install -d -m 0755 /var/lib/cloudflare-warp && sudo install -o root -g root -m 0600 ~/lab-secrets/mdm.xml /var/lib/cloudflare-warp/mdm.xml && sudo warp-cli mdm refresh'
```

On the agent guest, install the verified Gateway root certificate after staging it through the same private channel:

```sh
sudo install -o root -g root -m 0644 ~/lab-secrets/gateway-root.crt /usr/local/share/ca-certificates/demo-gateway-root.crt
sudo update-ca-certificates
warp-cli status
```

For the native systemd guide, start the process only after the Access application exists. Enable its Tunnel, then immediately confirm that an unauthenticated request to the guide hostname redirects to Access. Stop the Tunnel if the guide is reachable without authentication. Use the Docker section below instead if you choose that run mode:

```sh
sudo systemctl enable --now demo-agent-web.service
curl -fsS http://127.0.0.1:8765/health
sudo systemctl enable --now demo-agent-guide-tunnel.service
curl -I https://agent-guide.example.com/
```

The guide's `/run` endpoint triggers real synthetic traffic, so keep its exact hostname protected by the Terraform Access policy and give guide access only to the intended operator email. The agent process and guide bind to loopback; never expose port 8765 directly.

### Optional Docker guide on the agent guest

Use this instead of `demo-agent-web.service` if you want the CLI and browser guide packaged in one image. The origin guest, controlled Worker, One Client, Access application, and Cloudflare Tunnel still use the steps above. Docker Compose uses host networking so the guide binds only to the Ubuntu host's `127.0.0.1:8765` and the agent traffic uses the host's One Client path. Check your Docker host's routing and Gateway logs; host networking alone does not prove traffic passed through Gateway. The container reads `/etc/demo-agent/access.env` and the certificate pair already installed above; the image contains no credentials.

On the agent guest, with Docker Engine and the Compose plugin installed and with a checkout of this repository, use the wrapper so Compose can read the protected environment file as root while the container runs as the `demo-agent` UID:

```sh
sudo systemctl disable --now demo-agent-web.service
bash scripts/docker-guide.sh up -d --build guide
curl -fsS http://127.0.0.1:8765/health
bash scripts/docker-guide.sh run --rm --no-deps guide python -m demo_agent.cli identity
sudo systemctl enable --now demo-agent-guide-tunnel.service
```

Run `bash scripts/docker-guide.sh ps` to check the container and `bash scripts/docker-guide.sh down` before switching back to the native web service. Docker access is privileged on the host, and Docker administrators can inspect container environment values; use your normal administrator-controlled installation. Start the guide Tunnel only after the Access application is configured, then verify an unauthenticated request to the guide hostname redirects to Access.

## 6. Verify the lab

On the agent guest, run all six modes as the dedicated user with one script. It prints a UTC marker before each result and stops at the first unexpected local result; it does not save credentials or raw responses:

```sh
bash scripts/run-cli-checks.sh
```

For the Docker guide, run `bash scripts/run-cli-checks.sh --docker`. You can also run a single native mode when debugging:

```sh
sudo -u demo-agent demo-agent identity
sudo -u demo-agent demo-agent no-auth
sudo -u demo-agent demo-agent token-only
sudo -u demo-agent demo-agent authorized
sudo -u demo-agent demo-agent send-safe
sudo -u demo-agent demo-agent send-raw
```

Expected HTTP results are no request, 403, 403, 200, 200, and a Gateway block (403 or 302 to Cloudflare's block authority). Open the Access-protected guide and confirm its six buttons return sanitized, timestamped results. Match Access and Gateway logs to each run's UTC window. For the safe send, require a controlled Worker acceptance event. For the protected send, require a DLP block and no accepted Worker event in a bounded window. The CLI status alone does not prove non-receipt.

Rerun the local component tests at the top of this README after changing the lab. The live six-mode run is an integration check of your own policy configuration; the component tests use synthetic fixtures and do not make a Cloudflare deployment.

## Cleanup and limits

Review `terraform -chdir=infra/cloudflare plan -destroy` before removing the lab. Delete the Worker custom domain and secret through Wrangler, then apply a reviewed Terraform destroy plan. Remove guest files and certificates through your normal VM retirement process. Preserve evidence and any needed Terraform state before cleanup.

This is a deterministic demonstration, not an LLM or prompt-injection workload. Access machine-authentication decisions may need Access analytics beyond the dashboard's standard authentication log view. Gateway DLP policy and device behavior depend on the account's entitlements and pre-existing policy order. The installers and Terraform are reproducible, but this repository has not been exercised against a fresh third-party Cloudflare account; complete the preflight and live verification before using its results in a presentation.

## License

MIT. See [LICENSE](LICENSE).
