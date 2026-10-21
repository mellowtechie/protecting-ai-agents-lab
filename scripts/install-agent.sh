#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo 'Run as root on the agent guest' >&2; exit 1; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Requires Ubuntu 24.04' >&2; exit 1; }
root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gpg python3 python3-venv
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --dearmor --yes --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ noble main' > /etc/apt/sources.list.d/cloudflare-client.list
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflare-warp cloudflared

getent group demo-agent >/dev/null || groupadd --system demo-agent
id demo-agent >/dev/null 2>&1 || useradd --system --gid demo-agent --home /var/lib/demo-agent --create-home --shell /bin/bash demo-agent
getent group demo-cloudflared >/dev/null || groupadd --system demo-cloudflared
id demo-cloudflared >/dev/null 2>&1 || useradd --system --gid demo-cloudflared --home /nonexistent --shell /usr/sbin/nologin demo-cloudflared
install -d -o demo-agent -g demo-agent -m 0750 /opt/demo-agent /opt/demo-agent/demo_agent /opt/demo-agent/site /etc/demo-agent/pki
install -d -o root -g demo-agent -m 0750 /etc/demo-agent
install -d -o root -g root -m 0755 /etc/cloudflared
install -o demo-agent -g demo-agent -m 0644 "$root/demo/agent/demo_agent/"*.py /opt/demo-agent/demo_agent/
install -o demo-agent -g demo-agent -m 0644 "$root/demo/agent/requirements.txt" /opt/demo-agent/
install -o demo-agent -g demo-agent -m 0644 "$root/docs/demo-command-guide.html" /opt/demo-agent/site/index.html
install -o demo-agent -g demo-agent -m 0644 "$root/docs/favicon.png" "$root/llms.txt" /opt/demo-agent/site/
if [[ ! -x /opt/demo-agent/.venv/bin/python ]]; then
  runuser -u demo-agent -- python3 -m venv /opt/demo-agent/.venv
fi
runuser -u demo-agent -- /opt/demo-agent/.venv/bin/pip install --requirement /opt/demo-agent/requirements.txt
install -o root -g root -m 0755 "$root/infra/proxmox/bin/demo-agent" /usr/local/bin/demo-agent
install -o root -g root -m 0644 "$root/infra/proxmox/systemd/demo-agent-web.service" "$root/infra/proxmox/systemd/demo-agent-guide-tunnel.service" /etc/systemd/system/
systemctl daemon-reload
echo 'Agent installed. Install Access environment, certificate pair, WARP enrollment, and an Access-protected guide tunnel before starting services.'
