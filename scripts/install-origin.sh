#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo 'Run as root on the origin guest' >&2; exit 1; }
source /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 ]] || { echo 'Requires Debian 13' >&2; exit 1; }
root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl python3 python3-venv
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y cloudflared

getent group demo-private-api >/dev/null || groupadd --system demo-private-api
id demo-private-api >/dev/null 2>&1 || useradd --system --gid demo-private-api --home /var/lib/demo-private-api --create-home --shell /usr/sbin/nologin demo-private-api
getent group demo-cloudflared >/dev/null || groupadd --system demo-cloudflared
id demo-cloudflared >/dev/null 2>&1 || useradd --system --gid demo-cloudflared --home /nonexistent --shell /usr/sbin/nologin demo-cloudflared
install -d -o demo-private-api -g demo-private-api -m 0750 /opt/demo-private-api
install -d -o root -g root -m 0755 /etc/demo-private-api /etc/cloudflared
install -o demo-private-api -g demo-private-api -m 0644 "$root/demo/private-api/app.py" "$root/demo/private-api/requirements.txt" /opt/demo-private-api/
if [[ ! -x /opt/demo-private-api/.venv/bin/python ]]; then
  runuser -u demo-private-api -- python3 -m venv /opt/demo-private-api/.venv
fi
runuser -u demo-private-api -- /opt/demo-private-api/.venv/bin/pip install --requirement /opt/demo-private-api/requirements.txt
install -o root -g root -m 0644 "$root/infra/proxmox/systemd/demo-private-api.service" "$root/infra/proxmox/systemd/demo-cloudflared.service" /etc/systemd/system/
systemctl daemon-reload
echo 'Origin installed. Install /etc/demo-private-api/runtime.env and /etc/cloudflared/tunnel.env before starting the services.'
