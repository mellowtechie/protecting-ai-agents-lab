#!/usr/bin/env bash
set -euo pipefail
set +x

if [[ $# -eq 0 ]]; then
  printf 'Usage: %s <docker compose arguments>\n' "$0" >&2
  exit 2
fi

command -v docker >/dev/null || { printf 'Docker Compose is required\n' >&2; exit 1; }
command -v sudo >/dev/null || { printf 'sudo is required to read the protected agent environment\n' >&2; exit 1; }
uid=$(id -u demo-agent)
gid=$(id -g demo-agent)
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$repo_root"

exec sudo env DEMO_AGENT_UID="$uid" DEMO_AGENT_GID="$gid" docker compose "$@"
