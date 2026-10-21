#!/usr/bin/env bash
set -euo pipefail
set +x

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --docker ) ]]; then
  printf 'Usage: %s [--docker]\n' "$0" >&2
  exit 2
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
modes=(identity no-auth token-only authorized send-safe send-raw)

if [[ ${1:-} == --docker ]]; then
  cd "$repo_root"
else
  command -v sudo >/dev/null || { printf 'sudo is required\n' >&2; exit 1; }
fi

for mode in "${modes[@]}"; do
  printf '\nUTC %s | %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$mode"
  if [[ ${1:-} == --docker ]]; then
    bash scripts/docker-guide.sh run --rm --no-deps guide python -m demo_agent.cli "$mode"
  else
    sudo -u demo-agent demo-agent "$mode"
  fi
done

printf '\nAll six CLI modes returned their expected local results. Correlate policy and receiver logs before claiming live proof.\n'
