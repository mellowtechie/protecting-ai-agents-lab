#!/usr/bin/env bash
set -euo pipefail

umask 077

for command in step openssl grep stat mkdir chmod; do
  command -v "$command" >/dev/null || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 1
  }
done

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
SECRETS="$ROOT/.secrets"
PASSWORD="$SECRETS/ca-password"
OUTPUTS=(
  root-ca.crt
  root-ca.key
  demo-agent.crt
  demo-agent.key
  wrong-agent.crt
  wrong-agent.key
  short-expiry.crt
  short-expiry.key
)

file_mode() {
  local mode
  if mode=$(stat -c '%a' "$1" 2>/dev/null); then
    printf '%s\n' "$mode"
  else
    stat -f '%Lp' "$1"
  fi
}

file_owner() {
  local owner
  if owner=$(stat -c '%u' "$1" 2>/dev/null); then
    printf '%s\n' "$owner"
  else
    stat -f '%u' "$1"
  fi
}

owned_with_mode() {
  local path=$1 expected_mode=$2 owner mode
  owner=$(file_owner "$path") || return 1
  mode=$(file_mode "$path") || return 1
  [[ "$owner" == "$EUID" && "$mode" == "$expected_mode" ]]
}

# A caller-owned, non-writable parent prevents other principals from replacing .secrets; same-user processes are trusted.
if ! parent_owner=$(file_owner "$ROOT") || ! parent_mode=$(file_mode "$ROOT"); then
  printf 'refusing unsafe PKI parent directory\n' >&2
  exit 1
fi
if [[ "$parent_owner" != "$EUID" || ! "$parent_mode" =~ ^[0-7]+$ ]] || (( (8#$parent_mode & 0022) != 0 )); then
  printf 'refusing unsafe PKI parent directory\n' >&2
  exit 1
fi

if [[ ! -e "$SECRETS" && ! -L "$SECRETS" ]] && ! mkdir -m 0700 "$SECRETS" >/dev/null 2>&1; then
  printf 'refusing existing PKI secrets path\n' >&2
  exit 1
fi
if [[ -L "$SECRETS" || ! -d "$SECRETS" ]] || ! owned_with_mode "$SECRETS" 700; then
  printf 'refusing existing PKI secrets path\n' >&2
  exit 1
fi
cd "$ROOT"

for output in "${OUTPUTS[@]}"; do
  if [[ -e "$SECRETS/$output" || -L "$SECRETS/$output" ]]; then
    printf 'refusing existing PKI secrets path\n' >&2
    exit 1
  fi
done

if [[ -e "$PASSWORD" || -L "$PASSWORD" ]]; then
  if [[ -L "$PASSWORD" || ! -f "$PASSWORD" || ! -s "$PASSWORD" ]] || ! owned_with_mode "$PASSWORD" 600; then
    printf 'refusing existing PKI secrets path\n' >&2
    exit 1
  fi
elif ! (set -o noclobber; openssl rand -base64 32 > "$PASSWORD") 2>/dev/null; then
  printf 'failed to create CA password\n' >&2
  exit 1
fi

if ! owned_with_mode "$PASSWORD" 600 || [[ ! -s "$PASSWORD" ]]; then
  printf 'refusing existing PKI secrets path\n' >&2
  exit 1
fi

if ! step certificate create "Demo Agent Root CA" \
  "$SECRETS/root-ca.crt" "$SECRETS/root-ca.key" \
  --profile root-ca --password-file "$PASSWORD" >/dev/null 2>&1; then
  printf 'failed to issue PKI fixture: root-ca\n' >&2
  exit 1
fi
chmod 0600 "$SECRETS/root-ca.key"

issue_leaf() {
  local common_name=$1 name=$2 lifetime=$3
  if ! step certificate create "$common_name" \
    "$SECRETS/$name.crt" "$SECRETS/$name.key" \
    --profile leaf --not-after "$lifetime" \
    --ca "$SECRETS/root-ca.crt" --ca-key "$SECRETS/root-ca.key" \
    --ca-password-file "$PASSWORD" --no-password --insecure >/dev/null 2>&1; then
    printf 'failed to issue PKI fixture: %s\n' "$name" >&2
    exit 1
  fi
  chmod 0600 "$SECRETS/$name.key"
}

issue_leaf demo-agent demo-agent 8760h
issue_leaf wrong-agent wrong-agent 1h
issue_leaf demo-agent short-expiry 1m

openssl x509 -in .secrets/demo-agent.crt -noout -subject -nameopt RFC2253 | grep -Eq '^subject=CN=demo-agent$'
openssl x509 -in .secrets/wrong-agent.crt -noout -subject -nameopt RFC2253 | grep -Eq '^subject=CN=wrong-agent$'
if ! step certificate verify .secrets/demo-agent.crt --roots .secrets/root-ca.crt >/dev/null 2>&1; then
  printf 'failed to verify PKI fixture: demo-agent\n' >&2
  exit 1
fi
test "$(file_mode .secrets/root-ca.key)" = "600"
test "$(file_mode .secrets/demo-agent.key)" = "600"

printf 'PKI fixtures issued and verified\n'
