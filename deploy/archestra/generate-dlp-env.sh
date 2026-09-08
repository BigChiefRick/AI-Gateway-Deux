#!/usr/bin/env bash
set -euo pipefail

env_file="${1:-.env}"

if [[ ! -f "$env_file" ]]; then
  echo "Missing $env_file; create it from .env.example first." >&2
  exit 1
fi

for variable in DLP_POLICY_API_KEY DLP_ADMIN_API_KEY DLP_DB_PASSWORD DLP_IDENTITY_HMAC_KEY; do
  if grep -q "^${variable}=replace-with-" "$env_file" || ! grep -q "^${variable}=" "$env_file"; then
    value="$(openssl rand -hex 32)"
    if grep -q "^${variable}=" "$env_file"; then
      sed -i "s|^${variable}=.*|${variable}=${value}|" "$env_file"
    else
      printf '%s=%s\n' "$variable" "$value" >> "$env_file"
    fi
  fi
done

chmod 0600 "$env_file"
echo "DLP secrets are present in $env_file with mode 0600. Values were not printed."
