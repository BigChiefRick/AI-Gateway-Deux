#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_root="$(mktemp -d)"

cleanup() {
  rm -rf -- "${test_root}"
}
trap cleanup EXIT

source_ref="$(git -C "${repo_root}" write-tree)"
SOURCE_REF="${source_ref}" GITHUB_RUN_ID="deployment-transaction-test" \
  "${repo_root}/deploy/archestra/build-deployment-bundle.sh" \
  "${test_root}/artifacts" >/dev/null
bundle="${test_root}/artifacts/ai-gateway-deployment-${source_ref}.tar.gz"
(
  cd "$(dirname "${bundle}")"
  sha256sum -c "$(basename "${bundle}").sha256" >/dev/null
)
mkdir -p "${test_root}/source"
tar -xzf "${bundle}" -C "${test_root}/source"
source_root="${test_root}/source/ai-gateway"
target_root="${test_root}/target"

grep -Fq 'docker compose up -d --no-deps --force-recreate https-proxy' \
  "${source_root}/deploy/archestra/install-deployment.sh"
grep -Fq 'update-ca-certificates' \
  "${source_root}/deploy/archestra/install-deployment.sh"
grep -Fq 'curl_ready "https://${verify_host}/health"' \
  "${source_root}/deploy/archestra/verify.sh"
grep -Fq 'handle_path /gateway/*' \
  "${source_root}/deploy/archestra/Caddyfile"
grep -Fq 'https://${verify_host}/gateway/v1/models' \
  "${source_root}/deploy/archestra/verify.sh"

mkdir -p "${target_root}/archestra" "${target_root}/services/policy"
printf 'OLD_ARCHESTRA\n' > "${target_root}/archestra/old-marker"
printf 'OLD_POLICY\n' > "${target_root}/services/policy/old-marker"
printf 'DLP_POLICY_API_KEY=test-only-preserved-value\n' > "${target_root}/archestra/.env"
chmod 0600 "${target_root}/archestra/.env"

AI_GATEWAY_TARGET_ROOT="${target_root}" \
AI_GATEWAY_DEPLOY_SKIP_RUNTIME=true \
  "${source_root}/deploy/archestra/install-deployment.sh" >/dev/null

test -f "${target_root}/archestra/compose.yaml"
test -f "${target_root}/services/policy/Dockerfile"
test ! -e "${target_root}/archestra/old-marker"
test "$(stat -c '%a' "${target_root}/archestra/.env")" = "600"
grep -Fxq 'DLP_POLICY_API_KEY=test-only-preserved-value' "${target_root}/archestra/.env"
grep -Fxq "source_commit=${source_ref}" "${target_root}/DEPLOYMENT_MANIFEST.txt"

backups=("${target_root}"/releases/*)
test "${#backups[@]}" -eq 1
test -f "${backups[0]}/archestra/old-marker"
test -f "${backups[0]}/policy/old-marker"

printf 'PRESERVE_AFTER_FAILURE\n' > "${target_root}/archestra/pre-failure-marker"
printf 'PRESERVE_POLICY_AFTER_FAILURE\n' > "${target_root}/services/policy/pre-failure-marker"
if AI_GATEWAY_TARGET_ROOT="${target_root}" \
  AI_GATEWAY_DEPLOY_SKIP_RUNTIME=true \
  AI_GATEWAY_DEPLOY_TEST_FAIL_AFTER_SWAP=true \
  "${source_root}/deploy/archestra/install-deployment.sh" >/dev/null 2>&1; then
  echo "Injected deployment failure unexpectedly succeeded." >&2
  exit 1
fi

test -f "${target_root}/archestra/pre-failure-marker"
test -f "${target_root}/services/policy/pre-failure-marker"
grep -Fxq 'DLP_POLICY_API_KEY=test-only-preserved-value' "${target_root}/archestra/.env"

echo "DEPLOYMENT_INSTALL_TRANSACTION_TEST_OK"
