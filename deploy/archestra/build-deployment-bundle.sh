#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-dist}"
source_ref="${SOURCE_REF:-HEAD}"
workflow_run="${GITHUB_RUN_ID:-local}"
source_id="$(git rev-parse "${source_ref}")"
release_root="$(mktemp -d)"
bundle="${output_dir}/ai-gateway-deployment-${source_id}.tar.gz"

cleanup() {
  rm -rf -- "${release_root}"
}
trap cleanup EXIT

mkdir -p "${output_dir}" "${release_root}/content"
git archive --format=tar --prefix=ai-gateway/ "${source_ref}" \
  README.md \
  clients/windows \
  deploy/archestra \
  services/policy \
  services/web-research \
  docs/architecture.md \
  docs/end-user-guide.md \
  docs/guardrail-administration.md \
  docs/operational-readiness.md \
  docs/routing.md \
  docs/software-inventory.md \
  | tar -xf - -C "${release_root}/content"

printf 'source_commit=%s\nworkflow_run=%s\n' \
  "${source_id}" "${workflow_run}" \
  > "${release_root}/content/ai-gateway/DEPLOYMENT_MANIFEST.txt"

if find "${release_root}/content" -type f -name '.env' -print -quit | grep -q .; then
  echo 'Refusing to package a deployment .env file.' >&2
  exit 1
fi

tar -C "${release_root}/content" -czf "${bundle}" ai-gateway
bundle_name="$(basename "${bundle}")"
(
  cd "${output_dir}"
  sha256sum "${bundle_name}" > "${bundle_name}.sha256"
)
tar -tzf "${bundle}" > "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/compose.yaml' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/Caddyfile' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/configure-https-origin.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/configure-gateway-entra.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/services/policy/Dockerfile' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/services/web-research/Dockerfile' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/services/web-research/app/server.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/clients/windows/copy-guardrail-admin-token.ps1' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/clients/windows/stage-company-openai.ps1' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/clients/windows/commission-company-openai.ps1' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/clients/windows/rotate-bootstrap-admin.ps1' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/clients/windows/manage-end-user.ps1' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/clients/windows/trust-ai-gateway-ca.ps1' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/clients/windows/commission-gateway-entra.ps1' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/stage-company-openai.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/stage-mem0.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/commission-company-openai.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/activate-managed-routing.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/configure-managed-routing.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/rotate-bootstrap-admin.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/sync-member-default-agent.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/configure-managed-agent-baseline.py' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/deploy/archestra/managed-agent-system-prompt.txt' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/docs/end-user-guide.md' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/docs/operational-readiness.md' \
  "${release_root}/bundle-contents.txt"
grep -Fxq 'ai-gateway/docs/software-inventory.md' \
  "${release_root}/bundle-contents.txt"

printf '%s\n%s\n' "${bundle}" "${bundle}.sha256"
