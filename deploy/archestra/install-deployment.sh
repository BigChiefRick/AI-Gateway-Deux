#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_root="$(cd "${script_dir}/../.." && pwd)"
target_root="${AI_GATEWAY_TARGET_ROOT:-/opt/ai-gateway}"
skip_runtime="${AI_GATEWAY_DEPLOY_SKIP_RUNTIME:-false}"
inject_failure="${AI_GATEWAY_DEPLOY_TEST_FAIL_AFTER_SWAP:-false}"
manifest="${source_root}/DEPLOYMENT_MANIFEST.txt"

if [[ "${target_root}" == "/opt/ai-gateway" && "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root for ${target_root}." >&2
  exit 1
fi
if [[ "${target_root}" == "/opt/ai-gateway" && "${skip_runtime}" == "true" ]]; then
  echo "Runtime verification cannot be skipped for the live deployment root." >&2
  exit 1
fi
if [[ "${inject_failure}" == "true" && "${skip_runtime}" != "true" ]]; then
  echo "Failure injection is available only with the non-production test runtime." >&2
  exit 1
fi

for required in \
  "${manifest}" \
  "${source_root}/deploy/archestra/compose.yaml" \
  "${source_root}/deploy/archestra/Caddyfile" \
  "${source_root}/deploy/archestra/configure-https-origin.py" \
  "${source_root}/deploy/archestra/configure-gateway-entra.py" \
  "${source_root}/deploy/archestra/commission-company-openai.py" \
  "${source_root}/deploy/archestra/activate-managed-routing.py" \
  "${source_root}/deploy/archestra/configure-managed-routing.py" \
  "${source_root}/deploy/archestra/stage-mem0.py" \
  "${source_root}/deploy/archestra/rotate-bootstrap-admin.py" \
  "${source_root}/deploy/archestra/sync-member-default-agent.py" \
  "${source_root}/deploy/archestra/configure-managed-agent-baseline.py" \
  "${source_root}/deploy/archestra/managed-agent-system-prompt.txt" \
  "${source_root}/services/policy/Dockerfile" \
  "${source_root}/services/web-research/Dockerfile" \
  "${target_root}/archestra/.env" \
  "${target_root}/services/policy"; do
  if [[ ! -e "${required}" ]]; then
    echo "Required deployment input is missing: ${required}" >&2
    exit 1
  fi
done

source_id="$(awk -F= '$1 == "source_commit" {print $2}' "${manifest}")"
workflow_run="$(awk -F= '$1 == "workflow_run" {print $2}' "${manifest}")"
if [[ ! "${source_id}" =~ ^[0-9a-f]{40}$ || -z "${workflow_run}" ]]; then
  echo "Deployment manifest is incomplete or invalid." >&2
  exit 1
fi

command -v flock >/dev/null
command -v tar >/dev/null
install -d -m 0750 "${target_root}/releases"
exec 9>"${target_root}/.deploy.lock"
if ! flock -n 9; then
  echo "Another AI Gateway deployment is already in progress." >&2
  exit 1
fi

stage="$(mktemp -d "${target_root}/.deploy-stage.XXXXXX")"
backup="$(mktemp -d "${target_root}/releases/$(date -u +%Y%m%dT%H%M%SZ)-${source_id:0:12}.XXXXXX")"
installer_pid="${BASHPID}"
archestra_backed_up=false
policy_backed_up=false
web_research_backed_up=false
archestra_installed=false
policy_installed=false
web_research_installed=false
legacy_web_container=""
https_container_existed=false

if [[ "${skip_runtime}" != "true" ]] \
  && docker container inspect ai-gateway-https >/dev/null 2>&1; then
  https_container_existed=true
fi

cleanup() {
  rm -rf -- "${stage}"
}

rollback_files() {
  if [[ "${archestra_installed}" == "true" && -d "${target_root}/archestra" ]]; then
    mv "${target_root}/archestra" "${backup}/failed-archestra"
  fi
  if [[ "${policy_installed}" == "true" && -d "${target_root}/services/policy" ]]; then
    mv "${target_root}/services/policy" "${backup}/failed-policy"
  fi
  if [[ "${web_research_installed}" == "true" && -d "${target_root}/services/web-research" ]]; then
    mv "${target_root}/services/web-research" "${backup}/failed-web-research"
  fi
  if [[ "${archestra_backed_up}" == "true" && -d "${backup}/archestra" ]]; then
    mv "${backup}/archestra" "${target_root}/archestra"
  fi
  if [[ "${policy_backed_up}" == "true" && -d "${backup}/policy" ]]; then
    mv "${backup}/policy" "${target_root}/services/policy"
  fi
  if [[ "${web_research_backed_up}" == "true" && -d "${backup}/web-research" ]]; then
    mv "${backup}/web-research" "${target_root}/services/web-research"
  fi
}

wait_for_runtime() {
  local all_healthy attempt container health
  local -a containers=(archestra ai-gateway-dlp-postgres ai-gateway-dlp)
  if docker compose config --services | grep -Fxq web-research-mcp; then
    containers+=(gateway-web-research)
  fi
  if docker compose config --services | grep -Fxq https-proxy; then
    containers+=(ai-gateway-https)
  fi
  for attempt in $(seq 1 "${AI_GATEWAY_DEPLOY_WAIT_ATTEMPTS:-90}"); do
    all_healthy=true
    for container in "${containers[@]}"; do
      health="$(docker inspect \
        --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
        "${container}" 2>/dev/null || true)"
      if [[ "${health}" != "healthy" ]]; then
        all_healthy=false
        break
      fi
    done
    if [[ "${all_healthy}" == "true" ]]; then
      return 0
    fi
    sleep "${AI_GATEWAY_DEPLOY_WAIT_SECONDS:-2}"
  done
  echo "AI Gateway containers did not become healthy before verification." >&2
  return 1
}

install_caddy_root_ca() {
  local ca_target ca_temp
  ca_target="/usr/local/share/ca-certificates/gateway-ai-gateway-caddy-root.crt"
  ca_temp="$(mktemp)"
  if ! docker exec ai-gateway-https \
      cat /data/caddy/pki/authorities/local/root.crt >"${ca_temp}" \
    || [[ ! -s "${ca_temp}" ]]; then
    rm -f -- "${ca_temp}"
    echo "HTTPS proxy did not provide a usable public root CA." >&2
    return 1
  fi
  install -m 0644 "${ca_temp}" "${ca_target}"
  rm -f -- "${ca_temp}"
  update-ca-certificates >/dev/null
}

compose_build_and_start() {
  local recreate="${1:-false}"
  local -a build_services=(dlp-policy)
  local -a runtime_services=(archestra dlp-postgres dlp-policy)
  if docker compose config --services | grep -Fxq web-research-mcp; then
    build_services+=(web-research-mcp)
    runtime_services+=(web-research-mcp)
  fi
  if docker compose config --services | grep -Fxq https-proxy; then
    runtime_services+=(https-proxy)
  fi
  docker compose build "${build_services[@]}"
  if [[ "${recreate}" == "true" ]]; then
    docker compose up -d --force-recreate "${runtime_services[@]}"
  else
    docker compose up -d "${runtime_services[@]}"
    if docker compose config --services | grep -Fxq https-proxy; then
      # Caddy reads its bind-mounted Caddyfile only at process start.  The
      # source directory is atomically replaced without changing the mount
      # path, so Compose's config hash cannot reliably detect this update.
      docker compose up -d --no-deps --force-recreate https-proxy
    fi
  fi
}

restore_legacy_web_container() {
  if [[ -z "${legacy_web_container}" ]]; then
    return
  fi
  if docker container inspect gateway-web-research >/dev/null 2>&1; then
    docker rm -f gateway-web-research >/dev/null
  fi
  if docker container inspect "${legacy_web_container}" >/dev/null 2>&1; then
    docker rename "${legacy_web_container}" gateway-web-research
  fi
}

recover_runtime() {
  if [[ "${skip_runtime}" == "true" ]]; then
    return
  fi
  (
    cd "${target_root}/archestra"
    compose_build_and_start true
    wait_for_runtime
    install_caddy_root_ca
    python3 ./configure-dlp-profile.py
    python3 ./configure-managed-agent-baseline.py
    ./verify.sh
  ) || echo "WARNING: source rollback completed, but runtime recovery needs operator inspection." >&2
}

on_error() {
  status=$?
  if [[ "${BASHPID}" != "${installer_pid}" ]]; then
    return "${status}"
  fi
  trap - ERR
  set +e
  rollback_files
  restore_legacy_web_container
  if [[ "${https_container_existed}" != "true" ]] \
    && docker container inspect ai-gateway-https >/dev/null 2>&1; then
    docker rm -f ai-gateway-https >/dev/null
  fi
  recover_runtime
  echo "Deployment failed; previous source was restored. Failed release retained at ${backup}." >&2
  exit "${status}"
}

trap cleanup EXIT
trap on_error ERR

install -d -m 0750 \
  "${stage}/archestra" \
  "${stage}/services/policy" \
  "${stage}/services/web-research"
cp -a "${source_root}/deploy/archestra/." "${stage}/archestra/"
cp -a "${source_root}/services/policy/." "${stage}/services/policy/"
cp -a "${source_root}/services/web-research/." "${stage}/services/web-research/"
install -m 0600 "${target_root}/archestra/.env" "${stage}/archestra/.env"
python3 "${stage}/archestra/configure-https-origin.py" \
  --env-file "${stage}/archestra/.env" >/dev/null
install -m 0644 "${manifest}" "${stage}/archestra/DEPLOYMENT_MANIFEST.txt"

if [[ "${skip_runtime}" != "true" ]]; then
  DLP_POLICY_BUILD_CONTEXT="${stage}/services/policy" \
    WEB_RESEARCH_BUILD_CONTEXT="${stage}/services/web-research" \
    docker compose \
      --env-file "${stage}/archestra/.env" \
      -f "${stage}/archestra/compose.yaml" \
      config --quiet
fi

mv "${target_root}/archestra" "${backup}/archestra"
archestra_backed_up=true
mv "${target_root}/services/policy" "${backup}/policy"
policy_backed_up=true
if [[ -d "${target_root}/services/web-research" ]]; then
  mv "${target_root}/services/web-research" "${backup}/web-research"
  web_research_backed_up=true
fi
mv "${stage}/archestra" "${target_root}/archestra"
archestra_installed=true
mv "${stage}/services/policy" "${target_root}/services/policy"
policy_installed=true
mv "${stage}/services/web-research" "${target_root}/services/web-research"
web_research_installed=true

if [[ "${inject_failure}" == "true" ]]; then
  (false)
fi

if [[ "${skip_runtime}" != "true" ]]; then
  if docker container inspect gateway-web-research >/dev/null 2>&1; then
    existing_project="$(docker inspect \
      --format '{{index .Config.Labels "com.docker.compose.project"}}' \
      gateway-web-research 2>/dev/null || true)"
    if [[ "${existing_project}" != "ai-gateway-archestra" ]]; then
      legacy_web_container="gateway-web-research-legacy-${source_id:0:12}"
      if docker container inspect "${legacy_web_container}" >/dev/null 2>&1; then
        echo "Legacy web-research preservation name already exists: ${legacy_web_container}" >&2
        (false)
      fi
      docker rename gateway-web-research "${legacy_web_container}"
    fi
  fi
  (
    cd "${target_root}/archestra"
    compose_build_and_start false
    wait_for_runtime
    install_caddy_root_ca
    python3 ./configure-dlp-profile.py
    python3 ./configure-managed-agent-baseline.py
    ./verify.sh
  )
fi

if [[ -n "${legacy_web_container}" ]] \
  && docker container inspect "${legacy_web_container}" >/dev/null 2>&1; then
  docker rm -f "${legacy_web_container}" >/dev/null
fi

marker="$(mktemp "${target_root}/.deployment-manifest.XXXXXX")"
{
  cat "${manifest}"
  printf 'deployed_at=%s\nbackup=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${backup}"
} > "${marker}"
chmod 0644 "${marker}"
mv "${marker}" "${target_root}/DEPLOYMENT_MANIFEST.txt"

trap - ERR
echo "AI Gateway source ${source_id} deployed and verified; rollback source retained at ${backup}."
