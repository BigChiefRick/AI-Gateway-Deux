#!/usr/bin/env bash
set -euo pipefail

expected_digest="sha256:5bdf6d1f0b0e706778674103f7c29e50ef91aaa473584f70e417f8cbf62ab984"
verify_host="${ARCHESTRA_VERIFY_HOST:-192.0.2.10}"

curl_ready() {
  local attempt
  for attempt in $(seq 1 "${AI_GATEWAY_VERIFY_HTTP_ATTEMPTS:-45}"); do
    if curl --fail --silent --max-time 10 "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${AI_GATEWAY_VERIFY_HTTP_WAIT_SECONDS:-1}"
  done
  curl --fail --silent --show-error --max-time 10 "$@" >/dev/null
}

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

container_id="$(sudo docker compose ps -q archestra)"
if [[ -z "${container_id}" ]]; then
  echo "FAIL: Archestra container is not present" >&2
  exit 1
fi

container_state="$(sudo docker inspect --format '{{.State.Status}}' "${container_id}")"
container_health="$(sudo docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${container_id}")"
if [[ "${container_state}" != "running" || "${container_health}" != "healthy" ]]; then
  echo "FAIL: Archestra state=${container_state} health=${container_health}" >&2
  exit 1
fi

image_id="$(sudo docker inspect --format '{{.Image}}' "${container_id}")"
repo_digests="$(sudo docker image inspect --format '{{join .RepoDigests "\n"}}' "${image_id}")"
if ! grep -Fq "${expected_digest}" <<<"${repo_digests}"; then
  echo "FAIL: running image does not match pinned digest ${expected_digest}" >&2
  exit 1
fi

curl_ready "http://${verify_host}:9000/health"
curl_ready "http://${verify_host}:9000/openapi.json"
curl_ready "http://${verify_host}:3000/auth/sign-in"

https_container_id="$(sudo docker compose ps -q https-proxy)"
if [[ -z "${https_container_id}" ]]; then
  echo "FAIL: HTTPS proxy container is not present" >&2
  exit 1
fi
https_health="$(sudo docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${https_container_id}")"
if [[ "${https_health}" != "healthy" ]]; then
  echo "FAIL: HTTPS proxy health=${https_health}" >&2
  exit 1
fi
ca_certificate="$(mktemp)"
trap 'rm -f "${ca_certificate}"' EXIT
for attempt in $(seq 1 "${AI_GATEWAY_VERIFY_HTTP_ATTEMPTS:-45}"); do
  if sudo docker exec ai-gateway-https \
      test -s /data/caddy/pki/authorities/local/root.crt \
    && sudo docker exec ai-gateway-https \
      cat /data/caddy/pki/authorities/local/root.crt >"${ca_certificate}"; then
    break
  fi
  sleep "${AI_GATEWAY_VERIFY_HTTP_WAIT_SECONDS:-1}"
done
if [[ ! -s "${ca_certificate}" ]]; then
  echo "FAIL: HTTPS proxy did not produce its public root CA" >&2
  exit 1
fi
curl_ready --cacert "${ca_certificate}" "https://${verify_host}/health"
curl_ready --cacert "${ca_certificate}" "https://${verify_host}/openapi.json"
curl_ready --cacert "${ca_certificate}" "https://${verify_host}/auth/sign-in"
curl_ready --cacert "${ca_certificate}" "https://${verify_host}/guardrails/admin"
curl_ready "https://${verify_host}/health"
guardrail_anonymous_status="$(curl --silent --show-error --max-time 15 \
  --cacert "${ca_certificate}" --output /dev/null --write-out '%{http_code}' \
  "https://${verify_host}/guardrails/admin/api/profiles")"
if [[ "${guardrail_anonymous_status}" != "401" ]]; then
  echo "FAIL: guardrail admin API returned HTTP ${guardrail_anonymous_status}, expected 401 without a session or recovery credential" >&2
  exit 1
fi
curl_ready --cacert "${ca_certificate}" \
  --header "Authorization: Bearer ${DLP_ADMIN_API_KEY}" \
  "https://${verify_host}/guardrails/admin/api/profiles"
managed_gateway_anonymous_status="$(curl --silent --show-error --max-time 15 \
  --cacert "${ca_certificate}" --output /dev/null --write-out '%{http_code}' \
  "https://${verify_host}/gateway/v1/models")"
if [[ "${managed_gateway_anonymous_status}" != "401" ]]; then
  echo "FAIL: managed HTTPS gateway returned HTTP ${managed_gateway_anonymous_status}, expected 401 without a client credential" >&2
  exit 1
fi
curl_ready --cacert "${ca_certificate}" \
  --header "Authorization: Bearer ${DLP_POLICY_API_KEY}" \
  "https://${verify_host}/gateway/v1/models"
https_model_status="$(curl --silent --show-error --max-time 15 --cacert "${ca_certificate}" \
  --output /dev/null --write-out '%{http_code}' \
  "https://${verify_host}/v1/anthropic/v1/models")"
if [[ "${https_model_status}" != "401" ]]; then
  echo "FAIL: HTTPS LLM API route returned HTTP ${https_model_status}, expected 401 without credentials" >&2
  exit 1
fi

sudo docker exec archestra sh -lc '
  set -eu
  umask 077
  kubeconfig="$(mktemp)"
  trap '\''rm -f "${kubeconfig}"'\'' EXIT
  kind get kubeconfig --name archestra-mcp --internal >"${kubeconfig}"
  KUBECONFIG="${kubeconfig}" kubectl wait --for=condition=Ready pod --all --all-namespaces --timeout=90s
' >/dev/null

ollama_health="$(curl --fail --silent --show-error --max-time 10 http://127.0.0.1:11434/api/version)"
if [[ -z "${ollama_health}" ]]; then
  echo "FAIL: Ollama did not return a version" >&2
  exit 1
fi

if [[ ! -e /dev/dri/renderD128 ]]; then
  echo "FAIL: passed-through GPU render device is missing" >&2
  exit 1
fi

if ! sudo -u ollama env XDG_RUNTIME_DIR=/tmp vulkaninfo --summary 2>/dev/null | grep -Fq 'Intel(R) Iris(R) Xe Graphics'; then
  echo "FAIL: Vulkan did not enumerate the passed-through Intel Iris Xe GPU" >&2
  exit 1
fi

gpu_proof="$(curl --fail --silent --show-error --max-time 120 \
  http://127.0.0.1:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"granite4.1:3b","prompt":"Reply with exactly GPU_VERIFY_OK","stream":false,"options":{"num_predict":12}}')"

if ! python3 -c 'import json,sys; assert json.load(sys.stdin).get("response", "").strip() == "GPU_VERIFY_OK"' <<<"${gpu_proof}"; then
  echo "FAIL: granite4.1:3b did not complete the GPU proof prompt" >&2
  exit 1
fi

if ! ollama ps | grep -F 'granite4.1:3b' | grep -Fq '100% GPU'; then
  echo "FAIL: Ollama did not report granite4.1:3b on the GPU" >&2
  exit 1
fi

if ! sudo fuser /dev/dri/renderD128 >/dev/null 2>&1; then
  echo "FAIL: the Ollama model process is not holding the GPU render device" >&2
  exit 1
fi

dlp_container_id="$(sudo docker compose ps -q dlp-policy)"
dlp_database_id="$(sudo docker compose ps -q dlp-postgres)"
web_research_id="$(sudo docker compose ps -q web-research-mcp)"
if [[ -z "${dlp_container_id}" || -z "${dlp_database_id}" || -z "${web_research_id}" ]]; then
  echo "FAIL: DLP policy, database, or web-research container is not present" >&2
  exit 1
fi

for container_id in "${dlp_container_id}" "${dlp_database_id}" "${web_research_id}"; do
  state="$(sudo docker inspect --format '{{.State.Status}}' "${container_id}")"
  health="$(sudo docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${container_id}")"
  if [[ "${state}" != "running" || "${health}" != "healthy" ]]; then
    echo "FAIL: DLP container ${container_id} state=${state} health=${health}" >&2
    exit 1
  fi
done

dlp_image="$(sudo docker inspect --format '{{.Config.Image}}' "${dlp_container_id}")"
if [[ "${dlp_image}" != "ai-gateway/policy:0.8.5" ]]; then
  echo "FAIL: unexpected DLP image ${dlp_image}" >&2
  exit 1
fi

web_research_image="$(sudo docker inspect --format '{{.Config.Image}}' "${web_research_id}")"
if [[ "${web_research_image}" != "ai-gateway/web-research:0.1.0" ]]; then
  echo "FAIL: unexpected web-research image ${web_research_image}" >&2
  exit 1
fi

sudo docker exec gateway-web-research python -m app.verify

DLP_VERIFY_URL="http://${verify_host}:4200" python3 ./verify-dlp.py
./verify-rbac.sh

echo "PASS: Archestra ${container_health}; HTTP recovery and trusted HTTPS origin ready; API/UI/OpenAPI ready; KinD/Dagger ready; granite4.1:3b completed on Intel Vulkan GPU; DLP enforcement, restricted defaults, and six governed web/OCR/QR MCP tools ready"
