#!/usr/bin/env bash
set -euo pipefail

OLLAMA_VERSION="${OLLAMA_VERSION:-0.32.6}"
OLLAMA_MODEL="${OLLAMA_MODEL:-granite4.1:3b}"
OLLAMA_AGENT_MODEL="${OLLAMA_AGENT_MODEL:-granite4.1:3b}"
OLLAMA_LISTEN_ADDRESS="${OLLAMA_LISTEN_ADDRESS:-0.0.0.0:11434}"
OLLAMA_VULKAN="${OLLAMA_VULKAN:-1}"
OLLAMA_IGPU_ENABLE="${OLLAMA_IGPU_ENABLE:-1}"
GGML_VK_VISIBLE_DEVICES="${GGML_VK_VISIBLE_DEVICES:-0}"

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Run this script as the cloud-init user with passwordless sudo, not as root." >&2
  exit 1
fi

export OLLAMA_VERSION
curl -fsSL https://ollama.com/install.sh | sh

if [[ "${OLLAMA_VULKAN}" == "1" ]]; then
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libvulkan1 \
    linux-firmware \
    mesa-vulkan-drivers \
    vulkan-tools

  for gpu_group in render video; do
    if getent group "${gpu_group}" >/dev/null; then
      sudo usermod -aG "${gpu_group}" ollama
    fi
  done

  sudo setcap cap_perfmon+ep /usr/local/bin/ollama

  modprobe_options="$(mktemp)"
  printf '%s\n' 'options i915 enable_guc=3' >"${modprobe_options}"
  sudo install -m 0644 "${modprobe_options}" /etc/modprobe.d/ai-gateway-i915.conf
  rm -f "${modprobe_options}"
  sudo update-initramfs -u
fi

override_file="$(mktemp)"
trap 'rm -f "$override_file"' EXIT

printf '%s\n' \
  '[Service]' \
  "Environment=\"OLLAMA_HOST=${OLLAMA_LISTEN_ADDRESS}\"" \
  'Environment="OLLAMA_KEEP_ALIVE=5m"' \
  'Environment="OLLAMA_MAX_LOADED_MODELS=1"' \
  'Environment="OLLAMA_NUM_PARALLEL=1"' \
  "Environment=\"OLLAMA_VULKAN=${OLLAMA_VULKAN}\"" \
  "Environment=\"OLLAMA_IGPU_ENABLE=${OLLAMA_IGPU_ENABLE}\"" \
  "Environment=\"GGML_VK_VISIBLE_DEVICES=${GGML_VK_VISIBLE_DEVICES}\"" \
  > "$override_file"

sudo install -d -m 0755 /etc/systemd/system/ollama.service.d
sudo install -m 0644 "$override_file" /etc/systemd/system/ollama.service.d/override.conf
sudo systemctl daemon-reload
sudo systemctl enable ollama
sudo systemctl restart ollama

for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:11434/api/version >/dev/null; then
    break
  fi
  sleep 1
done

curl -fsS http://127.0.0.1:11434/api/version >/dev/null
ollama pull "$OLLAMA_MODEL"
if [[ "$OLLAMA_AGENT_MODEL" != "$OLLAMA_MODEL" ]]; then
  ollama pull "$OLLAMA_AGENT_MODEL"
fi

echo "Ollama version: $(ollama --version 2>/dev/null | tail -n 1)"
echo "Model installed: $OLLAMA_MODEL"
echo "Agent model installed: $OLLAMA_AGENT_MODEL"
curl -fsS http://127.0.0.1:11434/api/tags

if [[ "${OLLAMA_VULKAN}" == "1" ]]; then
  echo "A reboot is required before Intel GuC/Vulkan acceleration is active."
fi
