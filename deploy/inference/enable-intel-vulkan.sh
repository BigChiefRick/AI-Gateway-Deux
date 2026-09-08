#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Run this script as the cloud-init user with passwordless sudo, not as root." >&2
  exit 1
fi

if [[ ! -e /dev/dri/renderD128 ]]; then
  echo "Intel GPU render device /dev/dri/renderD128 is missing" >&2
  exit 1
fi

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
vulkan_override="$(mktemp)"
trap 'rm -f "${modprobe_options}" "${vulkan_override}"' EXIT

printf '%s\n' 'options i915 enable_guc=3' >"${modprobe_options}"
printf '%s\n' \
  '[Service]' \
  'Environment="OLLAMA_VULKAN=1"' \
  'Environment="OLLAMA_IGPU_ENABLE=1"' \
  'Environment="GGML_VK_VISIBLE_DEVICES=0"' \
  >"${vulkan_override}"

sudo install -m 0644 "${modprobe_options}" /etc/modprobe.d/ai-gateway-i915.conf
sudo install -d -m 0755 /etc/systemd/system/ollama.service.d
sudo install -m 0644 "${vulkan_override}" /etc/systemd/system/ollama.service.d/zz-ai-gateway-vulkan.conf
sudo update-initramfs -u
sudo systemctl daemon-reload

echo "Intel firmware and Ollama Vulkan configuration installed. Reboot is required."
