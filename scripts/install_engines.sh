#!/usr/bin/env bash
set -euo pipefail

mkdir -p bin

echo "Installing Xray..."
XRAY_URL="$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
  | jq -r '.assets[] | select(.name=="Xray-linux-64.zip") | .browser_download_url' | head -n1)"
if [ -z "$XRAY_URL" ] || [ "$XRAY_URL" = "null" ]; then
  echo "Could not find Xray-linux-64.zip"
  exit 1
fi
curl -fsSL "$XRAY_URL" -o /tmp/xray.zip
unzip -qo /tmp/xray.zip -d /tmp/xray
cp /tmp/xray/xray bin/xray
chmod +x bin/xray

echo "Installing sing-box..."
SB_URL="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
  | jq -r '.assets[] | select(.name | test("sing-box-.*-linux-amd64\\.tar\\.gz$")) | .browser_download_url' | head -n1)"
if [ -z "$SB_URL" ] || [ "$SB_URL" = "null" ]; then
  echo "Could not find sing-box linux-amd64 archive"
  exit 1
fi
curl -fsSL "$SB_URL" -o /tmp/sing-box.tar.gz
mkdir -p /tmp/sing-box
tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box --strip-components=1
cp /tmp/sing-box/sing-box bin/sing-box
chmod +x bin/sing-box

echo "Engines installed:"
bin/xray version | head -n1 || true
bin/sing-box version | head -n1 || true
