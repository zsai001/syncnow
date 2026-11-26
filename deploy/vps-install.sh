#!/usr/bin/env bash
# Non-interactive, zero-hang 1-line VPS installer for SyncNow Self-Hosted Relay (Linux amd64/arm64)
# After install completes, open http://<YOUR_SERVER_IP>:8787/setup in your browser to finish setup!
#
# Usage (no git clone required):
#   curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/vps-install.sh | sudo bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export SYSTEMD_PAGER=""

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root (e.g. curl -fsSL ... | sudo bash)" >&2
  exit 1
fi

REPO_TARBALL="${SYNCNOW_RELAY_TARBALL:-https://github.com/zsai001/syncnow/archive/refs/heads/main.tar.gz}"
INSTALL_BIN="/usr/local/bin/syncnow-relay"
DATA_DIR="/var/lib/syncnow-relay"
ENV_FILE="/etc/syncnow-relay.env"
SERVICE_FILE="/etc/systemd/system/syncnow-relay.service"

RELAY_ROOT=""
CLEANUP_TMP=0
cleanup() {
  if [[ "$CLEANUP_TMP" -eq 1 && -n "$RELAY_ROOT" && -d "$RELAY_ROOT" ]]; then
    rm -rf "$RELAY_ROOT"
  fi
}
trap cleanup EXIT

# Detect local directory when run via `bash deploy/vps-install.sh`, or fetch tarball when piped via `curl | sudo bash`
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
if [[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]]; then
  CANDIDATE_ROOT="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
  if [[ -f "$CANDIDATE_ROOT/main.go" ]]; then
    RELAY_ROOT="$CANDIDATE_ROOT"
  fi
fi

if [[ -z "$RELAY_ROOT" ]]; then
  RELAY_ROOT="$(mktemp -d /tmp/syncnow-vps-install.XXXXXX)"
  CLEANUP_TMP=1
  echo "==> 0. Downloading SyncNow Relay source..."
  curl --max-time 30 -fsSL "$REPO_TARBALL" | tar -xz --strip-components=1 -C "$RELAY_ROOT"
fi

echo "==> 1. Building or locating syncnow-relay Linux binary..."
if command -v go >/dev/null 2>&1; then
  (cd "$RELAY_ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$INSTALL_BIN" . < /dev/null)
elif [[ -x "$RELAY_ROOT/syncnow-relay" ]]; then
  install -m 0755 "$RELAY_ROOT/syncnow-relay" "$INSTALL_BIN"
else
  echo "Error: Go is not installed and no prebuilt ./syncnow-relay binary found." >&2
  echo "Install Go 1.22+ (e.g. apt-get update && apt-get install -y golang-go) and re-run." >&2
  exit 1
fi

chmod 0755 "$INSTALL_BIN"
"$INSTALL_BIN" --version

echo "==> 2. Creating dedicated syncnow user & persistent data directory ($DATA_DIR)..."
if ! id -u syncnow >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin syncnow || true
fi
mkdir -p "$DATA_DIR"
chown -R syncnow:syncnow "$DATA_DIR"
chmod 0700 "$DATA_DIR"

echo "==> 3. Writing default environment config ($ENV_FILE)..."
if [[ ! -f "$ENV_FILE" ]]; then
  cat >"$ENV_FILE" <<EOF
SYNCNOW_RELAY_ADDR=${SYNCNOW_RELAY_ADDR:-:8787}
SYNCNOW_RELAY_DATA=${DATA_DIR}
SYNCNOW_RUNTIME=linux-vps
SYNCNOW_AUTH_API=${SYNCNOW_AUTH_API:-https://api.xtags.top}
SYNCNOW_ALLOW_USERS=${SYNCNOW_ALLOW_USERS:-}
SYNCNOW_RELAY_TOKEN=${SYNCNOW_RELAY_TOKEN:-}
SYNCNOW_ADMIN_TOKEN=${SYNCNOW_ADMIN_TOKEN:-}
SYNCNOW_MAX_ENVELOPES=${SYNCNOW_MAX_ENVELOPES:-500}
SYNCNOW_MAX_BLOB_MB=${SYNCNOW_MAX_BLOB_MB:-25}
SYNCNOW_BLOB_TTL_DAYS=${SYNCNOW_BLOB_TTL_DAYS:-7}
SYNCNOW_MAX_TMP_FILE_MB=${SYNCNOW_MAX_TMP_FILE_MB:-1024}
SYNCNOW_MAX_TMP_TOTAL_MB=${SYNCNOW_MAX_TMP_TOTAL_MB:-8192}
SYNCNOW_TMP_TTL_HOURS=${SYNCNOW_TMP_TTL_HOURS:-12}
SYNCNOW_TMP_ACK_GRACE_MINUTES=${SYNCNOW_TMP_ACK_GRACE_MINUTES:-30}
EOF
  chmod 0600 "$ENV_FILE"
  chown root:syncnow "$ENV_FILE"
else
  echo "Preserving existing $ENV_FILE"
fi

echo "==> 4. Installing & starting systemd service (non-blocking)..."
install -m 0644 "$RELAY_ROOT/deploy/syncnow-relay.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable syncnow-relay >/dev/null 2>&1 || true
systemctl restart --no-block syncnow-relay

ADDR_PORT="$(grep -E '^SYNCNOW_RELAY_ADDR=' "$ENV_FILE" | cut -d= -f2 | awk -F: '{print $NF}')"
ADDR_PORT="${ADDR_PORT:-8787}"

echo "==> 5. Waiting up to 8s for relay HTTP readiness on port ${ADDR_PORT}..."
READY=0
for _ in 1 2 3 4 5 6 7 8; do
  if command -v curl >/dev/null 2>&1 && curl --max-time 2 -fsS "http://127.0.0.1:${ADDR_PORT}/ping" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done

if [[ "$READY" -eq 1 ]]; then
  echo "✓ SyncNow Self-Hosted Relay is live!"
else
  echo "! Relay started in background; check logs with: journalctl -u syncnow-relay -n 40 --no-pager"
fi

PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
PUBLIC_IP="${PUBLIC_IP:-YOUR_SERVER_IP}"

echo ""
echo "============================================================"
echo "  SyncNow Self-Hosted Relay Installed Successfully!"
echo "  Open Web Setup in browser:"
echo "    http://${PUBLIC_IP}:${ADDR_PORT}/setup"
echo "  Config : $ENV_FILE"
echo "  Logs   : journalctl -u syncnow-relay -f"
echo "============================================================"
