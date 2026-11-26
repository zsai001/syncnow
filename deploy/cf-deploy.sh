#!/usr/bin/env bash
# Direct Cloudflare Workers deployer for SyncNow Relay — ZERO Cloudflare GitHub App required!
# Works on Cloudflare Workers Free Plan (SQLite Durable Objects + Hibernatable WebSockets).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/cf-deploy.sh | bash
# Optional custom worker name:
#   curl -fsSL https://raw.githubusercontent.com/zsai001/syncnow/main/deploy/cf-deploy.sh | WORKER_NAME=my-syncnow bash
set -euo pipefail

REPO_TARBALL="${SYNCNOW_RELAY_TARBALL:-https://github.com/zsai001/syncnow/archive/refs/heads/main.tar.gz}"
WORKER_NAME="${WORKER_NAME:-}"
DRY_RUN="${CF_DEPLOY_DRY_RUN:-0}"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Error: Node.js (v18+) and npm are required to deploy directly via Wrangler." >&2
  echo "Install Node.js from https://nodejs.org (macOS: brew install node) and re-run." >&2
  exit 1
fi

WORK_DIR=""
CLEANUP_WORK_DIR=0
cleanup() {
  if [[ "$CLEANUP_WORK_DIR" -eq 1 && -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

# If already executed inside a cloned syncnow-relay directory, deploy directly from here;
# otherwise download the ~40KB source tarball into a clean temporary directory.
if [[ -f "./wrangler.toml" && -f "./cloudflare/src/index.ts" ]]; then
  WORK_DIR="$(pwd)"
  echo "==> 1. Using local syncnow-relay directory ($WORK_DIR)"
else
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/syncnow-cf-deploy.XXXXXX")"
  CLEANUP_WORK_DIR=1
  echo "==> 1. Downloading SyncNow Relay source (~40KB)..."
  curl --max-time 30 -fsSL "$REPO_TARBALL" | tar -xz --strip-components=1 -C "$WORK_DIR"
fi

cd "$WORK_DIR"

if [[ -n "$WORKER_NAME" ]]; then
  echo "==> Customizing worker name to: $WORKER_NAME"
  node -e '
    const fs = require("fs");
    const name = process.argv[1].replace(/[^a-z0-9-]/gi, "-").toLowerCase();
    let txt = fs.readFileSync("wrangler.toml", "utf8");
    txt = txt.replace(/^name\s*=\s*"[^"]*"/m, `name = "${name}"`);
    fs.writeFileSync("wrangler.toml", txt);
  ' "$WORKER_NAME"
fi

echo "==> 2. Installing Wrangler & TypeScript dependencies..."
npm install --no-audit --no-fund --loglevel=error

if [[ "$DRY_RUN" == "1" ]]; then
  echo "==> 3. Running Wrangler dry-run verification..."
  npx wrangler deploy --dry-run --outdir=.wrangler-dry-run
  rm -rf .wrangler-dry-run
  echo "✓ Dry-run succeeded!"
  exit 0
fi

echo "==> 3. Checking Cloudflare authentication (no GitHub App needed)..."
if ! npx wrangler whoami >/dev/null 2>&1; then
  echo "Opening Cloudflare login in your browser..."
  npx wrangler login
fi

R2_BUCKET_NAME="${R2_BUCKET_NAME:-syncnow-tmp-blobs}"
if [[ "${SKIP_R2:-0}" != "1" ]]; then
  echo "==> 3b. Probing Cloudflare R2 for large-file tmp storage ($R2_BUCKET_NAME)..."
  if npx wrangler r2 bucket list 2>/dev/null | grep -q "$R2_BUCKET_NAME" || npx wrangler r2 bucket create "$R2_BUCKET_NAME" >/dev/null 2>&1; then
    echo "✓ Cloudflare R2 bucket '$R2_BUCKET_NAME' is active — enabling zero-egress R2 tmp storage!"
    node -e '
      const fs = require("fs");
      const bucket = process.argv[1];
      let txt = fs.readFileSync("wrangler.toml", "utf8");
      if (!/^\s*\[\[r2_buckets\]\]/m.test(txt)) {
        txt += `\n[[r2_buckets]]\nbinding = "BLOBS"\nbucket_name = "${bucket}"\n`;
        fs.writeFileSync("wrangler.toml", txt);
      }
    ' "$R2_BUCKET_NAME"
    npx wrangler r2 bucket lifecycle add "$R2_BUCKET_NAME" "syncnow-tmp-safety-gc" "tmp/" --expire-days 3 --abort-multipart-days 1 --force >/dev/null 2>&1 || true
  else
    echo "ℹ R2 is not activated on this Cloudflare account yet; deploying with Free-Plan DO SQLite tmp fallback (128MB/file)."
    echo "  (Tip: Enable R2 for free in Cloudflare Dashboard and re-run this command anytime to unlock 1GB+ R2 tmp relay!)"
  fi
fi

echo "==> 4. Deploying SyncNow Relay directly to Cloudflare Workers..."
DEPLOY_LOG="$(mktemp "${TMPDIR:-/tmp}/syncnow-wrangler.XXXXXX")"
npx wrangler deploy 2>&1 | tee "$DEPLOY_LOG"
WORKER_URL="$(grep -Eo 'https://[a-zA-Z0-9._-]+\.workers\.dev' "$DEPLOY_LOG" | head -n 1 || true)"
rm -f "$DEPLOY_LOG"

echo ""
echo "============================================================"
echo "  ✓ SyncNow Relay deployed to Cloudflare Workers!"
if [[ -n "$WORKER_URL" ]]; then
  echo "  Open Web Setup in your browser:"
  echo "    ${WORKER_URL}/setup"
else
  echo "  Open your *.workers.dev URL in browser to finish /setup"
fi
echo "============================================================"
