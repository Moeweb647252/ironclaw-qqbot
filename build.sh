#!/usr/bin/env bash
# Build the QQ Bot channel WASM component.
#
# Prerequisites:
#   - Rust with wasm32-wasip2 target: rustup target add wasm32-wasip2
#   - wasm-tools for component creation: cargo install wasm-tools
#
# Output:
#   - qqbot.wasm
#   - qqbot.capabilities.json
#   - qqbot-wasm32-wasip2.tar.gz
#   - qqbot-wasm32-wasip2.tar.gz.sha256

set -euo pipefail

cd "$(dirname "$0")"

if ! rustup target list --installed | grep -qx 'wasm32-wasip2'; then
    echo "Error: wasm32-wasip2 target is not installed."
    echo "Install with: rustup target add wasm32-wasip2"
    exit 1
fi

if ! command -v wasm-tools >/dev/null 2>&1; then
    echo "Error: wasm-tools not found. Install with: cargo install wasm-tools"
    exit 1
fi

echo "Building QQ Bot channel WASM component..."

cargo build --release --target wasm32-wasip2

WASM_PATH="target/wasm32-wasip2/release/qqbot_channel.wasm"

if [ ! -f "$WASM_PATH" ]; then
    echo "Error: WASM output not found at $WASM_PATH"
    exit 1
fi

wasm-tools component new "$WASM_PATH" -o qqbot.wasm 2>/dev/null || cp "$WASM_PATH" qqbot.wasm
wasm-tools strip qqbot.wasm -o qqbot.wasm

tar -czf qqbot-wasm32-wasip2.tar.gz qqbot.wasm qqbot.capabilities.json
sha256sum qqbot-wasm32-wasip2.tar.gz > qqbot-wasm32-wasip2.tar.gz.sha256

echo "Built: qqbot.wasm ($(du -h qqbot.wasm | cut -f1))"
echo "Built: qqbot-wasm32-wasip2.tar.gz ($(du -h qqbot-wasm32-wasip2.tar.gz | cut -f1))"
echo ""
echo "Bundle contents:"
tar -tzf qqbot-wasm32-wasip2.tar.gz
echo ""
echo "Direct install:"
echo "  mkdir -p ~/.ironclaw/channels"
echo "  cp qqbot.wasm qqbot.capabilities.json ~/.ironclaw/channels/"
echo ""
echo "Artifact install:"
echo "  publish qqbot-wasm32-wasip2.tar.gz and use that URL in the IronClaw manifest"
echo ""
echo "Config note:"
echo "  This version currently reads app_id/app_secret from channel config,"
echo "  because the current IronClaw WASM host cannot inject secrets into"
echo "  the JSON body required by QQ token refresh."
