#!/usr/bin/env bash
# SkillLedger hook installer
# Copies or symlinks pre-install hooks to the correct locations for each ecosystem.
#
# Usage: hooks/install.sh [--ecosystem ECOSYSTEM] [--link]
#   --ecosystem: claude-code, mcp, npm, openclaw, all (default: all)
#   --link: Create symlinks instead of copies
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ECOSYSTEM="all"
USE_LINK=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --ecosystem) ECOSYSTEM="$2"; shift 2 ;;
        --link) USE_LINK=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

install_hook() {
    local src="$1"
    local dst="$2"
    local name="$3"

    if [ ! -f "$src" ]; then
        echo "ERROR: Source hook not found: $src" >&2
        return 1
    fi

    mkdir -p "$(dirname "$dst")"

    if [ "$USE_LINK" = true ]; then
        ln -sf "$src" "$dst"
        echo "Linked $name: $dst -> $src"
    else
        cp "$src" "$dst"
        chmod +x "$dst"
        echo "Installed $name: $dst"
    fi
}

install_claude_code() {
    local dst="${HOME}/.claude/hooks/pre-install/skillledger-verify.sh"
    install_hook "${SCRIPT_DIR}/claude-code-hook.sh" "$dst" "Claude Code hook"
}

install_mcp() {
    local dst="${HOME}/.config/mcp/hooks/pre-install/skillledger-verify.sh"
    install_hook "${SCRIPT_DIR}/mcp-hook.sh" "$dst" "MCP hook"
}

install_npm() {
    echo "npm hook: Add to package.json scripts.preinstall:"
    echo "  \"preinstall\": \"${SCRIPT_DIR}/npm-hook.sh \\\"\$npm_package_name\\\"\""
    echo ""
    echo "Or globally: npm config set script-shell ${SCRIPT_DIR}/npm-hook.sh"
}

install_openclaw() {
    local dst="${HOME}/.config/openclaw/hooks/pre-install/skillledger-verify.sh"
    install_hook "${SCRIPT_DIR}/openclaw-hook.sh" "$dst" "OpenClaw hook"
}

case "$ECOSYSTEM" in
    claude-code) install_claude_code ;;
    mcp) install_mcp ;;
    npm) install_npm ;;
    openclaw) install_openclaw ;;
    all)
        install_claude_code
        install_mcp
        install_npm
        install_openclaw
        ;;
    *)
        echo "Unknown ecosystem: $ECOSYSTEM" >&2
        echo "Supported: claude-code, mcp, npm, openclaw, all" >&2
        exit 1
        ;;
esac

echo ""
echo "Done. Set SKILLLEDGER_SERVICE_URL to point to your transparency log."
