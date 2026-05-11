#!/usr/bin/env bash
# UAT-10: Validate VPS install script runs without errors.
# Tests the hook installer in --dry-run-like mode (validates logic without
# actually installing to system directories).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_SCRIPT="$PROJECT_ROOT/hooks/install.sh"

ERRORS=0
TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

echo "Validating install.sh..."

# Check script exists and is executable-parseable
if [ ! -f "$INSTALL_SCRIPT" ]; then
  echo "  [FAIL] install.sh not found at $INSTALL_SCRIPT"
  exit 1
fi
echo "  [OK] install.sh exists"

# Syntax check
bash -n "$INSTALL_SCRIPT"
echo "  [OK] Syntax valid (bash -n)"

# Check all referenced hook scripts exist
echo ""
echo "Checking referenced hook scripts..."
for hook in claude-code-hook.sh mcp-hook.sh npm-hook.sh openclaw-hook.sh generic-hook.sh; do
  if [ -f "$PROJECT_ROOT/hooks/$hook" ]; then
    echo "  [OK] $hook exists"
    # Syntax check each hook
    bash -n "$PROJECT_ROOT/hooks/$hook"
  else
    echo "  [FAIL] $hook missing!"
    ERRORS=$((ERRORS + 1))
  fi
done

# Test install.sh with HOME overridden to temp dir (no system writes)
echo ""
echo "Running install.sh with sandboxed HOME..."
HOME="$TMPDIR_TEST" bash "$INSTALL_SCRIPT" --ecosystem all 2>&1 | head -20
INSTALL_EXIT=$?

if [ $INSTALL_EXIT -eq 0 ]; then
  echo "  [OK] install.sh completed successfully"
else
  echo "  [FAIL] install.sh exited with code $INSTALL_EXIT"
  ERRORS=$((ERRORS + 1))
fi

# Verify hooks were placed in expected locations
echo ""
echo "Verifying installed hooks..."
EXPECTED_PATHS=(
  "$TMPDIR_TEST/.claude/hooks/pre-install/skillledger-verify.sh"
  "$TMPDIR_TEST/.config/mcp/hooks/pre-install/skillledger-verify.sh"
)
for path in "${EXPECTED_PATHS[@]}"; do
  if [ -f "$path" ]; then
    echo "  [OK] $(basename "$(dirname "$(dirname "$path")")")/...hook installed"
  else
    echo "  [WARN] Expected hook not found: $path"
  fi
done

echo ""
if [ $ERRORS -eq 0 ]; then
  echo "VPS install script validation passed"
else
  echo "FAILED: $ERRORS errors found"
  exit 1
fi
