#!/usr/bin/env bash
# Pre-install verification hook for OpenClaw plugins
# Install: Add to your OpenClaw plugin install pipeline
#
# Environment variables:
#   SKILLLEDGER_POLICY     - Policy preset (default: moderate)
#   SKILLLEDGER_SERVICE_URL - Transparency log URL (default: http://localhost:8000)
#   SKILLLEDGER_SKIP_TLOG  - Set to "true" for offline mode
set -euo pipefail

ARTIFACT="${1:?Usage: openclaw-hook.sh <artifact-path>}"
POLICY="${SKILLLEDGER_POLICY:-moderate}"
SERVICE_URL="${SKILLLEDGER_SERVICE_URL:-http://localhost:8000}"
SKIP_TLOG="${SKILLLEDGER_SKIP_TLOG:-false}"

if ! command -v skillledger &>/dev/null; then
    echo "ERROR: skillledger not found in PATH. Install from https://github.com/skillledger/skillledger" >&2
    exit 1
fi

# Invoke: skillledger verify <artifact> with policy and service configuration
ARGS=(verify --artifact "$ARTIFACT" --preset "$POLICY" --service-url "$SERVICE_URL")
if [ "$SKIP_TLOG" = "true" ]; then
    ARGS+=(--skip-tlog)
fi

skillledger "${ARGS[@]}"
exit $?
