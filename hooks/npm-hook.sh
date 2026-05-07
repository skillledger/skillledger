#!/usr/bin/env bash
# Pre-install verification hook for npm-based skill packages
# Install: Add to package.json scripts:
#   "preinstall": "./hooks/npm-hook.sh ${npm_package_name}"
#
# For npm packages, the artifact path may need to be resolved from the
# npm cache or package tarball. This script expects the artifact path
# as the first argument.
#
# Environment variables:
#   SKILLLEDGER_POLICY     - Policy preset (default: moderate)
#   SKILLLEDGER_SERVICE_URL - Transparency log URL (default: https://log.skillledger.dev)
#   SKILLLEDGER_SKIP_TLOG  - Set to "true" for offline mode
set -euo pipefail

ARTIFACT="${1:?Usage: npm-hook.sh <artifact-path>}"
POLICY="${SKILLLEDGER_POLICY:-moderate}"
SERVICE_URL="${SKILLLEDGER_SERVICE_URL:-https://log.skillledger.dev}"
SKIP_TLOG="${SKILLLEDGER_SKIP_TLOG:-false}"

# Validate service URL uses HTTPS (except localhost for development)
case "$SERVICE_URL" in
  https://*) ;; # OK
  http://localhost*|http://127.0.0.1*) ;; # OK for dev
  *) echo "ERROR: SKILLLEDGER_SERVICE_URL must use HTTPS" >&2; exit 1 ;;
esac

if ! command -v skillledger &>/dev/null; then
    echo "ERROR: skillledger not found in PATH. Install from https://github.com/skillledger/skillledger" >&2
    exit 1
fi

# Invoke: skillledger verify <artifact> with policy and service configuration
ARGS=(verify --artifact "$ARTIFACT" --preset "$POLICY" --service-url "$SERVICE_URL")
if [ "${SKILLLEDGER_SKIP_TLOG:-}" = "true" ]; then
    echo "WARNING: Transparency log verification SKIPPED (SKILLLEDGER_SKIP_TLOG=true)" >&2
    echo "WARNING: This reduces supply-chain security guarantees" >&2
    ARGS+=(--skip-tlog)
fi

skillledger "${ARGS[@]}"
exit $?
