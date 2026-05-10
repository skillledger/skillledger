#!/usr/bin/env bash
# UAT-09: Validate Docker compose config syntax and required env vars.
# Does NOT start containers — only validates config.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

ERRORS=0

echo "Validating docker-compose.yml..."
# Provide required env vars for config validation
export POSTGRES_PASSWORD=validate
export SKILLLEDGER_ADMIN_API_KEY=validate
export SKILLLEDGER_JWT_SECRET=validate
export AUTH_SECRET=validate
export LOG_PRIVATE_KEY=validate

docker compose config --quiet
echo "  [OK] docker-compose.yml is valid"

echo "Validating docker-compose.prod.yml overlay..."
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
echo "  [OK] Production overlay is valid"

echo ""
echo "Checking required services defined..."
SERVICES=$(docker compose config --services)
for svc in skillledger-service skillledger-log postgres skillledger-dashboard; do
  if echo "$SERVICES" | grep -q "^${svc}$"; then
    echo "  [OK] Service '$svc' defined"
  else
    echo "  [FAIL] Service '$svc' missing!"
    ERRORS=$((ERRORS + 1))
  fi
done

echo ""
echo "Checking health checks defined..."
CONFIG=$(docker compose config)
for svc in postgres skillledger-log; do
  if echo "$CONFIG" | grep -A5 "${svc}:" | grep -q "healthcheck"; then
    echo "  [OK] $svc has healthcheck"
  else
    echo "  [WARN] $svc missing healthcheck"
  fi
done

echo ""
if [ $ERRORS -eq 0 ]; then
  echo "docker compose config validation passed"
else
  echo "FAILED: $ERRORS errors found"
  exit 1
fi
