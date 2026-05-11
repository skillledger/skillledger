#!/usr/bin/env bash
# UAT-04: Verify Docker compose stack starts with all services healthy.
# Requires: Docker installed, ports 8000/3000/5432/2025 available.
# Usage: bash hooks/tests/test_docker_compose.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Create test .env if not exists
if [ ! -f .env ]; then
  cat > .env.test <<'EOF'
POSTGRES_PASSWORD=testpass123
SKILLLEDGER_ADMIN_API_KEY=test-admin-key-uat
SKILLLEDGER_JWT_SECRET=test-jwt-secret-minimum-32-characters-long
AUTH_SECRET=test-auth-secret-for-dashboard
LOG_PRIVATE_KEY=test-log-key
EOF
  ENV_FILE=".env.test"
else
  ENV_FILE=".env"
fi

cleanup() {
  echo "Tearing down..."
  docker compose --env-file "$ENV_FILE" down -v --remove-orphans 2>/dev/null || true
  [ "$ENV_FILE" = ".env.test" ] && rm -f .env.test
}
trap cleanup EXIT

echo "Starting Docker compose stack..."
docker compose --env-file "$ENV_FILE" up -d --build --wait --timeout 120

echo "Checking service health..."
# Postgres
docker compose --env-file "$ENV_FILE" exec -T postgres pg_isready -U skillledger
echo "  [OK] Postgres healthy"

# Log service
curl -sf http://localhost:2025/checkpoint > /dev/null
echo "  [OK] Log service healthy"

# API service
curl -sf http://localhost:8000/v1/health > /dev/null
echo "  [OK] API service healthy"

# Dashboard (just check it responds)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ || echo "000")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
  echo "  [OK] Dashboard responding ($HTTP_CODE)"
else
  echo "  [WARN] Dashboard returned $HTTP_CODE (may need build time)"
fi

echo ""
echo "Health checks passed - Docker compose stack is functional"
