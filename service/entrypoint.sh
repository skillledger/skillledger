#!/usr/bin/env bash
# SkillLedger Service Entrypoint
# Runs database migrations before starting the application server.
# The SKILLLEDGER_DATABASE_URL env var is read by alembic/env.py.
set -euo pipefail

echo "SkillLedger Service - starting up"

# Run database migrations before accepting traffic.
# alembic/env.py reads SKILLLEDGER_DATABASE_URL from the environment
# and overrides the alembic.ini default (sqlite) with the production URL.
echo "Running database migrations..."
cd /app
alembic upgrade head

echo "Migrations complete. Starting uvicorn..."
exec uvicorn skillledger_service.main:app --host 0.0.0.0 --port 8000
