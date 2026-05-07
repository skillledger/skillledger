#!/usr/bin/env bash
# SkillLedger Service Entrypoint
# Runs database migrations before starting the application server.
# The SKILLLEDGER_DATABASE_URL env var is read by alembic/env.py.
set -euo pipefail

echo "SkillLedger Service - starting up"

cd /app

# Wait for database connectivity before running migrations (WR-02).
# On Railway/Render there is no depends_on; the DB may still be initializing.
if [ -n "${SKILLLEDGER_DATABASE_URL:-}" ] || [ -n "${DATABASE_URL:-}" ]; then
    echo "Waiting for database..."
    retries=0
    until python -c "
import asyncio, os
from sqlalchemy.ext.asyncio import create_async_engine
url = os.environ.get('SKILLLEDGER_DATABASE_URL') or os.environ.get('DATABASE_URL', '')
if url.startswith('postgresql://'):
    url = url.replace('postgresql://', 'postgresql+asyncpg://', 1)
async def check():
    e = create_async_engine(url)
    async with e.connect(): pass
    await e.dispose()
asyncio.run(check())
" 2>/dev/null; do
        retries=$((retries + 1))
        if [ $retries -ge 15 ]; then
            echo "Database not reachable after 30s — proceeding anyway (migrations may fail)"
            break
        fi
        echo "Database not ready, retrying in 2s..."
        sleep 2
    done
    echo "Database ready."
fi

# Run database migrations before accepting traffic.
# alembic/env.py reads SKILLLEDGER_DATABASE_URL from the environment
# and overrides the alembic.ini default (sqlite) with the production URL.
echo "Running database migrations..."
alembic upgrade head

echo "Migrations complete. Starting uvicorn..."
exec uvicorn skillledger_service.main:app --host 0.0.0.0 --port 8000
