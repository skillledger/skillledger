import json
import logging
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.models.threat import IocDomain, IocHash

logger = logging.getLogger(__name__)

# Path to bundled CLI data (relative to project root, works in Docker context)
_DATA_DIR = Path(__file__).resolve().parents[3] / "cli" / "internal" / "ioc" / "data"


async def seed_threat_data(session: AsyncSession) -> None:
    """Seed IOC data from bundled CLI JSON files if tables are empty.

    Per D-02: zero-touch deployment. Runs on every startup; no-op when
    tables already contain data. Per T-19-02 mitigation: checks row count
    before seeding to prevent duplicate inserts on restart.
    """
    count_result = await session.execute(select(func.count()).select_from(IocHash))
    hash_count = count_result.scalar_one()
    count_result2 = await session.execute(select(func.count()).select_from(IocDomain))
    domain_count = count_result2.scalar_one()

    if hash_count > 0 or domain_count > 0:
        logger.info(
            "Threat tables already seeded (hashes=%d, domains=%d)",
            hash_count,
            domain_count,
        )
        return

    # Seed IOC hashes
    hashes_path = _DATA_DIR / "ioc-hashes.json"
    if hashes_path.exists():
        data = json.loads(hashes_path.read_text())
        for entry in data:
            session.add(
                IocHash(
                    sha256=entry["sha256"],
                    description=entry.get("description", ""),
                    severity=entry.get("severity", "unknown"),
                    source=entry.get("source", ""),
                    reported_at=entry.get("reported_at"),
                )
            )
        logger.info("Seeded %d IOC hashes from %s", len(data), hashes_path)

    # Seed IOC domains
    domains_path = _DATA_DIR / "ioc-domains.json"
    if domains_path.exists():
        data = json.loads(domains_path.read_text())
        for entry in data:
            session.add(
                IocDomain(
                    domain=entry["domain"],
                    description=entry.get("description", ""),
                    severity=entry.get("severity", "unknown"),
                    source=entry.get("source", ""),
                    reported_at=entry.get("reported_at"),
                )
            )
        logger.info("Seeded %d IOC domains from %s", len(data), domains_path)

    await session.commit()
    logger.info("Threat data seeding complete")
