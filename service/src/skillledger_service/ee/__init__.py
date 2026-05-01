"""Enterprise edition package.

Provides load_ee_routers(app) to conditionally register enterprise-only
API routes when a valid license key is present.
"""

import logging

from fastapi import FastAPI

from skillledger_service.ee.license import validate_license_key

logger = logging.getLogger(__name__)

__all__ = ["load_ee_routers", "validate_license_key"]


def load_ee_routers(app: FastAPI) -> None:
    """Register all enterprise edition routers on *app*."""
    from skillledger_service.ee.routers.orgs import router as orgs_router

    app.include_router(orgs_router)
    logger.info("Enterprise edition routers loaded")
