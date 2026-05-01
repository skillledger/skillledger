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
    from skillledger_service.ee.routers.policy import router as policy_router
    from skillledger_service.ee.routers.events import router as events_router
    from skillledger_service.ee.routers.profiles import router as profiles_router
    from skillledger_service.ee.routers.billing_seats import router as billing_seats_router
    from skillledger_service.ee.routers.saml import router as saml_router

    app.include_router(orgs_router)
    app.include_router(policy_router)
    app.include_router(events_router)
    app.include_router(profiles_router)
    app.include_router(billing_seats_router)
    app.include_router(saml_router)
    logger.info("Enterprise edition routers loaded")
