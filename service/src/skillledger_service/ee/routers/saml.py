"""Enterprise SAML SSO router: SP-initiated login, ACS callback, JIT provisioning,
metadata generation, and admin configuration endpoints.

All SAML endpoints live under /ee/v1 and are loaded only when a valid enterprise
license key is present.
"""

import datetime
import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from fastapi.responses import RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from pydantic import BaseModel, ConfigDict, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.auth import hash_api_key
from skillledger_service.config import Settings
from skillledger_service.db import get_session, get_settings
from skillledger_service.ee.routers.orgs import require_org_role
from skillledger_service.models.organization import (
    Organization,
    OrgMembership,
    OrgRole,
)
from skillledger_service.models.saml_config import SamlConfig
from skillledger_service.models.user import RefreshToken, User
from skillledger_service.user_auth import create_access_token, create_refresh_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ee/v1", tags=["enterprise-saml"])

# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class SamlConfigRequest(BaseModel):
    metadata_xml: Optional[str] = None
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    x509_cert: Optional[str] = None
    attribute_mapping: Optional[dict] = None

    @model_validator(mode="after")
    def validate_config_source(self):
        has_metadata = self.metadata_xml is not None
        has_manual = all([self.entity_id, self.sso_url, self.x509_cert])
        if not has_metadata and not has_manual:
            raise ValueError(
                "Either metadata_xml or all of (entity_id, sso_url, x509_cert) must be provided"
            )
        return self


class SamlConfigResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    org_id: int
    entity_id: str
    sso_url: str
    slo_url: Optional[str] = None
    has_metadata_xml: bool
    attribute_mapping: Optional[dict] = None
    created_at: datetime.datetime
    updated_at: Optional[datetime.datetime] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def prepare_saml_request(request: Request) -> dict:
    """Convert FastAPI Request to python3-saml compatible request dict."""
    port = request.url.port
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname,
        "server_port": port if port else (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": {},
    }


def build_saml_settings(
    saml_config: SamlConfig, settings: Settings, slug: str
) -> dict:
    """Build python3-saml settings dict from SamlConfig + app Settings."""
    sp_entity_id = settings.saml_sp_entity_id or (
        f"{settings.service_url}/ee/v1/saml/{slug}/metadata"
    )
    sp_acs_url = f"{settings.service_url}/ee/v1/saml/{slug}/acs"

    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": saml_config.entity_id,
            "singleSignOnService": {
                "url": saml_config.sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": normalize_cert(saml_config.x509_cert),
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantNameIdEncrypted": False,
            "wantAssertionsEncrypted": False,
        },
    }


def normalize_cert(cert: str) -> str:
    """Strip PEM headers/footers and whitespace, return raw base64 only."""
    cert = re.sub(r"-----BEGIN CERTIFICATE-----", "", cert)
    cert = re.sub(r"-----END CERTIFICATE-----", "", cert)
    cert = re.sub(r"\s+", "", cert)
    return cert


def parse_idp_metadata(metadata_xml: str) -> dict:
    """Parse IdP metadata XML and extract entity_id, sso_url, x509_cert.

    Uses OneLogin_Saml2_IdPMetadataParser.parse() -- never parse_remote()
    to avoid SSRF (T-27-06).
    """
    parsed = OneLogin_Saml2_IdPMetadataParser.parse(metadata_xml)
    idp = parsed.get("idp", {})
    entity_id = idp.get("entityId", "")
    sso_url = idp.get("singleSignOnService", {}).get("url", "")
    x509_cert = idp.get("x509cert", "")
    return {
        "entity_id": entity_id,
        "sso_url": sso_url,
        "x509_cert": x509_cert,
    }


async def jit_provision(
    session: AsyncSession,
    email: str,
    org: Organization,
    attributes: dict,
    default_role: OrgRole = OrgRole.member,
) -> User:
    """Just-In-Time provisioning: create user and/or org membership from SAML assertion.

    Per D-08/D-09: role extracted from attributes via attribute_mapping, defaults to
    member. Never auto-assigns owner (T-27-07).
    """
    # 1. Find or create user
    user = (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
    if user is None:
        user = User(email=email)
        session.add(user)
        await session.flush()

    # 2. Find or create OrgMembership
    membership = (
        await session.execute(
            select(OrgMembership).where(
                OrgMembership.user_id == user.id,
                OrgMembership.org_id == org.id,
            )
        )
    ).scalar_one_or_none()

    created_membership = False
    if membership is None:
        # Determine role from attributes (validate against OrgRole enum)
        role = default_role
        if attributes:
            # Try to extract role from SAML attributes using org's mapping
            saml_config = (
                await session.execute(
                    select(SamlConfig).where(SamlConfig.org_id == org.id)
                )
            ).scalar_one_or_none()
            if saml_config and saml_config.attribute_mapping:
                role_attr_name = saml_config.attribute_mapping.get("role")
                if role_attr_name and role_attr_name in attributes:
                    raw_role = attributes[role_attr_name]
                    if isinstance(raw_role, list):
                        raw_role = raw_role[0] if raw_role else None
                    if raw_role:
                        try:
                            candidate = OrgRole(raw_role.lower())
                            # Never auto-assign owner via SAML (T-27-07)
                            if candidate != OrgRole.owner:
                                role = candidate
                        except ValueError:
                            pass

        membership = OrgMembership(user_id=user.id, org_id=org.id, role=role)
        session.add(membership)
        await session.commit()
        await session.refresh(user)
        created_membership = True

    # Fire-and-forget seat count sync after new membership (same pattern as accept_invite)
    if created_membership:
        try:
            from skillledger_service.ee.seat_billing import (
                get_or_create_seat,
                update_seat_count,
            )

            count_result = await session.execute(
                select(func.count())
                .select_from(OrgMembership)
                .where(OrgMembership.org_id == org.id)
            )
            member_count = count_result.scalar_one()
            seat = await get_or_create_seat(session, org)
            await update_seat_count(session, seat, member_count)
            await session.commit()
        except Exception:
            logger.warning(
                "Seat tracking failed after JIT provision for org %s (fire-and-forget)",
                org.id,
                exc_info=True,
            )
            await session.rollback()

    return user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/saml/{slug}/login")
async def saml_login(
    request: Request,
    slug: str = Path(...),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    """SP-initiated SAML login: redirect to IdP SSO URL with AuthnRequest."""
    # Look up org + SAML config
    org = (
        await session.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    saml_config = (
        await session.execute(
            select(SamlConfig).where(SamlConfig.org_id == org.id)
        )
    ).scalar_one_or_none()
    if not saml_config:
        raise HTTPException(404, "SAML not configured for this organization")

    saml_settings = build_saml_settings(saml_config, settings, slug)
    req = prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, old_settings=saml_settings)
    sso_url = auth.login()
    return RedirectResponse(url=sso_url, status_code=302)


@router.post("/saml/{slug}/acs")
async def saml_acs(
    request: Request,
    slug: str = Path(...),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    """SAML Assertion Consumer Service: validate response, JIT provision, issue JWT."""
    # Look up org + SAML config
    org = (
        await session.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    saml_config = (
        await session.execute(
            select(SamlConfig).where(SamlConfig.org_id == org.id)
        )
    ).scalar_one_or_none()
    if not saml_config:
        raise HTTPException(404, "SAML not configured for this organization")

    # Parse form data (SAML uses HTTP-POST binding, NOT JSON)
    form_data = await request.form()

    saml_settings = build_saml_settings(saml_config, settings, slug)
    req = prepare_saml_request(request)
    req["post_data"] = dict(form_data)

    auth = OneLogin_Saml2_Auth(req, old_settings=saml_settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        logger.warning("SAML ACS errors for org %s: %s", slug, errors)
        raise HTTPException(400, f"SAML validation failed: {', '.join(errors)}")

    email = auth.get_nameid()
    attributes = auth.get_attributes()

    # JIT provisioning
    user = await jit_provision(session, email, org, attributes)
    await session.commit()

    # Generate JWT tokens (identical to OTP flow per D-10)
    access_token = create_access_token(
        user.id, user.email, settings.jwt_secret, settings.jwt_algorithm
    )
    refresh_token = create_refresh_token(
        user.id, settings.jwt_secret, settings.jwt_algorithm
    )

    # Store refresh token hash (same pattern as auth_router verify_otp)
    now = datetime.datetime.now(datetime.timezone.utc)
    refresh_hash = hash_api_key(refresh_token)
    rt = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=now + datetime.timedelta(days=30),
    )
    session.add(rt)
    await session.commit()

    # Redirect with tokens in URL fragment
    callback_url = (
        f"{settings.dashboard_url}/auth/callback"
        f"#access_token={access_token}&refresh_token={refresh_token}"
    )
    return RedirectResponse(url=callback_url, status_code=302)


@router.get("/saml/{slug}/metadata")
async def saml_metadata(
    slug: str = Path(...),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    """Return SP metadata XML for IdP configuration."""
    org = (
        await session.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    saml_config = (
        await session.execute(
            select(SamlConfig).where(SamlConfig.org_id == org.id)
        )
    ).scalar_one_or_none()
    if not saml_config:
        raise HTTPException(404, "SAML not configured for this organization")

    saml_settings_dict = build_saml_settings(saml_config, settings, slug)
    saml_settings_obj = OneLogin_Saml2_Settings(saml_settings_dict)
    metadata = saml_settings_obj.get_sp_metadata()
    return Response(content=metadata, media_type="text/xml")


@router.put("/orgs/{slug}/saml")
async def configure_saml(
    body: SamlConfigRequest,
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
):
    """Configure or update SAML IdP settings for an organization (admin+)."""
    org, _, _ = ctx

    # Extract IdP details from metadata or manual entry
    if body.metadata_xml:
        parsed = parse_idp_metadata(body.metadata_xml)
        entity_id = parsed["entity_id"]
        sso_url = parsed["sso_url"]
        x509_cert = normalize_cert(parsed["x509_cert"])
    else:
        entity_id = body.entity_id
        sso_url = body.sso_url
        x509_cert = normalize_cert(body.x509_cert)

    # Default attribute mapping
    attribute_mapping = body.attribute_mapping or {
        "email": "NameID",
        "firstName": "User.FirstName",
        "lastName": "User.LastName",
        "role": "memberOf",
    }

    # Upsert
    existing = (
        await session.execute(
            select(SamlConfig).where(SamlConfig.org_id == org.id)
        )
    ).scalar_one_or_none()

    now = datetime.datetime.now(datetime.timezone.utc)
    if existing:
        existing.entity_id = entity_id
        existing.sso_url = sso_url
        existing.x509_cert = x509_cert
        existing.attribute_mapping = attribute_mapping
        if body.metadata_xml:
            existing.metadata_xml = body.metadata_xml
        existing.updated_at = now
        config = existing
    else:
        config = SamlConfig(
            org_id=org.id,
            entity_id=entity_id,
            sso_url=sso_url,
            x509_cert=x509_cert,
            metadata_xml=body.metadata_xml,
            attribute_mapping=attribute_mapping,
        )
        session.add(config)

    await session.commit()
    await session.refresh(config)

    return SamlConfigResponse(
        id=config.id,
        org_id=config.org_id,
        entity_id=config.entity_id,
        sso_url=config.sso_url,
        slo_url=config.slo_url,
        has_metadata_xml=config.metadata_xml is not None,
        attribute_mapping=config.attribute_mapping,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


@router.get("/orgs/{slug}/saml")
async def get_saml_config(
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
):
    """Get SAML configuration for an organization (admin+).

    Does NOT expose raw x509_cert or full metadata XML (T-27-05).
    """
    org, _, _ = ctx

    config = (
        await session.execute(
            select(SamlConfig).where(SamlConfig.org_id == org.id)
        )
    ).scalar_one_or_none()
    if not config:
        raise HTTPException(404, "SAML not configured for this organization")

    return SamlConfigResponse(
        id=config.id,
        org_id=config.org_id,
        entity_id=config.entity_id,
        sso_url=config.sso_url,
        slo_url=config.slo_url,
        has_metadata_xml=config.metadata_xml is not None,
        attribute_mapping=config.attribute_mapping,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


@router.delete("/orgs/{slug}/saml", status_code=204)
async def delete_saml_config(
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Delete SAML configuration for an organization (admin+)."""
    org, _, _ = ctx

    config = (
        await session.execute(
            select(SamlConfig).where(SamlConfig.org_id == org.id)
        )
    ).scalar_one_or_none()
    if not config:
        raise HTTPException(404, "SAML not configured for this organization")

    await session.delete(config)
    await session.commit()
