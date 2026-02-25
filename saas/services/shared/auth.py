"""
AIAAP Multi-Tenant Authentication
-----------------------------------
Provides the `get_tenant` FastAPI dependency used by all write endpoints.

When REQUIRE_API_KEY=false (default for local dev):
  - tenant_id is taken from the X-Tenant-Id header, defaulting to "default"
  - No API key validation is performed
  - Suitable for docker-compose local development and demos

When REQUIRE_API_KEY=true (production SaaS mode):
  - X-Api-Key header is required
  - tenant_id is DERIVED from the TenantApiKey DB record (cannot be spoofed)
  - X-Tenant-Id header is IGNORED to prevent tenant_id manipulation
  - Returns HTTP 403 if key is missing or invalid

Usage in a FastAPI route:
    from saas.services.shared.auth import get_tenant

    @router.post("/events", status_code=201)
    def ingest_event(req: IngestEventRequest, tenant_id: str = Depends(get_tenant), db=Depends(get_db)):
        ...

Bootstrap new tenants:
    python saas/scripts/bootstrap_tenant.py --tenant-id acme --description "Acme Corp"
    # Prints: AIAAP_API_KEY=<plain-text key>  (stored only as bcrypt hash in DB)
"""

import os
from functools import lru_cache

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from saas.services.shared.database import get_db

REQUIRE_API_KEY: bool = os.getenv("REQUIRE_API_KEY", "false").lower() == "true"


def _verify_key(plain_key: str, key_hash: str) -> bool:
    """bcrypt verify with lazy import (bcrypt is not installed in all environments)."""
    try:
        import bcrypt
        return bcrypt.checkpw(plain_key.encode(), key_hash.encode())
    except ImportError:
        # Fallback: constant-time string comparison (for dev without bcrypt)
        import hmac
        return hmac.compare_digest(plain_key, key_hash)


def _lookup_key(plain_key: str, db: Session):
    """Look up an active TenantApiKey by verifying the plain key against stored hashes."""
    from saas.services.shared.models import TenantApiKey
    # Fetch all active keys and bcrypt-verify (keys table is small per tenant)
    candidates = db.query(TenantApiKey).filter(TenantApiKey.active == True).all()  # noqa: E712
    for record in candidates:
        if _verify_key(plain_key, record.key_hash):
            return record
    return None


def get_tenant(
    x_api_key: str | None = Header(None, alias="X-Api-Key"),
    x_tenant_id: str | None = Header(None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
) -> str:
    """
    FastAPI dependency: resolves and validates the tenant for the current request.

    Returns the tenant_id string to be used in all DB queries and stored records.
    """
    if not REQUIRE_API_KEY:
        # Local dev / demo mode: trust the X-Tenant-Id header, default to "default"
        return x_tenant_id or "default"

    # Production mode: API key is mandatory; tenant_id derived from key record
    if not x_api_key:
        raise HTTPException(
            status_code=403,
            detail="X-Api-Key header is required. "
                   "Provision a key with: python saas/scripts/bootstrap_tenant.py",
        )

    key_record = _lookup_key(x_api_key, db)
    if not key_record:
        raise HTTPException(status_code=403, detail="Invalid or inactive API key.")

    # Security: return tenant from DB record - not from the request header
    return key_record.tenant_id
