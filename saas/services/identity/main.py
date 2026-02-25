"""
AIAAP Identity & JIT Service (port 8300)
-----------------------------------------
Manages AgentPrincipal records and Just-In-Time grants.
Exposes CRUD endpoints consumed by the dashboard and the detections engine.
"""

import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from saas.services.shared.database import create_all_tables

logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("aiaap_identity_starting")
    create_all_tables()
    logger.info("aiaap_identity_tables_ready")
    yield
    logger.info("aiaap_identity_stopping")


app = FastAPI(
    title="AIAAP Identity & JIT Service",
    version="0.1.0",
    description="Manages agent identity posture and just-in-time access grants.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from saas.services.identity.routes_principals import router as principals_router  # noqa: E402
from saas.services.identity.routes_jit        import router as jit_router         # noqa: E402
from saas.services.identity.routes_audit      import router as audit_router       # noqa: E402
from saas.services.identity.routes_pdp        import router as pdp_router         # noqa: E402
from saas.services.identity.routes_approvals  import router as approvals_router   # noqa: E402

app.include_router(principals_router, prefix="/api", tags=["Principals"])
app.include_router(jit_router,        prefix="/api", tags=["JIT Grants"])
app.include_router(audit_router,      prefix="/api", tags=["Audit"])
app.include_router(pdp_router,        prefix="/api", tags=["PDP"])
app.include_router(approvals_router,  prefix="/api", tags=["Approvals"])


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy", "service": "aiaap-identity", "version": "0.1.0"}
