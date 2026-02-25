"""
AIAAP Runtime Service (port 8400)
-----------------------------------
5th SaaS microservice - server-side content inspection.
Ports AIRS-CP injection + PII detection capabilities from inline proxy
into a telemetry-first, submit-and-analyze API.

Raw content is NEVER persisted - only detection metadata (sha256 hash + signals).

Endpoints:
  POST /api/runtime/analyze     - submit content for injection + PII scan
  GET  /api/runtime/detections  - query stored detection records
  GET  /health
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
    logger.info("aiaap_runtime_starting")
    create_all_tables()
    logger.info("aiaap_runtime_tables_ready")
    yield
    logger.info("aiaap_runtime_stopping")


app = FastAPI(
    title="AIAAP Runtime Service",
    version="0.1.0",
    description=(
        "Server-side runtime content inspection (injection + PII). "
        "Part of the AIRS Runtime Pack. Raw content is never persisted."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from saas.services.runtime.routes_runtime import router as runtime_router  # noqa: E402

app.include_router(runtime_router, prefix="/api", tags=["Runtime Detections"])


@app.get("/health", tags=["Health"])
def health():
    return {
        "status":  "healthy",
        "service": "aiaap-runtime",
        "version": "0.1.0",
        "pack":    "AIRS Runtime Pack",
    }
