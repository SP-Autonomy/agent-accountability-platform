"""
AIAAP Runtime Service - API Routes
------------------------------------
POST /api/runtime/analyze  - run injection + PII detectors, store RuntimeDetection rows
GET  /api/runtime/detections - query stored detections with filters
"""

import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

import structlog
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from saas.services.shared.database import get_db
from saas.services.shared.models import RuntimeDetection, Severity
from saas.services.runtime.detectors.injection import get_injection_detector
from saas.services.runtime.detectors.pii import get_pii_detector

logger = structlog.get_logger()

router = APIRouter()


# ── Request / Response schemas ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    tenant_id:  str = "default"
    trace_id:   Optional[str] = None
    agent_id:   Optional[str] = None
    direction:  str = "request"   # "request" | "response"
    content:    str


class DetectionResult(BaseModel):
    detector_type: str
    triggered:     bool
    severity:      str
    confidence:    float
    signal:        dict[str, Any]


class AnalyzeResponse(BaseModel):
    content_hash:   str
    detections:     list[DetectionResult]
    stored_ids:     list[int]
    has_injection:  bool
    has_pii:        bool
    max_severity:   str


# ── Severity ordering ─────────────────────────────────────────────────────────

_SEV_ORDER = ["low", "medium", "high", "critical"]


def _max_severity(*severities: str) -> str:
    best = "low"
    for s in severities:
        if s in _SEV_ORDER and _SEV_ORDER.index(s) > _SEV_ORDER.index(best):
            best = s
    return best


def _str_to_severity(s: str) -> Severity:
    mapping = {
        "critical": Severity.critical,
        "high":     Severity.high,
        "medium":   Severity.medium,
        "low":      Severity.low,
    }
    return mapping.get(s.lower(), Severity.low)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/runtime/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, db=Depends(get_db)):
    """
    Analyze submitted content for injection and PII.
    Raw content is NEVER stored - only the sha256 hash and detection signals.
    """
    content_hash = hashlib.sha256(req.content.encode("utf-8")).hexdigest()

    injection_detector = get_injection_detector()
    pii_detector       = get_pii_detector()

    injection_result = injection_detector.analyze(req.content)
    pii_result       = pii_detector.analyze(req.content)

    detections: list[DetectionResult] = []
    stored_ids: list[int] = []

    # ── Injection detection ────────────────────────────────────────────────────
    if injection_result["is_injection"]:
        det = DetectionResult(
            detector_type="injection",
            triggered=True,
            severity=injection_result["severity"],
            confidence=min(injection_result["score"], 1.0),
            signal={
                "categories_matched": injection_result["categories_matched"],
                "match_count":        injection_result["match_count"],
                "matches":            injection_result["matches"][:20],  # cap payload size
            },
        )
        detections.append(det)

        row = RuntimeDetection(
            tenant_id     = req.tenant_id,
            trace_id      = req.trace_id,
            agent_id      = req.agent_id,
            detector_type = "injection",
            severity      = _str_to_severity(injection_result["severity"]),
            confidence    = det.confidence,
            signal        = det.signal,
            content_hash  = content_hash,
            direction     = req.direction,
        )
        db.add(row)
        db.flush()
        stored_ids.append(row.id)
        logger.info(
            "runtime_injection_detected",
            tenant_id=req.tenant_id,
            agent_id=req.agent_id,
            severity=injection_result["severity"],
            categories=injection_result["categories_matched"],
        )

    # ── PII detection ─────────────────────────────────────────────────────────
    if pii_result["has_pii"]:
        det = DetectionResult(
            detector_type="pii",
            triggered=True,
            severity=pii_result["severity"],
            confidence=1.0,
            signal={
                "types_found":  pii_result["types_found"],
                "match_count":  pii_result["match_count"],
                "masked_snippet": pii_result["masked_content"][:500],
            },
        )
        detections.append(det)

        row = RuntimeDetection(
            tenant_id     = req.tenant_id,
            trace_id      = req.trace_id,
            agent_id      = req.agent_id,
            detector_type = "pii",
            severity      = _str_to_severity(pii_result["severity"]),
            confidence    = 1.0,
            signal        = det.signal,
            content_hash  = content_hash,
            direction     = req.direction,
        )
        db.add(row)
        db.flush()
        stored_ids.append(row.id)
        logger.info(
            "runtime_pii_detected",
            tenant_id=req.tenant_id,
            agent_id=req.agent_id,
            severity=pii_result["severity"],
            types=list(pii_result["types_found"].keys()),
        )

    db.commit()

    max_sev_parts = [d.severity for d in detections] or ["low"]
    max_severity  = "low"
    for s in max_sev_parts:
        if _SEV_ORDER.index(s) > _SEV_ORDER.index(max_severity):
            max_severity = s

    return AnalyzeResponse(
        content_hash  = content_hash,
        detections    = detections,
        stored_ids    = stored_ids,
        has_injection = injection_result["is_injection"],
        has_pii       = pii_result["has_pii"],
        max_severity  = max_severity,
    )


@router.get("/runtime/detections")
def list_detections(
    tenant_id:     str = "default",
    detector_type: Optional[str] = None,
    severity:      Optional[str] = None,
    agent_id:      Optional[str] = None,
    direction:     Optional[str] = None,
    limit:         int = Query(default=100, le=500),
    since:         Optional[str] = None,
    db=Depends(get_db),
):
    """
    List stored RuntimeDetection rows with optional filters.
    since: ISO datetime string, e.g. "2024-01-01T00:00:00Z"
    """
    q = db.query(RuntimeDetection).filter(RuntimeDetection.tenant_id == tenant_id)

    if detector_type:
        q = q.filter(RuntimeDetection.detector_type == detector_type)
    if severity:
        q = q.filter(RuntimeDetection.severity == _str_to_severity(severity))
    if agent_id:
        q = q.filter(RuntimeDetection.agent_id == agent_id)
    if direction:
        q = q.filter(RuntimeDetection.direction == direction)
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            q = q.filter(RuntimeDetection.timestamp >= since_dt)
        except ValueError:
            pass

    rows = q.order_by(RuntimeDetection.timestamp.desc()).limit(limit).all()

    return [
        {
            "id":            r.id,
            "tenant_id":     r.tenant_id,
            "trace_id":      r.trace_id,
            "agent_id":      r.agent_id,
            "detector_type": r.detector_type,
            "severity":      r.severity.value if r.severity else "low",
            "confidence":    r.confidence,
            "signal":        r.signal,
            "content_hash":  r.content_hash,
            "direction":     r.direction,
            "timestamp":     r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in rows
    ]
