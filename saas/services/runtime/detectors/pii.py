"""
PII Detector
-------------
Ported from AIRS-CP (ai-runtime-security-control-plane) with AIRS-CP dependencies removed.
Uses stdlib `re` only.

Detects 12 types of PII and masks them in the analyzed text.
Raw content is NEVER persisted by the runtime service - only detection metadata.
"""

import re
from dataclasses import dataclass
from typing import Any


# ── Severity constants ─────────────────────────────────────────────────────────

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH     = "high"
SEVERITY_MEDIUM   = "medium"
SEVERITY_LOW      = "low"

_SEVERITY_ORDER = [SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]


@dataclass
class PIIMatch:
    pattern_name: str
    match:        str
    start:        int
    end:          int
    mask:         str
    confidence:   float


# ── Pattern library (ported from AIRS-CP) ─────────────────────────────────────

PII_PATTERNS = {
    "ssn": {
        "pattern":     r"\b\d{3}-\d{2}-\d{4}\b",
        "mask":        "[REDACTED:ssn]",
        "description": "Social Security Number",
        "severity":    SEVERITY_HIGH,
        "confidence":  1.0,
    },
    "ssn_nodash": {
        "pattern":     r"\b\d{9}\b",
        "mask":        "[REDACTED:ssn]",
        "description": "SSN without dashes",
        "severity":    SEVERITY_HIGH,
        "confidence":  0.7,
    },
    "credit_card": {
        "pattern":     r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "mask":        "[REDACTED:credit_card]",
        "description": "Credit Card Number",
        "severity":    SEVERITY_HIGH,
        "confidence":  1.0,
    },
    "email": {
        "pattern":     r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "mask":        "[REDACTED:email]",
        "description": "Email Address",
        "severity":    SEVERITY_MEDIUM,
        "confidence":  1.0,
    },
    "phone_us": {
        "pattern":     r"\b(?:\+1[- ]?)?\(?[0-9]{3}\)?[- ]?[0-9]{3}[- ]?[0-9]{4}\b",
        "mask":        "[REDACTED:phone]",
        "description": "US Phone Number",
        "severity":    SEVERITY_MEDIUM,
        "confidence":  1.0,
    },
    "phone_intl": {
        "pattern":     r"\b\+[0-9]{1,3}[- ]?[0-9]{4,14}\b",
        "mask":        "[REDACTED:phone]",
        "description": "International Phone Number",
        "severity":    SEVERITY_MEDIUM,
        "confidence":  0.9,
    },
    "ip_address": {
        "pattern":     r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "mask":        "[REDACTED:ip]",
        "description": "IP Address",
        "severity":    SEVERITY_LOW,
        "confidence":  1.0,
    },
    "date_of_birth": {
        "pattern":     r"\b(?:DOB|Date\s+of\s+Birth|Birthday)[:\s]*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
        "mask":        "[REDACTED:dob]",
        "description": "Date of Birth",
        "severity":    SEVERITY_MEDIUM,
        "confidence":  1.0,
    },
    "passport": {
        "pattern":     r"\b[A-Z]{1,2}\d{6,9}\b",
        "mask":        "[REDACTED:passport]",
        "description": "Passport Number",
        "severity":    SEVERITY_HIGH,
        "confidence":  0.6,
    },
    "drivers_license": {
        "pattern":     r"\b(?:DL|License)[:\s#]*[A-Z0-9]{5,15}\b",
        "mask":        "[REDACTED:license]",
        "description": "Driver's License",
        "severity":    SEVERITY_HIGH,
        "confidence":  1.0,
    },
    "api_key": {
        "pattern":     r"\b(?:sk|pk|api)[_-]?(?:live|test)?[_-]?[A-Za-z0-9]{20,}\b",
        "mask":        "[REDACTED:api_key]",
        "description": "API Key",
        "severity":    SEVERITY_CRITICAL,
        "confidence":  1.0,
    },
    "aws_key": {
        "pattern":     r"\bAKIA[0-9A-Z]{16}\b",
        "mask":        "[REDACTED:aws_key]",
        "description": "AWS Access Key",
        "severity":    SEVERITY_CRITICAL,
        "confidence":  1.0,
    },
}


# ── Detector ───────────────────────────────────────────────────────────────────

class PIIDetector:
    def __init__(self):
        self._compiled: dict[str, tuple[re.Pattern, dict]] = {
            name: (re.compile(config["pattern"], re.IGNORECASE), config)
            for name, config in PII_PATTERNS.items()
        }

    def _detect(self, text: str) -> list[PIIMatch]:
        matches: list[PIIMatch] = []
        for name, (pattern, config) in self._compiled.items():
            for m in pattern.finditer(text):
                matches.append(PIIMatch(
                    pattern_name=name,
                    match=m.group(),
                    start=m.start(),
                    end=m.end(),
                    mask=config["mask"],
                    confidence=config["confidence"],
                ))
        matches.sort(key=lambda m: m.start)
        return matches

    def analyze(self, text: str) -> dict[str, Any]:
        matches = self._detect(text)

        # Mask in reverse so positions don't shift
        masked = text
        for m in reversed(matches):
            masked = masked[:m.start] + m.mask + masked[m.end:]

        max_severity = SEVERITY_LOW
        types_found: dict[str, int] = {}
        for m in matches:
            sev = PII_PATTERNS[m.pattern_name]["severity"]
            if _SEVERITY_ORDER.index(sev) > _SEVERITY_ORDER.index(max_severity):
                max_severity = sev
            types_found[m.pattern_name] = types_found.get(m.pattern_name, 0) + 1

        return {
            "has_pii":         len(matches) > 0,
            "match_count":     len(matches),
            "types_found":     types_found,
            "severity":        max_severity,
            "masked_content":  masked,
            "matches": [
                {
                    "pattern":    m.pattern_name,
                    "location":   f"char {m.start}-{m.end}",
                    "confidence": m.confidence,
                    "severity":   PII_PATTERNS[m.pattern_name]["severity"],
                }
                for m in matches
            ],
        }


# Singleton
_detector: PIIDetector | None = None


def get_pii_detector() -> PIIDetector:
    global _detector
    if _detector is None:
        _detector = PIIDetector()
    return _detector
