"""
Prompt Injection Detector
--------------------------
Ported from AIRS-CP (ai-runtime-security-control-plane) with AIRS-CP dependencies removed.
Uses stdlib `re` only - no ML, no sklearn required.

Detects 7 categories of injection attempts via regex pattern matching.
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
_SEVERITY_WEIGHTS = {SEVERITY_LOW: 0.25, SEVERITY_MEDIUM: 0.5, SEVERITY_HIGH: 0.75, SEVERITY_CRITICAL: 1.0}


@dataclass
class InjectionMatch:
    pattern_name:     str
    pattern_category: str
    match:            str
    start:            int
    end:              int
    severity:         str
    confidence:       float


# ── Pattern library (ported from AIRS-CP) ─────────────────────────────────────

INJECTION_PATTERNS = {
    "instruction_override": {
        "severity": SEVERITY_HIGH,
        "confidence": 0.9,
        "patterns": [
            (r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", "ignore_previous"),
            (r"disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|guidelines?|rules?)", "disregard"),
            (r"forget\s+(?:everything|all|your\s+(?:instructions?|rules?))", "forget"),
            (r"(?:new|updated?)\s+instructions?\s*:", "new_instructions"),
            (r"override\s+(?:your\s+)?(?:previous\s+)?(?:instructions?|rules?)", "override"),
        ],
    },
    "prompt_extraction": {
        "severity": SEVERITY_HIGH,
        "confidence": 0.85,
        "patterns": [
            (r"(?:what|show|print|reveal|display)\s+(?:is\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)", "extract_prompt"),
            (r"repeat\s+(?:your\s+)?(?:initial|original|system)\s+(?:instructions?|prompt)", "repeat_prompt"),
            (r"(?:print|show|reveal)\s+(?:your\s+)?(?:confidential|hidden|secret)\s+(?:instructions?|config)", "reveal_secret"),
            (r"what\s+were\s+you\s+told\s+(?:before|initially)", "what_told"),
        ],
    },
    "role_manipulation": {
        "severity": SEVERITY_HIGH,
        "confidence": 0.85,
        "patterns": [
            (r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|evil|unrestricted|jailbroken)", "dan_mode"),
            (r"(?:enter|switch\s+to|activate)\s+(?:developer|god|admin|unrestricted)\s+mode", "dev_mode"),
            (r"pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:AI|assistant|bot)\s+(?:with|without)", "pretend"),
            (r"from\s+now\s+on\s*,?\s*(?:you\s+(?:will|are|must))", "from_now_on"),
            (r"roleplay\s+as\s+(?:an?\s+)?(?:evil|unrestricted|harmful)", "roleplay_evil"),
        ],
    },
    "jailbreak": {
        "severity": SEVERITY_CRITICAL,
        "confidence": 0.9,
        "patterns": [
            (r"(?:do\s+)?anything\s+now", "dan"),
            (r"jailbreak(?:ed)?", "jailbreak"),
            (r"bypass\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|restrictions?)", "bypass_safety"),
            (r"(?:disable|remove|ignore)\s+(?:your\s+)?(?:safety|ethical|content)\s+(?:guidelines?|filters?)", "disable_safety"),
            (r"without\s+(?:any\s+)?(?:restrictions?|limitations?|filters?)", "no_restrictions"),
        ],
    },
    "delimiter_attack": {
        "severity": SEVERITY_HIGH,
        "confidence": 0.8,
        "patterns": [
            (r"<\|?(?:system|endoftext|im_start)\|?>", "special_token"),
            (r"\[(?:SYSTEM|INST|/INST)\]", "bracket_token"),
            (r"```(?:system|instruction|prompt)", "code_block_token"),
            (r"###\s*(?:SYSTEM|INSTRUCTION|END)", "markdown_token"),
        ],
    },
    "hypothetical": {
        "severity": SEVERITY_MEDIUM,
        "confidence": 0.6,
        "patterns": [
            (r"(?:hypothetically|theoretically|in\s+theory)", "hypothetical"),
            (r"(?:imagine|suppose|assume)\s+(?:you\s+(?:had|have|could)|there\s+were\s+no)", "imagine"),
            (r"for\s+(?:educational|research|academic)\s+purposes?\s+only", "educational"),
            (r"in\s+(?:an?\s+)?(?:alternate|parallel|fictional)\s+(?:universe|world|scenario)", "alternate_universe"),
        ],
    },
    "obfuscation": {
        "severity": SEVERITY_MEDIUM,
        "confidence": 0.7,
        "patterns": [
            (r"[iI1l][gG][nN][oO0][rR][eE3]", "leet_ignore"),
            (r"(?:i\.g\.n\.o\.r\.e|d\.i\.s\.r\.e\.g\.a\.r\.d)", "dotted"),
            (r"(?:i_g_n_o_r_e|d_i_s_r_e_g_a_r_d)", "underscored"),
        ],
    },
}


# ── Detector ───────────────────────────────────────────────────────────────────

class InjectionDetector:
    def __init__(self):
        self._compiled: dict[str, list[tuple[re.Pattern, str, float, str]]] = {}
        for category, config in INJECTION_PATTERNS.items():
            self._compiled[category] = [
                (re.compile(pattern, re.IGNORECASE), name, config["confidence"], config["severity"])
                for pattern, name in config["patterns"]
            ]

    def analyze(self, text: str) -> dict[str, Any]:
        matches: list[InjectionMatch] = []

        for category, patterns in self._compiled.items():
            for compiled, name, confidence, severity in patterns:
                for m in compiled.finditer(text):
                    matches.append(InjectionMatch(
                        pattern_name=name,
                        pattern_category=category,
                        match=m.group(),
                        start=m.start(),
                        end=m.end(),
                        severity=severity,
                        confidence=confidence,
                    ))

        matches.sort(key=lambda m: m.start)

        # Score
        pattern_score = 0.0
        for m in matches:
            pattern_score += _SEVERITY_WEIGHTS[m.severity] * m.confidence
        pattern_score = min(1.0, pattern_score)

        is_injection = pattern_score >= 0.5 or any(
            m.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL) and m.confidence >= 0.8
            for m in matches
        )

        max_severity = SEVERITY_LOW
        for m in matches:
            if _SEVERITY_ORDER.index(m.severity) > _SEVERITY_ORDER.index(max_severity):
                max_severity = m.severity

        by_category: dict[str, list] = {}
        for m in matches:
            by_category.setdefault(m.pattern_category, []).append({
                "pattern":  m.pattern_name,
                "match":    m.match[:80] + "..." if len(m.match) > 80 else m.match,
                "location": f"char {m.start}-{m.end}",
            })

        return {
            "is_injection":       is_injection,
            "score":              round(pattern_score, 3),
            "severity":           max_severity,
            "match_count":        len(matches),
            "categories_matched": list(by_category.keys()),
            "matches": [
                {
                    "category":   m.pattern_category,
                    "pattern":    m.pattern_name,
                    "severity":   m.severity,
                    "confidence": m.confidence,
                    "location":   f"char {m.start}-{m.end}",
                }
                for m in matches
            ],
        }


# Singleton
_detector: InjectionDetector | None = None


def get_injection_detector() -> InjectionDetector:
    global _detector
    if _detector is None:
        _detector = InjectionDetector()
    return _detector
