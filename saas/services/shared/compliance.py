"""
AIAAP Compliance Mapping
------------------------
Maps each AIAAP detection control to relevant regulatory and framework citations:
  - EU AI Act (2024/1689) Articles
  - NIST AI RMF (2023) functions and sub-categories
  - MITRE ATLAS (v2) techniques
  - OWASP LLM Top 10 (2025) items

Each entry is a ControlMapping dataclass that can be rendered by the compliance
dashboard or exported as JSON for GRC tools.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FrameworkRef:
    """A single framework citation with optional URL."""
    framework:   str   # e.g. "EU AI Act", "NIST AI RMF"
    identifier:  str   # e.g. "Article 9", "GOVERN 1.1"
    description: str   # Brief label of the requirement
    url:         str   = ""


@dataclass
class ControlMapping:
    control_id:   str                       # Internal ID, e.g. "ssrf_detection"
    control_name: str                       # Human-readable name
    control_desc: str                       # What the control detects / prevents
    risk_category: str                      # "runtime", "identity", "supply_chain", "behavioural"
    refs:          list[FrameworkRef] = field(default_factory=list)
    mitigates:     list[str]          = field(default_factory=list)  # MITRE ATLAS technique IDs
    owasp_llm:     list[str]          = field(default_factory=list)  # e.g. "LLM01"


# ── Framework reference helpers ───────────────────────────────────────────────

def _eu(article: str, desc: str) -> FrameworkRef:
    return FrameworkRef(
        framework="EU AI Act",
        identifier=article,
        description=desc,
        url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
    )


def _nist(sub_cat: str, desc: str) -> FrameworkRef:
    return FrameworkRef(
        framework="NIST AI RMF",
        identifier=sub_cat,
        description=desc,
        url="https://airc.nist.gov/RMF/1",
    )


def _atlas(tech_id: str, name: str) -> FrameworkRef:
    return FrameworkRef(
        framework="MITRE ATLAS",
        identifier=tech_id,
        description=name,
        url=f"https://atlas.mitre.org/techniques/{tech_id}",
    )


def _owasp(item: str, desc: str) -> FrameworkRef:
    return FrameworkRef(
        framework="OWASP LLM Top 10",
        identifier=item,
        description=desc,
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    )


# ── Control Mappings ──────────────────────────────────────────────────────────

CONTROLS: list[ControlMapping] = [

    # ── Runtime Detection Controls ────────────────────────────────────────────

    ControlMapping(
        control_id="ssrf_detection",
        control_name="SSRF / Metadata IP Detection",
        control_desc=(
            "Detects when an AI agent accesses cloud metadata services "
            "(169.254.169.254, metadata.google.internal) or performs "
            "server-side request forgery to internal endpoints."
        ),
        risk_category="runtime",
        refs=[
            _eu("Article 9(2)", "Risk management: identification and analysis of known risks"),
            _eu("Article 15(1)", "Accuracy, robustness and cybersecurity requirements"),
            _nist("MEASURE 2.5", "Risks to the organization from AI are monitored"),
            _nist("MANAGE 2.2", "Mechanisms are in place to respond to AI risks"),
            _atlas("AML.T0052", "Discover ML Model Ontology"),
            _atlas("AML.T0044", "Full ML Model Access"),
            _owasp("LLM07:2025", "System Prompt Leakage - exfiltration via SSRF"),
            _owasp("LLM02:2025", "Sensitive Information Disclosure"),
        ],
        mitigates=["AML.T0052", "AML.T0044"],
        owasp_llm=["LLM02", "LLM07"],
    ),

    ControlMapping(
        control_id="rbac_violation",
        control_name="Privileged Action Without JIT Grant",
        control_desc=(
            "Detects privileged tool calls (read_secrets, modify_iam, etc.) "
            "that occur without a valid JIT grant, indicating an agent "
            "operating outside its authorized scope."
        ),
        risk_category="identity",
        refs=[
            _eu("Article 9(2)(b)", "Risk management: evaluation of known risks and reasonably foreseeable misuse"),
            _eu("Article 13(1)", "Transparency and provision of information to deployers"),
            _nist("GOVERN 1.1", "Policies and procedures are in place to address AI risks"),
            _nist("GOVERN 2.2", "Organizational teams have clear accountabilities for AI risk"),
            _nist("MANAGE 1.1", "A risk treatment plan is developed and applied"),
            _atlas("AML.T0054", "LLM Prompt Injection - to escalate privileges"),
            _atlas("AML.T0056", "LLM Jailbreaking"),
            _owasp("LLM01:2025", "Prompt Injection"),
            _owasp("LLM05:2025", "Improper Output Handling - unauthorized action execution"),
        ],
        mitigates=["AML.T0054", "AML.T0056"],
        owasp_llm=["LLM01", "LLM05"],
    ),

    ControlMapping(
        control_id="confused_deputy",
        control_name="Confused Deputy / Cross-Agent Privilege Confusion",
        control_desc=(
            "Detects when two distinct agent identities appear in the same "
            "trace, indicating cross-agent token reuse or confused deputy "
            "attacks where Agent A is tricked into acting on behalf of Agent B."
        ),
        risk_category="identity",
        refs=[
            _eu("Article 9(2)(a)", "Risk management: identification of risks to health, safety or fundamental rights"),
            _eu("Article 13(3)(b)", "Transparency: information on the purpose, capabilities and limitations of the AI system"),
            _nist("GOVERN 6.2", "Policies and procedures are in place for AI actor accountability"),
            _nist("MEASURE 2.7", "AI risk factors are evaluated as AI and the wider context change"),
            _atlas("AML.T0054", "LLM Prompt Injection - indirect injection via tool output"),
            _atlas("AML.T0051.000", "LLM Plugin Compromise"),
            _owasp("LLM01:2025", "Prompt Injection - indirect via tool responses"),
            _owasp("LLM08:2025", "Excessive Agency - acting beyond intended authorization"),
        ],
        mitigates=["AML.T0054", "AML.T0051.000"],
        owasp_llm=["LLM01", "LLM08"],
    ),

    ControlMapping(
        control_id="overbroad_scope",
        control_name="Overbroad Tool Scope / Permission Creep",
        control_desc=(
            "Detects when an agent uses more distinct tools or destinations "
            "than its baseline profile allows, indicating excessive permission "
            "grants or scope creep."
        ),
        risk_category="runtime",
        refs=[
            _eu("Article 9(4)", "Risk management: adoption of suitable risk management measures"),
            _eu("Article 15(3)", "Robustness: appropriate measures to address unexpected inputs"),
            _nist("MAP 1.6", "Risks or impacts to individuals, groups, communities are examined"),
            _nist("MANAGE 3.1", "Responses to identified risks are implemented"),
            _atlas("AML.T0057", "LLM Meta Prompt Extraction - to discover available tools"),
            _owasp("LLM08:2025", "Excessive Agency"),
            _owasp("LLM06:2025", "Excessive Agency (2023) / Vector and Embedding Weaknesses"),
        ],
        mitigates=["AML.T0057"],
        owasp_llm=["LLM08"],
    ),

    ControlMapping(
        control_id="shadow_route",
        control_name="Shadow Route / Unauthorized Network Destination",
        control_desc=(
            "Detects when an agent contacts a destination not in its known "
            "baseline (shadow egress), which may indicate C2 communication, "
            "data exfiltration, or supply chain compromise."
        ),
        risk_category="runtime",
        refs=[
            _eu("Article 9(2)(c)", "Risk management: estimation and evaluation of risks that may emerge"),
            _eu("Article 15(1)", "Accuracy, robustness and cybersecurity"),
            _nist("MEASURE 2.5", "Risks to the organization from AI are monitored"),
            _nist("MANAGE 2.4", "Mechanisms are in place to recover from AI incidents"),
            _atlas("AML.T0048", "Discover ML Artifacts - data exfiltration"),
            _atlas("AML.T0044.000", "Model Evasion - using shadow routes to avoid detection"),
            _owasp("LLM02:2025", "Sensitive Information Disclosure - data exfiltration"),
            _owasp("LLM03:2025", "Supply Chain - contacting compromised upstream services"),
        ],
        mitigates=["AML.T0048"],
        owasp_llm=["LLM02", "LLM03"],
    ),

    ControlMapping(
        control_id="stolen_token",
        control_name="Stolen / Replayed Credential Detection",
        control_desc=(
            "Detects when the same credential or trace token is used from "
            "multiple principals or after expiry, indicating token theft "
            "or replay attacks."
        ),
        risk_category="identity",
        refs=[
            _eu("Article 9(2)(a)", "Risk management: identification of risks"),
            _eu("Article 15(1)", "Cybersecurity requirements for high-risk AI systems"),
            _nist("GOVERN 1.4", "Organizational teams are committed to AI transparency"),
            _nist("MANAGE 1.3", "Responses to identified risks are prioritized by risk"),
            _atlas("AML.T0054", "LLM Prompt Injection - token exfiltration via injection"),
            _owasp("LLM02:2025", "Sensitive Information Disclosure - credential leakage"),
            _owasp("LLM09:2025", "Misinformation - using stolen identity to produce false outputs"),
        ],
        mitigates=["AML.T0054"],
        owasp_llm=["LLM02", "LLM09"],
    ),

    # ── Cloud / IAM Controls ──────────────────────────────────────────────────

    ControlMapping(
        control_id="iam_escalation",
        control_name="IAM Privilege Escalation (AWS CloudTrail)",
        control_desc=(
            "Detects IAM privilege escalation actions (AttachRolePolicy, "
            "CreatePolicyVersion, PassRole, etc.) sourced from AWS CloudTrail, "
            "indicating AI agents or compromised pipelines attempting to "
            "elevate cloud permissions."
        ),
        risk_category="identity",
        refs=[
            _eu("Article 9(2)(b)", "Risk management: evaluation of known risks and reasonably foreseeable misuse"),
            _eu("Article 15(1)", "Cybersecurity: resistance to adversarial attempts"),
            _nist("GOVERN 2.2", "Organizational teams have clear accountabilities"),
            _nist("MANAGE 2.2", "Mechanisms are in place to respond to AI risks"),
            _atlas("AML.T0054", "LLM Prompt Injection - to trigger IAM actions"),
            _atlas("AML.T0056", "LLM Jailbreaking - bypassing safety to run privileged actions"),
            _owasp("LLM08:2025", "Excessive Agency - executing cloud IAM modifications"),
            _owasp("LLM01:2025", "Prompt Injection - indirect via tool output"),
        ],
        mitigates=["AML.T0054", "AML.T0056"],
        owasp_llm=["LLM01", "LLM08"],
    ),

    # ── Behavioural / Anomaly Controls ───────────────────────────────────────

    ControlMapping(
        control_id="behavioral_anomaly",
        control_name="Behavioural Baseline Anomaly (Z-score + Graph Drift)",
        control_desc=(
            "Statistical anomaly detection comparing current tool call "
            "patterns against a 7-day rolling baseline using z-scores for "
            "call volume, destination entropy, and privileged-action ratio; "
            "plus identity graph drift detection for new sensitive tools "
            "and destinations. Optional Isolation Forest ML model."
        ),
        risk_category="behavioural",
        refs=[
            _eu("Article 9(2)", "Risk management: identification and analysis of known and reasonably foreseeable risks"),
            _eu("Article 9(6)", "Risk management: post-market monitoring"),
            _eu("Article 15(2)", "Robustness: appropriate technical measures for accuracy"),
            _nist("MEASURE 1.1", "Context is established for measuring AI risks"),
            _nist("MEASURE 2.5", "Risks to the organization from AI are monitored"),
            _nist("MEASURE 2.9", "Risk treatment approaches are continually updated"),
            _nist("MANAGE 2.2", "Mechanisms are in place and tested for responding to AI risks"),
            _atlas("AML.T0040", "ML Model Inference API Access - anomalous calling patterns"),
            _atlas("AML.T0043", "Craft Adversarial Data - detect unusual input patterns"),
            _owasp("LLM04:2025", "Data and Model Poisoning - behavioral drift as an indicator"),
            _owasp("LLM08:2025", "Excessive Agency - spike in privileged action ratio"),
            _owasp("LLM01:2025", "Prompt Injection - behavioral change as a signal"),
        ],
        mitigates=["AML.T0040", "AML.T0043"],
        owasp_llm=["LLM01", "LLM04", "LLM08"],
    ),

    # ── Identity Posture ──────────────────────────────────────────────────────

    ControlMapping(
        control_id="jit_grant_enforcement",
        control_name="Just-in-Time Grant Enforcement",
        control_desc=(
            "Time-bound, scope-bound JIT grants required before any privileged "
            "tool execution. Grants expire automatically and are audited on "
            "every invocation. Prevents standing privilege and enforces "
            "least-privilege for AI agents."
        ),
        risk_category="identity",
        refs=[
            _eu("Article 9(4)(b)", "Risk management: adoption of suitable risk management measures"),
            _eu("Article 13(1)", "Transparency and provision of information to deployers"),
            _nist("GOVERN 1.1", "Policies and procedures are established to address AI risks"),
            _nist("GOVERN 6.1", "Policies are established for AI governance and risk management"),
            _nist("MANAGE 1.1", "Risks based on assessments are prioritized and treated"),
            _atlas("AML.T0056", "LLM Jailbreaking - mitigated by JIT scope enforcement"),
            _owasp("LLM08:2025", "Excessive Agency - mitigated by JIT least-privilege grants"),
            _owasp("LLM05:2025", "Improper Output Handling - bounded by grant scope"),
        ],
        mitigates=["AML.T0056"],
        owasp_llm=["LLM05", "LLM08"],
    ),

    ControlMapping(
        control_id="multi_tenant_isolation",
        control_name="Multi-Tenant API Key Enforcement",
        control_desc=(
            "Per-tenant bcrypt-hashed API keys derive the tenant_id server-side, "
            "preventing tenant spoofing. All queries are scoped to tenant_id. "
            "Supports REQUIRE_API_KEY=true for production enforcement."
        ),
        risk_category="identity",
        refs=[
            _eu("Article 9(2)(c)", "Risk management: estimation of risks emerging from data use"),
            _eu("Article 13(3)(a)", "Transparency: identity of the provider"),
            _nist("GOVERN 1.4", "Organizational teams are committed to AI transparency and accountability"),
            _nist("GOVERN 6.2", "Policies are in place for AI actor accountability"),
            _owasp("LLM09:2025", "Misinformation - prevented by tenant identity assurance"),
            _owasp("LLM02:2025", "Sensitive Information Disclosure - tenant data isolation"),
        ],
        mitigates=[],
        owasp_llm=["LLM02", "LLM09"],
    ),
]


# ── Lookup helpers ────────────────────────────────────────────────────────────

def get_control(control_id: str) -> Optional[ControlMapping]:
    """Return a control by its ID, or None if not found."""
    return next((c for c in CONTROLS if c.control_id == control_id), None)


def controls_by_framework(framework: str) -> list[ControlMapping]:
    """Return controls that reference a specific framework (partial match)."""
    fw = framework.lower()
    return [c for c in CONTROLS if any(fw in r.framework.lower() for r in c.refs)]


def controls_by_owasp(owasp_id: str) -> list[ControlMapping]:
    """Return controls covering a specific OWASP LLM item (e.g. 'LLM01')."""
    tag = owasp_id.upper().split(":")[0]  # normalise LLM01:2025 → LLM01
    return [c for c in CONTROLS if any(o.startswith(tag) for o in c.owasp_llm)]


def controls_by_category(category: str) -> list[ControlMapping]:
    """Return controls in a risk category: runtime, identity, behavioural, supply_chain."""
    return [c for c in CONTROLS if c.risk_category == category]


def compliance_summary() -> dict:
    """
    Return a high-level coverage summary suitable for dashboard KPIs.
    """
    eu_articles  = set()
    nist_cats    = set()
    atlas_techs  = set()
    owasp_items  = set()

    for c in CONTROLS:
        for r in c.refs:
            if "EU AI Act" in r.framework:
                eu_articles.add(r.identifier)
            elif "NIST" in r.framework:
                nist_cats.add(r.identifier.split(" ")[0])   # GOVERN, MAP, MEASURE, MANAGE
            elif "ATLAS" in r.framework:
                atlas_techs.add(r.identifier)
        for o in c.owasp_llm:
            owasp_items.add(o.split(":")[0])

    return {
        "total_controls":      len(CONTROLS),
        "eu_articles_covered": sorted(eu_articles),
        "nist_functions":      sorted(nist_cats),
        "atlas_techniques":    sorted(atlas_techs),
        "owasp_llm_items":     sorted(owasp_items),
        "categories": {
            cat: len(controls_by_category(cat))
            for cat in ("runtime", "identity", "behavioural", "supply_chain")
        },
    }
