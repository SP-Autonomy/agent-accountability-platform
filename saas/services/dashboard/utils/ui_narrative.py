"""
AIAAP Dashboard - shared narrative header helper.

Pages import:
    from utils.ui_narrative import render_narrative_header, render_filter_summary

render_narrative_header() renders a compact "What this page answers" block with
optional golden-path CTAs to the next logical page.

render_filter_summary() renders a one-liner that tells the user how many agents
are visible vs. hidden by the current Operational/Lab mode filter.
"""

from __future__ import annotations

import streamlit as st


def render_narrative_header(
    outcome: str,
    what: list[str],
    why: list[str],
    next_steps: list[str],
    primary_cta: dict | None = None,
    secondary_cta: dict | None = None,
) -> None:
    """
    Render a compact narrative strip below the page title.

    Args:
        outcome:     One-line answer to "what do I get from this page?"
        what:        Short bullets describing what the page shows.
        why:         Short bullets explaining why it matters.
        next_steps:  Short bullets for recommended next actions.
        primary_cta: Optional dict {"label": str, "page": str} for st.page_link.
        secondary_cta: Same structure as primary_cta.
    """
    st.caption(outcome)

    with st.expander("What · Why · Next steps", expanded=False):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**What you see**")
            for item in what:
                st.markdown(f"- {item}")
        with c2:
            st.markdown("**Why it matters**")
            for item in why:
                st.markdown(f"- {item}")
        with c3:
            st.markdown("**Recommended next steps**")
            for item in next_steps:
                st.markdown(f"- {item}")

    # CTAs - inline buttons using st.page_link (requires Streamlit ≥ 1.31)
    if primary_cta or secondary_cta:
        cta_cols = st.columns([2, 2, 6])
        if primary_cta:
            with cta_cols[0]:
                try:
                    st.page_link(
                        primary_cta["page"],
                        label=f"→ {primary_cta['label']}",
                        use_container_width=True,
                    )
                except Exception:
                    pass  # page_link unavailable in older Streamlit
        if secondary_cta:
            with cta_cols[1]:
                try:
                    st.page_link(
                        secondary_cta["page"],
                        label=f"→ {secondary_cta['label']}",
                        use_container_width=True,
                    )
                except Exception:
                    pass


def render_filter_summary(
    all_principals: list[dict],
    filtered_principals: list[dict],
    include_labs: bool,
) -> None:
    """
    Show a one-liner: "Showing N agents · M lab agents hidden in Operational mode."
    Only shown when something is actually hidden.
    """
    total   = len(all_principals)
    visible = len(filtered_principals)
    hidden  = total - visible

    if include_labs or hidden == 0:
        # Operational mode but nothing hidden (no lab agents in DB) - silent
        if include_labs and total > 0:
            st.caption(
                f"Lab mode: showing all {total} agent(s) including scenario / test agents."
            )
        return

    st.caption(
        f"Operational mode: showing **{visible}** of {total} agent(s) · "
        f"**{hidden}** lab agent(s) hidden. "
        f"Toggle _Include lab agents_ in the sidebar to show them."
    )
