"""SentinelForge Dashboard — AI Cyber Defense Command Center."""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

# --- Page Config ---
st.set_page_config(
    page_title="SentinelForge",
    page_icon="⛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Dark Theme CSS ---
st.markdown("""
<style>
    .stApp { background-color: #0e1117; }
    .metric-card {
        background: linear-gradient(135deg, #1a1f2e 0%, #161b22 100%);
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px;
        margin: 5px;
        text-align: center;
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        margin: 5px 0;
    }
    .metric-label {
        color: #8b949e;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .severity-critical { color: #ff4444; border-left: 4px solid #ff4444; }
    .severity-high { color: #ff8800; border-left: 4px solid #ff8800; }
    .severity-medium { color: #ffcc00; border-left: 4px solid #ffcc00; }
    .severity-low { color: #44bb44; border-left: 4px solid #44bb44; }
    .severity-info { color: #4488ff; border-left: 4px solid #4488ff; }
    .event-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 15px;
        margin: 8px 0;
    }
    .status-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-approved { background: #238636; color: white; }
    .badge-rejected { background: #da3633; color: white; }
    .badge-proposed { background: #1f6feb; color: white; }
    .badge-executed { background: #8957e5; color: white; }
    .badge-denied { background: #da3633; color: white; }
    .badge-pending { background: #d29922; color: white; }
    .agent-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px;
        margin: 4px;
        text-align: center;
    }
    .agent-healthy { border-left: 3px solid #238636; }
    .agent-idle { border-left: 3px solid #8b949e; }
    .mitre-tag {
        display: inline-block;
        background: #1f2937;
        border: 1px solid #374151;
        border-radius: 4px;
        padding: 2px 8px;
        margin: 2px;
        font-size: 0.8rem;
        color: #60a5fa;
        font-family: monospace;
    }
    div[data-testid="stSidebar"] {
        background: #0d1117;
        border-right: 1px solid #21262d;
    }
    .approval-card {
        background: #1c1f26;
        border: 2px solid #d29922;
        border-radius: 8px;
        padding: 15px;
        margin: 8px 0;
    }
    .canary-card {
        background: #1a1f2e;
        border: 1px solid #2ea043;
        border-radius: 6px;
        padding: 10px 14px;
        margin: 6px 0;
        font-family: monospace;
        font-size: 0.85rem;
        color: #7ee787;
    }
    .timeout-bar {
        background: #30363d;
        border-radius: 4px;
        overflow: hidden;
        height: 6px;
        margin: 6px 0;
    }
    .timeout-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 1s linear;
    }
</style>
""", unsafe_allow_html=True)


# --- Auth Gate ---
def check_auth() -> bool:
    password = os.environ.get("SF_DASHBOARD_PASSWORD", "")
    if not password or password == "changeme":  # noqa: S105
        return True
    if st.session_state.get("authenticated"):
        return True
    st.markdown("## ⛡ SentinelForge Login")
    with st.form("login_form"):
        pwd = st.text_input("Dashboard Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if pwd == password:
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Invalid password")
    return False


if not check_auth():
    st.stop()


# --- Helpers ---
SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high": "#ff8800",
    "medium": "#ffcc00",
    "low": "#44bb44",
    "info": "#4488ff",
}

MITRE_LABELS = {
    "T1110": "Brute Force", "T1046": "Network Service Discovery",
    "T1548": "Abuse Elevation Control", "T1048": "Exfiltration Over Alternative Protocol",
    "T1059": "Command and Scripting Interpreter", "T1021": "Remote Services",
    "T1003": "OS Credential Dumping", "T1486": "Data Encrypted for Impact",
    "T1566": "Phishing", "T1078": "Valid Accounts", "T1136": "Create Account",
    "T1098": "Account Manipulation", "T1070": "Indicator Removal",
    "T1543": "Create or Modify System Process", "T1055": "Process Injection",
    "T1071": "Application Layer Protocol", "T1105": "Ingress Tool Transfer",
    "T1112": "Modify Registry", "T1531": "Account Access Removal",
    "T1558": "Steal or Forge Kerberos Tickets", "T1565": "Data Manipulation",
    "T1571": "Non-Standard Port",
}


def severity_icon(sev: str) -> str:
    icons = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\U0001f7e2", "info": "\U0001f535"}
    return icons.get(sev, "⚪")


def metric_card(label: str, value: str | int, color: str = "#58a6ff") -> str:
    return f"""<div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value" style="color: {color};">{value}</div>
    </div>"""


def format_seconds(s: float) -> str:
    m, sec = divmod(int(s), 60)
    return f"{m}:{sec:02d}"


def _get_db():
    try:
        from sentinelforge.core.database import get_database
        return get_database()
    except Exception:
        return None


def _load_audit_entries(source: str = "auto") -> list[dict]:
    if source != "file":
        db = _get_db()
        if db:
            try:
                return db.get_audit_entries(limit=200)
            except Exception:  # noqa: S110
                pass  # Graceful fallback to file
    p = Path("./data/audit.log")
    if not p.exists():
        return []
    entries = []
    with open(p) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def _load_db_events(hours: int = 24) -> list[dict]:
    db = _get_db()
    if db:
        try:
            return db.get_recent_events(hours=hours, limit=200)
        except Exception:  # noqa: S110
            pass  # Graceful fallback
    return []


def _load_db_reports() -> list[dict]:
    db = _get_db()
    if db:
        try:
            return db.get_reports(limit=50)
        except Exception:  # noqa: S110
            pass  # Graceful fallback
    return []


def _load_db_pending_approvals() -> list[dict]:
    db = _get_db()
    if db:
        try:
            return db.get_pending_approvals()
        except Exception:  # noqa: S110
            pass  # Graceful fallback
    return []


def _resolve_approval(action_id: str, approved: bool, decided_by: str) -> None:
    db = _get_db()
    if db:
        try:
            db.resolve_approval(action_id, approved, decided_by)
        except Exception:  # noqa: S110
            pass  # Best-effort persistence


# --- Sidebar ---
with st.sidebar:
    st.markdown("## ⛡ SentinelForge")
    st.markdown("**AI Cyber Defense Agent**")
    st.divider()

    st.markdown("### System Status")
    try:
        from sentinelforge.core.health import get_health_monitor
        hm = get_health_monitor()
        health = hm.check()
        status_color = "#238636" if health.healthy else "#da3633"
        status_text = "HEALTHY" if health.healthy else "DEGRADED"
        st.markdown(f'<span style="color:{status_color}; font-weight:bold;">● {status_text}</span>', unsafe_allow_html=True)
        if health.cpu_percent > 0:
            st.progress(health.cpu_percent / 100, text=f"CPU: {health.cpu_percent:.0f}%")
            st.progress(health.memory_percent / 100, text=f"Memory: {health.memory_percent:.0f}%")
        if health.warnings:
            for w in health.warnings:
                st.warning(w, icon="⚠️")
    except Exception:
        st.markdown('<span style="color:#8b949e;">○ Status unavailable</span>', unsafe_allow_html=True)

    st.divider()

    st.markdown("### Agent Pipeline")
    agents = ["Monitor", "Investigator", "Containment", "Guardian", "Responder", "Explainer"]
    for agent in agents:
        st.markdown(f'<div class="agent-card agent-idle">▸ {agent}</div>', unsafe_allow_html=True)

    st.divider()

    if st.button("\U0001f50d Verify Audit Chain", use_container_width=True):
        from sentinelforge.core.audit import get_audit_logger
        audit = get_audit_logger()
        valid, count = audit.verify_chain()
        if valid:
            st.success(f"Chain valid ({count} entries)")
        else:
            st.error(f"Chain BROKEN at entry {count}")

    auto_refresh = st.checkbox("Auto-refresh (10s)", value=False)
    if auto_refresh:
        time.sleep(10)
        st.rerun()

    st.divider()
    st.caption(f"v0.4.0 | {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")


# --- Main Header ---
st.markdown("# ⛡ SentinelForge Command Center")

# --- Top Metrics ---
result = st.session_state.get("last_result")

db_pending = _load_db_pending_approvals()
db_events = _load_db_events()

if result:
    cols = st.columns(6)
    pending_count = len(db_pending) or len(getattr(result, "pending_approvals", []))
    metrics = [
        ("Events", len(result.events), "#58a6ff"),
        ("Investigations", len(result.investigations), "#8957e5"),
        ("Actions", len(result.executed_actions), "#238636"),
        ("Pending", pending_count, "#d29922" if pending_count else "#238636"),
        ("Violations", len(result.safety_violations), "#da3633" if result.safety_violations else "#238636"),
        ("Escalations", len(result.human_escalations), "#d29922" if result.human_escalations else "#238636"),
    ]
    for col, (label, value, color) in zip(cols, metrics, strict=False):
        col.markdown(metric_card(label, value, color), unsafe_allow_html=True)
elif db_events:
    cols = st.columns(4)
    cols[0].markdown(metric_card("DB Events (24h)", len(db_events), "#58a6ff"), unsafe_allow_html=True)
    cols[1].markdown(metric_card("Pending Approvals", len(db_pending), "#d29922" if db_pending else "#238636"), unsafe_allow_html=True)

    db_reports = _load_db_reports()
    cols[2].markdown(metric_card("Reports", len(db_reports), "#8957e5"), unsafe_allow_html=True)

    audit_entries = _load_audit_entries()
    cols[3].markdown(metric_card("Audit Entries", len(audit_entries), "#58a6ff"), unsafe_allow_html=True)


# --- Tabs ---
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "\U0001f4e1 Live Events",
    "\U0001f50d Investigations",
    "\U0001f6e1 Actions & Approvals",
    "\U0001f4cb Reports",
    "\U0001f5fa MITRE ATT&CK Map",
    "\U0001f4dc Audit Log",
])

# --- Tab 1: Live Events ---
with tab1:
    col_ctrl1, col_ctrl2, col_ctrl3 = st.columns([2, 1, 1])

    with col_ctrl1:
        scenario = st.selectbox(
            "Simulation Scenario",
            ["brute_force", "ransomware", "lateral_movement"],
            label_visibility="collapsed",
        )
    with col_ctrl2:
        use_llm = st.checkbox("Use LLM Analysis", value=False)
    with col_ctrl3:
        run_clicked = st.button("▶ Run Defense Cycle", type="primary", use_container_width=True)

    if run_clicked:
        with st.spinner("Running agent pipeline..."):
            from sentinelforge.core.orchestrator import run_defense_cycle
            from sentinelforge.simulation.scenarios import run_scenario

            initial = run_scenario(scenario)
            result = asyncio.run(run_defense_cycle(initial_state=initial, use_llm=use_llm))
            st.session_state["last_result"] = result
            st.rerun()

    events_to_show = []
    if result:
        events_to_show = [
            {"event_type": e.event_type, "description": e.description,
             "severity": e.severity.value, "source_ip": e.source_ip,
             "confidence": e.confidence, "timestamp": e.timestamp.strftime('%H:%M:%S'),
             "mitre_techniques": e.mitre_techniques, "source": e.source,
             "raw_data": e.raw_data}
            for e in result.events
        ]
    elif db_events:
        events_to_show = [
            {"event_type": e.get("event_type", ""), "description": e.get("description", ""),
             "severity": e.get("severity", "info"), "source_ip": e.get("source_ip", ""),
             "confidence": e.get("confidence", 0), "timestamp": e.get("timestamp", ""),
             "mitre_techniques": e.get("mitre_techniques", []),
             "source": e.get("source", ""), "raw_data": e.get("raw_data", {})}
            for e in db_events
        ]

    if events_to_show:
        st.markdown("### Threat Timeline")
        severity_filter = st.multiselect(
            "Filter by severity",
            ["critical", "high", "medium", "low", "info"],
            default=["critical", "high", "medium"],
        )
        filtered = [e for e in events_to_show if e["severity"] in severity_filter]

        for event in filtered:
            sev = event["severity"]
            icon = severity_icon(sev)
            color = SEVERITY_COLORS.get(sev, "#8b949e")
            desc = event["description"][:80] if event["description"] else ""

            with st.expander(
                f"{icon} **{event['event_type'].upper()}** — {desc} "
                f"| {event['timestamp']}",
                expanded=(sev in ("critical", "high")),
            ):
                ecol1, ecol2 = st.columns([3, 1])
                with ecol1:
                    st.markdown(f"**Source:** `{event['source']}` | **Source IP:** `{event['source_ip'] or 'N/A'}`")
                    st.markdown(f"**Confidence:** {event['confidence']:.0%}")
                    techniques = event.get("mitre_techniques", [])
                    if techniques:
                        if isinstance(techniques, str):
                            techniques = json.loads(techniques)
                        tags = " ".join(
                            f'<span class="mitre-tag">{t} — {MITRE_LABELS.get(t, "")}</span>'
                            for t in techniques
                        )
                        st.markdown(f"**MITRE:** {tags}", unsafe_allow_html=True)
                with ecol2:
                    st.markdown(f'<div style="background:{color}; color:white; padding:8px; border-radius:6px; text-align:center; font-weight:bold;">{sev.upper()}</div>', unsafe_allow_html=True)

                raw = event.get("raw_data", {})
                if raw and raw != {}:
                    if isinstance(raw, str):
                        raw = json.loads(raw)
                    st.code(json.dumps(raw, indent=2, default=str), language="json")

        if not filtered:
            st.info("No events matching the selected severity filters.")
    else:
        st.info("Run a defense cycle to see live events, or check database for historical data.")


# --- Tab 2: Investigations ---
with tab2:
    if result and result.investigations:
        for inv in result.investigations:
            sev = inv.severity.value
            icon = severity_icon(sev)
            with st.expander(f"{icon} {inv.summary[:100]}", expanded=False):
                icol1, icol2, icol3 = st.columns(3)
                icol1.metric("Severity", sev.upper())
                icol2.metric("Confidence", f"{inv.confidence:.0%}")
                icol3.metric("Assets", len(inv.affected_assets))

                st.markdown(f"**Root Cause:** {inv.root_cause}")
                st.markdown(f"**Affected Assets:** `{'`, `'.join(inv.affected_assets)}`")

                if inv.mitre_techniques:
                    tags = " ".join(
                        f'<span class="mitre-tag">{t} — {MITRE_LABELS.get(t, "")}</span>'
                        for t in inv.mitre_techniques
                    )
                    st.markdown(f"**MITRE:** {tags}", unsafe_allow_html=True)

                if inv.recommended_actions:
                    st.markdown("**Recommended Actions:**")
                    for ra in inv.recommended_actions:
                        st.markdown(f"  - `{ra}`")

                if inv.reasoning_trace:
                    st.markdown("**Reasoning Trace:**")
                    for step in inv.reasoning_trace:
                        st.markdown(f"  ▸ {step}")
    else:
        st.info("No investigations yet.")


# --- Tab 3: Actions & Approvals ---
with tab3:
    if result:
        acol1, acol2, acol3, acol4 = st.columns(4)
        acol1.markdown(metric_card("Proposed", len(result.proposed_actions), "#1f6feb"), unsafe_allow_html=True)
        acol2.markdown(metric_card("Approved", len(result.approved_actions), "#238636"), unsafe_allow_html=True)
        acol3.markdown(metric_card("Executed", len(result.executed_actions), "#8957e5"), unsafe_allow_html=True)
        denied_count = len([a for a in result.proposed_actions if a.status.value in ("rejected", "denied")])
        acol4.markdown(metric_card("Denied", denied_count, "#da3633"), unsafe_allow_html=True)

    # DB-backed pending approvals
    if db_pending:
        st.markdown("### ⏳ Pending Approvals (Database)")
        for i, row in enumerate(db_pending):
            action_id = row.get("action_id", "")
            try:
                action_data = json.loads(row.get("action_data", "{}"))
            except (json.JSONDecodeError, TypeError):
                action_data = {}

            requested_at = row.get("requested_at", "")
            timeout_seconds = row.get("timeout_seconds", 300)
            reason = row.get("reason", "")

            try:
                req_time = datetime.fromisoformat(requested_at)
                elapsed = (datetime.now(timezone.utc) - req_time).total_seconds()
            except (ValueError, TypeError):
                elapsed = 0

            remaining = max(0, timeout_seconds - elapsed)
            pct = remaining / timeout_seconds if timeout_seconds > 0 else 0
            bar_color = "#238636" if pct > 0.5 else "#d29922" if pct > 0.2 else "#da3633"

            action_type = action_data.get("action_type", "unknown")
            target = action_data.get("target", "unknown")
            risk = action_data.get("risk_score", 0)
            reversible = action_data.get("reversible", True)

            st.markdown(f"""<div class="approval-card">
                <strong>{action_type}</strong> on <code>{target}</code>
                &nbsp;|&nbsp; Risk: <strong>{risk:.2f}</strong>
                &nbsp;|&nbsp; {'Reversible' if reversible else 'IRREVERSIBLE'}
                <br><small>{reason}</small>
                <div class="timeout-bar">
                    <div class="timeout-fill" style="width:{pct*100:.0f}%; background:{bar_color};"></div>
                </div>
                <small style="color:#8b949e;">Time remaining: {format_seconds(remaining)} / {format_seconds(timeout_seconds)}</small>
            </div>""", unsafe_allow_html=True)

            bcol1, bcol2 = st.columns(2)
            with bcol1:
                if st.button("✅ Approve", key=f"db_approve_{i}"):
                    _resolve_approval(action_id, True, "dashboard_user")
                    st.success(f"Approved: {action_type} on {target}")
                    st.rerun()
            with bcol2:
                if st.button("❌ Deny", key=f"db_deny_{i}"):
                    _resolve_approval(action_id, False, "dashboard_user")
                    st.warning(f"Denied: {action_type} on {target}")
                    st.rerun()

    # In-memory pending approvals (fallback)
    elif result:
        pending_approvals = getattr(result, "pending_approvals", [])
        if pending_approvals:
            st.markdown("### ⏳ Pending Approvals")
            for i, pa in enumerate(pending_approvals):
                action = pa.action
                elapsed = (datetime.now(timezone.utc) - pa.requested_at).total_seconds()
                remaining = max(0, pa.timeout_seconds - elapsed)
                pct = remaining / pa.timeout_seconds if pa.timeout_seconds > 0 else 0
                bar_color = "#238636" if pct > 0.5 else "#d29922" if pct > 0.2 else "#da3633"

                st.markdown(f"""<div class="approval-card">
                    <strong>{action.action_type}</strong> on <code>{action.target}</code>
                    &nbsp;|&nbsp; Risk: <strong>{action.risk_score:.2f}</strong>
                    &nbsp;|&nbsp; {'Reversible' if action.reversible else 'IRREVERSIBLE'}
                    <br><small>{pa.reason}</small>
                    <div class="timeout-bar">
                        <div class="timeout-fill" style="width:{pct*100:.0f}%; background:{bar_color};"></div>
                    </div>
                    <small style="color:#8b949e;">Time remaining: {format_seconds(remaining)} / {format_seconds(pa.timeout_seconds)}</small>
                </div>""", unsafe_allow_html=True)

                if action.canary_result:
                    st.markdown(f'<div class="canary-card">Canary: {action.canary_result}</div>', unsafe_allow_html=True)

                bcol1, bcol2 = st.columns(2)
                with bcol1:
                    if st.button("✅ Approve", key=f"approve_pa_{i}"):
                        pa.approved = True
                        pa.decided_by = "dashboard_user"
                        pa.decided_at = datetime.now(timezone.utc)
                        st.success(f"Approved: {action.action_type} on {action.target}")
                        st.rerun()
                with bcol2:
                    if st.button("❌ Deny", key=f"deny_pa_{i}"):
                        pa.approved = False
                        pa.decided_by = "dashboard_user"
                        pa.decided_at = datetime.now(timezone.utc)
                        st.warning(f"Denied: {action.action_type} on {action.target}")
                        st.rerun()

    if result:
        if result.human_escalations:
            st.markdown("### ⚠️ Human Escalations")
            for i, escalation in enumerate(result.human_escalations):
                st.markdown(f"""<div class="approval-card">
                    <strong>Escalation #{i+1}:</strong> {escalation}
                </div>""", unsafe_allow_html=True)

        if result.safety_violations:
            st.markdown("### Safety Violations")
            for v in result.safety_violations:
                st.error(f"⛔ {v}")

        st.markdown("### All Actions")
        for action in result.proposed_actions:
            status = action.status.value
            badge_class = {
                "approved": "badge-approved", "rejected": "badge-rejected",
                "denied": "badge-denied", "proposed": "badge-proposed",
                "executed": "badge-executed",
            }.get(status, "badge-proposed")

            with st.expander(f"`{action.action_type}` → `{action.target}` [{status.upper()}]"):
                st.markdown(f'<span class="status-badge {badge_class}">{status.upper()}</span>', unsafe_allow_html=True)
                dcol1, dcol2 = st.columns(2)
                with dcol1:
                    st.markdown(f"**Risk Score:** {action.risk_score:.2f}")
                    st.markdown(f"**Reversible:** {'Yes' if action.reversible else 'No'}")
                    st.markdown(f"**Human Required:** {'Yes' if action.requires_human else 'No'}")
                with dcol2:
                    st.markdown(f"**Reasoning:** {action.reasoning}")
                    if action.rollback_procedure:
                        st.markdown(f"**Rollback:** `{action.rollback_procedure}`")

                if action.canary_result:
                    st.markdown(f'<div class="canary-card">Canary preview: {action.canary_result}</div>', unsafe_allow_html=True)
                if action.execution_output:
                    st.markdown(f"**Execution Output:** `{action.execution_output}`")

    elif not db_pending:
        st.info("No actions yet.")


# --- Tab 4: Reports ---
with tab4:
    reports_shown = False

    if result and result.reports:
        reports_shown = True
        for report in result.reports:
            sev = report.severity.value
            with st.expander(f"{severity_icon(sev)} {report.title}", expanded=False):
                st.markdown(f"**Severity:** {sev.upper()}")
                st.markdown(f"**Executive Summary:** {report.executive_summary}")

                if report.timeline:
                    st.markdown("**Timeline:**")
                    for entry in report.timeline:
                        st.markdown(f"  `{entry.get('time', 'N/A')}` — {entry.get('description', '')}")

                if report.actions_taken:
                    st.markdown(f"**Actions Taken:** {len(report.actions_taken)}")

                if report.recommendations:
                    st.markdown("**Recommendations:**")
                    for r in report.recommendations:
                        st.markdown(f"  - {r}")

                if report.mitre_mapping:
                    tags = " ".join(f'<span class="mitre-tag">{t}</span>' for t in report.mitre_mapping)
                    st.markdown(f"**MITRE:** {tags}", unsafe_allow_html=True)

    db_reports = _load_db_reports()
    if db_reports and not reports_shown:
        st.markdown("### Historical Reports (Database)")
        for rpt in db_reports:
            sev = rpt.get("severity", "info")
            title = rpt.get("title", "Untitled Report")
            with st.expander(f"{severity_icon(sev)} {title}", expanded=False):
                st.markdown(f"**Severity:** {sev.upper()}")
                st.markdown(f"**Summary:** {rpt.get('executive_summary', '')}")
                st.markdown(f"**Timestamp:** {rpt.get('timestamp', '')}")

                recs = rpt.get("recommendations", [])
                if recs:
                    st.markdown("**Recommendations:**")
                    for r in recs:
                        st.markdown(f"  - {r}")
        reports_shown = True

    if not reports_shown:
        st.info("No reports generated yet.")


# --- Tab 5: MITRE ATT&CK Map ---
with tab5:
    st.markdown("### MITRE ATT&CK Technique Coverage")

    technique_counts: dict[str, int] = {}

    if result:
        for event in result.events:
            for t in event.mitre_techniques:
                technique_counts[t] = technique_counts.get(t, 0) + 1
    elif db_events:
        for event in db_events:
            techniques = event.get("mitre_techniques", [])
            if isinstance(techniques, str):
                techniques = json.loads(techniques)
            for t in techniques:
                technique_counts[t] = technique_counts.get(t, 0) + 1

    if technique_counts:
        tactic_groups = {
            "Initial Access": ["T1566", "T1078", "T1190", "T1133"],
            "Execution": ["T1059", "T1204"],
            "Persistence": ["T1543", "T1136", "T1547"],
            "Privilege Escalation": ["T1548", "T1055", "T1068", "T1134"],
            "Defense Evasion": ["T1070", "T1112", "T1562", "T1036", "T1027"],
            "Credential Access": ["T1003", "T1110", "T1558", "T1056"],
            "Discovery": ["T1046", "T1082", "T1083", "T1057", "T1018", "T1049", "T1016", "T1033"],
            "Lateral Movement": ["T1021"],
            "Collection": ["T1565", "T1005", "T1560"],
            "Exfiltration": ["T1048", "T1041"],
            "Impact": ["T1486", "T1531"],
            "Command and Control": ["T1071", "T1571", "T1105"],
        }

        for tactic, techniques in tactic_groups.items():
            hits = [(t, technique_counts.get(t, 0)) for t in techniques if technique_counts.get(t, 0) > 0]
            if hits:
                st.markdown(f"**{tactic}**")
                for tid, count in hits:
                    label = MITRE_LABELS.get(tid, tid)
                    intensity = min(count / 10, 1.0)
                    r = int(255 * intensity)
                    bar_color = f"rgb({r}, {100 - int(50*intensity)}, {50 - int(30*intensity)})"
                    st.markdown(
                        f'<div style="background:#1a1f2e; padding:6px 12px; margin:2px 0; border-radius:4px; border-left:4px solid {bar_color};">'
                        f'<code>{tid}</code> — {label} '
                        f'<span style="float:right; color:{bar_color}; font-weight:bold;">{count} hits</span></div>',
                        unsafe_allow_html=True,
                    )
                st.markdown("")

        st.divider()
        st.markdown(f"**Total techniques detected:** {len(technique_counts)}")
        st.markdown(f"**Total technique hits:** {sum(technique_counts.values())}")
    else:
        st.info("No MITRE techniques detected. Run a defense cycle to see mapping.")


# --- Tab 6: Audit Log ---
with tab6:
    entries = _load_audit_entries()
    if entries:
        st.markdown(f"**Total audit entries:** {len(entries)}")

        agent_filter = st.multiselect(
            "Filter by agent",
            list({e.get("agent", "unknown") for e in entries}),
            default=[],
        )

        filtered_entries = entries
        if agent_filter:
            filtered_entries = [e for e in entries if e.get("agent") in agent_filter]

        for entry in reversed(filtered_entries[-50:]):
            agent = entry.get("agent", "unknown")
            action = entry.get("action", "")
            status = entry.get("status", "")
            ts = entry.get("timestamp", "")
            entry_hash = entry.get("entry_hash", "")

            status_icon_map = {
                "executed": "✅", "approved": "\U0001f7e2",
                "rejected": "\U0001f534", "failed": "⚠️",
                "denied": "\U0001f534",
            }
            s_icon = status_icon_map.get(status, "○")

            with st.expander(f"{s_icon} `{agent}` — {action} [{status}] {ts}"):
                st.markdown(f"**Hash:** `{entry_hash[:24]}...`" if entry_hash else "")
                prev_hash = entry.get("previous_hash", "")
                if prev_hash:
                    st.markdown(f"**Previous Hash:** `{prev_hash[:24]}...`")
                st.code(json.dumps(entry, indent=2, default=str), language="json")
    else:
        st.info("No audit entries yet. Run a defense cycle to generate audit data.")
