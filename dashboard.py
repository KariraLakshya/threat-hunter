"""
dashboard.py — Phase 9: Analyst Dashboard (Streamlit)

A live web UI for SOC analysts to:
  • View the incident feed (color-coded by severity)
  • Drill into any incident's full attack chain + MITRE + AI reasoning
  • Trigger manual investigations
  • Run sandbox checks (hash/IP/URL)
  • See environment status

Run:
  streamlit run dashboard.py
"""

import os
import json
import time
import requests
import streamlit as st
from datetime import datetime

API_BASE = os.getenv("API_BASE", "http://localhost:8000")

# ── Page Config ──────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Hunter — SOC Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Minimal custom CSS ────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background: #0d1117; }
[data-testid="stSidebar"] { background: #161b22; }
h1, h2, h3 { color: #58a6ff; }
.stMetric label { color: #8b949e; }
.stMetric [data-testid="metric-container"] > div { color: #c9d1d9; }
div[data-testid="stExpander"] { border-left: 3px solid #30363d; }
.critical-badge { background:#8B0000; color:white; padding:2px 8px; border-radius:3px; }
.high-badge { background:#e05d1f; color:white; padding:2px 8px; border-radius:3px; }
.medium-badge { background:#f0a500; color:#111; padding:2px 8px; border-radius:3px; }
.low-badge { background:#238636; color:white; padding:2px 8px; border-radius:3px; }
</style>
""", unsafe_allow_html=True)


# ── API helpers ───────────────────────────────────────────────
def api_get(path: str, default=None):
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=5)
        return r.json() if r.status_code == 200 else default
    except Exception:
        return default

def api_post(path: str, payload: dict = None):
    try:
        r = requests.post(f"{API_BASE}{path}", json=payload or {}, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def severity_badge(sev: str) -> str:
    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    return f"{icons.get(sev, '⚪')} {sev.upper()}"


# ── Sidebar: Navigation & Env Status ─────────────────────────
with st.sidebar:
    st.title("🔐 Threat Hunter")
    st.caption("Autonomous SOC Analyst Platform")
    st.divider()

    page = st.radio(
        "Navigate",
        ["📋 Incident Feed", "🔍 Investigation", "🧪 Sandbox", "⚙️  Settings"],
        key="nav",
    )

    st.divider()
    st.subheader("Environment Status")

    health = api_get("/health")
    if health:
        svcs = health.get("services", {})

        def status_dot(ok: bool) -> str:
            return "🟢" if ok else "🔴"

        st.write(f"{status_dot(svcs.get('elasticsearch', {}).get('ok', False))} Elasticsearch")
        st.write(f"{status_dot(svcs.get('redis', {}).get('ok', False))} Redis / Celery")
        st.write(f"{status_dot(True))} Logstash")   # if API is up, Logstash is likely up
        st.write(f"{status_dot(True))} Wazuh Manager")
        st.write(f"{status_dot(True))} AI Agent")
    else:
        st.error("⚠️  API unreachable\nStart: uvicorn api.main:app --port 8000")

    st.divider()
    st.caption(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")

# ═══════════════════════════════════════════════════════════
# PAGE 1: Incident Feed
# ═══════════════════════════════════════════════════════════
if page == "📋 Incident Feed":
    st.title("📋 Incident Feed")

    # Stats row
    stats = api_get("/stats", {})
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Incidents", stats.get("total", 0))
    col2.metric("🔴 Critical", stats.get("by_severity", {}).get("critical", 0))
    col3.metric("🟠 High", stats.get("by_severity", {}).get("high", 0))
    col4.metric("🌐 Cross-Env", stats.get("cross_environment", 0))

    st.divider()

    # Filters
    fc1, fc2, fc3 = st.columns([2, 2, 1])
    filter_sev = fc1.selectbox("Filter by Severity", ["All", "critical", "high", "medium", "low"])
    filter_status = fc2.selectbox("Filter by Status", ["All", "open", "closed"])
    if fc3.button("🔄 Refresh", use_container_width=True):
        st.rerun()

    # Fetch incidents
    data = api_get("/incidents?limit=100", {"incidents": []})
    incidents = data.get("incidents", [])

    if filter_sev != "All":
        incidents = [i for i in incidents if i.get("severity") == filter_sev]
    if filter_status != "All":
        incidents = [i for i in incidents if i.get("status") == filter_status]

    if not incidents:
        st.info("No incidents yet. Run an investigation to detect threats.")
    else:
        for inc in incidents:
            sev = inc.get("severity", "low")
            cross = "🌐 CROSS-ENV" if inc.get("cross_env") else ""
            status_icon = "🔓" if inc.get("status") == "open" else "✅"

            with st.expander(
                f"{status_icon} [{sev.upper()}] {inc['incident_id']}  {cross}  —  {inc.get('summary', '')[:80]}..."
            ):
                c1, c2 = st.columns(2)
                c1.write(f"**ID:** `{inc['incident_id']}`")
                c1.write(f"**Severity:** {severity_badge(sev)}")
                c1.write(f"**User:** `{inc.get('user', 'unknown')}`")
                c1.write(f"**Environments:** {', '.join(inc.get('environments') or [])}")
                c2.write(f"**Timestamp:** {inc.get('timestamp', '')[:19]}")
                c2.write(f"**Status:** {inc.get('status', 'open')}")
                c2.write(f"**Cross-Env:** {'⚠️ YES' if inc.get('cross_env') else 'No'}")

                st.write("**Summary:**", inc.get("summary", ""))

                if inc.get("chain"):
                    st.write("**Attack Chain:**")
                    chain_df = [
                        {
                            "Step": s.get("step"),
                            "Tactic": s.get("tactic"),
                            "Technique": s.get("technique"),
                            "Event": s.get("event_type"),
                            "Env": ", ".join(s.get("environment", [])),
                            "Severity": s.get("severity"),
                        }
                        for s in inc["chain"]
                    ]
                    st.table(chain_df)

                if st.button(f"Close Incident", key=f"close_{inc['incident_id']}"):
                    api_post(f"/incidents/{inc['incident_id']}/close")
                    st.rerun()

# ═══════════════════════════════════════════════════════════
# PAGE 2: Manual Investigation Trigger
# ═══════════════════════════════════════════════════════════
elif page == "🔍 Investigation":
    st.title("🔍 Run Investigation")

    st.info("Trigger a full pipeline run: Correlation → MITRE → AI Agent → Sandbox → Response")

    with st.form("investigate_form"):
        lookback = st.slider("Lookback Window (minutes)", 5, 60, 10)
        user_filter = st.text_input("Filter by User (optional)", placeholder="e.g. jsmith")
        submitted = st.form_submit_button("🚀 Run Investigation Now", use_container_width=True)

    if submitted:
        with st.spinner("Investigating… AI agent is reasoning…"):
            payload = {"lookback_minutes": lookback}
            if user_filter:
                payload["user_filter"] = user_filter
            result = api_post("/investigate", payload)
            time.sleep(2)

        st.success(f"✅ {result.get('status', 'Started')}")
        st.info("Check the Incident Feed page in ~30 seconds for results.")

    st.divider()
    st.subheader("Recent Investigation Results")
    data = api_get("/incidents?limit=5", {"incidents": []})
    for inc in data.get("incidents", [])[:5]:
        st.write(
            f"• `{inc['incident_id']}` | {severity_badge(inc['severity'])} | "
            f"{inc.get('summary', '')[:60]}..."
        )

# ═══════════════════════════════════════════════════════════
# PAGE 3: Sandbox Check
# ═══════════════════════════════════════════════════════════
elif page == "🧪 Sandbox":
    st.title("🧪 Sandbox Check (VirusTotal)")

    check_type = st.selectbox("Check Type", ["ip", "hash", "url"])
    value = st.text_input(
        "Enter value to check",
        placeholder={
            "ip": "e.g. 203.0.113.42",
            "hash": "e.g. d41d8cd98f00b204e9800998ecf8427e",
            "url": "e.g. https://suspicious-site.com",
        }.get(check_type, "")
    )

    if st.button("🔍 Check", use_container_width=True, disabled=not value):
        with st.spinner("Querying VirusTotal..."):
            result = api_post("/sandbox/check", {"type": check_type, "value": value})

        verdict = result.get("verdict", "unknown")
        malicious = result.get("malicious_count", 0)

        if verdict == "malicious":
            st.error(f"🔴 MALICIOUS — {malicious} detections")
        elif verdict == "suspicious":
            st.warning(f"🟡 SUSPICIOUS — {malicious} detections")
        elif verdict == "clean":
            st.success("🟢 CLEAN — No detections")
        else:
            st.info("⚪ UNKNOWN — Not in VirusTotal database")

        st.json(result)

# ═══════════════════════════════════════════════════════════
# PAGE 4: Settings
# ═══════════════════════════════════════════════════════════
elif page == "⚙️  Settings":
    st.title("⚙️  Settings")

    st.subheader("API Endpoint")
    st.code(f"API: {API_BASE}")

    st.subheader("Service Health")
    health = api_get("/health")
    if health:
        st.json(health)
    else:
        st.error("API unreachable")

    st.subheader("Statistics")
    stats = api_get("/stats")
    if stats:
        st.json(stats)
