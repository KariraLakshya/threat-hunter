"""
response_engine.py — Phase 8: Response Automation

FIX: All config values (SLACK_WEBHOOK, SMTP_*, ALERT_EMAIL, ALERT_ROUTING)
are now read inside functions via helper getters instead of at module import
time. This means changes saved via POST /integrations/save → os.environ are
picked up immediately without requiring a uvicorn restart.
"""

import os
import json
import logging
import sqlite3
import smtplib
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any

import requests
import boto3
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("response_engine")

# ── Static config (never changes at runtime) ──────────────────
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
AWS_REGION     = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
DB_PATH        = os.getenv("INCIDENTS_DB", "incidents/incidents.db")


# ── Dynamic config — read fresh from os.environ every call ────
# These are callables, not module-level constants, so any write
# to os.environ (e.g. from /integrations/save) takes effect
# immediately without restarting uvicorn.

def _slack_webhook() -> str:
    return os.environ.get("SLACK_WEBHOOK") or os.environ.get("SLACK_WEBHOOK_URL", "")

def _smtp_host() -> str:
    return os.environ.get("SMTP_HOST", "smtp.gmail.com")

def _smtp_port() -> int:
    return int(os.environ.get("SMTP_PORT", "587"))

def _smtp_user() -> str:
    return os.environ.get("SMTP_USER", "")

def _smtp_pass() -> str:
    return os.environ.get("SMTP_PASS") or os.environ.get("SMTP_PASSWORD", "")

def _alert_email() -> str:
    return os.environ.get("ALERT_EMAIL") or os.environ.get("ALERT_EMAIL_TO", "")

def _routing() -> Dict[str, Dict[str, bool]]:
    """Per-severity routing rules saved by the Integrations page."""
    raw = os.environ.get("ALERT_ROUTING", "")
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return {
        "critical": {"slack": True,  "email": True},
        "high":     {"slack": True,  "email": True},
        "medium":   {"slack": True,  "email": False},
        "low":      {"slack": False, "email": False},
    }


# ── Database ─────────────────────────────────────────────────

def init_db(db_path: str = DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            timestamp   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            is_attack   INTEGER,
            user        TEXT,
            environments TEXT,
            cross_env   INTEGER,
            summary     TEXT,
            actions     TEXT,
            status      TEXT DEFAULT 'open',
            conclusion  TEXT,
            chain       TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS remediation_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            action      TEXT NOT NULL,
            result      TEXT
        )
    """)
    conn.commit()
    conn.close()


def _is_cross_env(chain: List[Dict]) -> bool:
    """
    True only when the chain has events from BOTH on-prem AND cloud.
    The old approach checked the cross_environment flag per step, but the
    correlation engine sets that flag on ALL events for a user once a
    cross-env pattern is detected — so every incident was tagged cross-env.
    """
    all_envs: set = set()
    for step in chain:
        for env in step.get("environment", []):
            all_envs.add(env)
    has_onprem = any(e.startswith("on-") or e == "on-premise" for e in all_envs)
    has_cloud  = any(e in ("aws", "azure", "gcp") for e in all_envs)
    return has_onprem and has_cloud


def save_incident(incident_id: str, conclusion: Dict, chain: List[Dict]) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO incidents
        (incident_id, timestamp, severity, is_attack, user, environments,
         cross_env, summary, actions, status, conclusion, chain)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        incident_id,
        datetime.now(timezone.utc).isoformat(),
        conclusion.get("severity", "medium"),
        int(conclusion.get("is_real_attack", True)),
        chain[0].get("user", "unknown") if chain else "unknown",
        json.dumps(list({e for step in chain for e in step.get("environment", [])})),
        int(_is_cross_env(chain)),
        conclusion.get("summary", ""),
        json.dumps(conclusion.get("immediate_actions", [])),
        "open",
        json.dumps(conclusion),
        json.dumps(chain),
    ))
    conn.commit()
    conn.close()
    try:
        from agent.rag import RAGRetriever
        RAGRetriever().index_incident(incident_id, conclusion.get("summary", ""), conclusion)
    except Exception as e:
        log.warning(f"[Response] RAG indexing skipped: {e}")


def log_remediation(incident_id: str, action: str, result: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO remediation_log (incident_id, timestamp, action, result) VALUES (?,?,?,?)",
        (incident_id, datetime.now(timezone.utc).isoformat(), action, result)
    )
    conn.commit()
    conn.close()


# ── Alert Channels ────────────────────────────────────────────

def send_slack(incident_id: str, severity: str, summary: str,
               chain: List[Dict], actions: List[str]) -> bool:
    webhook = _slack_webhook()          # fresh read every call
    if not webhook:
        log.warning("[Response] SLACK_WEBHOOK not set — skipping Slack alert")
        return False
    color = {"low":"#36a64f","medium":"#f0a500","high":"#e05d1f","critical":"#8B0000"}.get(severity,"#808080")
    cross_env = any(s.get("cross_environment") for s in chain)
    envs = list({e for step in chain for e in step.get("environment", [])})
    payload = {
        "attachments": [{
            "color": color,
            "title": f"🔐 [{severity.upper()}] Incident {incident_id}",
            "text": summary,
            "fields": [
                {"title": "Environments",     "value": ", ".join(envs),                                    "short": True},
                {"title": "Cross-Env Attack", "value": "⚠️ YES" if cross_env else "No",                    "short": True},
                {"title": "Attack Chain",     "value": " → ".join(s["tactic"] for s in chain),             "short": False},
                {"title": "Immediate Actions","value": "\n".join(f"• {a}" for a in actions[:5]),           "short": False},
            ],
            "footer": "Autonomous Threat Hunter",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }
    try:
        r = requests.post(webhook, json=payload, timeout=10)
        if r.status_code == 200:
            log.info(f"[Response] Slack alert sent for {incident_id}")
            return True
        log.warning(f"[Response] Slack error {r.status_code}: {r.text}")
        return False
    except Exception as e:
        log.error(f"[Response] Slack failed: {e}")
        return False


def send_email(incident_id: str, severity: str, summary: str,
               chain: List[Dict], actions: List[str]) -> bool:
    smtp_user = _smtp_user()            # fresh reads
    smtp_pass = _smtp_pass()
    alert_to  = _alert_email()
    if not all([smtp_user, smtp_pass, alert_to]):
        log.warning("[Response] Email not fully configured — skipping")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{severity.upper()}] Security Incident {incident_id}"
        msg["From"]    = smtp_user
        msg["To"]      = alert_to
        chain_html = "".join(
            f"<tr><td>{s['step']}</td><td>{s['tactic']}</td><td>{s['technique']}</td>"
            f"<td>{s['user']}</td><td>{s['source_ip']}</td><td>{', '.join(s.get('environment',[]))}</td></tr>"
            for s in chain
        )
        html = f"""<html><body>
        <h2 style='color:darkred'>🔐 Incident {incident_id} — {severity.upper()}</h2>
        <p><strong>Summary:</strong> {summary}</p>
        <h3>Attack Chain</h3>
        <table border='1' cellpadding='5'>
        <tr><th>Step</th><th>Tactic</th><th>Technique</th><th>User</th><th>IP</th><th>Env</th></tr>
        {chain_html}</table>
        <h3>Immediate Actions</h3>
        <ul>{"".join(f"<li>{a}</li>" for a in actions)}</ul>
        <p><em>Autonomous Threat Hunter</em></p></body></html>"""
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(_smtp_host(), _smtp_port()) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        log.info(f"[Response] Email sent for {incident_id}")
        return True
    except Exception as e:
        log.error(f"[Response] Email failed: {e}")
        return False


# ── AWS Auto-Remediation ──────────────────────────────────────

def disable_iam_key(username: str, incident_id: str) -> str:
    try:
        iam = boto3.client("iam", region_name=AWS_REGION)
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        disabled = []
        for key in keys:
            iam.update_access_key(UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive")
            disabled.append(key["AccessKeyId"])
        result = f"Disabled {len(disabled)} key(s): {', '.join(disabled)}"
        log_remediation(incident_id, f"disable_iam_keys:{username}", result)
        return result
    except Exception as e:
        log_remediation(incident_id, f"disable_iam_keys:{username}", f"ERROR: {e}")
        return f"Failed: {e}"


def stop_ec2_instance(instance_id: str, incident_id: str) -> str:
    try:
        ec2 = boto3.client("ec2", region_name=AWS_REGION)
        ec2.stop_instances(InstanceIds=[instance_id])
        result = f"Stopped EC2 instance {instance_id}"
        log_remediation(incident_id, f"stop_ec2:{instance_id}", result)
        return result
    except Exception as e:
        log_remediation(incident_id, f"stop_ec2:{instance_id}", f"ERROR: {e}")
        return f"Failed: {e}"


# ── Main Response Dispatcher ──────────────────────────────────

class ResponseEngine:
    def __init__(self):
        init_db()

    def respond(
        self,
        conclusion: Dict[str, Any],
        chain: List[Dict],
        sandbox_results: Optional[Dict] = None,
        compromised_iam_user: Optional[str] = None,
        suspicious_ec2_instances: Optional[List[str]] = None,
    ) -> Dict:
        incident_id    = f"INC-{str(uuid.uuid4())[:6].upper()}"
        severity       = conclusion.get("severity", "medium").lower()
        summary        = conclusion.get("summary", "Security incident detected")
        actions_recommended = conclusion.get("immediate_actions", [])
        severity_level = SEVERITY_ORDER.get(severity, 2)

        routing     = _routing()                              # fresh read
        sev_routing = routing.get(severity, {"slack": True, "email": True})

        log.info(f"[Response] 🚨 {incident_id} | severity={severity} | routing={sev_routing}")

        save_incident(incident_id, conclusion, chain)
        actions_taken = [f"Incident {incident_id} created in database"]

        if sev_routing.get("slack", False):
            if send_slack(incident_id, severity, summary, chain, actions_recommended):
                actions_taken.append("Slack alert sent")

        if sev_routing.get("email", False):
            if send_email(incident_id, severity, summary, chain, actions_recommended):
                actions_taken.append("Email alert sent to SOC team")

        if severity_level >= 4:
            if compromised_iam_user:
                actions_taken.append(f"IAM: {disable_iam_key(compromised_iam_user, incident_id)}")
            for iid in (suspicious_ec2_instances or []):
                actions_taken.append(f"EC2: {stop_ec2_instance(iid, incident_id)}")

        return {
            "incident_id":       incident_id,
            "severity":          severity,
            "summary":           summary,
            "actions_taken":     actions_taken,
            "cross_environment": any(s.get("cross_environment") for s in chain),
            "timestamp":         datetime.now(timezone.utc).isoformat(),
        }