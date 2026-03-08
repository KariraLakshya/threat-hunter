"""
response_engine.py — Phase 8: Response Automation

Takes an incident conclusion from the AI agent and:
- LOW    → Log incident only
- MEDIUM → Slack alert
- HIGH   → Slack + Email alert
- CRITICAL → All above + AWS auto-remediation (disable IAM keys, stop EC2)

Also stores incidents in a SQLite database.
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

# ── Config ───────────────────────────────────────────────────
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL_TO", "")
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
DB_PATH = os.getenv("INCIDENTS_DB", "incidents/incidents.db")

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Database ─────────────────────────────────────────────────

def init_db(db_path: str = DB_PATH):
    """Initialize the incidents SQLite database."""
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
        conclusion.get("severity", "medium").lower(),
        int(conclusion.get("is_real_attack", True)),
        chain[0].get("user", "unknown") if chain else "unknown",
        json.dumps(list({e for step in chain for e in step.get("environment", [])})),
        int(any(step.get("cross_environment") for step in chain)),
        conclusion.get("summary", ""),
        json.dumps(conclusion.get("immediate_actions", [])),
        "open",
        json.dumps(conclusion),
        json.dumps(chain),
    ))
    conn.commit()
    conn.close()

    # Index into RAG vector store so future investigations can retrieve this incident
    try:
        from agent.rag import RAGRetriever
        RAGRetriever().index_incident(
            incident_id,
            conclusion.get("summary", ""),
            conclusion,
        )
    except Exception as e:
        log.warning(f"[Response] RAG indexing skipped: {e}")


def log_remediation(incident_id: str, action: str, result: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO remediation_log (incident_id, timestamp, action, result)
        VALUES (?,?,?,?)
    """, (incident_id, datetime.now(timezone.utc).isoformat(), action, result))
    conn.commit()
    conn.close()


# ── Alert Channels ────────────────────────────────────────────

def send_slack(incident_id: str, severity: str, summary: str,
               chain: List[Dict], actions: List[str]) -> bool:
    if not SLACK_WEBHOOK:
        log.warning("[Response] SLACK_WEBHOOK_URL not set — skipping Slack alert")
        return False

    color = {"low": "#36a64f", "medium": "#f0a500", "high": "#e05d1f", "critical": "#8B0000"}.get(severity, "#808080")
    cross_env = any(s.get("cross_environment") for s in chain)
    envs = list({e for step in chain for e in step.get("environment", [])})

    payload = {
        "attachments": [{
            "color": color,
            "title": f"🔐 [{severity.upper()}] Incident {incident_id}",
            "text": summary,
            "fields": [
                {"title": "Environments", "value": ", ".join(envs), "short": True},
                {"title": "Cross-Env Attack", "value": "⚠️ YES" if cross_env else "No", "short": True},
                {"title": "Attack Chain", "value": " → ".join(s["tactic"] for s in chain), "short": False},
                {"title": "Immediate Actions", "value": "\n".join(f"• {a}" for a in actions[:5]), "short": False},
            ],
            "footer": "Autonomous Threat Hunter",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }
    try:
        r = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        if r.status_code == 200:
            log.info(f"[Response] Slack alert sent for {incident_id}")
            return True
        else:
            log.warning(f"[Response] Slack error {r.status_code}")
            return False
    except Exception as e:
        log.error(f"[Response] Slack failed: {e}")
        return False


def send_email(incident_id: str, severity: str, summary: str,
               chain: List[Dict], actions: List[str]) -> bool:
    if not all([SMTP_USER, SMTP_PASS, ALERT_EMAIL]):
        log.warning("[Response] Email not configured — skipping")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{severity.upper()}] Security Incident {incident_id}"
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL

        chain_html = "".join(
            f"<tr><td>{s['step']}</td><td>{s['tactic']}</td><td>{s['technique']}</td>"
            f"<td>{s['user']}</td><td>{s['source_ip']}</td><td>{', '.join(s.get('environment',[]))}</td></tr>"
            for s in chain
        )
        html = f"""
        <html><body>
        <h2 style="color:darkred">🔐 Security Incident {incident_id} — {severity.upper()}</h2>
        <p><strong>Summary:</strong> {summary}</p>
        <h3>Attack Chain</h3>
        <table border="1" cellpadding="5">
        <tr><th>Step</th><th>Tactic</th><th>Technique</th><th>User</th><th>IP</th><th>Env</th></tr>
        {chain_html}
        </table>
        <h3>Immediate Actions Required</h3>
        <ul>{"".join(f"<li>{a}</li>" for a in actions)}</ul>
        <p><em>Generated by Autonomous Threat Hunter</em></p>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        log.info(f"[Response] Email sent for {incident_id}")
        return True
    except Exception as e:
        log.error(f"[Response] Email failed: {e}")
        return False


# ── AWS Auto-Remediation ──────────────────────────────────────

def disable_iam_key(username: str, incident_id: str) -> str:
    """Disable all IAM access keys for a compromised user."""
    try:
        iam = boto3.client("iam", region_name=AWS_REGION)
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        disabled = []
        for key in keys:
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive"
            )
            disabled.append(key["AccessKeyId"])
            log.warning(f"[Response] Disabled IAM key {key['AccessKeyId']} for user {username}")
        result = f"Disabled {len(disabled)} key(s): {', '.join(disabled)}"
        log_remediation(incident_id, f"disable_iam_keys:{username}", result)
        return result
    except Exception as e:
        log.error(f"[Response] IAM disable failed: {e}")
        log_remediation(incident_id, f"disable_iam_keys:{username}", f"ERROR: {e}")
        return f"Failed: {e}"


def stop_ec2_instance(instance_id: str, incident_id: str) -> str:
    """Stop a suspicious EC2 instance."""
    try:
        ec2 = boto3.client("ec2", region_name=AWS_REGION)
        ec2.stop_instances(InstanceIds=[instance_id])
        result = f"Stopped EC2 instance {instance_id}"
        log.warning(f"[Response] {result}")
        log_remediation(incident_id, f"stop_ec2:{instance_id}", result)
        return result
    except Exception as e:
        log.error(f"[Response] EC2 stop failed: {e}")
        log_remediation(incident_id, f"stop_ec2:{instance_id}", f"ERROR: {e}")
        return f"Failed: {e}"


# ── Main Response Dispatcher ──────────────────────────────────

class ResponseEngine:
    """
    Phase 8: Dispatches alerts and remediation based on severity.
    """

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
        """
        Main response dispatcher.
        Returns a response report with all actions taken.
        """
        incident_id = f"INC-{str(uuid.uuid4())[:6].upper()}"
        severity = conclusion.get("severity", "medium").lower()
        summary = conclusion.get("summary", "Security incident detected")
        actions_recommended = conclusion.get("immediate_actions", [])
        severity_level = SEVERITY_ORDER.get(severity, 2)

        log.info(f"[Response] 🚨 {incident_id} | severity={severity}")

        # Save to DB
        save_incident(incident_id, conclusion, chain)

        actions_taken = []

        # ── LOW: Log only ─────────────────────────────
        log.info(f"[Response] Incident logged: {incident_id}")
        actions_taken.append(f"Incident {incident_id} created in database")

        # ── MEDIUM: + Slack ───────────────────────────
        if severity_level >= 2:
            ok = send_slack(incident_id, severity, summary, chain, actions_recommended)
            if ok:
                actions_taken.append("Slack alert sent")

        # ── HIGH: + Email ─────────────────────────────
        if severity_level >= 3:
            ok = send_email(incident_id, severity, summary, chain, actions_recommended)
            if ok:
                actions_taken.append("Email alert sent to SOC team")

        # ── CRITICAL: + AWS remediation ───────────────
        if severity_level >= 4:
            if compromised_iam_user:
                result = disable_iam_key(compromised_iam_user, incident_id)
                actions_taken.append(f"IAM: {result}")

            for instance_id in (suspicious_ec2_instances or []):
                result = stop_ec2_instance(instance_id, incident_id)
                actions_taken.append(f"EC2: {result}")

        report = {
            "incident_id": incident_id,
            "severity": severity,
            "summary": summary,
            "actions_taken": actions_taken,
            "cross_environment": any(s.get("cross_environment") for s in chain),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        log.info(f"[Response] Done. Actions: {actions_taken}")
        return report
