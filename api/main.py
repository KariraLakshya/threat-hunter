"""
main.py — Phase 8: FastAPI Backend

REST API that ties together the entire pipeline:
  POST /investigate   → run full investigation pipeline on queued events
  GET  /incidents     → list all incidents from the database
  GET  /incidents/{id} → get full incident details
  POST /sandbox/check → check a hash/URL/IP via VirusTotal
  GET  /health        → check all services are running

Start:
  uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import json
import sqlite3
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
import re as _re
from datetime import datetime as _dt, timezone as _tz
import re
from pathlib import Path
load_dotenv()
log = logging.getLogger("api")

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme123")
DB_PATH = os.getenv("INCIDENTS_DB", "incidents/incidents.db")

app = FastAPI(
    title="Autonomous Threat Hunter API",
    description="SOC Analyst Platform — Phase 8",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """On API startup: init DB and bulk-index any existing incidents into RAG."""
    # Ensure the incidents table exists before any request hits the DB
    from response.response_engine import init_db
    init_db()
    log.info("[API] Database initialized")

    # Sync existing incidents into the RAG vector store
    try:
        from agent.rag import RAGRetriever
        count = RAGRetriever().index_incidents_from_db()
        log.info(f"[API] Startup RAG sync: {count} incidents indexed")
    except Exception as e:
        log.warning(f"[API] Startup RAG sync skipped: {e}")


# ── Pydantic Models ───────────────────────────────────────────

class SandboxCheckRequest(BaseModel):
    type: str           # "ip" | "hash" | "url"
    value: str

class InvestigateRequest(BaseModel):
    lookback_minutes: Optional[int] = 10
    user_filter: Optional[str] = None
    force_run: Optional[bool] = False


# ── Helpers ───────────────────────────────────────────────────

def get_es():
    return Elasticsearch(ES_HOST, basic_auth=("elastic", ELASTIC_PASSWORD), verify_certs=False)

def get_db():
    return sqlite3.connect(DB_PATH)


def _scalar(val):
    """If val is a list, return the last non-empty element; else return as-is."""
    if isinstance(val, list):
        non_empty = [v for v in val if v not in (None, "")]
        return non_empty[-1] if non_empty else ""
    return val or ""


def _adapt_logstash_doc(doc: dict):
    """
    Convert an ES document into a NormalizedEvent.

    Two doc formats arrive in security-* indices:
    - On-prem (Logstash): raw grok output, fields may be arrays
    - Cloud (aws_collector): already NormalizedEvent.to_dict(), clean scalars

    Detection: cloud docs have `source_service` set (cloudtrail/guardduty).
    """
    from collector.schema import NormalizedEvent

    # ── Cloud docs — already normalized, just reconstruct ────────────
    if doc.get("source_service") in ("cloudtrail", "guardduty", "azure_monitor"):
        event_type = doc.get("event_type", "")
        if not event_type:
            return None
        return NormalizedEvent(
            event_id=doc.get("event_id", ""),
            timestamp=doc.get("timestamp") or doc.get("@timestamp", ""),
            environment=doc.get("environment", "aws"),
            event_type=event_type,
            severity=doc.get("severity", "medium"),
            user=doc.get("user", "unknown"),
            source_ip=doc.get("source_ip", ""),
            source_host=doc.get("source_host"),
            cloud_resource=doc.get("cloud_resource"),
            raw_log=doc.get("raw_log", ""),
            source_service=doc.get("source_service", ""),
        )

    # ── On-prem Logstash docs — flatten multi-value arrays ───────────
    event_type = _scalar(doc.get("event_type") or doc.get("type", ""))
    if not event_type:
        return None

    return NormalizedEvent(
        event_id=_scalar(doc.get("event_id", "")),
        timestamp=_scalar(doc.get("timestamp") or doc.get("@timestamp", "")),
        environment="on-premise",
        event_type=event_type,
        user=_scalar(doc.get("user", "unknown")),
        source_ip=_scalar(doc.get("source_ip", "")),
        source_host=_scalar(doc.get("source_host", "")),
        severity=_scalar(doc.get("severity", "low")),
        raw_log=str(doc.get("raw_log", "")),
        source_service="logstash",
    )


# ── Routes ────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    """Check all services."""
    results = {}

    # Elasticsearch
    try:
        es = get_es()
        info = es.cluster.health()
        results["elasticsearch"] = {"status": info["status"], "ok": True}
    except Exception as e:
        results["elasticsearch"] = {"status": "unreachable", "ok": False, "error": str(e)}

    # Database
    try:
        conn = get_db()
        conn.execute("SELECT COUNT(*) FROM incidents")
        conn.close()
        results["database"] = {"status": "ok", "ok": True}
    except Exception as e:
        results["database"] = {"status": "error", "ok": False, "error": str(e)}

    # Redis
    try:
        import redis
        r = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=6379)
        r.ping()
        results["redis"] = {"status": "ok", "ok": True}
    except Exception as e:
        results["redis"] = {"status": "unreachable", "ok": False, "error": str(e)}

    overall = all(v["ok"] for v in results.values())
    return {
        "overall": "healthy" if overall else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": results,
    }
def _parse_docker_uptime(started_at: str) -> str:
    """Convert Docker's StartedAt ISO string to a human-readable uptime."""
    try:
        start = _dt.fromisoformat(started_at.replace("Z", "+00:00"))
        delta = _dt.now(_tz.utc) - start
        total = int(delta.total_seconds())
        days, rem = divmod(total, 86400)
        hours, rem = divmod(rem, 3600)
        mins = rem // 60
        if days:
            return f"{days}d {hours}h {mins}m"
        if hours:
            return f"{hours}h {mins}m"
        return f"{mins}m"
    except Exception:
        return "–"


@app.get("/docker-status")
def docker_status():
    """
    Return real-time status for all Docker containers on the host.
    Uses the Docker SDK (unix socket or tcp — same as `docker ps`).
    Falls back gracefully if Docker is not accessible.
    """
    try:
        import docker  # type: ignore
        client = docker.from_env()
        containers = client.containers.list(all=True)

        result = []
        for ct in containers:
            ct.reload()  # refresh attrs
            attrs      = ct.attrs
            state      = attrs.get("State", {})
            started_at = state.get("StartedAt", "")
            status     = state.get("Status", "unknown")       # running / exited / …
            health     = state.get("Health", {}).get("Status", "") or ""   # healthy / starting / …

            # Short image name (strip digest/sha)
            image_tag = ""
            try:
                tags = ct.image.tags
                image_tag = tags[0] if tags else ct.image.short_id
            except Exception:
                image_tag = "unknown"

            result.append({
                "name":   ct.name,
                "status": status,
                "state":  health or status,
                "uptime": _parse_docker_uptime(started_at) if status == "running" else "–",
                "image":  image_tag,
            })

        return {
            "containers":  result,
            "fetched_at":  _dt.now(_tz.utc).isoformat(),
        }

    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Docker SDK not installed. Run: pip install docker"
        )
    except Exception as e:
        log.warning(f"[docker-status] {e}")
        raise HTTPException(
            status_code=503,
            detail=f"Cannot connect to Docker daemon: {e}"
        )
# ── Pydantic request models ───────────────────────────────────

class SlackConfigRequest(BaseModel):
    webhook_url: str

class EmailConfigRequest(BaseModel):
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str
    smtp_pass: str
    alert_email: str

class SaveIntegrationsRequest(BaseModel):
    slack_webhook:  str = ""
    smtp_host:      str = "smtp.gmail.com"
    smtp_port:      int = 587
    smtp_user:      str = ""
    smtp_pass:      str = ""
    alert_email:    str = ""
    routing:        dict = {}   # {"critical":{"slack":true,"email":true}, …}


# ── Helper: patch a key=value line in .env ────────────────────

def _env_path() -> Path:
    """Resolve .env relative to this file (repo root)."""
    return Path(__file__).parent.parent / ".env"


def _upsert_env(key: str, value: str) -> None:
    """Write or update a KEY=value line in .env without clobbering other keys."""
    path = _env_path()
    if not path.exists():
        path.write_text("")
    text = path.read_text()
    pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
    new_line = f'{key}="{value}"'
    if pattern.search(text):
        text = pattern.sub(new_line, text)
    else:
        text = text.rstrip("\n") + f"\n{new_line}\n"
    path.write_text(text)


# ── Test Slack ────────────────────────────────────────────────

@app.post("/integrations/test-slack")
def test_slack(req: SlackConfigRequest):
    """
    Send a real test message to the provided Slack webhook.
    Uses the same payload format as the response engine.
    """
    import requests as _requests
    if not req.webhook_url.startswith("https://hooks.slack.com/"):
        raise HTTPException(status_code=400, detail="Invalid Slack webhook URL")

    payload = {
        "attachments": [{
            "color": "#36a64f",
            "title": "🔐 [TEST] Threat Hunter — Connection Verified",
            "text": "Your Slack integration is working correctly. Alerts will appear here when incidents are detected.",
            "fields": [
                {"title": "Source",   "value": "Autonomous Threat Hunter", "short": True},
                {"title": "Severity", "value": "TEST",                      "short": True},
            ],
            "footer": "Autonomous Threat Hunter · test message",
            "ts": int(__import__("time").time()),
        }]
    }
    try:
        r = _requests.post(req.webhook_url, json=payload, timeout=8)
        if r.status_code == 200 and r.text == "ok":
            return {"ok": True, "detail": "Test message delivered to Slack"}
        else:
            raise HTTPException(
                status_code=502,
                detail=f"Slack returned {r.status_code}: {r.text}"
            )
    except _requests.exceptions.ConnectionError:
        raise HTTPException(status_code=502, detail="Could not reach Slack — check network")
    except _requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Slack webhook timed out")


# ── Test Email ────────────────────────────────────────────────

@app.post("/integrations/test-email")
def test_email(req: EmailConfigRequest):
    """
    Send a real test email via SMTP (Gmail app-password or any SMTP).
    Uses the same STARTTLS flow as response_engine.send_email().
    """
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    if not req.smtp_user or not req.smtp_pass or not req.alert_email:
        raise HTTPException(status_code=400, detail="smtp_user, smtp_pass and alert_email are required")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "[TEST] Threat Hunter — Email Alert Verified"
    msg["From"]    = req.smtp_user
    msg["To"]      = req.alert_email

    html = """
    <html><body style="font-family:monospace;background:#0a0a0a;color:#d4d4d4;padding:24px">
    <h2 style="color:#22c55e">✅ Email integration working</h2>
    <p>Your Threat Hunter email alerts are configured correctly.</p>
    <p>Incident reports will be delivered here when the AI agent detects threats.</p>
    <hr style="border-color:#333"/>
    <p style="color:#666;font-size:12px">Autonomous Threat Hunter · test message</p>
    </body></html>
    """
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(req.smtp_host, req.smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(req.smtp_user, req.smtp_pass)
            server.send_message(msg)
        return {"ok": True, "detail": f"Test email sent to {req.alert_email}"}
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(
            status_code=401,
            detail="SMTP authentication failed — for Gmail use an App Password, not your account password"
        )
    except smtplib.SMTPConnectError:
        raise HTTPException(status_code=502, detail=f"Cannot connect to {req.smtp_host}:{req.smtp_port}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Save config to .env ───────────────────────────────────────

@app.post("/integrations/save")
def save_integrations(req: SaveIntegrationsRequest):
    """
    Persist Slack webhook + SMTP config into the .env file so the
    response engine picks them up on next restart (or hot-reload).
    Routing rules are stored as a JSON string under ALERT_ROUTING.
    """
    updates: dict[str, str] = {}

    if req.slack_webhook:
        updates["SLACK_WEBHOOK"] = req.slack_webhook
    if req.smtp_host:
        updates["SMTP_HOST"] = req.smtp_host
    if req.smtp_port:
        updates["SMTP_PORT"] = str(req.smtp_port)
    if req.smtp_user:
        updates["SMTP_USER"] = req.smtp_user
    if req.smtp_pass:
        updates["SMTP_PASS"] = req.smtp_pass
    if req.alert_email:
        updates["ALERT_EMAIL"] = req.alert_email
    if req.routing:
        import json as _json
        updates["ALERT_ROUTING"] = _json.dumps(req.routing)

    try:
        for key, val in updates.items():
            _upsert_env(key, val)
        # Also update os.environ so response_engine picks up changes immediately
        # (without needing a server restart)
        for key, val in updates.items():
            os.environ[key] = val
        return {"ok": True, "updated": list(updates.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write .env: {e}")


# ── Read current config (for pre-filling the form) ───────────

@app.get("/integrations/config")
def get_integrations_config():
    """
    Return current integration config from environment.
    Passwords are masked — never sent in plaintext.
    """
    return {
        "slack_webhook":  os.getenv("SLACK_WEBHOOK", ""),
        "smtp_host":      os.getenv("SMTP_HOST", "smtp.gmail.com"),
        "smtp_port":      int(os.getenv("SMTP_PORT", "587")),
        "smtp_user":      os.getenv("SMTP_USER", ""),
        "smtp_pass_set":  bool(os.getenv("SMTP_PASS", "")),   # true/false only — never expose password
        "alert_email":    os.getenv("ALERT_EMAIL", ""),
        "routing":        __import__("json").loads(os.getenv("ALERT_ROUTING", "{}")),
    }
@app.post("/investigate")
async def investigate_endpoint(req: InvestigateRequest, background_tasks: BackgroundTasks):
    """
    Pull recent events from Elasticsearch, run full pipeline:
    Correlation → MITRE → AI Agent → Sandbox → Response.
    """
    background_tasks.add_task(_run_investigation, req.lookback_minutes, req.user_filter)
    return {
        "status": "Investigation started in background",
        "lookback_minutes": req.lookback_minutes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _run_investigation(lookback_minutes: int, user_filter: Optional[str]):
    """Background task: full pipeline run."""
    try:
        from collector.schema import NormalizedEvent
        from correlation.correlation_engine import CorrelationEngine
        from mitre.mitre_mapper import MITREMapper
        from agent.ai_agent import investigate
        from sandbox.sandbox import SandboxChecker
        from response.response_engine import ResponseEngine

        es = get_es()
        engine = CorrelationEngine(window_minutes=lookback_minutes)
        mapper = MITREMapper()
        sandbox = SandboxChecker()
        response = ResponseEngine()

        # Pull events from ES
        since = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": since}}},
                    ]
                }
            },
            "size": 500,
        }
        if user_filter:
            query["query"]["bool"]["filter"].append({"term": {"user": user_filter}})

        raw = es.search(index="security-*", body=query)
        hits = raw["hits"]["hits"]
        log.info(f"[API] Found {len(hits)} raw events in ES")

        events = []
        for hit in hits:
            try:
                events.append(_adapt_logstash_doc(hit["_source"]))
            except Exception as e:
                log.debug(f"[API] Skipping doc {hit.get('_id')}: {e}")

        events = [e for e in events if e is not None]
        log.info(f"[API] {len(events)} events mapped to NormalizedEvent")

        if not events:
            log.info("[API] No events in window — nothing to investigate")
            return

        # Correlate
        sec_events = engine.correlate(events)
        if not sec_events:
            log.info("[API] No events exceeded thresholds")
            return

        # MITRE map
        mapped = mapper.map_events(sec_events)
        chain = mapper.build_attack_chain(mapped)

        # Sandbox: check IPs
        all_ips = list({step["source_ip"] for step in chain if step.get("source_ip")})
        sb_results = sandbox.enrich_attack_chain(chain, all_ips)

        # AI investigation
        conclusion = investigate(chain)

        # Boost confidence if VT found malicious IPs
        if sb_results["confidence_boost"] > 0:
            old = conclusion.get("confidence", 0.5)
            conclusion["confidence"] = min(old + sb_results["confidence_boost"], 1.0)
            log.info(f"[API] Confidence boosted by sandbox: {old:.2f} → {conclusion['confidence']:.2f}")

        # Response
        iam_user = next((step["user"] for step in chain if "aws" in step.get("environment", [])), None)
        report = response.respond(conclusion, chain, sb_results, compromised_iam_user=iam_user)

        log.info(f"[API] Investigation complete → {report['incident_id']}")

    except Exception as e:
        log.error(f"[API] Investigation failed: {e}", exc_info=True)


@app.get("/incidents")
def list_incidents(limit: int = 50, status: Optional[str] = None):
    """List all incidents from the database."""
    try:
        conn = get_db()
        if status:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status=? ORDER BY timestamp DESC LIMIT ?",
                (status, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        conn.close()

        columns = ["incident_id", "timestamp", "severity", "is_attack", "user",
                   "environments", "cross_env", "summary", "actions", "status", "conclusion", "chain"]
        incidents = []
        for row in rows:
            d = dict(zip(columns, row))
            for field in ("environments", "actions", "conclusion", "chain"):
                if d.get(field):
                    try:
                        d[field] = json.loads(d[field])
                    except Exception:
                        pass
            incidents.append(d)
        return {"incidents": incidents, "count": len(incidents)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    """Get full details of a specific incident."""
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

        columns = ["incident_id", "timestamp", "severity", "is_attack", "user",
                   "environments", "cross_env", "summary", "actions", "status", "conclusion", "chain"]
        d = dict(zip(columns, row))
        for field in ("environments", "actions", "conclusion", "chain"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    pass
        return d
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/incidents/{incident_id}/close")
def close_incident(incident_id: str):
    """Mark an incident as closed and re-index it in the RAG store."""
    conn = get_db()
    conn.execute("UPDATE incidents SET status='closed' WHERE incident_id=?", (incident_id,))
    conn.commit()

    # Re-index with closed status so future RAG queries see it as a resolved reference
    try:
        row = conn.execute(
            "SELECT summary, conclusion FROM incidents WHERE incident_id=?",
            (incident_id,)
        ).fetchone()
        conn.close()
        if row:
            summary, conclusion_json = row
            conclusion = json.loads(conclusion_json) if conclusion_json else {}
            conclusion["status"] = "closed"
            from agent.rag import RAGRetriever
            RAGRetriever().index_incident(incident_id, summary or "", conclusion)
    except Exception as e:
        log.warning(f"[API] RAG re-index on close failed: {e}")
        conn.close()

    return {"incident_id": incident_id, "status": "closed"}


@app.post("/sandbox/check")
def sandbox_check(req: SandboxCheckRequest):
    """Check a hash, IP, or URL via VirusTotal."""
    from sandbox.sandbox import SandboxChecker
    checker = SandboxChecker()
    if req.type == "ip":
        return checker.check_ip(req.value)
    elif req.type == "hash":
        return checker.check_hash(req.value)
    elif req.type == "url":
        return checker.check_url(req.value)
    else:
        raise HTTPException(status_code=400, detail="type must be 'ip', 'hash', or 'url'")


@app.get("/stats")
def stats():
    """Dashboard stats: incident counts by severity."""
    try:
        conn = get_db()
        rows = conn.execute("""
            SELECT severity, COUNT(*) as count
            FROM incidents GROUP BY severity
        """).fetchall()
        cross = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE cross_env=1"
        ).fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        conn.close()
        return {
            "total": total,
            "by_severity": dict(rows),
            "cross_environment": cross,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
