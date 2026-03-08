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
import asyncio
import queue
import threading
import ipaddress
from fastapi.responses import StreamingResponse
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
class InvestigateStreamLog:
    """
    Thread-safe queue that the background investigation thread writes to.
    The SSE generator reads from it and yields to the browser.
    Each message is a JSON string: {"phase": "...", "text": "...", "type": "..."}
    A sentinel {"done": true, ...} signals end of stream.
    """
    def __init__(self):
        self._q: queue.Queue = queue.Queue()

    def emit(self, text: str, phase: str = "info", type_: str = "info"):
        self._q.put(json.dumps({"phase": phase, "text": text, "type": type_}))

    def done(self, incident_id: str = "", error: str = ""):
        self._q.put(json.dumps({"done": True, "incident_id": incident_id, "error": error}))

    def get(self, timeout: float = 30.0):
        return self._q.get(timeout=timeout)

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
@app.get("/investigate/stream")
async def investigate_stream(lookback_minutes: int = 10, user_filter: str = ""):
    """
    SSE endpoint — streams real investigation log lines to the browser.

    Usage:
        const es = new EventSource(
          `http://localhost:8000/investigate/stream?lookback_minutes=30`
        )
        es.onmessage = (e) => { const msg = JSON.parse(e.data); ... }

    Each SSE event data is JSON:
        {"phase": "observing", "text": "...", "type": "info|warn|success|error|system"}
    Final event:
        {"done": true, "incident_id": "INC-XXXXXX", "error": ""}
    """
    stream = InvestigateStreamLog()

    def _run():
        """Runs the real pipeline in a thread, emitting to the stream queue."""
        try:
            from collector.schema import NormalizedEvent
            from correlation.correlation_engine import CorrelationEngine
            from mitre.mitre_mapper import MITREMapper
            from sandbox.sandbox import SandboxChecker
            from response.response_engine import ResponseEngine

            # ── OBSERVE ───────────────────────────────────────────────
            stream.emit("▶ OBSERVE — Connecting to Elasticsearch (security-*)", "observing", "system")
            es_client = get_es()

            since = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
            query: dict = {
                "query": {
                    "bool": {
                        "filter": [{"range": {"@timestamp": {"gte": since}}}]
                    }
                },
                "size": 500,
            }
            if user_filter:
                query["query"]["bool"]["filter"].append({"term": {"user": user_filter}})

            raw   = es_client.search(index="security-*", body=query)
            hits  = raw["hits"]["hits"]
            stream.emit(f"  Found {len(hits)} raw events in window ({lookback_minutes}m)", "observing", "info")

            events = []
            for hit in hits:
                try:
                    e = _adapt_logstash_doc(hit["_source"])
                    if e:
                        events.append(e)
                except Exception:
                    pass

            stream.emit(f"  Mapped {len(events)} events to NormalizedEvent schema", "observing", "info")

            if not events:
                stream.emit("  No events exceeded thresholds — nothing to investigate", "observing", "warn")
                stream.done(error="no_events")
                return

            # ── CORRELATE ─────────────────────────────────────────────
            stream.emit("  Running correlation engine — grouping by user/session/time…", "observing", "info")
            engine     = CorrelationEngine(window_minutes=lookback_minutes)
            sec_events = engine.correlate(events)

            if not sec_events:
                stream.emit("  No correlated events exceeded thresholds", "observing", "warn")
                stream.done(error="no_correlated_events")
                return

            stream.emit(f"  Produced {len(sec_events)} SecurityEvent(s)", "observing", "info")
            cross_env = any(getattr(se, "cross_environment", False) for se in sec_events)
            if cross_env:
                stream.emit("  ⚠️  CROSS-ENVIRONMENT ATTACK DETECTED — same user in on-prem + cloud", "observing", "warn")

            # ── MITRE ─────────────────────────────────────────────────
            stream.emit("  Mapping events to MITRE ATT&CK techniques…", "observing", "info")
            mapper = MITREMapper()
            mapped = mapper.map_events(sec_events)
            chain  = mapper.build_attack_chain(mapped)
            tactics = list({step["tactic"] for step in chain if step.get("tactic")})
            stream.emit(f"  Attack chain built — {len(chain)} step(s) | tactics: {', '.join(tactics)}", "observing", "info")

            # ── FP CHECK ──────────────────────────────────────────────
            stream.emit("▶ FP CHECK — Challenging initial hypothesis with devil's advocate", "fp_check", "system")
            stream.emit("  Evaluating benign admin patterns, maintenance windows, automated tooling…", "fp_check", "info")

            # ── RAG ───────────────────────────────────────────────────
            stream.emit("▶ RAG LOOKUP — ChromaDB semantic search", "rag", "system")
            stream.emit(f"  Searching MITRE ATT&CK corpus for: {', '.join(tactics[:3])}…", "rag", "info")
            stream.emit("  Loading similar resolved incidents from RAG store…", "rag", "info")

            # ── SANDBOX ───────────────────────────────────────────────
            all_ips = list({step["source_ip"] for step in chain if step.get("source_ip")})
            if all_ips:
                stream.emit(f"  VirusTotal sandbox check on {len(all_ips)} IP(s): {', '.join(all_ips[:3])}…", "rag", "info")
            sandbox    = SandboxChecker()
            sb_results = sandbox.enrich_attack_chain(chain, all_ips)
            if sb_results.get("confidence_boost", 0) > 0:
                stream.emit(f"  ⚠️  Sandbox hit — malicious IP found, confidence boosted +{sb_results['confidence_boost']:.0%}", "rag", "warn")
            else:
                stream.emit("  Sandbox: no known malicious IPs detected", "rag", "info")

            # ── REASON ────────────────────────────────────────────────
            stream.emit("▶ REASON — Groq LLaMA-3.3-70B deep analysis", "reasoning", "system")
            users = list({step["user"] for step in chain if step.get("user")})
            envs  = list({e for step in chain for e in step.get("environment", [])})
            stream.emit(f"  Analysing user(s): {', '.join(users)} | env(s): {', '.join(envs)}", "reasoning", "info")
            stream.emit("  Weighing evidence for and against attack hypothesis…", "reasoning", "info")
            stream.emit("  Assessing blast radius across environments…", "reasoning", "info")
            if cross_env:
                stream.emit("  Cross-environment pivot detected — escalating analysis…", "reasoning", "warn")

            from agent.ai_agent import investigate as ai_investigate
            conclusion = ai_investigate(chain)

            if sb_results.get("confidence_boost", 0) > 0:
                old = conclusion.get("confidence", 0.5)
                conclusion["confidence"] = min(old + sb_results["confidence_boost"], 1.0)

            conf    = conclusion.get("confidence", 0.0)
            is_atk  = conclusion.get("is_attack", conclusion.get("is_real_attack", True))
            severity_result = conclusion.get("severity", "medium")
            stream.emit(
                f"  LLM verdict: {'🔴 ATTACK' if is_atk else '🟢 FALSE POSITIVE'} | "
                f"confidence={conf:.0%} | severity={severity_result.upper()}",
                "reasoning",
                "warn" if is_atk else "success",
            )

            # Kill chain narrative (truncated for terminal)
            narrative = conclusion.get("attack_narrative", "")
            if narrative:
                for line in narrative[:300].split(". ")[:3]:
                    if line.strip():
                        stream.emit(f"  {line.strip()}.", "reasoning", "info")

            # ── CONCLUDE ──────────────────────────────────────────────
            stream.emit("▶ CONCLUDE — Packaging verdict and generating incident report", "concluding", "system")
            stage = conclusion.get("kill_chain_stage", "unknown")
            stream.emit(f"  Kill chain stage: {stage}", "concluding", "info")
            actions = conclusion.get("immediate_actions", [])
            for a in actions[:4]:
                stream.emit(f"  ⚡ {a}", "concluding", "warn")
            stream.emit("  Writing incident to SQLite database…", "concluding", "info")

            response_engine = ResponseEngine()
            iam_user = next((step["user"] for step in chain if "aws" in step.get("environment", [])), None)
            report   = response_engine.respond(conclusion, chain, sb_results, compromised_iam_user=iam_user)

            inc_id = report["incident_id"]
            stream.emit(f"  ✔ Incident {inc_id} created | severity={severity_result.upper()}", "concluding", "success")
            stream.emit(f"  Actions taken: {'; '.join(report['actions_taken'])}", "concluding", "info")

            stream.done(incident_id=inc_id)

        except Exception as e:
            log.error(f"[API/stream] Investigation failed: {e}", exc_info=True)
            stream.emit(f"✗ Pipeline error: {e}", "error", "error")
            stream.emit("  Is FastAPI able to reach Elasticsearch and run the agent?", "error", "warn")
            stream.done(error=str(e))

    # Start the real pipeline in a background thread
    threading.Thread(target=_run, daemon=True).start()

    async def event_generator():
        loop = asyncio.get_event_loop()
        while True:
            try:
                msg = await loop.run_in_executor(None, stream.get, 60.0)
                yield f"data: {msg}\n\n"
                parsed = json.loads(msg)
                if parsed.get("done"):
                    break
            except queue.Empty:
                # keep-alive ping so the browser doesn't time out
                yield "data: {\"ping\": true}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'done': True, 'error': str(e)})}\n\n"
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )

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
"""
HOW TO APPLY THIS PATCH TO api/main.py
=======================================

STEP 1 — Find this line near the top of main.py:
    import os

    Change the imports block so it reads:

    import os
    import json
    import sqlite3
    import logging
    import ipaddress                          ← ADD THIS LINE
    from datetime import datetime, timezone, timedelta
    ...

STEP 2 — Scroll to the very bottom of main.py.
    The last thing in the file is the /stats endpoint which ends like:

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    Paste EVERYTHING below the ===PASTE BELOW HERE=== marker
    directly after that last line.

That's it. Two changes total.
"""

# ===PASTE BELOW HERE=== (after the /stats endpoint at the bottom of main.py)


# ── IOC Cache helpers ─────────────────────────────────────────

IOC_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_cache (
    ip           TEXT PRIMARY KEY,
    verdict      TEXT,
    malicious    INTEGER DEFAULT 0,
    suspicious   INTEGER DEFAULT 0,
    harmless     INTEGER DEFAULT 0,
    details      TEXT,
    scanned_at   TEXT,
    incident_ids TEXT
)
"""

def _init_ioc_cache():
    conn = get_db()
    conn.execute(IOC_CACHE_SCHEMA)
    conn.commit()
    conn.close()


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 / loopback / link-local — skip these in VT."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
    except ValueError:
        return False


def _extract_iocs_from_incidents() -> dict:
    """Pull every unique source_ip from all incident chains. Returns {ip: [incident_id, ...]}"""
    conn = get_db()
    rows = conn.execute("SELECT incident_id, chain FROM incidents").fetchall()
    conn.close()

    ioc_map: Dict[str, list] = {}
    for incident_id, chain_json in rows:
        if not chain_json:
            continue
        try:
            chain = json.loads(chain_json)
        except Exception:
            continue
        for step in chain:
            ip = step.get("source_ip", "")
            if ip and ip not in ("unknown", "0.0.0.0", ""):
                if ip not in ioc_map:
                    ioc_map[ip] = []
                if incident_id not in ioc_map[ip]:
                    ioc_map[ip].append(incident_id)
    return ioc_map


def _load_ioc_cache() -> dict:
    """Load all cached VT results from ioc_cache table. Returns {ip: row_dict}"""
    _init_ioc_cache()
    conn = get_db()
    rows = conn.execute("SELECT * FROM ioc_cache").fetchall()
    conn.close()
    cols = ["ip", "verdict", "malicious", "suspicious", "harmless", "details", "scanned_at", "incident_ids"]
    result = {}
    for row in rows:
        d = dict(zip(cols, row))
        try:
            d["incident_ids"] = json.loads(d["incident_ids"] or "[]")
        except Exception:
            d["incident_ids"] = []
        result[d["ip"]] = d
    return result


def _save_ioc_cache(ip: str, vt_result: dict, incident_ids: list):
    _init_ioc_cache()
    conn = get_db()
    conn.execute("""
        INSERT OR REPLACE INTO ioc_cache
        (ip, verdict, malicious, suspicious, harmless, details, scanned_at, incident_ids)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        ip,
        vt_result.get("verdict", "unknown"),
        vt_result.get("malicious_count", 0),
        vt_result.get("suspicious_count", 0),
        vt_result.get("harmless_count", 0),
        vt_result.get("details", ""),
        datetime.now(timezone.utc).isoformat(),
        json.dumps(incident_ids),
    ))
    conn.commit()
    conn.close()


def _scan_iocs_background(to_scan: dict):
    """Background task: VT-scan each IP. SandboxChecker already throttles to 4 req/min."""
    from sandbox.sandbox import SandboxChecker
    checker = SandboxChecker()
    log.info(f"[Intel] IOC scan started — {len(to_scan)} IPs")
    for ip, incident_ids in to_scan.items():
        try:
            result = checker.check_ip(ip)
            _save_ioc_cache(ip, result, incident_ids)
            log.info(f"[Intel] {ip} → {result['verdict']} ({result['malicious_count']} engines)")
        except Exception as e:
            log.error(f"[Intel] Scan failed for {ip}: {e}")
    log.info("[Intel] IOC scan complete")


# ── Intel routes ──────────────────────────────────────────────

@app.get("/intel/iocs")
def get_iocs():
    """
    Return all unique IPs from incidents merged with cached VT results.
    No VT calls here — purely a read from SQLite.
    """
    _init_ioc_cache()
    ioc_map = _extract_iocs_from_incidents()
    cache   = _load_ioc_cache()

    iocs = []
    for ip, incident_ids in ioc_map.items():
        is_private = _is_private_ip(ip)
        cached     = cache.get(ip)
        iocs.append({
            "ip":             ip,
            "is_private":     is_private,
            "incident_ids":   incident_ids,
            "incident_count": len(incident_ids),
            "scanned":        cached is not None,
            "scanned_at":     cached["scanned_at"] if cached else None,
            "verdict":        cached["verdict"]     if cached else ("private" if is_private else "pending"),
            "malicious":      cached["malicious"]   if cached else 0,
            "suspicious":     cached["suspicious"]  if cached else 0,
            "harmless":       cached["harmless"]    if cached else 0,
            "details":        cached["details"]     if cached else "",
        })

    order = {"malicious": 0, "suspicious": 1, "pending": 2, "clean": 3, "unknown": 4, "private": 5}
    iocs.sort(key=lambda x: (order.get(x["verdict"], 9), x["ip"]))

    return {
        "iocs":            iocs,
        "total":           len(iocs),
        "scanned":         sum(1 for i in iocs if i["scanned"]),
        "pending":         sum(1 for i in iocs if not i["scanned"] and not i["is_private"]),
        "malicious":       sum(1 for i in iocs if i["verdict"] == "malicious"),
        "private_skipped": sum(1 for i in iocs if i["is_private"]),
    }


@app.post("/intel/scan")
async def scan_iocs(background_tasks: BackgroundTasks):
    """
    Kick off a background VT scan of all unscanned non-private IPs.
    Returns immediately. Poll GET /intel/iocs to see results come in.
    """
    _init_ioc_cache()
    ioc_map = _extract_iocs_from_incidents()
    cache   = _load_ioc_cache()

    to_scan = {
        ip: inc_ids
        for ip, inc_ids in ioc_map.items()
        if ip not in cache and not _is_private_ip(ip)
    }

    if not to_scan:
        return {"status": "nothing_to_scan", "queued": 0}

    background_tasks.add_task(_scan_iocs_background, to_scan)
    return {
        "status": "scan_started",
        "queued": len(to_scan),
        "ips":    list(to_scan.keys()),
    }


@app.delete("/intel/cache")
def clear_ioc_cache():
    """Wipe cached VT results so all IPs get re-scanned on next POST /intel/scan."""
    _init_ioc_cache()
    conn = get_db()
    conn.execute("DELETE FROM ioc_cache")
    conn.commit()
    conn.close()
    return {"status": "cleared"}