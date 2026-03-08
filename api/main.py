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
        print(f"[DEBUG] Found {len(hits)} raw documents in ES since {since}")

        events = []
        for hit in hits:
            try:
                ev = _adapt_logstash_doc(hit["_source"])
                if ev:
                    events.append(ev)
            except Exception as e:
                log.debug(f"[API] Skipping doc {hit.get('_id')}: {e}")

        print(f"[DEBUG] Adapted {len(events)} events to NormalizedEvent")
        if events:
            print(f"[DEBUG] First event type: {events[0].event_type}, user: {events[0].user}, ts: {events[0].timestamp}")

        if not events:
            log.info("[API] No events in window — nothing to investigate")
            return

        # Correlate
        sec_events = engine.correlate(events)
        print(f"[DEBUG] Correlated into {len(sec_events)} SecurityEvents")
        if not sec_events:
            log.info("[API] No events exceeded thresholds")
            return

        # MITRE map
        mapped = mapper.map_events(sec_events)
        chain = mapper.build_attack_chain(mapped)
        print(f"[DEBUG] Built attack chain with {len(chain)} steps")

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
            if "severity" in d:
                d["severity"] = d["severity"].lower()
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
        if "severity" in d:
            d["severity"] = d["severity"].lower()
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
        normalized_severity = {}
        for sev, count in rows:
            normalized_severity[sev.lower()] = normalized_severity.get(sev.lower(), 0) + count

        return {
            "total": total,
            "by_severity": normalized_severity,
            "cross_environment": cross,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


CALDERA_URL = "http://localhost:8888"
CALDERA_HEADERS = {"KEY": "9yhqWNFrVcnhUE9k37GCZ_wEPQnW4L1ppmiEP7-puf8", "Content_Type": "application/json"}

@app.get("/caldera/operations")
def get_caldera_operations():
    """Proxy live operations from Caldera (Legacy)."""
    try:
        import requests
        import base64
        resp = requests.get(f"{CALDERA_URL}/api/v2/operations", headers=CALDERA_HEADERS, timeout=5)
        if resp.status_code != 200:
            return {"active": False, "chain": []}
            
        ops = resp.json()
        active_op = next((o for o in ops if o.get("state") == "running"), None)
        if not active_op:
            return {"active": False, "chain": []}

        # Fetch detailed chain for the active operation
        op_id = active_op["id"]
        chain_resp = requests.get(f"{CALDERA_URL}/api/v2/operations/{op_id}/links", headers=CALDERA_HEADERS, timeout=5)
        links = chain_resp.json()
        
        chain = []
        for link in links:
            try:
                cmd = base64.b64decode(link.get("command", "")).decode("utf-8") if link.get("command") else ""
            except Exception:
                cmd = link.get("command", "")
            
            chain.append({
                "id": link.get("id"),
                "technique_id": link.get("ability", {}).get("technique_id"),
                "status": "Success" if link.get("status") == 0 else "Failed" if link.get("status") > 0 else "Running/Timeout",
                "command": cmd,
                "finish": link.get("finish", "Pending...")
            })

        return {"active": True, "name": active_op.get("name"), "chain": chain}
    except Exception:
        return {"active": False, "chain": []}

@app.get("/attack/logs")
def get_attack_logs():
    """Reads the raw Metasploit attack log directly from the sandbox directory."""
    log_path = os.path.join("sandbox", "metasploit", "attack.log")
    if not os.path.exists(log_path):
        return {"logs": "Dashboard: Waiting for attack to start..."}
    
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            # Filter out noisy Ruby/Gem deprecation warnings
            filtered = [l for l in lines if "Gem::Platform.match" not in l and "deprecated" not in l]
            content = "".join(filtered)
            # Return last 5000 characters to prevent UI lag
            return {"logs": content[-5000:]}
    except Exception as e:
        return {"logs": f"Error reading logs: {str(e)}"}

