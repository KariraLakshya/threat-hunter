import asyncio
import json

from api.main import _run_investigation
from correlation.correlation_engine import CorrelationEngine
from mitre.mitre_mapper import MITREMapper
from agent.ai_agent import investigate
from sandbox.sandbox import SandboxChecker
from response.response_engine import ResponseEngine
from api.main import get_es, _adapt_logstash_doc
from datetime import datetime, timezone, timedelta
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("test")

def run():
    lookback_minutes = 30
    log.info(f"Running investigation with lookback={lookback_minutes}m")
    
    es = get_es()
    engine = CorrelationEngine(window_minutes=lookback_minutes)
    mapper = MITREMapper()
    sandbox = SandboxChecker()
    response = ResponseEngine()

    since = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
    query = {"query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": since}}}]}}, "size": 500}

    raw = es.search(index="security-*", body=query)
    hits = raw["hits"]["hits"]
    log.info(f"Found {len(hits)} raw events")

    events = []
    for hit in hits:
        ev = _adapt_logstash_doc(hit["_source"])
        if ev: events.append(ev)
        
    log.info(f"Mapped {len(events)} events")

    if not events:
        log.info("No events")
        return

    sec_events = engine.correlate(events)
    if not sec_events:
        log.info("No correlated events exceeded thresholds")
        return

    mapped = mapper.map_events(sec_events)
    chain = mapper.build_attack_chain(mapped)
    
    all_ips = list({step["source_ip"] for step in chain if step.get("source_ip")})
    sb_results = sandbox.enrich_attack_chain(chain, all_ips)

    # ── AI Investigation (Tests RAG accuracy) ──
    conclusion = investigate(chain)
    
    if sb_results["confidence_boost"] > 0:
        conclusion["confidence"] = min(conclusion.get("confidence", 0.5) + sb_results["confidence_boost"], 1.0)

    iam_user = next((step["user"] for step in chain if "aws" in step.get("environment", [])), None)
    
    print("\n" + "="*80)
    print("🤖 RAG AGENT INVESTIGATION COMPLETE")
    print("="*80)
    print(f"Is Attack: {conclusion.get('is_attack')} (Confidence: {conclusion.get('confidence')})")
    print(f"Severity: {conclusion.get('severity')}")
    print(f"\nNarrative:\n{conclusion.get('attack_narrative')}")
    print(f"\nImmediate Actions:\n * " + "\n * ".join(conclusion.get('immediate_actions', [])))
    print("="*80 + "\n")

if __name__ == "__main__":
    run()
