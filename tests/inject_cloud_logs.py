"""
inject_cloud_logs.py — Inject fake cloud events into Elasticsearch for E2E testing

Simulates a cross-environment attack:
    jsmith brute-forces on-prem → pivots to AWS console (same IP) →
    creates IAM key → bulk S3 download → deletes CloudTrail

Run AFTER inject_logs.py so the correlation engine sees both halves:
    python tests/inject_logs.py          # on-prem events
    python tests/inject_cloud_logs.py    # cloud pivot events

Then trigger the investigation as normal.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from collector.cloud_simulator import make_cross_env_cloud_chain

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme123")


def main():
    es = Elasticsearch(
        ES_HOST,
        basic_auth=("elastic", ELASTIC_PASSWORD),
        verify_certs=False,
    )

    # Verify connection
    try:
        health = es.cluster.health()
        print(f"\n[✓] Connected to Elasticsearch (status: {health['status']})")
    except Exception as e:
        print(f"\n[✗] Cannot connect to Elasticsearch: {e}")
        sys.exit(1)

    # Generate the cloud attack chain
    events = make_cross_env_cloud_chain(
        user="jsmith",
        attacker_ip="203.0.113.42",   # same IP as inject_logs.py — ties them together
        start_offset=300,              # 5 min after on-prem events
    )

    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"security-cloud-{today}"

    print(f"\n{'=' * 60}")
    print(f"  Threat Hunter — Cloud Event Injector")
    print(f"  Target index: {index_name}")
    print(f"  Events:       {len(events)}")
    print(f"{'=' * 60}\n")

    SEVERITY_ICONS = {
        "low": "🟢",
        "medium": "🟡",
        "high": "🟠",
        "critical": "🔴",
    }

    success_count = 0
    for i, event in enumerate(events, 1):
        doc = event.to_dict()
        # Add @timestamp for Kibana
        doc["@timestamp"] = doc["timestamp"]
        try:
            es.index(index=index_name, id=event.event_id, document=doc)
            icon = SEVERITY_ICONS.get(event.severity, "⚪")
            print(f"  [{i:02d}/{len(events)}] {icon} {event.event_type:<35} | {event.user:<10} | {event.source_ip} | {event.environment}")
            success_count += 1
        except Exception as e:
            print(f"  [{i:02d}/{len(events)}] ✗ Failed: {e}")

    print(f"\n[✓] {success_count}/{len(events)} cloud events indexed to {index_name}")
    print(f"\n[→] Now trigger investigation:")
    print(f"    Invoke-RestMethod -Method POST -Uri \"http://localhost:8000/investigate\"")
    print(f"        -ContentType \"application/json\" -Body '{{\"lookback_minutes\": 30}}'")
    print(f"\n[→] Expected: cross_environment=true, severity=critical, 5+ step chain\n")


if __name__ == "__main__":
    main()
