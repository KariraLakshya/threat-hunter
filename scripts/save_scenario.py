"""
save_scenario.py — After running a Stratus Red Team technique, call this script
to pull the real CloudTrail/GuardDuty events from Elasticsearch and save them
as a named scenario file for later RAG indexing.

Usage:
    stratus-red-team detonate sts.assume-role          # Run the attack
    python scripts/save_scenario.py T1078.004          # Save the real logs
    stratus-red-team cleanup sts.assume-role           # Clean up
"""

import sys
import os
import json
import logging
from datetime import datetime, timezone, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elasticsearch import Elasticsearch
from dotenv import load_dotenv

from mitre.mitre_mapper import FULL_MAP

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("save_scenario")

# Map MITRE technique ID → Stratus technique name (for labeling)
TECHNIQUE_LABEL = {
    "T1078.004": "Valid Accounts: Cloud Accounts (Console Login)",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials (CreateAccessKey)",
    "T1530":     "Data from Cloud Storage (S3 GetObject)",
    "T1496":     "Resource Hijacking (EC2 RunInstances)",
    "T1562.008": "Impair Defenses: Disable Cloud Logs (DeleteTrail)",
    "T1526":     "Cloud Service Discovery (GuardDuty finding)",
}

def save_scenario(technique_id: str, lookback_minutes: int = 15):
    es = Elasticsearch(
        os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200"),
        basic_auth=(os.getenv("ELASTIC_USER", "elastic"), os.getenv("ELASTIC_PASSWORD", "changeme123"))
    )

    # Find which event_types map to this technique
    target_event_types = [
        etype for etype, mapping in FULL_MAP.items()
        if mapping.get("technique") == technique_id
    ]

    if not target_event_types:
        log.error(f"Technique {technique_id} is not mapped in mitre_mapper.py")
        return

    query = {
        "query": {
            "bool": {
                "filter": [
                    {"terms": {"environment": ["aws"]}},
                    {"terms": {"event_type": target_event_types}}
                ]
            }
        },
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    result = es.search(index="security-cloud-*", body=query)
    hits = result["hits"]["hits"]

    if not hits:
        log.error(f"No cloud events found for technique {technique_id} (mapped to {target_event_types}). Did the simulator run?")
        return

    # Build scenario object
    scenario = {
        "technique_id": technique_id,
        "technique_label": TECHNIQUE_LABEL.get(technique_id, technique_id),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source": "aws-api-simulator",
        "event_count": len(hits),
        "events": [hit["_source"] for hit in hits]
    }

    os.makedirs("data/scenarios", exist_ok=True)
    filename = f"data/scenarios/stratus_{technique_id.replace('.', '_')}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(scenario, f, indent=2, default=str)

    log.info(f"Saved {len(hits)} real events to {filename}")
    log.info(f"Now run:  python scripts/load_scenarios_to_rag.py")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/save_scenario.py <TECHNIQUE_ID> [lookback_minutes]")
        print("Example: python scripts/save_scenario.py T1562.008 120")
        sys.exit(1)

    lookback = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    save_scenario(sys.argv[1], lookback)
