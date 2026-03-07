"""
load_scenarios_to_rag.py — Load saved Stratus Red Team scenario files into
ChromaDB so the AI Agent's RAG has real attack log context.

Usage:
    python scripts/load_scenarios_to_rag.py               # Load all scenarios
    python scripts/load_scenarios_to_rag.py T1562.008     # Load one technique
"""

import os
import sys
import json
import logging
import glob

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.rag import RAGRetriever

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("scenario_loader")


def format_event_for_embedding(event: dict) -> str:
    """Convert a NormalizedEvent dict into a text document for ChromaDB."""
    parts = []
    parts.append(f"event_type: {event.get('event_type', 'unknown')}")
    parts.append(f"environment: {event.get('environment', 'unknown')}")
    parts.append(f"source_service: {event.get('source_service', 'unknown')}")
    if event.get("src_ip"):    parts.append(f"src_ip: {event['src_ip']}")
    if event.get("user"):      parts.append(f"user: {event['user']}")
    if event.get("dst_host"):  parts.append(f"dst_host: {event['dst_host']}")
    if event.get("raw"):
        raw = event["raw"] if isinstance(event["raw"], str) else json.dumps(event["raw"])
        parts.append(f"raw: {raw[:500]}")  # cap at 500 chars per event
    return "\n".join(parts)


def load_scenarios(technique_filter: str = None):
    rag = RAGRetriever()
    client = rag._get_client()

    col = client.get_or_create_collection(
        name="attack_samples",
        embedding_function=rag._ef,
        metadata={"hnsw:space": "cosine"}
    )

    pattern = "data/scenarios/stratus_*.json"
    files = glob.glob(pattern)
    if not files:
        log.error("No scenario files found. Run a Stratus attack first, then use save_scenario.py")
        return

    total_indexed = 0

    for filepath in files:
        with open(filepath, "r", encoding="utf-8") as f:
            scenario = json.load(f)

        technique_id = scenario.get("technique_id", "unknown")
        if technique_filter and technique_id != technique_filter:
            continue

        events = scenario.get("events", [])
        label = scenario.get("technique_label", technique_id)
        source = scenario.get("source", "stratus")
        log.info(f"Loading {len(events)} events for {technique_id} ({label})...")

        batch_docs, batch_ids, batch_meta = [], [], []

        for i, event in enumerate(events):
            doc_text = (
                f"Technique: {technique_id} — {label}\n"
                f"Source: {source}\n"
                f"{format_event_for_embedding(event)}"
            )
            doc_id = f"{technique_id.replace('.', '_')}_{i}"

            # Use upsert so re-running is idempotent
            batch_docs.append(doc_text)
            batch_ids.append(doc_id)
            batch_meta.append({"technique": technique_id, "source": source})

        if batch_docs:
            col.upsert(ids=batch_ids, documents=batch_docs, metadatas=batch_meta)
            total_indexed += len(batch_docs)

    log.info(f"Done. Total indexed into ChromaDB 'attack_samples': {total_indexed} events")
    log.info(f"Total collection size: {col.count()} documents")


if __name__ == "__main__":
    technique_filter = sys.argv[1] if len(sys.argv) > 1 else None
    load_scenarios(technique_filter)
