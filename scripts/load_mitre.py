"""
load_mitre.py — Parse the official MITRE ATT&CK STIX dataset and embed
ONLY the 15 techniques we actively map in mitre_mapper.py into ChromaDB.

This replaces the hardcoded MITRE_KB dictionary in rag.py with real,
authoritative MITRE definitions including detection guidance and examples.

Usage:
    # First download the data (once):
    # Invoke-WebRequest -Uri https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -OutFile data/mitre_attack.json

    python scripts/load_mitre.py
"""

import json
import os
import sys
import logging
import uuid

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.rag import RAGRetriever

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("load_mitre")

# Exactly the techniques we map in mitre_mapper.py
TARGET_TECHNIQUE_IDS = {
    "T1110",     # Brute Force
    "T1078",     # Valid Accounts
    "T1552",     # Unsecured Credentials
    "T1021.002", # Remote Services: SMB/Windows Admin Shares
    "T1059",     # Command and Scripting Interpreter
    "T1041",     # Exfiltration Over C2 Channel
    "T1046",     # Network Service Discovery
    "T1078.004", # Valid Accounts: Cloud Accounts
    "T1098.001", # Account Manipulation: Additional Cloud Credentials
    "T1530",     # Data from Cloud Storage
    "T1496",     # Resource Hijacking
    "T1562.008", # Impair Defenses: Disable Cloud Logs
    "T1526",     # Cloud Service Discovery
}

DATA_FILE = "data/mitre_attack.json"


def extract_technique_id(stix_object: dict) -> str | None:
    """Extract the ATT&CK technique ID (e.g., T1110) from a STIX object."""
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def format_technique_doc(obj: dict, technique_id: str) -> str:
    """
    Format a STIX attack-pattern into a rich text document for embedding.
    Includes name, description, detection guidance, and data sources.
    """
    name = obj.get("name", "Unknown")
    description = obj.get("description", "No description available.")
    detection = obj.get("x_mitre_detection", "No specific detection guidance.")
    platforms = ", ".join(obj.get("x_mitre_platforms", []))
    data_sources = ", ".join(obj.get("x_mitre_data_sources", []))
    
    # Keep it focused — cap description at 600 chars and detection at 400 chars
    # to avoid embedding noise from long prose
    description = description[:600] + "..." if len(description) > 600 else description
    detection = detection[:400] + "..." if len(detection) > 400 else detection

    doc = (
        f"MITRE ATT&CK Technique: {technique_id} — {name}\n"
        f"Platforms: {platforms}\n\n"
        f"Description:\n{description}\n\n"
        f"Detection Guidance:\n{detection}\n\n"
        f"Data Sources: {data_sources}"
    )
    return doc


def load_mitre():
    if not os.path.exists(DATA_FILE):
        log.error(f"MITRE STIX file not found at {DATA_FILE}")
        log.error("Download it first:")
        log.error("  Invoke-WebRequest -Uri https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -OutFile data/mitre_attack.json")
        return

    log.info(f"Loading MITRE STIX data from {DATA_FILE}...")
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        stix_bundle = json.load(f)

    all_objects = stix_bundle.get("objects", [])
    log.info(f"Total STIX objects in bundle: {len(all_objects)}")

    # Filter to only attack-pattern objects (technique definitions)
    techniques = [o for o in all_objects if o.get("type") == "attack-pattern" and not o.get("revoked")]
    log.info(f"Total active attack-patterns: {len(techniques)}")

    rag = RAGRetriever()
    client = rag._get_client()
    col = client.get_or_create_collection(
        name="mitre_techniques",
        embedding_function=rag._ef,
        metadata={"hnsw:space": "cosine"}
    )

    found_ids = set()
    docs, ids, metas = [], [], []

    for obj in techniques:
        technique_id = extract_technique_id(obj)
        if not technique_id:
            continue

        # Check against our target set
        if technique_id not in TARGET_TECHNIQUE_IDS:
            continue

        found_ids.add(technique_id)
        doc_text = format_technique_doc(obj, technique_id)

        docs.append(doc_text)
        ids.append(f"mitre_{technique_id.replace('.', '_')}")
        metas.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "source": "mitre_attack_stix",
            "tactic": obj.get("kill_chain_phases", [{}])[0].get("phase_name", "unknown")
        })
        log.info(f"  ✓ Found {technique_id}: {obj.get('name')}")

    if docs:
        col.upsert(ids=ids, documents=docs, metadatas=metas)
        log.info(f"\nSuccessfully loaded {len(docs)} MITRE techniques into ChromaDB 'mitre_techniques' collection.")

    # Report any missing techniques
    missing = TARGET_TECHNIQUE_IDS - found_ids
    if missing:
        log.warning(f"\nWarning: These technique IDs were not found in the STIX bundle:")
        for m in sorted(missing):
            log.warning(f"  - {m}")


if __name__ == "__main__":
    load_mitre()
