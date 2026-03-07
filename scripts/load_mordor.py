"""
load_mordor.py — Load targeted Mordor (OTRF) datasets into ChromaDB for RAG.

This script prevents bloat by ONLY loading examples for techniques 
we actively detect in our mitre_mapper.py.

Usage: 
1. Download specific JSON files from OTRF/Security-Datasets
2. Place them in data/mordor/
3. Run: python scripts/load_mordor.py
"""

import os
import json
import glob
import logging
import uuid
import sys

# Ensure we can import from the parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.rag import RAGRetriever

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("mordor_loader")

# We ONLY care about the techniques we actually map in the SOC
TARGET_TECHNIQUES = {
    "T1110", "T1078", "T1552", "T1021.002", "T1059", 
    "T1041", "T1046", "T1078.004", "T1098.001", "T1530", 
    "T1496", "T1562.008", "T1526"
}

def load_mordor_logs(data_dir: str = "data/mordor"):
    if not os.path.exists(data_dir):
        log.error(f"Directory {data_dir} not found. Please create it and add Mordor JSON files.")
        return

    rag = RAGRetriever()
    client = rag._get_client()
    
    # Create a dedicated collection for real attack samples
    col = client.get_or_create_collection(
        name="attack_samples",
        embedding_function=rag._ef,
        metadata={"hnsw:space": "cosine"}
    )

    import zipfile, tempfile

    zip_files = glob.glob(os.path.join(data_dir, "*.zip"))
    json_files = glob.glob(os.path.join(data_dir, "*.json"))
    all_sources = zip_files + json_files

    if not all_sources:
        log.warning(f"No ZIP or JSON files found in {data_dir}.")
        return

    docs_to_insert = []
    ids_to_insert = []
    metadatas_to_insert = []

    seen_hashes = set()  # deduplication
    MAX_PER_FILE = 200   # cap per zip file to avoid bloat from repetitive loops

    def parse_jsonl_lines(lines, filename):
        """Parse JSONL lines from Mordor/Sysmon/WEC format, with deduplication."""
        results = []
        file_count = 0
        for line in lines:
            if not line.strip():
                continue
            if file_count >= MAX_PER_FILE:
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_id = event.get("EventID") or event.get("event_id")
            message  = event.get("Message", "")
            host     = event.get("host", event.get("Hostname", ""))
            utctime  = event.get("UtcTime", "")
            user     = event.get("User", event.get("SubjectUserName", event.get("TargetUserName", "")))
            cmd_line = event.get("CommandLine", event.get("Image", ""))

            if not message and not cmd_line:
                continue
            if len(str(message)) < 10 and not cmd_line:
                continue

            # Deduplicate on the semantic content, not time/host (those differ per run)
            dedup_key = f"{cmd_line}|{str(message)[:200]}"
            key_hash = hash(dedup_key)
            if key_hash in seen_hashes:
                continue
            seen_hashes.add(key_hash)

            doc = f"Source: mordor | File: {filename}\n"
            if host:     doc += f"Host: {host}\n"
            if utctime:  doc += f"Time: {utctime}\n"
            if user:     doc += f"User: {user}\n"
            if cmd_line: doc += f"CommandLine: {cmd_line}\n"
            if message:  doc += f"Message: {str(message)[:400]}\n"

            results.append((doc, {"source": "mordor", "filename": filename}))
            file_count += 1
        return results


    for file_path in all_sources:
        filename = os.path.basename(file_path)
        log.info(f"Processing {filename}...")
        try:
            if file_path.endswith(".zip"):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    for inner_name in zf.namelist():
                        with zf.open(inner_name) as f:
                            lines = f.read().decode("utf-8", errors="replace").splitlines()
                            parsed = parse_jsonl_lines(lines, filename)
                            for doc, meta in parsed:
                                docs_to_insert.append(doc)
                                ids_to_insert.append(str(uuid.uuid4()))
                                metadatas_to_insert.append(meta)
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for line in lines:
                    if not line.strip(): continue
                    event = json.loads(line)
                    
                    # Extract typical Windows Event fields
                    event_id = event.get("EventID")
                    channel = event.get("Channel")
                    event_data = event.get("EventData", {})
                    
                    # Basic noise filtering - only keep high-value Event IDs
                    # 4624/4625 (Logins), 4688 (Process Creation), 5140 (Network Share)
                    if event_id not in [4624, 4625, 4688, 5140, 3]:
                        continue
                        
                    cmd_line = event_data.get("CommandLine", "")
                    user = event_data.get("TargetUserName", "") or event_data.get("SubjectUserName", "")
                    
                    if not cmd_line and not user:
                        continue # Skip empty logs
                        
                    doc_string = f"EventID: {event_id} | Channel: {channel}\n"
                    if user: doc_string += f"User: {user}\n"
                    if cmd_line: doc_string += f"CommandLine: {cmd_line}\n"
                    
                    doc_id = str(uuid.uuid4())
                    
                    docs_to_insert.append(doc_string)
                    ids_to_insert.append(doc_id)
                    metadatas_to_insert.append({"source": "mordor", "filename": filename})
                    
        except Exception as e:
            log.error(f"Failed to parse {filename}: {e}")

    if docs_to_insert:
        BATCH_SIZE = 5000
        total = len(docs_to_insert)
        for i in range(0, total, BATCH_SIZE):
            batch_docs  = docs_to_insert[i:i+BATCH_SIZE]
            batch_ids   = ids_to_insert[i:i+BATCH_SIZE]
            batch_metas = metadatas_to_insert[i:i+BATCH_SIZE]
            col.upsert(ids=batch_ids, documents=batch_docs, metadatas=batch_metas)
            log.info(f"  Upserted batch {i//BATCH_SIZE + 1}: {len(batch_docs)} docs")
        log.info(f"\nSuccessfully loaded {total} Windows attack log snippets into ChromaDB 'attack_samples' collection.")
    else:
        log.info("No relevant high-value logs found in the provided files.")

if __name__ == "__main__":
    load_mordor_logs()
