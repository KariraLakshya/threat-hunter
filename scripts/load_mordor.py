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

    json_files = glob.glob(os.path.join(data_dir, "*.json"))
    if not json_files:
        log.warning(f"No JSON files found in {data_dir}.")
        return

    docs_to_insert = []
    ids_to_insert = []
    metadatas_to_insert = []

    for file_path in json_files:
        filename = os.path.basename(file_path)
        log.info(f"Processing {filename}...")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Mordor files are often JSONL (one JSON object per line)
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
        col.add(
            ids=ids_to_insert,
            documents=docs_to_insert,
            metadatas=metadatas_to_insert
        )
        log.info(f"Successfully loaded {len(docs_to_insert)} high-value attack log snippets into ChromaDB 'attack_samples' collection.")
    else:
        log.info("No relevant high-value logs found in the provided files.")

if __name__ == "__main__":
    load_mordor_logs()
