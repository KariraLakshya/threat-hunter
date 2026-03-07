"""
load_cloud_rag.py — Load Cloud simulation logs into ChromaDB for RAG context.

Since the Mordor dataset is Windows-only, this script indexes our known
cloud attack scenarios (from Stratus Red Team and GuardDuty sample findings)
so the AI Agent has rich examples of AWS attacks.

Usage:
    python scripts/load_cloud_rag.py
"""

import os
import sys
import logging
import uuid
import json

# Ensure we can import from the parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.rag import RAGRetriever

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cloud_loader")


# Hardcoded examples of the 6 Cloud MITRE techniques we map.
# These match what Stratus Red Team and GuardDuty sample findings look like.
CLOUD_SCENARIOS = [
    {
        "technique": "T1078.004",
        "name": "Cloud Console Login from Unusual IP",
        "source": "CloudTrail",
        "log_sample": json.dumps({
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "jsmith"
            },
            "responseElements": {"ConsoleLogin": "Success"},
            "sourceIPAddress": "45.22.12.9" # Unusual IP
        }, indent=2)
    },
    {
        "technique": "T1098.001",
        "name": "IAM Persistence (CreateAccessKey)",
        "source": "CloudTrail",
        "log_sample": json.dumps({
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "jsmith"},
            "requestParameters": {"userName": "developer-backup"}
        }, indent=2)
    },
    {
        "technique": "T1530",
        "name": "S3 Data Exfiltration",
        "source": "CloudTrail",
        "log_sample": json.dumps({
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "requestParameters": {"bucketName": "company-confidential-data", "key": "customer_db_dump.sql"},
            "userIdentity": {"type": "IAMUser", "userName": "jsmith"}
        }, indent=2)
    },
    {
        "technique": "T1496",
        "name": "Resource Hijacking (EC2 Cryptomining)",
        "source": "CloudTrail",
        "log_sample": json.dumps({
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "requestParameters": {
                "instanceType": "p3.8xlarge", # Expensive GPU instance
                "imageId": "ami-0abcdef1234567890",
                "minCount": 5
            },
            "userIdentity": {"type": "IAMUser", "userName": "jsmith"}
        }, indent=2)
    },
    {
        "technique": "T1562.008",
        "name": "Impair Defenses (Delete CloudTrail)",
        "source": "CloudTrail",
        "log_sample": json.dumps({
            "eventName": "DeleteTrail",
            "eventSource": "cloudtrail.amazonaws.com",
            "requestParameters": {"name": "main-security-trail"},
            "userIdentity": {"type": "IAMUser", "userName": "jsmith"}
        }, indent=2)
    },
    {
        "technique": "T1526",
        "name": "GuardDuty Sample Finding - Discovery",
        "source": "GuardDuty",
        "log_sample": json.dumps({
            "type": "Recon:IAMUser/UserPermissions",
            "severity": 5.0,
            "title": "Principal jsmith is performing reconnaissance",
            "description": "API calls commonly associated with reconnaissance were observed from this principal"
        }, indent=2)
    }
]

def load_cloud_scenarios():
    rag = RAGRetriever()
    client = rag._get_client()
    
    # Use the same collection as Mordor so the AI queries one place
    col = client.get_or_create_collection(
        name="attack_samples",
        embedding_function=rag._ef,
        metadata={"hnsw:space": "cosine"}
    )
    
    docs_to_insert = []
    ids_to_insert = []
    metadatas_to_insert = []
    
    for scenario in CLOUD_SCENARIOS:
        doc_string = (
            f"Technique: {scenario['technique']} - {scenario['name']}\n"
            f"Source: {scenario['source']}\n"
            f"Log Sample:\n{scenario['log_sample']}"
        )
        
        docs_to_insert.append(doc_string)
        ids_to_insert.append(str(uuid.uuid4()))
        metadatas_to_insert.append({
            "source": f"stratus_{scenario['source'].lower()}",
            "technique": scenario["technique"]
        })
        
    col.add(
        ids=ids_to_insert,
        documents=docs_to_insert,
        metadatas=metadatas_to_insert
    )
    
    log.info(f"Successfully loaded {len(CLOUD_SCENARIOS)} AWS Cloud attack scenarios into ChromaDB.")

if __name__ == "__main__":
    load_cloud_scenarios()
