"""
rag.py — RAG (Retrieval-Augmented Generation) for the AI Agent

Provides two retrievers:
  1. MITRERetriever   — semantic search over MITRE ATT&CK technique descriptions
  2. IncidentRetriever — semantic search over past incident summaries from SQLite

Both use ChromaDB (local, no server) + sentence-transformers embeddings (free, offline).
Results are injected into the Reason prompt's `mitre_context` and `past_incidents` fields.

Usage:
    rag = RAGRetriever()
    mitre_ctx  = rag.get_mitre_context(["Brute Force", "Lateral Movement"])
    past_incs  = rag.get_past_incidents("brute force credential theft aws")
"""

import os
import json
import logging
import sqlite3
from typing import List, Dict

import chromadb
from chromadb.utils import embedding_functions

log = logging.getLogger("rag")

DB_PATH = os.getenv("INCIDENTS_DB", "incidents/incidents.db")
CHROMA_PATH = os.getenv("CHROMA_PATH", "incidents/chroma_db")

# Use a small, fast, offline embedding model
EMBED_MODEL = "all-MiniLM-L6-v2"


# ── MITRE ATT&CK Knowledge Base ───────────────────────────────
# Curated descriptions of the most common techniques in this project.
# Each entry: technique_id → {name, tactic, description, indicators, mitigations}

MITRE_KB: List[Dict] = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries attempt to gain access by systematically guessing credentials. "
            "Indicators: many failed logins in short time from same IP, often followed by "
            "a successful login. Typical pattern: 5-50 failures then 1 success."
        ),
        "indicators": "High volume failed logins, single source IP, multiple target accounts",
        "mitigations": "Account lockout policy, MFA, IP allowlisting, rate limiting on auth endpoints",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "description": (
            "Adversaries use stolen or legitimately obtained credentials to gain initial "
            "access. Often follows credential dumping or phishing. The login itself looks "
            "normal — context matters: unusual time, new geolocation, new device."
        ),
        "indicators": "Login from unusual IP/country, login outside business hours, login after brute force",
        "mitigations": "MFA, anomalous login alerting, impossible travel detection",
    },
    {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": (
            "Adversaries search for credentials stored insecurely: bash history, config "
            "files, environment variables, AWS credential files (~/.aws/credentials). "
            "Often executed after initial access to escalate privileges."
        ),
        "indicators": "Access to ~/.ssh/, ~/.aws/credentials, /etc/passwd, .env files",
        "mitigations": "Secrets management (Vault, AWS Secrets Manager), file access monitoring",
    },
    {
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries use valid accounts to interact with remote network shares over SMB. "
            "Common tools: PsExec, WMI. Indicator: SMB connections to non-standard hosts "
            "from a workstation that doesn't normally access servers directly."
        ),
        "indicators": "Unusual SMB traffic, access to ADMIN$, IPC$, C$ shares, PsExec artifacts",
        "mitigations": "Disable SMB where not needed, host firewall rules, privileged access workstations",
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Data is exfiltrated over the existing C2 channel. Indicators: large outbound "
            "transfers to external IPs, especially outside business hours. Often follows "
            "lateral movement and collection phases."
        ),
        "indicators": "Large outbound data transfer, unusual destination IP, data staged before transfer",
        "mitigations": "DLP, egress filtering, anomalous transfer volume alerting",
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Reconnaissance",
        "description": (
            "Adversaries scan for open ports and services to identify targets. Often the "
            "first phase of lateral movement. Indicators: rapid connections to many ports "
            "or many hosts from a single source within a short window."
        ),
        "indicators": "High rate of connection attempts, sequential port probing, ICMP sweeps",
        "mitigations": "Network segmentation, IDS/IPS, port scan detection alerts",
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries abuse command-line interfaces and scripting languages to execute "
            "malicious code. Common: PowerShell, bash, Python. Indicators: unusual parent "
            "process spawning shells, obfuscated commands, base64-encoded payloads."
        ),
        "indicators": "Unusual script execution, base64 encoded commands, living-off-the-land binaries",
        "mitigations": "Script block logging, AMSI, AppLocker, PowerShell constrained mode",
    },
    {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access / Persistence",
        "description": (
            "Adversaries use compromised cloud account credentials (IAM users, service accounts) "
            "to access cloud environments. Often combination with on-prem compromise: "
            "steal credentials on-prem, pivot to cloud. GuardDuty finding: UnauthorizedAccess."
        ),
        "indicators": "Console login from new IP, API calls from unusual region, after on-prem compromise",
        "mitigations": "MFA on all AWS console access, CloudTrail logging, AWS Config rules",
    },
    {
        "id": "T1098.001",
        "name": "Account Manipulation: Additional Cloud Credentials",
        "tactic": "Persistence",
        "description": (
            "Adversaries create additional credentials (access keys) on existing accounts "
            "to maintain persistence. Even if the stolen password is rotated, the key survives. "
            "CloudTrail event: CreateAccessKey for another user."
        ),
        "indicators": "CreateAccessKey API call, especially for other IAM users, outside normal hours",
        "mitigations": "Alert on CreateAccessKey events, enforce key rotation, limit IAM key creation",
    },
    {
        "id": "T1562.008",
        "name": "Impair Defenses: Disable Cloud Logs",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries disable CloudTrail, GuardDuty, or VPC Flow Logs to blind defenders "
            "and cover their tracks. This is a strong indicator of a sophisticated attacker. "
            "CloudTrail events: DeleteTrail, StopLogging, UpdateTrail."
        ),
        "indicators": "DeleteTrail, StopLogging API calls, often as first action after gaining cloud access",
        "mitigations": "CloudTrail log validation, multi-region trails, S3 Object Lock, alert on trail changes",
    },
    {
        "id": "T1530",
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": (
            "Adversaries access S3 buckets, Azure Blob Storage, or GCS to collect data. "
            "Indicators: GetObject calls on sensitive buckets, ListBuckets enumeration, "
            "large volumes of object downloads. Often followed by exfiltration."
        ),
        "indicators": "Bulk S3 GetObject calls, access to buckets not normally accessed, new IAM principal",
        "mitigations": "S3 bucket policies, VPC endpoints, S3 Access Analyzer, Macie for sensitive data",
    },
    {
        "id": "T1496",
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": (
            "Adversaries hijack compute resources for cryptomining or other purposes. "
            "Indicators: unexpected EC2 instance launches (especially GPU types), "
            "high CPU usage, unusual instance types in new regions."
        ),
        "indicators": "RunInstances API for large/GPU instance types, new regions, unusual AMIs",
        "mitigations": "EC2 instance type restrictions via SCP, budget alerts, unused instance detection",
    },
]


def _format_mitre(entry: Dict) -> str:
    """Format a MITRE entry into a single document string for embedding."""
    return (
        f"[{entry['id']}] {entry['name']} | Tactic: {entry['tactic']}\n"
        f"Description: {entry['description']}\n"
        f"Indicators: {entry['indicators']}\n"
        f"Mitigations: {entry['mitigations']}"
    )


class RAGRetriever:
    """
    Unified RAG retriever for both MITRE context and past incidents.

    Lazy-initialises ChromaDB on first use so no startup cost
    if RAG is not called.
    """

    def __init__(self):
        self._client = None
        self._mitre_collection = None
        self._incident_collection = None
        self._ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBED_MODEL
        )

    def _get_client(self) -> chromadb.Client:
        if self._client is None:
            os.makedirs(CHROMA_PATH, exist_ok=True)
            self._client = chromadb.PersistentClient(path=CHROMA_PATH)
        return self._client

    # ── MITRE Collection ──────────────────────────────────────

    def _get_mitre_collection(self):
        if self._mitre_collection is not None:
            return self._mitre_collection

        client = self._get_client()
        col = client.get_or_create_collection(
            name="mitre_techniques",
            embedding_function=self._ef,
            metadata={"hnsw:space": "cosine"},
        )

        # Seed on first run (idempotent — uses IDs)
        if col.count() == 0:
            log.info("[RAG] Seeding MITRE knowledge base into ChromaDB…")
            col.add(
                ids=[e["id"] for e in MITRE_KB],
                documents=[_format_mitre(e) for e in MITRE_KB],
                metadatas=[{"tactic": e["tactic"], "name": e["name"]} for e in MITRE_KB],
            )
            log.info(f"[RAG] Indexed {len(MITRE_KB)} MITRE techniques")

        self._mitre_collection = col
        return col

    def get_mitre_context(self, tactics: List[str], n_results: int = 4) -> str:
        """
        Retrieve the most relevant MITRE technique descriptions for the given tactics.
        Returns a formatted string ready to inject into the Reason prompt.
        """
        if not tactics:
            return "No MITRE context available."

        try:
            col = self._get_mitre_collection()
            query = " ".join(tactics)
            results = col.query(query_texts=[query], n_results=min(n_results, col.count()))
            docs = results.get("documents", [[]])[0]
            if not docs:
                return "No relevant MITRE techniques found."
            return "\n\n---\n".join(docs)
        except Exception as e:
            log.error(f"[RAG] MITRE retrieval failed: {e}")
            return "MITRE context unavailable."

    # ── Incident Collection ───────────────────────────────────

    def _get_incident_collection(self):
        if self._incident_collection is not None:
            return self._incident_collection
        client = self._get_client()
        col = client.get_or_create_collection(
            name="past_incidents",
            embedding_function=self._ef,
            metadata={"hnsw:space": "cosine"},
        )
        self._incident_collection = col
        return col

    def index_incident(self, incident_id: str, summary: str, conclusion: Dict) -> None:
        """
        Index a closed/completed incident into ChromaDB for future RAG retrieval.
        Called by ResponseEngine after saving to SQLite.
        """
        try:
            col = self._get_incident_collection()
            # Build a rich document from the incident
            doc = (
                f"Incident: {incident_id}\n"
                f"Summary: {summary}\n"
                f"Severity: {conclusion.get('severity', 'unknown')}\n"
                f"Attack narrative: {conclusion.get('attack_narrative', '')}\n"
                f"Kill chain: {conclusion.get('kill_chain_stage', '')}\n"
                f"Attacker objective: {conclusion.get('attacker_objective', '')}\n"
                f"Evidence: {'; '.join(conclusion.get('evidence_for_attack', []))}"
            )
            col.upsert(
                ids=[incident_id],
                documents=[doc],
                metadatas={"severity": conclusion.get("severity", "unknown")},
            )
            log.info(f"[RAG] Indexed incident {incident_id}")
        except Exception as e:
            log.error(f"[RAG] Failed to index incident: {e}")

    def index_incidents_from_db(self) -> int:
        """
        Bulk-index all past incidents from SQLite into ChromaDB.
        Run once at startup or as a scheduled job.
        """
        count = 0
        try:
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT incident_id, summary, conclusion FROM incidents"
            ).fetchall()
            conn.close()
            for incident_id, summary, conclusion_json in rows:
                try:
                    conclusion = json.loads(conclusion_json) if conclusion_json else {}
                    self.index_incident(incident_id, summary or "", conclusion)
                    count += 1
                except Exception:
                    pass
        except Exception as e:
            log.error(f"[RAG] DB index failed: {e}")
        log.info(f"[RAG] Bulk-indexed {count} past incidents")
        return count

    def get_past_incidents(self, hypothesis: str, n_results: int = 3) -> str:
        """
        Retrieve similar past incidents to provide as context to the Reason prompt.
        Returns formatted string ready to inject into past_incidents field.
        """
        try:
            col = self._get_incident_collection()
            if col.count() == 0:
                return "No past incidents in knowledge base yet."
            results = col.query(
                query_texts=[hypothesis],
                n_results=min(n_results, col.count()),
            )
            docs = results.get("documents", [[]])[0]
            if not docs:
                return "No similar past incidents found."
            return "\n\n---\n".join(docs)
        except Exception as e:
            log.error(f"[RAG] Incident retrieval failed: {e}")
            return "Past incident context unavailable."
