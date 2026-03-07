# Autonomous Security Threat Hunter

An AI-powered SOC platform that ingests logs from on-premise and cloud environments, correlates suspicious events, maps them to the MITRE ATT&CK framework, and uses an LLM agent to autonomously investigate and conclude whether an attack is real.

---

## How It Works — End-to-End Flow

```
On-Prem Logs              Cloud Logs (AWS)
(Syslog/Logstash)         (CloudTrail / GuardDuty)
        |                          |
        v                          v
  [Logstash]             [aws_collector.py]
        |                          |
        +----------+---------------+
                   |
                   v
          [Elasticsearch]
          security-onprem-*
          security-cloud-*
                   |
                   v
        [api/main.py — FastAPI]
          /investigate endpoint
                   |
                   v
      [correlation_engine.py]
      Groups events into attack chains
      Detects cross-environment pivots
                   |
                   v
        [mitre_mapper.py]
        Maps each step to MITRE
        ATT&CK tactics + techniques
                   |
                   v
          [agent/ai_agent.py]
          LangGraph state machine:
          Observe → Reason → Conclude
          (with RAG context + FP check)
                   |
                   v
          [sandbox/sandbox.py]
          VirusTotal IP/hash/URL check
          Boosts AI confidence score
                   |
                   v
        [response/response_engine.py]
        Saves incident to SQLite
        Sends Slack / email alert
```

---

## File-by-File Explanation

### Infrastructure

| File | What it does |
|------|-------------|
| `docker-compose.yml` | Starts the full stack: Elasticsearch, Logstash, Wazuh, Suricata, Redis |
| `logstash/pipeline/security.conf` | Logstash pipeline — receives syslog on port 5000, parses with grok, tags event types, sends to ES |
| `requirements.txt` | All Python dependencies |
| `.env` | API keys and config (never committed to git) |

---

### Phase 1–2: Log Collection

| File | What it does |
|------|-------------|
| `collector/schema.py` | Defines `NormalizedEvent` — the universal event schema shared by all collectors |
| `collector/normalizer.py` | Converts raw CloudTrail JSON and GuardDuty findings into `NormalizedEvent` objects |
| `collector/aws_collector.py` | Polls AWS CloudTrail + GuardDuty every 5 min (via boto3) and indexes events into `security-cloud-*` |
| `collector/tasks.py` | Celery task scheduler — runs `aws_collector` every `CLOUD_POLL_MINUTES` (default: 5) |
| `collector/cloud_simulator.py` | Generates fake CloudTrail/GuardDuty events for testing without real AWS credentials |

---

### Phase 3–4: Correlation

| File | What it does |
|------|-------------|
| `correlation/correlation_engine.py` | Reads events from ES, groups them into attack chains using 10-min time windows, detects cross-environment pivots (same user in on-prem + cloud = escalate to CRITICAL) |

---

### Phase 5: MITRE ATT&CK Mapping

| File | What it does |
|------|-------------|
| `mitre/mitre_mapper.py` | Maps each event type to a MITRE ATT&CK tactic + technique ID. Builds a kill chain timeline. Supported: T1110 (Brute Force), T1078 (Valid Accounts), T1562.008 (Disable Cloud Logs), and 11 others |

---

### Phase 6: AI Investigation Agent

| File | What it does |
|------|-------------|
| `agent/ai_agent.py` | LangGraph state machine with 4 nodes: **Observe** (load events), **Reason** (LLM with RAG context produces structured JSON), **Query** (fetches 24h of ES history for the primary user, injects cross-env signal), **Conclude** (final verdict with confidence score) |
| `agent/schemas.py` | Pydantic models for structured LLM output: `InitialTriage`, `FalsePositiveCheck`, `ThreatConclusion` |
| `agent/rag.py` | ChromaDB-based RAG — retrieves MITRE technique descriptions and past incident summaries to enrich LLM prompts |

---

### Phase 7: Sandbox Verification

| File | What it does |
|------|-------------|
| `sandbox/sandbox.py` | Queries VirusTotal for IPs, file hashes, and URLs found in the attack chain. Returns a verdict (malicious / suspicious / clean) and a confidence delta passed to the AI agent |

---

### Phase 8: Response + API

| File | What it does |
|------|-------------|
| `api/main.py` | FastAPI server — exposes `/investigate` (trigger pipeline), `/incidents` (list results), `/sandbox/check` (VT lookup), `/health` (service status), `/stats` (counts by severity) |
| `response/response_engine.py` | Saves concluded incidents to SQLite, sends Slack webhook + email alerts, triggers AWS IAM key revocation for critical cloud incidents |
| `incidents/incidents.db` | SQLite database storing all incidents, attack chains, and AI conclusions |

---

### Testing & DevOps

| File | What it does |
|------|-------------|
| `tests/inject_logs.py` | Sends 15 fake on-prem attack events to Logstash (jsmith brute force → login → lateral movement → data exfil) |
| `tests/inject_cloud_logs.py` | Directly indexes 7 fake cloud events into ES (AWS console login → IAM key created → S3 bulk download → CloudTrail deleted → GuardDuty finding) |
| `.devcontainer/devcontainer.json` | GitHub Codespaces configuration |
| `.gitpod.yml` | Gitpod workspace configuration |
| `setup_codespace.sh` | Rebuilds `.env` from cloud environment secrets (Codespaces / Gitpod) |

---

## Running the Project

```bash
# 1. Start infrastructure
docker compose up -d

# 2. Wait ~60s for Elasticsearch, then start API
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# 3. Inject test events (simulates a cross-environment attack)
python tests/inject_logs.py          # on-prem: jsmith brute force chain
python tests/inject_cloud_logs.py    # cloud: same jsmith pivots to AWS

# 4. Trigger investigation
curl -X POST http://localhost:8000/investigate \
  -H "Content-Type: application/json" \
  -d '{"lookback_minutes": 90}'

# 5. View results
# Check api/main.py logs or incidents/incidents.db for results
```

---

## Key Design Decisions

- **LangGraph** for the AI agent loop — clean state machine with cycle detection (`MAX_ITERATIONS = 3`)
- **Structured output (Pydantic)** — LLM responses are validated against schemas, preventing hallucinated JSON
- **RAG (ChromaDB)** — MITRE descriptions + past incident summaries injected into prompts for context
- **Dual-index ES** — on-prem goes to `security-onprem-*`, cloud goes to `security-cloud-*`, queries span both
- **Cross-environment signal** — if `query_more_logs` finds the same user in both environments in 24h, a synthetic signal is injected into the LLM context explicitly naming the pivot
- **Groq API** for LLM inference — free tier, fast (~1–2s per call), uses `llama-3.3-70b-versatile`
