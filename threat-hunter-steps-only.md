# 🔐 Autonomous Security Threat Hunter
### Hybrid Cloud + On-Premise | Step-by-Step Architecture Blueprint

---

## 📋 Table of Contents

1. [What We Are Building](#1-what-we-are-building)
2. [Why Hybrid Architecture](#2-why-hybrid-architecture)
3. [Final Tech Stack](#3-final-tech-stack)
4. [Master Architecture Flow](#4-master-architecture-flow)
5. [Phase 1 — On-Premise Log Ingestion](#phase-1--on-premise-log-ingestion)
6. [Phase 2 — Cloud Log Ingestion](#phase-2--cloud-log-ingestion)
7. [Phase 3 — Normalization Layer](#phase-3--normalization-layer)
8. [Phase 4 — Correlation Engine](#phase-4--correlation-engine)
9. [Phase 5 — MITRE ATT&CK Mapping](#phase-5--mitre-attck-mapping)
10. [Phase 6 — AI Investigation Agent](#phase-6--ai-investigation-agent)
11. [Phase 7 — Sandbox Verification](#phase-7--sandbox-verification)
12. [Phase 8 — Response Automation](#phase-8--response-automation)
13. [Phase 9 — Analyst Dashboard](#phase-9--analyst-dashboard)
14. [Attack Scenarios Covered](#14-attack-scenarios-covered)
15. [End-to-End Example](#15-end-to-end-example)
16. [Storage Requirements](#16-storage-requirements)
17. [GitHub & Secrets Management](#17-github--secrets-management)
18. [Project Timeline](#18-project-timeline)

---

## 1. What We Are Building

An **Autonomous AI SOC Analyst** that monitors both on-premise servers and cloud infrastructure, detects attacks across both, and responds automatically — without constant human involvement.

```
On-Premise Logs ──┐
AWS CloudTrail    ├──→ Normalize → Correlate → MITRE Map
Azure Monitor     ──┘       → AI Agent → Sandbox → Respond
```

### 6 Attack Scenarios Covered

| Environment | Scenario | MITRE Techniques |
|-------------|----------|-----------------|
| On-Premise | Brute Force → Account Takeover | T1110, T1078 |
| On-Premise | Lateral Movement via SMB | T1021, T1550 |
| On-Premise | Malware + Data Exfiltration | T1059, T1041 |
| Cloud (AWS) | IAM Privilege Escalation | T1078.004, T1098 |
| Cloud (AWS) | S3 Bucket Data Theft | T1530 |
| Cloud (AWS) | Cryptojacking via EC2 | T1496 |

---

## 2. Why Hybrid Architecture

Most companies today run a mix of on-premise servers AND cloud (AWS/Azure/GCP). Attackers exploit both:

- They brute-force SSH on your on-premise server
- They steal AWS keys from that same server
- They then log into AWS and steal all your S3 data

A platform that only watches one side **misses the full attack**. The most dangerous and hardest-to-detect attack pattern is a **cross-environment pivot** — where the attacker starts on-premise and moves to cloud in the same session.

```
On-Premise                     Cloud (AWS)
──────────                     ───────────
Brute force SSH   ──────────→  Login to AWS Console
Steal credentials ──────────→  Attach Admin IAM Policy
Access credential file ─────→  Download all S3 data
```

This platform catches the entire chain as one unified incident.

---

## 3. Final Tech Stack

### Log Collection

| Purpose | Tool |
|---------|------|
| On-premise SIEM & agents | Wazuh |
| Network intrusion detection | Suricata |
| Windows process monitoring | Sysmon |
| AWS log collection | AWS CloudTrail + GuardDuty |
| Azure log collection | Azure Monitor + Microsoft Defender |
| GCP log collection | GCP Cloud Audit Logs |

### Data Pipeline & Storage

| Purpose | Tool |
|---------|------|
| Log ingestion pipeline | Logstash |
| Log storage & search | Elasticsearch |
| SIEM visualization | Kibana |
| Async task processing | Celery + Redis |

### AI & Intelligence

| Purpose | Tool |
|---------|------|
| AI agent orchestration | LangGraph |
| LLM (cloud option) | OpenAI GPT-4o |
| LLM (private option) | Ollama + Llama 3 (logs stay local) |
| Past incident search | ChromaDB (vector database) |
| Attack chain analysis | NetworkX |
| MITRE ATT&CK data | STIX/TAXII dataset |

### Application

| Purpose | Tool |
|---------|------|
| REST API backend | FastAPI |
| Analyst dashboard | Streamlit (MVP) → React (production) |
| Sandbox verification | VirusTotal API |
| Containerization | Docker + Docker Compose |
| Language | Python 3.10+ |

---

## 4. Master Architecture Flow

```
╔══════════════════════════════════════════════════════════════╗
║                     LOG SOURCE LAYER                         ║
╠══════════════════════╦═══════════════════════════════════════╣
║   ON-PREMISE         ║           CLOUD                       ║
║                      ║                                       ║
║  • Linux servers     ║  • AWS CloudTrail (API calls)         ║
║  • Windows machines  ║  • AWS GuardDuty (threat intel)       ║
║  • Network traffic   ║  • AWS VPC Flow Logs                  ║
║  • Firewall logs     ║  • Azure Monitor (sign-ins)           ║
║  • IDS/IPS alerts    ║  • Azure Defender (threats)           ║
║                      ║  • GCP Cloud Audit Logs               ║
╚══════════╪═══════════╩══════════════╪════════════════════════╝
           │                          │
           ▼                          ▼
╔══════════════════════════════════════════════════════════════╗
║              INGESTION & NORMALIZATION LAYER                 ║
║                                                              ║
║  All logs → one standard format:                             ║
║  { timestamp, user, source_ip, environment,                  ║
║    event_type, resource, severity, raw_log }                 ║
║                                                              ║
║              Stored in Elasticsearch                         ║
╚══════════════════════════╪═══════════════════════════════════╝
                           │
                           ▼
╔══════════════════════════════════════════════════════════════╗
║                   CORRELATION ENGINE                         ║
║                                                              ║
║  Groups events by: User | IP | Session | Time Window         ║
║  Detects cross-environment patterns:                         ║
║  "Same user suspicious on-prem AND in AWS within 10 min"     ║
╚══════════════════════════╪═══════════════════════════════════╝
                           │
                           ▼
╔══════════════════════════════════════════════════════════════╗
║              MITRE ATT&CK MAPPING ENGINE                     ║
║                                                              ║
║  Rule-based mapping (fast, no hallucination)                 ║
║  Events → Tactic → Technique → Sub-technique                 ║
║  Covers both on-premise AND cloud techniques                 ║
╚══════════════════════════╪═══════════════════════════════════╝
                           │
                           ▼
╔══════════════════════════════════════════════════════════════╗
║           AI INVESTIGATION AGENT (LangGraph)                 ║
║                                                              ║
║  Step 1: Observe → read the full attack chain                ║
║  Step 2: Hypothesize → form initial theory                   ║
║  Step 3: Query More Logs → gather extra evidence             ║
║  Step 4: Reason → evaluate all evidence                      ║
║  Step 5: Conclude → generate incident report                 ║
║                                                              ║
║  If confidence < 70%, loops back to gather more evidence     ║
╚══════════════╪═══════════════════════════╪═══════════════════╝
               │                           │
               ▼                           ▼
╔══════════════════════╗    ╔══════════════════════════════════╗
║  SANDBOX VERIFIER    ║    ║      RESPONSE ENGINE             ║
║                      ║    ║                                  ║
║  Check via           ║    ║  LOW    → Log incident           ║
║  VirusTotal API:     ║    ║  MEDIUM → Slack alert            ║
║  • File hashes       ║    ║  HIGH   → Slack + Email          ║
║  • URLs              ║    ║  CRITICAL → + Block IP           ║
║  • IP addresses      ║    ║             Disable IAM keys     ║
║  • Domains           ║    ║             Stop EC2 instances   ║
╚══════════════════════╝    ╚══════════════╪═══════════════════╝
                                           │
                                           ▼
                        ╔══════════════════════════════════════╗
                        ║        ANALYST DASHBOARD             ║
                        ║                                      ║
                        ║  • Live incident feed                ║
                        ║  • Attack chain timeline             ║
                        ║  • MITRE ATT&CK heatmap              ║
                        ║  • AI reasoning trace                ║
                        ║  • Sandbox results                   ║
                        ║  • One-click response actions        ║
                        ╚══════════════════════════════════════╝
```

---

## Phase 1 – On-Premise Log Ingestion

**Goal**: Collect logs from your servers and network into Elasticsearch.

### Step 1.1 — Set up Elasticsearch, Kibana, and Logstash using Docker
- Run all three as Docker containers using Docker Compose
- Elasticsearch stores all logs
- Kibana gives you a visual interface
- Logstash is the pipeline that processes incoming logs

### Step 1.2 — Install Wazuh on your servers
- Install Wazuh Manager on your central server
- Install Wazuh Agent on every Linux and Windows machine you want to monitor
- The agent collects: auth logs, system logs, file changes, process activity

### Step 1.3 — Set up Suricata for network monitoring
- Install Suricata on your network gateway or a dedicated machine
- It monitors all network traffic and raises alerts for suspicious activity
- Connect it to Logstash so alerts flow into Elasticsearch

### Step 1.4 — Configure Logstash pipelines
- Write pipeline rules that tell Logstash how to parse each log type
- Tag every log with: source type, environment (on-premise), and detected event type
- Example tags: `failed_login`, `successful_login`, `port_scan`, `lateral_movement_smb`

### Step 1.5 — Verify logs are flowing
- Open Kibana at `http://localhost:5601`
- Confirm you can see logs indexed in Elasticsearch
- Test by intentionally triggering a failed SSH login and checking it appears

---

## Phase 2 – Cloud Log Ingestion

**Goal**: Pull AWS, Azure, and GCP logs into the same Elasticsearch.

### Step 2.1 — Enable AWS CloudTrail
- Go to AWS Console → CloudTrail → Create Trail
- Enable logging for all regions
- Store logs in an S3 bucket
- Enable CloudTrail Insights for anomaly detection

### Step 2.2 — Enable AWS GuardDuty
- Go to AWS Console → GuardDuty → Enable
- GuardDuty automatically detects threats like unusual API calls, compromised credentials, and crypto mining
- It produces findings you can pull via API

### Step 2.3 — Enable VPC Flow Logs
- Go to AWS Console → VPC → Your VPC → Flow Logs → Create
- Logs all network traffic going in and out of your cloud infrastructure

### Step 2.4 — Build an AWS log collector (Python script)
- Write a Python script using `boto3` (AWS SDK)
- Script pulls CloudTrail events every 5 minutes
- Script pulls GuardDuty findings every 5 minutes
- Script pushes everything into Elasticsearch under index `security-cloud-*`

### Step 2.5 — Enable Azure Monitor (if using Azure)
- Go to Azure Portal → Azure Monitor → Diagnostic Settings
- Enable Sign-in logs, Audit logs, Activity logs
- Use the Azure SDK (`azure-monitor-query`) to pull logs into Elasticsearch

### Step 2.6 — Schedule cloud collectors
- Use Celery + Redis to run the cloud collector scripts automatically every 5 minutes
- This keeps your Elasticsearch continuously updated with cloud logs

---

## Phase 3 – Normalization Layer

**Goal**: Every log from every source looks the same before it enters the rest of the pipeline.

### Why This Matters
AWS calls a login event `ConsoleLogin`. Linux calls it `Accepted password`. Azure calls it `Sign-in`. The correlation engine cannot group these unless they all become `successful_login` in a standard format.

### Step 3.1 — Define the universal event schema
Every log, regardless of source, must be converted to these standard fields:

| Field | Description | Example |
|-------|-------------|---------|
| `event_id` | Unique ID for this event | `EVT-a3f2-1705` |
| `timestamp` | When it happened (UTC) | `2025-01-15T10:23:45Z` |
| `environment` | Where it came from | `on-premise` / `aws` / `azure` |
| `user` | Who triggered it | `jsmith` |
| `source_ip` | Origin IP address | `192.168.1.105` |
| `event_type` | Our internal classification | `failed_login` |
| `severity` | How serious | `low` / `medium` / `high` / `critical` |
| `cloud_resource` | Affected cloud resource (if any) | `arn:aws:s3:::my-bucket` |
| `raw_log` | Original log for reference | `...` |

### Step 3.2 — Write normalization rules for each source
- Linux auth log → detect `Failed password` → tag as `failed_login`
- AWS `ConsoleLogin` API call → tag as `cloud_console_login`
- AWS `AttachUserPolicy` → tag as `iam_privilege_escalation`
- AWS `GetObject` × many calls → tag as `s3_data_access`
- AWS `RunInstances` → tag as `ec2_instance_launched`
- Azure failed sign-in → tag as `failed_login`

### Step 3.3 — Apply normalization in the Logstash pipeline
- Add normalization rules directly into your Logstash config
- For cloud logs, apply normalization in the Python collector before indexing to Elasticsearch

---

## Phase 4 – Correlation Engine

**Goal**: Find patterns across events and group related ones into a single security incident.

### Step 4.1 — Define correlation windows
- Set a time window (e.g., 10 minutes)
- Any events from the same user or same IP within that window are considered related

### Step 4.2 — Define thresholds for each event type
| Event Type | Threshold | Reason |
|-----------|-----------|--------|
| `failed_login` | 5+ events | Brute force attempt |
| `s3_data_access` | 100+ events | Bulk data theft |
| `iam_privilege_escalation` | 1 event | Always suspicious |
| `ec2_instance_launched` | 3+ events | Possible cryptojacking |
| `port_scan` | 20+ ports | Reconnaissance |

### Step 4.3 — Query Elasticsearch for recent events
- Every 5 minutes, query all indexes (`security-onprem-*` and `security-cloud-*`)
- Pull all events from the last 10 minutes

### Step 4.4 — Group events by identity
- Group by: `(user, event_type, environment)`
- Count events in each group
- If count exceeds threshold → create a correlated SecurityEvent

### Step 4.5 — Cross-environment correlation (the key feature)
- After grouping, check: is the same user appearing in BOTH on-premise AND cloud logs?
- If yes → tag all their events with `cross-environment-attack`
- Escalate severity automatically (this is the most dangerous pattern)

### Step 4.6 — Output
- A list of SecurityEvent objects ready for MITRE mapping
- Each event has: user, IP, event type, count, severity, environment, session ID

---

## Phase 5 – MITRE ATT&CK Mapping

**Goal**: Convert security events into threat intelligence using the MITRE framework.

### Step 5.1 — Download the MITRE ATT&CK dataset
- Download the STIX format dataset from the MITRE GitHub repository
- Store locally so the system works offline

### Step 5.2 — Build a mapping table (rule-based, NOT AI)
This is important: use deterministic rules here, not the LLM. The LLM is for reasoning, not for lookup.

**On-Premise Mappings:**
| Event Type | MITRE Tactic | Technique |
|-----------|-------------|-----------|
| `failed_login` | Credential Access | T1110 — Brute Force |
| `successful_login` | Initial Access | T1078 — Valid Accounts |
| `lateral_movement_smb` | Lateral Movement | T1021.002 — SMB/Admin Shares |
| `malware_execution` | Execution | T1059 — Command Interpreter |
| `large_data_transfer` | Exfiltration | T1041 — Exfil Over C2 |
| `port_scan` | Reconnaissance | T1046 — Network Service Discovery |

**Cloud Mappings:**
| Event Type | MITRE Tactic | Technique |
|-----------|-------------|-----------|
| `iam_privilege_escalation` | Privilege Escalation | T1078.004 — Cloud Accounts |
| `iam_key_created` | Persistence | T1098.001 — Additional Cloud Credentials |
| `s3_data_access` | Collection | T1530 — Data from Cloud Storage |
| `ec2_instance_launched` | Impact | T1496 — Resource Hijacking |
| `cloudtrail_deleted` | Defense Evasion | T1562.008 — Disable Cloud Logs |
| `cloud_console_login` | Initial Access | T1078.004 — Cloud Accounts |

### Step 5.3 — Build the attack chain
- Take all correlated events sorted by timestamp
- Map each one to its MITRE technique
- Output: a timeline showing tactic progression (e.g., Reconnaissance → Initial Access → Privilege Escalation → Exfiltration)

---

## Phase 6 – AI Investigation Agent

**Goal**: Use AI to reason about the attack chain like a human analyst would.

### Why LangGraph?
A single LLM prompt asking "is this an attack?" is too simple. Real investigation is a loop: gather evidence → form hypothesis → check if hypothesis holds → gather more evidence if unsure → conclude. LangGraph lets you build this loop.

### Step 6.1 — Define the agent states
The agent moves through these steps:

```
[Observe] → [Hypothesize] → [Query More Logs] → [Reason] → [Conclude]
                                    ↑                  │
                                    └── if confidence < 70% ──┘
```

### Step 6.2 — Build the Observe step
- Feed the full MITRE-mapped attack chain to the LLM
- Ask it to form an initial hypothesis
- The LLM outputs: hypothesis text + initial confidence score (0–1)

### Step 6.3 — Build the Query More Logs step
- Based on the hypothesis, query Elasticsearch for more context
- Example: if hypothesis is "brute force then cloud pivot", search for ALL activity from that user and IP in the last 24 hours across both environments
- This gives the LLM additional evidence to work with

### Step 6.4 — Build the Reason step
- Feed the LLM: original attack chain + additional log context + initial hypothesis
- Ask it to answer:
  - Is this a real attack or false positive?
  - Did the attacker pivot between on-premise and cloud?
  - What stage of the kill chain is this?
  - What is the blast radius?
  - What will the attacker do next?
  - What should we do immediately?
- LLM outputs structured JSON with all answers + updated confidence score

### Step 6.5 — Loop or conclude
- If confidence is below 70% and fewer than 3 iterations have run → go back to Query More Logs
- If confidence is above 70% or max iterations reached → conclude

### Step 6.6 — Generate the incident report
- Final output includes:
  - Is it an attack? (yes/no)
  - Kill chain stage
  - Whether a cross-environment pivot happened
  - Blast radius (on-prem + cloud)
  - Recommended immediate actions
  - Confidence score
  - Plain-English summary

### Step 6.7 — LLM privacy decision
| Option | Tool | Pros | Cons |
|--------|------|------|------|
| Cloud LLM | OpenAI GPT-4o | Best reasoning quality | Log data sent to OpenAI |
| Local LLM | Ollama + Llama 3 | Data never leaves your system | Slightly lower quality |

For regulated industries (healthcare, finance, government) → use Ollama. For portfolio/dev → GPT-4o is fine.

---

## Phase 7 – Sandbox Verification

**Goal**: Verify suspicious files, URLs, hashes, and IPs against external threat intelligence.

### Step 7.1 — Sign up for VirusTotal API
- Free tier: 4 lookups per minute (enough for development)
- Paid tier: needed for production volume

### Step 7.2 — Implement hash checking
- When a suspicious file is found on an endpoint, extract its MD5/SHA256 hash
- Query VirusTotal: how many antivirus engines flag this hash as malicious?
- More than 3 detections → flag as malicious

### Step 7.3 — Implement IP reputation checking
- For any suspicious source IP in your attack chain
- Query VirusTotal: is this IP known for malicious activity?
- More than 5 malicious detections → flag the IP

### Step 7.4 — Implement URL checking
- For any URLs found in logs (email links, web requests)
- Query VirusTotal: is this URL flagged?

### Step 7.5 — Feed results back to AI agent
- Sandbox results enrich the attack chain
- If the source IP is known malicious → confidence score increases
- If a file hash is known malware → incident severity escalates automatically

---

## Phase 8 – Response Automation

**Goal**: Take automatic actions based on incident severity, for both on-premise and cloud.

### Step 8.1 — Define the response matrix

| Severity | On-Premise Actions | Cloud Actions |
|----------|-------------------|--------------|
| Low | Log incident only | Log incident only |
| Medium | Slack alert | Slack alert |
| High | Slack + Email alert | Slack + Email + Disable suspicious IAM key |
| Critical | All above + page on-call | All above + Stop EC2 instances + Revoke all IAM access for user |

### Step 8.2 — Create incident records
- Every investigation generates a unique incident ID (e.g., `INC-A3F2B1`)
- Store: timestamp, conclusion, attack chain, actions taken, status (open/closed)
- Save to database (SQLite for MVP, PostgreSQL for production)

### Step 8.3 — Set up Slack alerting
- Create a Slack Incoming Webhook URL in your Slack workspace
- Send a structured alert message including: incident ID, severity, summary, environments affected, recommended actions

### Step 8.4 — Set up email alerting
- Use Python's SMTP library to send email alerts
- Send to your SOC team email for High and Critical incidents

### Step 8.5 — Set up AWS auto-remediation
- For critical cloud incidents, use the AWS SDK (boto3) to:
  - Disable the compromised user's IAM access keys
  - Detach overly permissive IAM policies
  - Stop suspicious EC2 instances
- Always log what automated action was taken and when

### Step 8.6 — Build the FastAPI backend
- Expose all functionality as REST API endpoints:
  - `POST /investigate` → runs full pipeline
  - `GET /incidents` → returns all incidents
  - `POST /sandbox/check` → checks a hash/URL/IP
  - `GET /health` → checks all services are running

---

## Phase 9 – Analyst Dashboard

**Goal**: A visual interface for analysts to monitor, investigate, and respond.

### Step 9.1 — Set up Streamlit (MVP)
- Streamlit lets you build a working web UI in Python in a few hours
- Connect it to your FastAPI backend
- Upgrade to React later when the core logic is proven

### Step 9.2 — Build the incident feed
- Show all open incidents in a table
- Columns: Incident ID, Timestamp, Severity, Environments, Cross-Env Attack (yes/no), Summary
- Color code by severity: red for critical, orange for high, yellow for medium

### Step 9.3 — Build the investigation panel
- Click any incident to see full details:
  - The complete attack chain timeline
  - Each event mapped to its MITRE technique
  - The AI's reasoning trace (step by step)
  - Sandbox results
  - Actions taken

### Step 9.4 — Build the manual investigation trigger
- A "Run Investigation Now" button that kicks off the full pipeline
- Shows a spinner while the AI is reasoning
- Displays the result when done

### Step 9.5 — Build the sandbox check panel
- Simple input: paste a hash, URL, or IP
- Click check → shows verdict (clean / malicious / unknown) and detection count

### Step 9.6 — Build the environment status bar
- Shows live status of each monitored environment:
  - On-Premise: Active / Offline
  - AWS: Connected / Error
  - Azure: Connected / Error
  - AI Agent: Ready / Processing

---

## 14. Attack Scenarios Covered

### On-Premise Scenarios

**Scenario 1: Brute Force → Account Takeover**
```
50+ failed SSH logins → Successful login → Credential file accessed
T1110 (Brute Force) → T1078 (Valid Accounts) → T1552 (Credentials in Files)
```

**Scenario 2: Lateral Movement**
```
Compromised machine → SMB connections to other servers → Admin share access
T1021.002 (SMB) → T1550 (Alternate Auth Material)
```

**Scenario 3: Malware + Exfiltration**
```
Suspicious script runs → Outbound C2 connection → Large data upload
T1059 (Script Execution) → T1071 (C2 Protocol) → T1041 (Exfiltration)
```

### Cloud Scenarios

**Scenario 4: AWS IAM Privilege Escalation**
```
Login from unusual country → Admin policy attached to own user → New access key created
T1078.004 → T1098.001 → T1087.004
```

**Scenario 5: S3 Data Exfiltration**
```
500+ GetObject API calls in 5 minutes on sensitive bucket → Data copied externally
T1530 (Cloud Storage Data) → T1041 (Exfiltration)
```

**Scenario 6: Cryptojacking**
```
10 GPU EC2 instances launched in unusual region → 99% CPU → Traffic to mining pool
T1496 (Resource Hijacking) → T1571 (Non-Standard Port)
```

### The Cross-Environment Scenario (Most Dangerous)
```
ON-PREM: Credential theft → CLOUD: AWS Console login with stolen creds
→ CLOUD: Admin IAM policy attached → CLOUD: Full S3 exfiltration

Same incident, two environments, full attack chain caught by one platform
```

---

## 15. End-to-End Example

**Scenario: Cross-environment attack — on-premise breach leading to cloud data theft**

```
09:15  Phishing email clicked → malicious script runs on workstation
       → Detected as: malware_execution (T1059)

09:20  Attacker SSH brute forces from IP 203.0.113.42
       → 47 failed logins detected → failed_login × 47 (T1110)

09:21  Successful SSH login with stolen password
       → Detected as: successful_login (T1078)

09:22  Attacker reads ~/.aws/credentials on the server
       → Detected as: credential_file_access (T1552)

09:23  Same IP logs into AWS Console with stolen keys
       → Detected as: cloud_console_login, unusual_location (T1078.004)

09:25  AttachUserPolicy: AdministratorAccess given to attacker's IAM user
       → Detected as: iam_privilege_escalation (T1098) — CRITICAL

09:27  847 GetObject calls on S3 bucket "company-financials" in 2 minutes
       → Detected as: s3_data_access × 847 (T1530)

─────────────────────────────────────────────────────────────
PLATFORM PROCESSES:

Correlation Engine:
  Groups all events under user "jsmith" across on-prem + cloud
  Detects: same user in both environments within 12 minutes
  Tags: cross-environment-attack
  Escalates: all events to HIGH/CRITICAL

MITRE Chain built:
  T1059 → T1110 → T1078 → T1552 → T1078.004 → T1098 → T1530

AI Agent runs:
  Observe:      "Credential theft and cloud pivot suspected"
  Query Logs:   Pulls 24h history for jsmith + 203.0.113.42
  Reason:       Confidence 0.94 — "Confirmed cross-env attack"
  Conclude:     CRITICAL. Full S3 access. Immediate containment needed.

Sandbox:
  IP 203.0.113.42 → VirusTotal → 12 malicious detections
  → Confidence increases to 0.97

Response Engine:
  Creates: INC-A3F2B1
  Slack:   🔴 CRITICAL cross-environment attack detected
  AWS:     IAM keys for jsmith disabled automatically
  Email:   SOC team notified with full timeline

Dashboard:
  Incident appears in red at top of feed
  Full attack chain visible across both environments
  Analyst clicks "Review" to confirm and close
```

---

## 16. Storage Requirements

| Setup | Storage Needed |
|-------|---------------|
| Development / Testing (fake logs) | 50–100 GB |
| Small lab (5–10 machines, 30-day retention) | 300–500 GB |
| Medium production (50+ machines, 90-day retention) | 2–5 TB |

**Biggest storage factor**: Elasticsearch log retention. Set automatic deletion of logs older than 30 days to cut storage by 60–80%.

**Cloud logs are smaller than on-premise logs** because they only capture API-level events, not raw system logs.

---

## 17. GitHub & Secrets Management

### Never push these to GitHub
- `.env` file (contains all your API keys and passwords)
- `incidents/` folder (contains real security findings)
- `esdata/` folder (Elasticsearch data volume)
- Any `.pem`, `.key`, or `service-account.json` files

### Always push a `.env.example` instead
A copy of your `.env` file with all real values replaced by placeholders like `your_api_key_here`. Anyone cloning the repo copies this file, renames it to `.env`, and fills in their own values.

### Before your first commit
- Create `.gitignore` first and add all sensitive paths
- Run `git status` to verify `.env` is not being tracked
- If you accidentally committed `.env` at any point, simply deleting the file is not enough — you must purge it from git history using BFG Repo Cleaner

---

## 18. Project Timeline

| Week | Phase | Milestone |
|------|-------|-----------|
| 1 | Phase 1 | ELK + Wazuh running, on-prem logs flowing |
| 2 | Phase 2 | AWS CloudTrail logs in Elasticsearch |
| 3 | Phase 3 | All logs normalized to same schema |
| 4 | Phase 4 | Correlation detecting 3 on-prem scenarios |
| 5 | Phase 4 | Correlation detecting 3 cloud scenarios |
| 6 | Phase 5 | MITRE mapping working for all 6 scenarios |
| 7–8 | Phase 6 | AI agent reasoning correctly on test cases |
| 9 | Phase 7 | Sandbox checking IPs, hashes, URLs |
| 10 | Phase 8 | Slack + email alerts firing, AWS auto-remediation |
| 11–12 | Phase 9 | Full dashboard showing incidents live |
| 13 | Testing | End-to-end demo with simulated cross-env attack |

### Quick Win Path (First 3 Days)
1. Day 1: Docker Compose up → Kibana showing fake logs
2. Day 2: Correlation engine processing sample CloudTrail JSON
3. Day 3: AI agent reasoning on canned attack chain → producing conclusion
4. **You have a convincing demo by end of Day 3**

---

> 💡 **Key insight for interviews and demos**: The cross-environment correlation is what makes this project stand out. Every company has this gap — their on-premise SIEM doesn't talk to their cloud security tools. When you demonstrate catching an attack that pivots from a Linux server to AWS in a single unified incident, that's a genuinely impressive capability.

---

*Platform: Python · LangGraph · Elasticsearch · Wazuh · AWS CloudTrail · MITRE ATT&CK · FastAPI · Streamlit*
