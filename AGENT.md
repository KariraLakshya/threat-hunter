# AGENT.md — Autonomous Security Threat Hunter

## What This File Is

This file tells the Antigravity AI agent how to behave while building this project.
Full architecture, steps, and tech stack are already documented in:
- `threat-hunter-steps-only.md` → all build phases and architecture
- `autonomous-threat-hunter-final.md` → full code reference

The agent should read those files. This file only defines agent behavior rules.

---

## How The Agent Should Work

### Read Before Acting
Before writing any code, the agent must:
1. Read the current phase section from `threat-hunter-steps-only.md`
2. Read only that phase — not the entire document
3. Then act

### One Phase At A Time
- Complete Phase 1 fully before reading Phase 2
- Test after every phase
- Confirm with the user before moving to the next phase
- Never jump ahead

### Minimal Token Usage Rules
- **Do not summarize** what you just read — act on it directly
- **Do not explain** what you are about to do — just do it
- **Do not repeat** file contents back — reference them by name
- **Do not re-read** a phase you already completed
- **Skip optional steps** on first pass unless user asks

---

## Build Order

Read and build phases in this exact order. Stop at each checkpoint.

```
Phase 1  →  Infrastructure (Docker, ELK, Wazuh)
Phase 2  →  Cloud Ingestion (AWS CloudTrail, GuardDuty)
Phase 3  →  Normalization
Phase 4  →  Correlation Engine
Phase 5  →  MITRE Mapping
Phase 6  →  AI Agent (LangGraph)
Phase 7  →  Sandbox (VirusTotal)
Phase 8  →  Response Engine
Phase 9  →  FastAPI Backend
Phase 10 →  Dashboard (Streamlit)
Phase 11 →  Testing
```

---

## Checkpoints

After each phase, stop and ask the user:
> "Phase X complete. [One line confirming what works]. Continue to Phase X+1?"

Do not proceed without confirmation.

---

## File & Secret Rules

- All secrets go in `.env` only — never hardcode
- Create `.env.example` with placeholder values
- Add `.env`, `incidents/`, `esdata/` to `.gitignore` immediately
- Only create files needed for the current phase

---

## If Something Breaks

1. Print the exact error
2. State which step caused it
3. Attempt one fix
4. If still broken, ask the user — do not loop endlessly

---

## LLM Choice

- If `OPENAI_API_KEY` is set → use GPT-4o
- If not → use Ollama + Llama3 (local, free, no API cost)
- Ask the user which they prefer at the start of Phase 6

---

## That's It

All other details — architecture, code logic, tech stack, attack scenarios — are in the two markdown files listed at the top. Read them phase by phase as needed.
