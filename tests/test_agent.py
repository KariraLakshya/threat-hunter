"""
test_agent.py — Quick isolated test of the AI agent pipeline

Tests: schema validation → prompts → Groq API → structured output → RAG
Does NOT require Docker or Elasticsearch to be running.

Run:
    python tests/test_agent.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

# ── Minimal sample attack chain (mirrors what MITREMapper produces) ──────────
SAMPLE_CHAIN = [
    {
        "step": 1,
        "timestamp": "2026-03-01T01:00:00Z",
        "event_type": "failed_login",
        "user": "jsmith",
        "source_ip": "203.0.113.42",
        "environment": ["on-premise"],
        "tactic": "Credential Access",
        "technique": "T1110",
        "technique_name": "Brute Force",
        "severity": "medium",
        "count": 10,
        "cross_environment": False,
        "mitre_url": "https://attack.mitre.org/techniques/T1110/",
    },
    {
        "step": 2,
        "timestamp": "2026-03-01T01:03:00Z",
        "event_type": "successful_login",
        "user": "jsmith",
        "source_ip": "203.0.113.42",
        "environment": ["on-premise"],
        "tactic": "Initial Access",
        "technique": "T1078",
        "technique_name": "Valid Accounts",
        "severity": "high",
        "count": 1,
        "cross_environment": False,
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
    },
    {
        "step": 3,
        "timestamp": "2026-03-01T01:05:00Z",
        "event_type": "lateral_movement_smb",
        "user": "jsmith",
        "source_ip": "192.168.1.105",
        "environment": ["on-premise", "aws"],  # cross-env!
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "severity": "high",
        "count": 3,
        "cross_environment": True,
        "mitre_url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    {
        "step": 4,
        "timestamp": "2026-03-01T01:07:00Z",
        "event_type": "large_data_transfer",
        "user": "jsmith",
        "source_ip": "192.168.1.105",
        "environment": ["on-premise", "aws"],
        "tactic": "Exfiltration",
        "technique": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "severity": "critical",
        "count": 1,
        "cross_environment": True,
        "mitre_url": "https://attack.mitre.org/techniques/T1041/",
    },
]


def test_rag():
    print("\n── 1. Testing RAG retriever ─────────────────────────")
    from agent.rag import RAGRetriever

    rag = RAGRetriever()

    tactics = ["Credential Access", "Lateral Movement", "Exfiltration"]
    mitre_ctx = rag.get_mitre_context(tactics, n_results=3)
    print(f"  MITRE context retrieved: {len(mitre_ctx)} chars")
    print(f"  Preview: {mitre_ctx[:200]}…")

    past = rag.get_past_incidents("brute force then lateral movement", n_results=2)
    print(f"  Past incidents: {past[:100]}…")
    print("  ✅ RAG OK")


def test_schemas():
    print("\n── 2. Testing Pydantic schemas ──────────────────────")
    from agent.schemas import InitialTriage, FalsePositiveCheck, ThreatConclusion

    t = InitialTriage(
        events_summary="10 failed logins followed by success",
        timeline_analysis="Logical brute-force sequence",
        false_positive_indicators=[],
        tactics_identified=["Credential Access", "Initial Access"],
        hypothesis="Brute force attack succeeded",
        confidence=0.75,
        needs_more_context=False,
    )
    print(f"  InitialTriage: confidence={t.confidence} ✅")

    tc = ThreatConclusion(
        is_attack=True,
        confidence=0.85,
        evidence_for_attack=["10 failed logins", "success from same IP"],
        evidence_against_attack=[],
        attack_narrative="Attacker brute-forced jsmith's account",
        kill_chain_stage="Lateral Movement",
        attacker_objective="Data exfiltration",
        attacker_next_step="Exfiltrate sensitive data via S3",
        systems_at_risk=["192.168.1.105", "AWS S3"],
        business_impact="critical",
        immediate_actions=["Disable jsmith's account", "Block 203.0.113.42"],
        short_term_actions=["Reset all credentials", "Review CloudTrail"],
        monitoring_actions=["Watch for new logins from 203.0.113.42"],
        summary="Confirmed cross-environment brute force leading to lateral movement.",
    )
    print(f"  ThreatConclusion: is_attack={tc.is_attack} severity={tc.business_impact} ✅")


def test_agent():
    print("\n── 3. Testing full AI agent (calls Groq API) ────────")
    from agent.ai_agent import investigate

    print("  Sending attack chain to agent…")
    conclusion = investigate(SAMPLE_CHAIN)

    print(f"\n  ── Agent Conclusion ──")
    print(f"  is_attack:       {conclusion.get('is_attack')}")
    print(f"  confidence:      {conclusion.get('confidence', 0):.2f}")
    print(f"  business_impact: {conclusion.get('business_impact')}")
    print(f"  kill_chain:      {conclusion.get('kill_chain_stage')}")
    print(f"  objective:       {conclusion.get('attacker_objective')}")
    print(f"  iterations:      {conclusion.get('iterations_taken')}")
    print(f"  fp_recommend:    {conclusion.get('fp_check_recommendation')}")
    print(f"\n  Immediate actions:")
    for a in conclusion.get("immediate_actions", []):
        print(f"    • {a}")
    print(f"\n  Summary: {conclusion.get('summary', '')}")
    print("\n  ✅ Agent investigation complete")

    return conclusion


if __name__ == "__main__":
    import traceback

    print("=" * 60)
    print("  Threat Hunter — Agent + RAG Test")
    print("=" * 60)

    passed = 0
    failed = 0

    for name, fn in [("RAG", test_rag), ("Schemas", test_schemas), ("Agent", test_agent)]:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"\n  ✗ {name} FAILED: {e}")
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Results: {passed} passed / {failed} failed")
    print("=" * 60)
