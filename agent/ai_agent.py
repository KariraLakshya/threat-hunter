"""
ai_agent.py — Phase 6: AI Investigation Agent (LangGraph)

State machine:
  [Observe] → [FP Check] → [Reason] → [Conclude]
                                 ↑          │
                                 └── loop ──┘  (if confidence < 0.70)

LLM: Groq (free, fast) — falls back to Ollama Llama3 if no key set.
Prompts: see agent/prompts.py
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, TypedDict, Optional

from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_community.llms import Ollama

from .prompts import (
    OBSERVE_PROMPT_TEMPLATE,
    REASON_PROMPT_TEMPLATE,
    FP_CHECK_PROMPT_TEMPLATE,
)
from .schemas import InitialTriage, FalsePositiveCheck, ThreatConclusion
from .rag import RAGRetriever

# singleton — shared across all nodes in a run
_rag = RAGRetriever()

load_dotenv()
log = logging.getLogger("ai_agent")

MAX_ITERATIONS = 3
CONFIDENCE_THRESHOLD = 0.70
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


# ── LLM Selection ────────────────────────────────────────────

def get_llm():
    """Return Groq ChatGroq if API key set, else Ollama Llama3 (local, free)."""
    if GROQ_API_KEY:
        log.info(f"[AI Agent] Using Groq — model: {GROQ_MODEL}")
        return ChatGroq(model=GROQ_MODEL, temperature=0.1, api_key=GROQ_API_KEY)
    else:
        log.info("[AI Agent] Using Ollama Llama3 (local)")
        return Ollama(model="llama3", temperature=0.1)


# ── Agent State ──────────────────────────────────────────────

class AgentState(TypedDict):
    # Input
    attack_chain: List[Dict]
    additional_logs: List[Dict]
    # Working memory
    hypothesis: str
    fp_check_result: Dict
    mitre_context: str        # injected by retrieve_context node
    past_incidents: str       # injected by retrieve_context node
    reasoning: str
    iteration: int
    confidence: float
    # Output
    conclusion: Dict[str, Any]
    done: bool


# ── Helpers ───────────────────────────────────────────────────

def _chain_to_text(chain: List[Dict]) -> str:
    lines = ["=== ATTACK CHAIN ==="]
    for step in chain:
        lines.append(
            f"[Step {step['step']}] {step.get('timestamp','')[:19]} | "
            f"Tactic: {step['tactic']} | Technique: {step['technique']} "
            f"({step['technique_name']}) | user={step['user']} | "
            f"ip={step['source_ip']} | env={step['environment']} | "
            f"count={step['count']} | severity={step['severity']}"
        )
    if any(s.get("cross_environment") for s in chain):
        lines.append("\n⚠️  CROSS-ENVIRONMENT ATTACK: same user active on-premise AND in cloud.")
    return "\n".join(lines)



def _mitre_context(chain: List[Dict]) -> str:
    """Build a short MITRE reference string from the chain (fallback only)."""
    seen = {}
    for step in chain:
        t = step.get("technique")
        if t and t not in seen:
            seen[t] = f"{t} — {step.get('technique_name', '')} ({step.get('tactic', '')})"
    return "\n".join(seen.values()) if seen else "No MITRE context available."


# ── RAG Node ──────────────────────────────────────────────────

def retrieve_context(state: AgentState) -> AgentState:
    """
    RAG step: retrieve MITRE technique descriptions and similar past incidents.
    Runs AFTER FP Check (so hypothesis is already refined) and BEFORE Reason
    (so Reason gets rich, relevant context injected into its prompt).
    """
    log.info("[AI Agent] RAG — retrieving MITRE context + past incidents")
    chain = state["attack_chain"]
    hypothesis = state["hypothesis"]

    # Collect unique tactics from the attack chain
    tactics = list({step.get("tactic", "") for step in chain if step.get("tactic")})

    # 1. Semantic MITRE lookup by tactic names
    mitre_ctx = _rag.get_mitre_context(tactics, n_results=4)
    log.info(f"[RAG] Retrieved MITRE context ({len(mitre_ctx)} chars)")

    # 2. Similar past incidents by hypothesis text
    past = _rag.get_past_incidents(hypothesis, n_results=3)
    log.info(f"[RAG] Retrieved past incidents ({len(past)} chars)")

    return {
        **state,
        "mitre_context": mitre_ctx,
        "past_incidents": past,
    }


# ── Agent Nodes ───────────────────────────────────────────────

def observe(state: AgentState) -> AgentState:
    """Step 1: Initial triage — structured output via InitialTriage schema."""
    log.info(f"[AI Agent] Observe (iteration {state['iteration'] + 1})")
    llm = get_llm().with_structured_output(InitialTriage)
    chain_text = _chain_to_text(state["attack_chain"])
    prompt = OBSERVE_PROMPT_TEMPLATE.format_messages(attack_chain=chain_text)
    try:
        result: InitialTriage = llm.invoke(prompt)
        return {
            **state,
            "hypothesis": result.hypothesis,
            "confidence": result.confidence,
            "iteration": state["iteration"] + 1,
        }
    except Exception as e:
        log.error(f"[AI Agent] Observe error: {e}")
        return {**state, "hypothesis": "Observation failed", "confidence": 0.3, "iteration": state["iteration"] + 1}


def fp_check(state: AgentState) -> AgentState:
    """Step 2: Devil's advocate — structured output via FalsePositiveCheck schema."""
    log.info("[AI Agent] FP Check — challenging hypothesis")
    llm = get_llm().with_structured_output(FalsePositiveCheck)
    chain_text = _chain_to_text(state["attack_chain"])
    prompt = FP_CHECK_PROMPT_TEMPLATE.format_messages(
        hypothesis=state["hypothesis"],
        confidence=state["confidence"],
        attack_chain=chain_text,
    )
    try:
        result: FalsePositiveCheck = llm.invoke(prompt)
        log.info(
            f"[AI Agent] FP check: fp_likelihood={result.fp_likelihood:.2f} "
            f"recommendation={result.recommendation} "
            f"confidence: {state['confidence']:.2f} → {result.revised_confidence:.2f}"
        )
        return {
            **state,
            "fp_check_result": result.model_dump(),
            "confidence": result.revised_confidence,
        }
    except Exception as e:
        log.error(f"[AI Agent] FP check error: {e}")
        return {**state, "fp_check_result": {}}


def reason(state: AgentState) -> AgentState:
    """Step 3: Deep analysis — structured output via ThreatConclusion schema."""
    log.info(f"[AI Agent] Reason (iteration {state['iteration']})")
    llm = get_llm().with_structured_output(ThreatConclusion)
    chain_text = _chain_to_text(state["attack_chain"])

    additional = (
        json.dumps(state["additional_logs"][:20], indent=2)
        if state["additional_logs"]
        else "No additional logs available."
    )
    fp_result = state.get("fp_check_result", {})
    past_incidents_ctx = (
        f"FP check notes: {fp_result.get('false_positive_explanation', 'N/A')}\n"
        f"FP indicators: {fp_result.get('fp_indicators', [])}\n\n"
        f"Similar past incidents:\n{state.get('past_incidents', 'None')}"
    ) if fp_result else state.get("past_incidents", "No past incident data.")

    prompt = REASON_PROMPT_TEMPLATE.format_messages(
        attack_chain=chain_text,
        hypothesis=state["hypothesis"],
        additional_context=additional,
        mitre_context=state.get("mitre_context", _mitre_context(state["attack_chain"])),
        past_incidents=past_incidents_ctx,
    )
    try:
        result: ThreatConclusion = llm.invoke(prompt)
        return {
            **state,
            "reasoning": result.attack_narrative,
            "confidence": result.confidence,
            "conclusion": result.model_dump(),
        }
    except Exception as e:
        log.error(f"[AI Agent] Reason error: {e}")
        return {**state, "confidence": 0.3, "conclusion": {}}


def should_continue(state: AgentState) -> str:
    """Route: loop for more evidence or proceed to conclude."""
    recommendation = state.get("fp_check_result", {}).get("recommendation", "")
    if recommendation == "likely_false_positive":
        log.info("[AI Agent] FP check recommends likely FP → Conclude")
        return "conclude"
    if state["confidence"] >= CONFIDENCE_THRESHOLD:
        log.info(f"[AI Agent] Confidence {state['confidence']:.2f} ≥ threshold → Conclude")
        return "conclude"
    if state["iteration"] >= MAX_ITERATIONS:
        log.info("[AI Agent] Max iterations → Conclude")
        return "conclude"
    log.info(f"[AI Agent] Confidence {state['confidence']:.2f} < threshold → Query more logs")
    return "query_logs"


def query_more_logs(state: AgentState) -> AgentState:
    """
    Query ES for 24h of activity for the primary user in the attack chain.
    Appends results to additional_logs so the Reason node has richer context.
    Also detects cross-environment activity for the same user.
    """
    new_iter = state["iteration"] + 1
    log.info(f"[AI Agent] Querying more logs (iteration {new_iter}/{MAX_ITERATIONS})")

    chain = state["attack_chain"]
    # Pick the primary user from the attack chain
    users = [step.get("user", "") for step in chain if step.get("user")]
    primary_user = max(set(users), key=users.count) if users else "unknown"

    extra_logs = list(state.get("additional_logs") or [])

    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(
            os.getenv("ES_HOST", "http://localhost:9200"),
            basic_auth=("elastic", os.getenv("ELASTIC_PASSWORD", "changeme123")),
            verify_certs=False,
        )
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-24h"}}},
                        {"term": {"user": primary_user}},
                    ]
                }
            },
            "size": 50,
            "sort": [{"@timestamp": {"order": "asc"}}],
        }
        resp = es.search(index="security-*", body=query)
        hits = resp.get("hits", {}).get("hits", [])
        new_docs = [h["_source"] for h in hits]
        extra_logs.extend(new_docs)

        # Check cross-environment: same user in both on-prem and cloud
        envs = {doc.get("environment", "") for doc in new_docs if doc.get("environment")}
        has_onprem = any(e.startswith("on-") for e in envs)
        has_cloud  = any(e in ("aws", "azure", "gcp") for e in envs)
        if has_onprem and has_cloud:
            log.warning(
                f"[AI Agent] 🚨 CROSS-ENV: user={primary_user} seen in {envs} "
                "over last 24h — strong indicator of lateral pivot"
            )
            # Append a synthetic cross-env signal so the LLM sees it
            extra_logs.append({
                "type": "cross_environment_signal",
                "user": primary_user,
                "environments": list(envs),
                "message": (
                    f"User '{primary_user}' has activity in BOTH on-premise AND cloud "
                    f"environments ({', '.join(envs)}) in the last 24 hours. "
                    "This is consistent with a lateral pivot from on-premise to cloud."
                ),
            })

        log.info(
            f"[AI Agent] Fetched {len(new_docs)} additional log entries for user={primary_user}"
        )

    except Exception as e:
        log.warning(f"[AI Agent] query_more_logs ES query failed: {e}")

    return {**state, "iteration": new_iter, "additional_logs": extra_logs}



def conclude(state: AgentState) -> AgentState:
    """Final step: package the conclusion into a clean incident dict."""
    conclusion = state.get("conclusion", {})
    fp = state.get("fp_check_result", {})

    if not conclusion:
        conclusion = {
            "is_attack": True,
            "confidence": state["confidence"],
            "business_impact": "medium",
            "summary": state["hypothesis"],
            "immediate_actions": ["Review affected systems", "Escalate to senior analyst"],
        }

    conclusion.update({
        "investigation_complete": True,
        "final_confidence": state["confidence"],
        "iterations_taken": state["iteration"],
        "fp_check_recommendation": fp.get("recommendation", "N/A"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        # Normalise field names for response engine compatibility
        "is_real_attack": conclusion.get("is_attack", conclusion.get("is_real_attack", True)),
        "severity": conclusion.get("business_impact", "medium"),
    })

    log.info(
        f"[AI Agent] Investigation complete — "
        f"attack={conclusion.get('is_real_attack')} "
        f"confidence={state['confidence']:.2f} "
        f"severity={conclusion.get('severity')}"
    )
    return {**state, "conclusion": conclusion, "done": True}


# ── Build the LangGraph ───────────────────────────────────────

def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("observe", observe)
    graph.add_node("fp_check", fp_check)
    graph.add_node("retrieve_context", retrieve_context)   # RAG node
    graph.add_node("reason", reason)
    graph.add_node("query_logs", query_more_logs)
    graph.add_node("conclude", conclude)

    graph.set_entry_point("observe")
    graph.add_edge("observe", "fp_check")             # 1. triage
    graph.add_edge("fp_check", "retrieve_context")   # 2. RAG lookup
    graph.add_edge("retrieve_context", "reason")     # 3. deep analysis
    graph.add_conditional_edges(
        "reason",
        should_continue,
        {"conclude": "conclude", "query_logs": "query_logs"},
    )
    graph.add_edge("query_logs", "reason")
    graph.add_edge("conclude", END)

    return graph.compile()


# ── Public API ────────────────────────────────────────────────

def investigate(attack_chain: List[Dict], additional_logs: List[Dict] = None) -> Dict:
    """
    Run the full AI investigation on a MITRE-mapped attack chain.

    Args:
        attack_chain: Output of MITREMapper.build_attack_chain()
        additional_logs: Extra events from ES (optional)
    Returns:
        Conclusion dict — is_real_attack, severity, immediate_actions, summary, etc.
    """
    initial_state: AgentState = {
        "attack_chain": attack_chain,
        "additional_logs": additional_logs or [],
        "hypothesis": "",
        "fp_check_result": {},
        "mitre_context": "",
        "past_incidents": "",
        "reasoning": "",
        "iteration": 0,
        "confidence": 0.0,
        "conclusion": {},
        "done": False,
    }
    graph = build_graph()
    final_state = graph.invoke(initial_state)
    return final_state["conclusion"]
