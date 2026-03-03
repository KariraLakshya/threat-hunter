from langchain_core.prompts import ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate

# ─────────────────────────────────────────
# SYSTEM PROMPT — defines WHO the LLM is
# This stays constant across all calls
# ─────────────────────────────────────────
SYSTEM_PROMPT = """You are an autonomous SOC (Security Operations Center) analyst \
with 10 years of experience in incident response and threat hunting.

Your analysis must follow these rules:
1. Always reason step by step before reaching conclusions
2. Distinguish between confirmed evidence and assumptions
3. Consider alternative explanations before concluding attack
4. Never exceed your evidence — if uncertain, say so explicitly
5. Always map findings to specific MITRE ATT&CK techniques
6. Prioritize actions by urgency — immediate vs within 24h vs monitoring

Your environment context:
- You are monitoring a mid-sized enterprise network
- Normal business hours are 09:00-18:00 local time
- Alerts outside business hours carry higher suspicion weight
- Internal IP range: 10.0.0.0/8 and 192.168.0.0/16
- External IPs are always higher suspicion by default

Output rules:
- Always respond in valid JSON matching the exact schema provided
- Never add explanation text outside the JSON structure
- Never use markdown code fences around your JSON
- If evidence is insufficient, reflect that in confidence score below 0.5"""


# ─────────────────────────────────────────
# OBSERVE PROMPT — first look at attack chain
# ─────────────────────────────────────────
OBSERVE_PROMPT_TEMPLATE = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template(SYSTEM_PROMPT),
    HumanMessagePromptTemplate.from_template("""
ATTACK CHAIN EVENTS:
{attack_chain}

TASK:
Perform initial triage of this attack chain.

Think through this step by step:
STEP 1 — What event types are present?
STEP 2 — What is the timeline? Is there a logical sequence?
STEP 3 — Are there any obvious false positive indicators?
STEP 4 — What MITRE tactics are represented?
STEP 5 — What is your initial confidence this is a real attack?

Respond with this exact JSON:
{{
  "events_summary": "brief description of what events you see",
  "timeline_analysis": "is the sequence logical for an attack?",
  "false_positive_indicators": ["list any FP indicators or empty list"],
  "tactics_identified": ["list of MITRE tactics present"],
  "hypothesis": "your initial theory about what is happening",
  "confidence": 0.0,
  "needs_more_context": true
}}
""")
])


# ─────────────────────────────────────────
# REASON PROMPT — deep analysis with full context
# ─────────────────────────────────────────
REASON_PROMPT_TEMPLATE = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template(SYSTEM_PROMPT),
    HumanMessagePromptTemplate.from_template("""
ATTACK CHAIN EVENTS:
{attack_chain}

INITIAL HYPOTHESIS:
{hypothesis}

ADDITIONAL LOG CONTEXT (from deeper investigation):
{additional_context}

MITRE ATT&CK REFERENCE CONTEXT:
{mitre_context}

SIMILAR PAST INCIDENTS:
{past_incidents}

TASK:
Perform deep analysis using ALL available context above.

Think through this carefully:

EVIDENCE ASSESSMENT:
- What evidence confirms an attack?
- What evidence suggests false positive?
- What evidence is ambiguous?

ATTACK NARRATIVE:
- If this is an attack, tell the complete story of what happened
- What did the attacker do first, second, third?
- What is their likely objective?

RISK ASSESSMENT:
- What systems or data are at risk?
- How far has the attacker progressed?
- What is the potential business impact?

RESPONSE PRIORITY:
- What must be done in the next 15 minutes?
- What must be done in the next 24 hours?
- What should be monitored going forward?

Respond with this exact JSON:
{{
  "is_attack": true,
  "confidence": 0.0,
  "evidence_for_attack": ["list of confirming evidence"],
  "evidence_against_attack": ["list of FP indicators"],
  "attack_narrative": "complete story of the attack",
  "kill_chain_stage": "current stage",
  "attacker_objective": "what the attacker is trying to achieve",
  "attacker_next_step": "predicted next action",
  "systems_at_risk": ["list of systems"],
  "business_impact": "low/medium/high/critical",
  "immediate_actions": ["must do in 15 minutes"],
  "short_term_actions": ["must do in 24 hours"],
  "monitoring_actions": ["ongoing monitoring"],
  "summary": "concise human readable summary"
}}
""")
])


# ─────────────────────────────────────────
# FALSE POSITIVE CHECK PROMPT
# New prompt — specifically designed to
# challenge the hypothesis before concluding
# ─────────────────────────────────────────
FP_CHECK_PROMPT_TEMPLATE = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template(SYSTEM_PROMPT),
    HumanMessagePromptTemplate.from_template("""
CURRENT HYPOTHESIS:
{hypothesis}

CURRENT CONFIDENCE:
{confidence}

ATTACK CHAIN:
{attack_chain}

TASK:
Play devil's advocate. Try to explain this alert as a FALSE POSITIVE.

Consider:
- Could this be a legitimate admin performing maintenance?
- Could this be an automated backup or monitoring tool?
- Could this be a developer running tests?
- Could the timing be explained by business processes?
- Are the volumes actually unusual for this environment?

Respond with this exact JSON:
{{
  "false_positive_explanation": "best innocent explanation for these events",
  "fp_likelihood": 0.0,
  "fp_indicators": ["specific things that suggest false positive"],
  "attack_indicators": ["specific things that confirm attack despite FP check"],
  "revised_confidence": 0.0,
  "recommendation": "investigate_further/confirm_attack/likely_false_positive"
}}
""")
])
