from pydantic import BaseModel, Field
from typing import List, Optional

class InitialTriage(BaseModel):
    events_summary: str
    timeline_analysis: str
    false_positive_indicators: List[str]
    tactics_identified: List[str]
    hypothesis: str
    confidence: float = Field(ge=0.0, le=1.0)
    needs_more_context: bool

class FalsePositiveCheck(BaseModel):
    false_positive_explanation: str
    fp_likelihood: float = Field(ge=0.0, le=1.0)
    fp_indicators: List[str]
    attack_indicators: List[str]
    revised_confidence: float = Field(ge=0.0, le=1.0)
    recommendation: str  # investigate_further/confirm_attack/likely_false_positive

class ThreatConclusion(BaseModel):
    is_attack: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_for_attack: List[str]
    evidence_against_attack: List[str]
    attack_narrative: str
    kill_chain_stage: str
    attacker_objective: str
    attacker_next_step: str
    systems_at_risk: List[str]
    business_impact: str  # low/medium/high/critical
    immediate_actions: List[str]
    short_term_actions: List[str]
    monitoring_actions: List[str]
    summary: str
