"""
mitre_mapper.py — Phase 5: MITRE ATT&CK Mapping

Rule-based mapping of SecurityEvents to MITRE tactics and techniques.
Deterministic: no LLM involved — fast and zero hallucination risk.

Reference: https://attack.mitre.org/
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from correlation.correlation_engine import SecurityEvent
from collector.schema import EventType


# ── MITRE Mapping Tables ─────────────────────────────────────

ON_PREM_MAP: Dict[str, Dict] = {
    EventType.FAILED_LOGIN: {
        "tactic": "Credential Access",
        "technique": "T1110",
        "technique_name": "Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    EventType.SUCCESSFUL_LOGIN: {
        "tactic": "Initial Access",
        "technique": "T1078",
        "technique_name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    EventType.CREDENTIAL_FILE_ACCESS: {
        "tactic": "Credential Access",
        "technique": "T1552",
        "technique_name": "Unsecured Credentials",
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    EventType.LATERAL_MOVEMENT_SMB: {
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    EventType.MALWARE_EXECUTION: {
        "tactic": "Execution",
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    EventType.LARGE_DATA_TRANSFER: {
        "tactic": "Exfiltration",
        "technique": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    EventType.PORT_SCAN: {
        "tactic": "Reconnaissance",
        "technique": "T1046",
        "technique_name": "Network Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
}

CLOUD_MAP: Dict[str, Dict] = {
    EventType.IAM_PRIVILEGE_ESCALATION: {
        "tactic": "Privilege Escalation",
        "technique": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/004/",
    },
    EventType.IAM_KEY_CREATED: {
        "tactic": "Persistence",
        "technique": "T1098.001",
        "technique_name": "Account Manipulation: Additional Cloud Credentials",
        "url": "https://attack.mitre.org/techniques/T1098/001/",
    },
    EventType.S3_DATA_ACCESS: {
        "tactic": "Collection",
        "technique": "T1530",
        "technique_name": "Data from Cloud Storage",
        "url": "https://attack.mitre.org/techniques/T1530/",
    },
    EventType.EC2_INSTANCE_LAUNCHED: {
        "tactic": "Impact",
        "technique": "T1496",
        "technique_name": "Resource Hijacking",
        "url": "https://attack.mitre.org/techniques/T1496/",
    },
    EventType.CLOUDTRAIL_DELETED: {
        "tactic": "Defense Evasion",
        "technique": "T1562.008",
        "technique_name": "Impair Defenses: Disable Cloud Logs",
        "url": "https://attack.mitre.org/techniques/T1562/008/",
    },
    EventType.CLOUD_CONSOLE_LOGIN: {
        "tactic": "Initial Access",
        "technique": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/004/",
    },
    EventType.UNUSUAL_LOCATION: {
        "tactic": "Initial Access",
        "technique": "T1078",
        "technique_name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    EventType.GUARDDUTY_FINDING: {
        "tactic": "Discovery",
        "technique": "T1526",
        "technique_name": "Cloud Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1526/",
    },
}

# Merge both maps — cloud takes priority for cloud event types
FULL_MAP = {**ON_PREM_MAP, **CLOUD_MAP}

# MITRE tactic ordering (kill chain progression)
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass
class MappedEvent:
    """SecurityEvent enriched with MITRE ATT&CK information."""
    security_event: SecurityEvent
    tactic: str
    technique: str
    technique_name: str
    mitre_url: str
    kill_chain_stage: int   # position in TACTIC_ORDER

    def to_dict(self) -> dict:
        d = self.security_event.to_dict()
        d.update({
            "mitre_tactic": self.tactic,
            "mitre_technique": self.technique,
            "mitre_technique_name": self.technique_name,
            "mitre_url": self.mitre_url,
            "kill_chain_stage": self.kill_chain_stage,
        })
        return d


class MITREMapper:
    """
    Phase 5: Maps SecurityEvents → MITRE ATT&CK tactics and techniques.
    Also builds attack chain timelines.
    """

    def map_event(self, sec_event: SecurityEvent) -> MappedEvent:
        """Map a single SecurityEvent to MITRE."""
        mapping = FULL_MAP.get(sec_event.event_type)

        if mapping:
            tactic = mapping["tactic"]
            technique = mapping["technique"]
            name = mapping["technique_name"]
            url = mapping["url"]
        else:
            tactic = "Unknown"
            technique = "T0000"
            name = sec_event.event_type.replace("_", " ").title()
            url = "https://attack.mitre.org/"

        # Update the security event object too
        sec_event.mitre_tactic = tactic
        sec_event.mitre_technique = technique

        stage = TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else 0

        return MappedEvent(
            security_event=sec_event,
            tactic=tactic,
            technique=technique,
            technique_name=name,
            mitre_url=url,
            kill_chain_stage=stage,
        )

    def map_events(self, sec_events: List[SecurityEvent]) -> List[MappedEvent]:
        """Map a list of SecurityEvents to MITRE, sorted by kill chain stage."""
        mapped = [self.map_event(e) for e in sec_events]
        mapped.sort(key=lambda m: (m.security_event.first_seen, m.kill_chain_stage))
        return mapped

    def build_attack_chain(self, mapped_events: List[MappedEvent]) -> List[Dict]:
        """
        Build an attack chain timeline — tactic progression over time.

        Returns:
            List of dicts describing each step in the attack chain,
            ordered chronologically.
        """
        chain = []
        for i, me in enumerate(mapped_events):
            chain.append({
                "step": i + 1,
                "timestamp": me.security_event.first_seen,
                "event_type": me.security_event.event_type,
                "user": me.security_event.user,
                "source_ip": me.security_event.source_ip,
                "environment": me.security_event.environments,
                "tactic": me.tactic,
                "technique": me.technique,
                "technique_name": me.technique_name,
                "severity": me.security_event.severity,
                "count": me.security_event.count,
                "cross_environment": me.security_event.cross_environment,
                "mitre_url": me.mitre_url,
            })
        return chain

    def get_attack_summary(self, chain: List[Dict]) -> str:
        """Produce a human-readable summary of the attack chain."""
        if not chain:
            return "No attack chain."
        tactics = " → ".join(step["tactic"] for step in chain)
        techniques = " → ".join(step["technique"] for step in chain)
        users = list({step["user"] for step in chain})
        envs = list({env for step in chain for env in step.get("environment", [])})
        cross_env = any(step.get("cross_environment") for step in chain)

        summary = (
            f"Attack Chain ({len(chain)} steps):\n"
            f"  Tactics:    {tactics}\n"
            f"  Techniques: {techniques}\n"
            f"  Users:      {', '.join(users)}\n"
            f"  Environments: {', '.join(envs)}\n"
        )
        if cross_env:
            summary += "  ⚠️  CROSS-ENVIRONMENT ATTACK DETECTED\n"
        return summary
