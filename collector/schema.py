"""
schema.py — Universal Event Schema

Every log from every source (on-premise, AWS, Azure) is normalized
into this standard NormalizedEvent format before entering the pipeline.
This is the core of Phase 3.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


@dataclass
class NormalizedEvent:
    """
    Universal security event — same fields regardless of source.

    On-premise logs, AWS CloudTrail, GuardDuty, and Azure Monitor
    are all converted to this format before Elasticsearch indexing.
    """

    # ── Core Identity ───────────────────────────────────────
    event_id: str = field(default_factory=lambda: f"EVT-{str(uuid.uuid4())[:8].upper()}")
    timestamp: str = ""                    # ISO 8601 UTC

    # ── Classification ──────────────────────────────────────
    environment: str = ""                 # "on-premise" | "aws" | "azure" | "gcp"
    event_type: str = ""                  # "failed_login" | "iam_privilege_escalation" | ...
    severity: str = "low"                 # "low" | "medium" | "high" | "critical"

    # ── Actor ───────────────────────────────────────────────
    user: str = ""
    source_ip: str = ""

    # ── Resource ────────────────────────────────────────────
    cloud_resource: Optional[str] = None  # ARN, bucket name, etc.
    source_host: Optional[str] = None     # On-prem hostname

    # ── MITRE ───────────────────────────────────────────────
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

    # ── Cross-env tracking ──────────────────────────────────
    session_id: Optional[str] = None
    cross_env_flag: bool = False

    # ── Raw ─────────────────────────────────────────────────
    raw_log: str = ""
    source_service: str = ""              # "cloudtrail" | "guardduty" | "wazuh" | "suricata"

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp or datetime.utcnow().isoformat() + "Z",
            "environment": self.environment,
            "event_type": self.event_type,
            "severity": self.severity,
            "user": self.user,
            "source_ip": self.source_ip,
            "cloud_resource": self.cloud_resource,
            "source_host": self.source_host,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "session_id": self.session_id,
            "cross_env_flag": self.cross_env_flag,
            "raw_log": self.raw_log,
            "source_service": self.source_service,
        }


# ── Event type constants ────────────────────────────────────
class EventType:
    # On-premise
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    LATERAL_MOVEMENT_SMB = "lateral_movement_smb"
    MALWARE_EXECUTION = "malware_execution"
    LARGE_DATA_TRANSFER = "large_data_transfer"
    PORT_SCAN = "port_scan"
    CREDENTIAL_FILE_ACCESS = "credential_file_access"
    # Cloud
    CLOUD_CONSOLE_LOGIN = "cloud_console_login"
    IAM_PRIVILEGE_ESCALATION = "iam_privilege_escalation"
    IAM_KEY_CREATED = "iam_key_created"
    S3_DATA_ACCESS = "s3_data_access"
    EC2_INSTANCE_LAUNCHED = "ec2_instance_launched"
    CLOUDTRAIL_DELETED = "cloudtrail_deleted"
    GUARDDUTY_FINDING = "guardduty_finding"
    UNUSUAL_LOCATION = "unusual_location"
