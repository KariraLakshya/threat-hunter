"""
cloud_simulator.py — Fake cloud event generator for testing

Produces realistic NormalizedEvent objects that mirror what
aws_collector.py + normalizer.py would produce from real AWS APIs.

Used by:
    tests/inject_cloud_logs.py  — index into ES for E2E testing
    tests/test_agent.py         — unit test cross-env detection

Attack scenario simulated (cross-environment pivot):
    On-prem brute force (jsmith) → AWS console login (same IP) →
    IAM key created → S3 bulk download → CloudTrail deleted
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List

from .schema import NormalizedEvent, EventType


def _ts(offset_seconds: int = 0) -> str:
    """Return ISO timestamp offset from now."""
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def make_cross_env_cloud_chain(
    user: str = "jsmith",
    attacker_ip: str = "203.0.113.42",  # same IP as on-prem brute force
    internal_ip: str = "192.168.1.105",
    start_offset: int = 300,            # seconds after on-prem events
) -> List[NormalizedEvent]:
    """
    Generate a full cross-environment cloud attack chain for user `user`.
    All events use the same attacker_ip to tie them to the on-prem chain.

    Chain:
      1. AWS console login success (same IP as on-prem brute force)
      2. IAM access key created (persistence)
      3. S3 bulk object downloads (collection)
      4. CloudTrail trail deleted (defense evasion)
      5. GuardDuty: UnauthorizedAccess finding
    """
    t = start_offset

    events: List[NormalizedEvent] = [

        # ── 1. AWS Console Login (Initial Access — cloud pivot) ──────
        NormalizedEvent(
            event_id=f"EVT-CLD-{str(uuid.uuid4())[:8].upper()}",
            timestamp=_ts(t),
            environment="aws",
            event_type=EventType.CLOUD_CONSOLE_LOGIN,
            severity="high",
            user=user,
            source_ip=attacker_ip,
            cloud_resource="arn:aws:iam::123456789012:user/jsmith",
            raw_log='{"eventName":"ConsoleLogin","responseElements":{"ConsoleLogin":"Success"}}',
            source_service="cloudtrail",
        ),

        # ── 2. IAM Access Key Created (Persistence) ──────────────────
        NormalizedEvent(
            event_id=f"EVT-CLD-{str(uuid.uuid4())[:8].upper()}",
            timestamp=_ts(t + 120),
            environment="aws",
            event_type=EventType.IAM_KEY_CREATED,
            severity="high",
            user=user,
            source_ip=attacker_ip,
            cloud_resource=f"AKIA{'X' * 16}",
            raw_log='{"eventName":"CreateAccessKey","requestParameters":{"userName":"jsmith"}}',
            source_service="cloudtrail",
        ),

        # ── 3. S3 Bulk Downloads × 3 (Collection) ────────────────────
        *[
            NormalizedEvent(
                event_id=f"EVT-CLD-{str(uuid.uuid4())[:8].upper()}",
                timestamp=_ts(t + 180 + (i * 20)),
                environment="aws",
                event_type=EventType.S3_DATA_ACCESS,
                severity="medium",
                user=user,
                source_ip=attacker_ip,
                cloud_resource=f"arn:aws:s3:::company-sensitive-data/file{i}.zip",
                raw_log=f'{{"eventName":"GetObject","requestParameters":{{"bucketName":"company-sensitive-data","key":"file{i}.zip"}}}}',
                source_service="cloudtrail",
            )
            for i in range(3)
        ],

        # ── 4. CloudTrail Deleted (Defense Evasion) ──────────────────
        NormalizedEvent(
            event_id=f"EVT-CLD-{str(uuid.uuid4())[:8].upper()}",
            timestamp=_ts(t + 300),
            environment="aws",
            event_type=EventType.CLOUDTRAIL_DELETED,
            severity="critical",
            user=user,
            source_ip=attacker_ip,
            cloud_resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events",
            raw_log='{"eventName":"DeleteTrail","requestParameters":{"name":"management-events"}}',
            source_service="cloudtrail",
        ),

        # ── 5. GuardDuty Finding (corroborating signal) ───────────────
        NormalizedEvent(
            event_id=f"EVT-GD-{str(uuid.uuid4())[:8].upper()}",
            timestamp=_ts(t + 360),
            environment="aws",
            event_type=EventType.GUARDDUTY_FINDING,
            severity="critical",
            user=user,
            source_ip=attacker_ip,
            cloud_resource="arn:aws:iam::123456789012:user/jsmith",
            raw_log='{"Type":"UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B","Severity":8.0}',
            source_service="guardduty",
        ),
    ]

    return events
