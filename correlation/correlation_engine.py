"""
correlation_engine.py — Phase 4: Correlation Engine

Groups normalized events by identity (user/IP) within a time window,
detects thresholds, and identifies cross-environment attack patterns.

This is the key feature: detecting the same user acting suspiciously
on BOTH on-premise systems AND cloud within the same time window.
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collector.schema import NormalizedEvent, EventType

log = logging.getLogger("correlation_engine")


# ── Thresholds ──────────────────────────────────────────────
THRESHOLDS = {
    EventType.FAILED_LOGIN:             5,    # brute force
    EventType.S3_DATA_ACCESS:           100,  # bulk data theft
    EventType.IAM_PRIVILEGE_ESCALATION: 1,    # always suspicious
    EventType.EC2_INSTANCE_LAUNCHED:    3,    # cryptojacking
    EventType.PORT_SCAN:                20,   # recon
    EventType.CLOUDTRAIL_DELETED:       1,    # defense evasion
    EventType.LATERAL_MOVEMENT_SMB:     2,    # lateral movement
    EventType.MALWARE_EXECUTION:        1,    # always alert
    EventType.LARGE_DATA_TRANSFER:      1,    # exfiltration
}

WINDOW_MINUTES = 10   # time window for correlation


@dataclass
class SecurityEvent:
    """
    A correlated security event — ready for MITRE mapping.
    Produced by the correlation engine when thresholds are exceeded.
    """
    session_id: str
    user: str
    source_ip: str
    event_type: str
    count: int
    severity: str
    environments: List[str]            # ["on-premise", "aws"] for cross-env
    cross_environment: bool = False
    raw_events: List[NormalizedEvent] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    incident_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "user": self.user,
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "count": self.count,
            "severity": self.severity,
            "environments": self.environments,
            "cross_environment": self.cross_environment,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "incident_id": self.incident_id,
        }


class CorrelationEngine:
    """
    Phase 4: Groups events → detects patterns → produces SecurityEvents.

    Algorithm:
    1. Bucket events by (user, event_type) within the time window
    2. Check if count exceeds threshold for the event type
    3. After grouping, check cross-environment: same user in on-prem + cloud
    4. Cross-env matches escalate to CRITICAL
    """

    def __init__(self, window_minutes: int = WINDOW_MINUTES):
        self.window = timedelta(minutes=window_minutes)

    def _parse_ts(self, ts: str) -> datetime:
        """Parse ISO timestamp to UTC-aware datetime."""
        try:
            ts = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.now(timezone.utc)

    def _severity_escalate(self, base: str, cross_env: bool) -> str:
        """Escalate severity for cross-environment attacks."""
        order = ["low", "medium", "high", "critical"]
        idx = order.index(base) if base in order else 0
        if cross_env:
            idx = min(idx + 2, len(order) - 1)
        return order[idx]

    def _make_session_id(self, user: str, event_type: str) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        return f"SES-{user[:6].upper()}-{event_type[:6].upper()}-{ts}"

    def correlate(self, events: List[NormalizedEvent]) -> List[SecurityEvent]:
        """
        Main correlation loop.

        Args:
            events: Raw normalized events (from ES query or streaming)
        Returns:
            List of SecurityEvent objects that exceeded thresholds
        """
        if not events:
            return []

        now = datetime.now(timezone.utc)
        window_start = now - self.window

        # Filter to time window
        in_window = [
            e for e in events
            if self._parse_ts(e.timestamp) >= window_start
        ]

        log.info(f"[Correlation] {len(in_window)}/{len(events)} events in {self.window} window")

        # ── Step 1: Group by (user, event_type) ───────────────
        # Key: (user, event_type)  → list of events
        groups: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
        for event in in_window:
            key = (event.user or "unknown", event.event_type)
            groups[key].append(event)

        # ── Step 2: Apply thresholds ───────────────────────────
        security_events: List[SecurityEvent] = []
        user_env_map: Dict[str, set] = defaultdict(set)  # user → {environments}

        for (user, event_type), group in groups.items():
            threshold = THRESHOLDS.get(event_type, 999)
            if len(group) < threshold:
                continue

            # Get environments involved
            envs = list({e.environment for e in group if e.environment})
            for env in envs:
                user_env_map[user].add(env)

            # Get IPs (most common one)
            ips = [e.source_ip for e in group if e.source_ip]
            source_ip = max(set(ips), key=ips.count) if ips else "unknown"

            # Get severity (worst in group)
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            base_severity = max(
                (e.severity for e in group),
                key=lambda s: severity_order.get(s, 0),
                default="low"
            )

            # Timestamps
            timestamps = sorted(self._parse_ts(e.timestamp) for e in group)
            first_seen = timestamps[0].isoformat()
            last_seen = timestamps[-1].isoformat()

            sec_event = SecurityEvent(
                session_id=self._make_session_id(user, event_type),
                user=user,
                source_ip=source_ip,
                event_type=event_type,
                count=len(group),
                severity=base_severity,
                environments=envs,
                raw_events=group,
                first_seen=first_seen,
                last_seen=last_seen,
            )
            security_events.append(sec_event)

        # ── Step 3: Cross-environment detection ────────────────
        for sec_event in security_events:
            user = sec_event.user
            all_user_envs = user_env_map.get(user, set())
            has_onprem = any(e.startswith("on-") for e in all_user_envs)
            has_cloud = any(e in ("aws", "azure", "gcp") for e in all_user_envs)

            if has_onprem and has_cloud:
                sec_event.cross_environment = True
                sec_event.environments = list(all_user_envs)
                sec_event.severity = self._severity_escalate(
                    sec_event.severity, cross_env=True
                )
                log.warning(
                    f"[Correlation] ⚠️  CROSS-ENV ATTACK: user={user} "
                    f"envs={sec_event.environments} severity={sec_event.severity}"
                )

        log.info(
            f"[Correlation] Produced {len(security_events)} SecurityEvents "
            f"({sum(1 for e in security_events if e.cross_environment)} cross-env)"
        )
        return security_events
