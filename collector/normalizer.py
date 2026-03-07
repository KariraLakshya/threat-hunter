"""
normalizer.py — Phase 3: Normalization Layer

Converts raw logs from ANY source into NormalizedEvent objects.
Sources: AWS CloudTrail, AWS GuardDuty, Azure Monitor (stub), and
raw on-premise events already tagged by Logstash.

Rule: deterministic mapping only — no LLM involved here.
"""

import re
from datetime import datetime, timezone
from typing import Optional
from .schema import NormalizedEvent, EventType


class CloudTrailNormalizer:
    """
    Converts a raw AWS CloudTrail event dict into a NormalizedEvent.
    CloudTrail API reference: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/
    """

    # API call → our internal event_type mapping
    EVENT_TYPE_MAP = {
        "ConsoleLogin": EventType.CLOUD_CONSOLE_LOGIN,
        "AttachUserPolicy": EventType.IAM_PRIVILEGE_ESCALATION,
        "AttachRolePolicy": EventType.IAM_PRIVILEGE_ESCALATION,
        "PutUserPolicy": EventType.IAM_PRIVILEGE_ESCALATION,
        "CreateAccessKey": EventType.IAM_KEY_CREATED,
        "GetObject": None,          # counted separately — see normalize()
        "DeleteTrail": EventType.CLOUDTRAIL_DELETED,
        "StopLogging": EventType.CLOUDTRAIL_DELETED,
        "RunInstances": EventType.EC2_INSTANCE_LAUNCHED,
    }

    # API calls that get severity boost based on context
    HIGH_SEVERITY_CALLS = {
        "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
        "DeleteTrail", "StopLogging",
    }

    def normalize(self, raw: dict) -> Optional[NormalizedEvent]:
        try:
            event_name = raw.get("eventName", "")
            user_identity = raw.get("userIdentity", {})
            source_ip = raw.get("sourceIPAddress", "")
            timestamp = raw.get("eventTime", datetime.now(timezone.utc).isoformat())
            resources = raw.get("resources", [])

            # Determine user
            user = (
                user_identity.get("userName")
                or user_identity.get("sessionContext", {})
                    .get("sessionIssuer", {}).get("userName")
                or user_identity.get("principalId", "unknown")
            )

            # Determine event type
            event_type = self.EVENT_TYPE_MAP.get(event_name)
            if event_type is None:
                # Unknown API call — still record it
                event_type = f"aws_{event_name.lower()}"

            # Determine cloud resource
            cloud_resource = None
            if resources:
                cloud_resource = resources[0].get("ARN") or resources[0].get("resourceName")
            elif raw.get("requestParameters"):
                params = raw["requestParameters"]
                cloud_resource = (
                    params.get("bucketName")
                    or params.get("roleName")
                    or params.get("userName")
                )

            # Severity
            severity = "medium"
            if event_name in self.HIGH_SEVERITY_CALLS:
                severity = "high"
            elif event_name in {"CreateAccessKey", "RunInstances"}:
                severity = "medium"

            # Failed console login → low severity but flag it
            if event_name == "ConsoleLogin":
                response = raw.get("responseElements", {}) or {}
                if response.get("ConsoleLogin") == "Failure":
                    event_type = EventType.FAILED_LOGIN
                    severity = "low"

            return NormalizedEvent(
                timestamp=timestamp,
                environment="aws",
                event_type=event_type,
                severity=severity,
                user=user,
                source_ip=source_ip,
                cloud_resource=cloud_resource,
                raw_log=str(raw),
                source_service="cloudtrail",
            )

        except Exception as e:
            print(f"[normalizer] CloudTrail parse error: {e}")
            return None


class GuardDutyNormalizer:
    """
    Converts a raw AWS GuardDuty finding dict into a NormalizedEvent.
    """

    SEVERITY_MAP = {
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "critical",
    }

    # GuardDuty finding type prefixes → event types
    FINDING_TYPE_MAP = {
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B": EventType.CLOUD_CONSOLE_LOGIN,
        "PrivilegeEscalation:IAMUser":                      EventType.IAM_PRIVILEGE_ESCALATION,
        "Persistence:IAMUser/UserPermissions":               EventType.IAM_KEY_CREATED,
        "Exfiltration:S3":                                   EventType.S3_DATA_ACCESS,
        "CryptoCurrency:EC2":                                EventType.EC2_INSTANCE_LAUNCHED,
        "UnauthorizedAccess:EC2":                            EventType.UNUSUAL_LOCATION,
    }

    def normalize(self, finding: dict) -> Optional[NormalizedEvent]:
        try:
            finding_type = finding.get("Type", "")
            severity_num = finding.get("Severity", 1.0)
            title = finding.get("Title", "")
            description = finding.get("Description", "")
            resource = finding.get("Resource", {})
            service = finding.get("Service", {})
            updated_at = finding.get("UpdatedAt", datetime.now(timezone.utc).isoformat())

            # Map numeric severity (1-10) to our labels
            if severity_num >= 7.0:
                severity = "critical"
            elif severity_num >= 4.0:
                severity = "high"
            elif severity_num >= 2.0:
                severity = "medium"
            else:
                severity = "low"

            # Determine event type from finding type prefix
            event_type = EventType.GUARDDUTY_FINDING
            for prefix, etype in self.FINDING_TYPE_MAP.items():
                if finding_type.startswith(prefix):
                    event_type = etype
                    break

            # Extract actor
            action = service.get("Action", {})
            source_ip = (
                action.get("NetworkConnectionAction", {}).get("RemoteIpDetails", {}).get("IpAddressV4")
                or action.get("AwsApiCallAction", {}).get("RemoteIpDetails", {}).get("IpAddressV4")
                or "unknown"
            )

            user = "unknown"
            if "AccessKeyDetails" in resource:
                user = resource["AccessKeyDetails"].get("UserName", "unknown")
            elif "InstanceDetails" in resource:
                user = resource["InstanceDetails"].get("InstanceId", "unknown")

            cloud_resource = (
                resource.get("S3BucketDetails", [{}])[0].get("Name")
                or resource.get("InstanceDetails", {}).get("InstanceId")
                or resource.get("AccessKeyDetails", {}).get("AccessKeyId")
            )

            return NormalizedEvent(
                timestamp=updated_at,
                environment="aws",
                event_type=event_type,
                severity=severity,
                user=user,
                source_ip=source_ip,
                cloud_resource=cloud_resource,
                raw_log=str(finding),
                source_service="guardduty",
            )

        except Exception as e:
            print(f"[normalizer] GuardDuty parse error: {e}")
            return None


class AzureNormalizer:
    """
    Stub normalizer for Azure Monitor sign-in and activity logs.
    Expand in Phase 2.5 if Azure is in scope.
    """

    def normalize(self, raw: dict) -> Optional[NormalizedEvent]:
        try:
            status = raw.get("status", {})
            result = status.get("value", "")
            user = raw.get("userPrincipalName", raw.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "unknown"))
            source_ip = raw.get("ipAddress", "unknown")
            timestamp = raw.get("createdDateTime", datetime.now(timezone.utc).isoformat())

            if result == "failure":
                event_type = EventType.FAILED_LOGIN
                severity = "low"
            else:
                event_type = EventType.SUCCESSFUL_LOGIN
                severity = "medium"

            return NormalizedEvent(
                timestamp=timestamp,
                environment="azure",
                event_type=event_type,
                severity=severity,
                user=user,
                source_ip=source_ip,
                raw_log=str(raw),
                source_service="azure_monitor",
            )

        except Exception as e:
            print(f"[normalizer] Azure parse error: {e}")
            return None
