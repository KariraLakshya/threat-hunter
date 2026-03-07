"""
aws_collector.py — Phase 2: AWS Cloud Log Ingestion

Polls AWS CloudTrail and GuardDuty every 5 minutes.
Normalizes events via Phase 3 normalizer.
Indexes to Elasticsearch under security-cloud-YYYY.MM.dd.

Usage (one-shot run):
    python -m collector.aws_collector

Usage (via Celery — Phase 2 scheduler):
    celery -A collector.tasks worker --beat --loglevel=info
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import boto3
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

from .schema import NormalizedEvent
from .normalizer import CloudTrailNormalizer, GuardDutyNormalizer

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("aws_collector")

# ── Configuration ───────────────────────────────────────────
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme123")
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
POLL_MINUTES = int(os.getenv("CLOUD_POLL_MINUTES", "5"))


def get_es_client() -> Elasticsearch:
    return Elasticsearch(
        ES_HOST,
        basic_auth=("elastic", ELASTIC_PASSWORD),
        verify_certs=False,
    )


def index_events(es: Elasticsearch, events: List[NormalizedEvent]) -> int:
    """Bulk-index normalized events into security-cloud-* daily index."""
    if not events:
        return 0

    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"security-cloud-{today}"

    actions = [
        {
            "_index": index_name,
            "_id": event.event_id,
            "_source": event.to_dict(),
        }
        for event in events
    ]

    success, errors = helpers.bulk(es, actions, raise_on_error=False)
    if errors:
        log.warning(f"Bulk index errors: {errors[:3]}")
    return success


# ── CloudTrail Collector ─────────────────────────────────────

class CloudTrailCollector:
    def __init__(self):
        self.client = boto3.client("cloudtrail", region_name=AWS_REGION)
        self.normalizer = CloudTrailNormalizer()

    def collect(self, lookback_minutes: int = POLL_MINUTES) -> List[NormalizedEvent]:
        """Pull CloudTrail events from the last N minutes."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=lookback_minutes)

        log.info(f"[CloudTrail] Pulling events {start_time.isoformat()} → {end_time.isoformat()}")

        events = []
        paginator = self.client.get_paginator("lookup_events")

        try:
            pages = paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={"MaxItems": 1000, "PageSize": 50},
            )
            for page in pages:
                for raw_event in page.get("Events", []):
                    # CloudTrail wraps the actual event in CloudTrailEvent (JSON string)
                    cloud_trail_json = raw_event.get("CloudTrailEvent", "{}")
                    try:
                        detail = json.loads(cloud_trail_json)
                    except json.JSONDecodeError:
                        detail = raw_event

                    normalized = self.normalizer.normalize(detail)
                    if normalized:
                        events.append(normalized)

        except Exception as e:
            log.error(f"[CloudTrail] Collection failed: {e}")

        log.info(f"[CloudTrail] Collected {len(events)} events")
        return events


# ── GuardDuty Collector ──────────────────────────────────────

class GuardDutyCollector:
    def __init__(self):
        self.client = boto3.client("guardduty", region_name=AWS_REGION)
        self.normalizer = GuardDutyNormalizer()
        self._detector_id: Optional[str] = None

    def _get_detector_id(self) -> Optional[str]:
        if self._detector_id:
            return self._detector_id
        try:
            detectors = self.client.list_detectors()
            detector_ids = detectors.get("DetectorIds", [])
            if detector_ids:
                self._detector_id = detector_ids[0]
                return self._detector_id
            log.warning("[GuardDuty] No detectors found. Enable GuardDuty in AWS Console.")
        except Exception as e:
            log.error(f"[GuardDuty] Cannot get detector ID: {e}")
        return None

    def collect(self, lookback_minutes: int = POLL_MINUTES) -> List[NormalizedEvent]:
        """Pull GuardDuty findings updated in the last N minutes."""
        detector_id = self._get_detector_id()
        if not detector_id:
            return []

        since = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
        log.info(f"[GuardDuty] Pulling findings updated since {since}")

        try:
            # List finding IDs updated since lookback time
            paginator = self.client.get_paginator("list_findings")
            pages = paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "updatedAt": {
                            "GreaterThanOrEqual": int(
                                (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).timestamp() * 1000
                            )
                        }
                    }
                },
                PaginationConfig={"MaxItems": 100},
            )

            finding_ids = []
            for page in pages:
                finding_ids.extend(page.get("FindingIds", []))

            if not finding_ids:
                log.info("[GuardDuty] No new findings.")
                return []

            # Get full finding details (max 50 per call)
            events = []
            for i in range(0, len(finding_ids), 50):
                batch = finding_ids[i:i + 50]
                response = self.client.get_findings(DetectorId=detector_id, FindingIds=batch)
                for finding in response.get("Findings", []):
                    normalized = self.normalizer.normalize(finding)
                    if normalized:
                        events.append(normalized)

            log.info(f"[GuardDuty] Collected {len(events)} findings")
            return events

        except Exception as e:
            log.error(f"[GuardDuty] Collection failed: {e}")
            return []


# ── Main collection run ──────────────────────────────────────

def run_collection(lookback: int = POLL_MINUTES):
    """Run one full collection cycle: CloudTrail + GuardDuty → Elasticsearch."""
    log.info("=" * 60)
    log.info(f"  AWS Cloud Log Collector — starting run (lookback: {lookback}m)")
    log.info("=" * 60)

    es = get_es_client()

    # Verify ES connection
    try:
        info = es.info()
        log.info(f"[ES] Connected — cluster: {info['cluster_name']}")
    except Exception as e:
        log.error(f"[ES] Cannot connect: {e}")
        return

    all_events: List[NormalizedEvent] = []

    # Collect CloudTrail
    try:
        ct = CloudTrailCollector()
        all_events.extend(ct.collect(lookback_minutes=lookback))
    except Exception as e:
        log.error(f"CloudTrail collector error: {e}")

    # Collect GuardDuty
    try:
        gd = GuardDutyCollector()
        all_events.extend(gd.collect(lookback_minutes=lookback))
    except Exception as e:
        log.error(f"GuardDuty collector error: {e}")

    # Index everything
    indexed = index_events(es, all_events)
    log.info(f"[ES] Indexed {indexed} events to security-cloud-*")
    log.info("=" * 60)
    return indexed


if __name__ == "__main__":
    import sys
    lookback = int(sys.argv[1]) if len(sys.argv) > 1 else POLL_MINUTES
    run_collection(lookback)
