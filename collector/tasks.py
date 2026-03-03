"""
tasks.py — Phase 2: Celery Task Scheduler

Schedules cloud log collection to run every 5 minutes automatically.
Uses Redis as the message broker and result backend.

Start with:
    celery -A collector.tasks worker --beat --loglevel=info

Or just beat (scheduler) separately:
    celery -A collector.tasks beat --loglevel=info
"""

import os
from celery import Celery
from celery.schedules import crontab
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
POLL_MINUTES = int(os.getenv("CLOUD_POLL_MINUTES", "5"))

# ── Celery app ───────────────────────────────────────────────
app = Celery(
    "threat_hunter",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["collector.tasks"],
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Beat schedule: run cloud collection every 5 minutes
    beat_schedule={
        "collect-aws-logs": {
            "task": "collector.tasks.collect_aws_logs",
            "schedule": POLL_MINUTES * 60,  # seconds
            "options": {"expires": POLL_MINUTES * 60 - 30},
        },
    },
)


@app.task(bind=True, max_retries=3, default_retry_delay=60)
def collect_aws_logs(self):
    """
    Celery task: run one full AWS collection cycle.
    Retries up to 3 times on failure (60s delay between retries).
    """
    try:
        from .aws_collector import run_collection
        count = run_collection()
        return {"status": "ok", "indexed": count}
    except Exception as exc:
        raise self.retry(exc=exc)
