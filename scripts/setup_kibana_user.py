"""
setup_kibana_user.py — Set the kibana_system password in Elasticsearch.

Run this ONCE after Elasticsearch is up and healthy.
The kibana_system user is a built-in ES user that Kibana uses
to communicate with Elasticsearch.

Usage:
    python scripts/setup_kibana_user.py
"""

import os
import sys
import requests
import time

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme123")
KIBANA_PASSWORD = os.getenv("KIBANA_PASSWORD", "changeme123")


def wait_for_es(max_retries=30, delay=5):
    """Wait for Elasticsearch to be healthy."""
    print(f"[...] Waiting for Elasticsearch at {ES_HOST}")
    for i in range(max_retries):
        try:
            r = requests.get(
                f"{ES_HOST}/_cluster/health",
                auth=("elastic", ELASTIC_PASSWORD),
                timeout=5
            )
            if r.status_code == 200:
                status = r.json().get("status", "unknown")
                print(f"[✓] Elasticsearch is up — cluster status: {status}")
                return True
        except requests.ConnectionError:
            pass
        print(f"    Retry {i+1}/{max_retries}...")
        time.sleep(delay)
    print("[✗] Elasticsearch did not become healthy in time.")
    return False


def set_kibana_password():
    """Set the kibana_system user's password."""
    print(f"\n[...] Setting kibana_system password")
    r = requests.post(
        f"{ES_HOST}/_security/user/kibana_system/_password",
        auth=("elastic", ELASTIC_PASSWORD),
        json={"password": KIBANA_PASSWORD},
        headers={"Content-Type": "application/json"},
        timeout=10
    )
    if r.status_code == 200:
        print("[✓] kibana_system password set successfully.")
        return True
    else:
        print(f"[✗] Failed: {r.status_code} — {r.text}")
        return False


def create_index_template():
    """Create an index template for security-onprem-* with proper mappings."""
    print(f"\n[...] Creating index template 'security-onprem'")
    template = {
        "index_patterns": ["security-onprem-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "ingested_at": {"type": "date"},
                    "environment": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "source_host": {"type": "keyword"},
                    "event_id": {"type": "keyword"},
                    "message": {"type": "text"},
                    "raw_log": {"type": "text"},
                    "cloud_resource": {"type": "keyword"},
                    "wazuh_rule_id": {"type": "keyword"},
                    "wazuh_description": {"type": "text"}
                }
            }
        },
        "priority": 100
    }
    r = requests.put(
        f"{ES_HOST}/_index_template/security-onprem",
        auth=("elastic", ELASTIC_PASSWORD),
        json=template,
        headers={"Content-Type": "application/json"},
        timeout=10
    )
    if r.status_code == 200:
        print("[✓] Index template 'security-onprem' created.")
        return True
    else:
        print(f"[✗] Failed: {r.status_code} — {r.text}")
        return False


if __name__ == "__main__":
    if not wait_for_es():
        sys.exit(1)

    ok1 = set_kibana_password()
    ok2 = create_index_template()

    print("\n" + "=" * 60)
    if ok1 and ok2:
        print("  Setup complete! Kibana should now connect successfully.")
        print("  Open Kibana: http://localhost:5601")
        print("  Login: elastic / " + ELASTIC_PASSWORD)
    else:
        print("  Setup had errors — check output above.")
    print("=" * 60)
