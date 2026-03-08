import json
import socket
import time
import os
import sys
import uuid
import requests
import argparse
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collector.schema import NormalizedEvent

load_dotenv()

# --- Configuration ---
LOGSTASH_HOST = "localhost"
LOGSTASH_PORT = 5000
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = "elastic"
ES_PASS = os.getenv("ELASTIC_PASSWORD", "changeme123")
API_BASE_URL = "http://localhost:8000"

# --- Common Identity ---
ATTACKER_IP = "185.192.69.42"
LEGIT_ADMIN_IP = "10.0.5.22"
TARGET_USER = "jsmith"
ADMIN_USER = "admin_user"
TARGET_HOST = "prod-web-server-01"

def get_es():
    return Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS), verify_certs=False)

def send_onprem_log(event):
    """Sends a host-based log to Logstash TCP input."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        payload = json.dumps(event) + "\n"
        sock.sendall(payload.encode("utf-8"))
        sock.close()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send on-prem log: {e}")
        return False

def inject_cloud_event(es, event):
    """Injects a cloud-based event directly into Elasticsearch."""
    try:
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        index_name = f"security-cloud-{today}"
        doc = event.to_dict()
        doc["@timestamp"] = doc["timestamp"]
        es.index(index=index_name, id=event.event_id, document=doc)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to inject cloud event: {e}")
        return False

def run_critical(es, now):
    """Scenario: High Confidence Cross-Env Attack (ART + SRT)"""
    print(f"[*] Mode: CRITICAL (Expected Confidence: 90%+)")
    
    # ART Host logs
    for i in range(10): # Noisy brute force
        ts = (now - timedelta(minutes=10) + timedelta(seconds=i*2)).isoformat() + "Z"
        send_onprem_log({
            "timestamp": ts, "environment": "on-premise", "user": TARGET_USER,
            "source_ip": ATTACKER_IP, "event_type": "failed_login", "severity": "low",
            "source_host": TARGET_HOST, "raw_log": f"sshd: Failed password for {TARGET_USER}"
        })

    # Success & Cred Theft
    send_onprem_log({
        "timestamp": (now - timedelta(minutes=9)).isoformat() + "Z",
        "environment": "on-premise", "user": TARGET_USER, "source_ip": ATTACKER_IP,
        "event_type": "successful_login", "severity": "medium", "source_host": TARGET_HOST,
        "raw_log": f"sshd: Accepted password for {TARGET_USER}"
    })
    send_onprem_log({
        "timestamp": (now - timedelta(minutes=8)).isoformat() + "Z",
        "environment": "on-premise", "user": TARGET_USER, "source_ip": ATTACKER_IP,
        "event_type": "credential_file_access", "severity": "high", "source_host": TARGET_HOST,
        "raw_log": f"audit: read /home/{TARGET_USER}/.aws/credentials"
    })

    # SRT Cloud logs
    inject_cloud_event(es, NormalizedEvent(
        timestamp=(now - timedelta(minutes=7)).isoformat() + "Z", environment="aws",
        event_type="cloud_console_login", severity="medium", user=TARGET_USER,
        source_ip=ATTACKER_IP, source_service="cloudtrail"
    ))
    inject_cloud_event(es, NormalizedEvent(
        timestamp=(now - timedelta(minutes=5)).isoformat() + "Z", environment="aws",
        event_type="iam_privilege_escalation", severity="critical", user=TARGET_USER,
        source_ip=ATTACKER_IP, source_service="cloudtrail"
    ))
    inject_cloud_event(es, NormalizedEvent(
        timestamp=(now - timedelta(minutes=2)).isoformat() + "Z", environment="aws",
        event_type="s3_data_access", severity="high", user=TARGET_USER,
        source_ip=ATTACKER_IP, source_service="cloudtrail", 
        raw_log="Bulk Download from corporate-secrets"
    ))

def run_stealth(es, now):
    """Scenario: Medium Confidence / Ambiguous Attack"""
    print(f"[*] Mode: STEALTH (Expected Confidence: 50-60%)")
    
    # 1. Single successful login from a VPN IP (unusual but not brute forced)
    send_onprem_log({
        "timestamp": (now - timedelta(minutes=12)).isoformat() + "Z",
        "environment": "on-premise", "user": "developer_alpha", "source_ip": "45.15.22.11",
        "event_type": "successful_login", "severity": "low", "source_host": "dev-box",
        "raw_log": "sshd: Accepted publickey for developer_alpha"
    })

    # 2. Unusual enumeration commands (not necessarily malicious)
    send_onprem_log({
        "timestamp": (now - timedelta(minutes=10)).isoformat() + "Z",
        "environment": "on-premise", "user": "developer_alpha", "source_ip": "45.15.22.11",
        "event_type": "port_scan", "severity": "low", "source_host": "dev-box",
        "raw_log": "Internal enumeration of 10.0.0.1/24"
    })

    # 3. AWS Resource Discovery
    inject_cloud_event(es, NormalizedEvent(
        timestamp=(now - timedelta(minutes=5)).isoformat() + "Z", environment="aws",
        event_type="guardduty_finding", severity="medium", user="developer_alpha",
        source_ip="45.15.22.11", source_service="guardduty",
        raw_log="Unusual CloudTrail enumeration detected"
    ))

def run_fp(es, now):
    """Scenario: Low Confidence / False Positive (Admin maintenance)"""
    print(f"[*] Mode: FALSE-POSITIVE (Expected Confidence: 10-20%)")
    
    # 1. Admin login from known Office IP
    send_onprem_log({
        "timestamp": (now - timedelta(minutes=15)).isoformat() + "Z",
        "environment": "on-premise", "user": ADMIN_USER, "source_ip": LEGIT_ADMIN_IP,
        "event_type": "successful_login", "severity": "low", "source_host": "admin-workstation",
        "raw_log": "Legitimate admin session started"
    })

    # 2. Automated S3 backup (many GetObjects but from legit source)
    inject_cloud_event(es, NormalizedEvent(
        timestamp=(now - timedelta(minutes=10)).isoformat() + "Z", environment="aws",
        event_type="s3_data_access", severity="low", user=ADMIN_USER,
        source_ip=LEGIT_ADMIN_IP, source_service="cloudtrail",
        raw_log="Automated backup sync: s3://backups/logs"
    ))
    
    # 3. Routine IAM Rotation
    inject_cloud_event(es, NormalizedEvent(
        timestamp=(now - timedelta(minutes=5)).isoformat() + "Z", environment="aws",
        event_type="iam_key_created", severity="low", user=ADMIN_USER,
        source_ip=LEGIT_ADMIN_IP, source_service="cloudtrail",
        raw_log="Rotated IAM keys for service-account-backup"
    ))

def main():
    parser = argparse.ArgumentParser(description="Multi-Scenario Demo Injector")
    parser.add_argument("--mode", choices=["critical", "stealth", "fp"], default="critical", 
                        help="Attack scenario to inject (default: critical)")
    parser.add_argument("--lookback", type=int, default=15, help="Lookback window for API trigger")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(f" 🚀 THREAT HUNTER - DEMO INJECTOR [{args.mode.upper()}]")
    print("="*60 + "\n")

    es = get_es()
    now = datetime.now(timezone.utc)

    if args.mode == "critical":
        run_critical(es, now)
    elif args.mode == "stealth":
        run_stealth(es, now)
    elif args.mode == "fp":
        run_fp(es, now)

    print("\n" + "="*60)
    print(" ✅ INJECTION COMPLETE")
    print(" 🔎 Triggering AI Investigation...")
    print("="*60 + "\n")

    try:
        resp = requests.post(f"{API_BASE_URL}/investigate", json={"lookback_minutes": args.lookback, "force_run": True})
        if resp.status_code == 200:
            print("[✓] Investigation started. Check dashboard in 10-20 seconds.")
        else:
            print(f"[✗] API Error: {resp.text}")
    except Exception as e:
        print(f"[✗] Network Error: {e}")

if __name__ == "__main__":
    main()
