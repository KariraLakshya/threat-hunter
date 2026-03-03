"""
inject_logs.py — Send sample security events to Logstash TCP input.

Usage:
    python tests/inject_logs.py

Sends a mix of failed logins, successful logins, and other events
to Logstash on localhost:5000 (TCP/JSON). Used to verify Phase 1
log ingestion pipeline.
"""

import json
import socket
import time
from datetime import datetime, timezone, timedelta

LOGSTASH_HOST = "localhost"
LOGSTASH_PORT = 5000

# ── Sample events simulating an attack scenario ────────────
def generate_sample_events():
    """Generate a realistic brute-force → login → credential theft scenario."""
    now = datetime.now(timezone.utc)
    attacker_ip = "203.0.113.42"
    target_user = "jsmith"

    events = []

    # 1) Brute force: 10 failed SSH logins
    for i in range(10):
        events.append({
            "timestamp": (now + timedelta(seconds=i * 2)).isoformat(),
            "environment": "on-premise",
            "user": target_user,
            "source_ip": attacker_ip,
            "event_type": "failed_login",
            "severity": "low",
            "message": f"Failed password for {target_user} from {attacker_ip} port 22 ssh2",
            "source_host": "prod-web-01",
            "raw_log": f"Feb 26 10:0{i}:00 prod-web-01 sshd[12345]: Failed password for {target_user} from {attacker_ip} port 54321 ssh2"
        })

    # 2) Successful login after brute force
    events.append({
        "timestamp": (now + timedelta(seconds=25)).isoformat(),
        "environment": "on-premise",
        "user": target_user,
        "source_ip": attacker_ip,
        "event_type": "successful_login",
        "severity": "medium",
        "message": f"Accepted password for {target_user} from {attacker_ip} port 22 ssh2",
        "source_host": "prod-web-01",
        "raw_log": f"Feb 26 10:05:25 prod-web-01 sshd[12345]: Accepted password for {target_user} from {attacker_ip} port 54321 ssh2"
    })

    # 3) Credential file access
    events.append({
        "timestamp": (now + timedelta(seconds=30)).isoformat(),
        "environment": "on-premise",
        "user": target_user,
        "source_ip": attacker_ip,
        "event_type": "credential_file_access",
        "severity": "high",
        "message": f"User {target_user} accessed /home/{target_user}/.aws/credentials",
        "source_host": "prod-web-01",
        "raw_log": f"audit: user={target_user} action=open path=/home/{target_user}/.aws/credentials"
    })

    # 4) Port scan from internal host
    events.append({
        "timestamp": (now + timedelta(seconds=40)).isoformat(),
        "environment": "on-premise",
        "user": "unknown",
        "source_ip": "192.168.1.55",
        "event_type": "port_scan",
        "severity": "medium",
        "message": "Nmap scan detected from 192.168.1.55 targeting 192.168.1.0/24",
        "source_host": "ids-sensor-01",
        "raw_log": "suricata alert: ET SCAN Nmap -sS"
    })

    # 5) Lateral movement via SMB
    events.append({
        "timestamp": (now + timedelta(seconds=50)).isoformat(),
        "environment": "on-premise",
        "user": target_user,
        "source_ip": "192.168.1.105",
        "event_type": "lateral_movement_smb",
        "severity": "high",
        "message": f"SMB admin share accessed: \\\\192.168.1.200\\C$ by {target_user}",
        "source_host": "prod-web-01",
        "raw_log": f"Wazuh alert: SMB share access to admin share by {target_user}"
    })

    # 6) Large outbound data transfer (exfiltration)
    events.append({
        "timestamp": (now + timedelta(seconds=60)).isoformat(),
        "environment": "on-premise",
        "user": target_user,
        "source_ip": "192.168.1.105",
        "event_type": "large_data_transfer",
        "severity": "critical",
        "message": "Outbound transfer of 2.4 GB to external IP 198.51.100.10",
        "source_host": "prod-web-01",
        "raw_log": "netflow: src=192.168.1.105 dst=198.51.100.10 bytes=2400000000 duration=180s"
    })

    return events


def send_events(events):
    """Send JSON events to Logstash TCP input."""
    print(f"\n{'='*60}")
    print(f"  Threat Hunter — Sample Log Injector")
    print(f"  Target: {LOGSTASH_HOST}:{LOGSTASH_PORT}")
    print(f"  Events: {len(events)}")
    print(f"{'='*60}\n")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        print(f"[✓] Connected to Logstash at {LOGSTASH_HOST}:{LOGSTASH_PORT}\n")

        for i, event in enumerate(events):
            payload = json.dumps(event) + "\n"
            sock.sendall(payload.encode("utf-8"))
            severity_icon = {
                "low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"
            }.get(event.get("severity", ""), "⚪")

            print(f"  [{i+1:02d}/{len(events):02d}] {severity_icon} {event['event_type']:30s} | {event.get('user', 'n/a'):10s} | {event.get('source_ip', 'n/a')}")
            time.sleep(0.2)

        sock.close()
        print(f"\n[✓] All {len(events)} events sent successfully.")
        print(f"[→] Check Elasticsearch: curl http://localhost:9200/security-onprem-*/_count -u elastic:changeme123")
        print(f"[→] Check Kibana: http://localhost:5601 → Discover → security-onprem-*\n")

    except ConnectionRefusedError:
        print(f"[✗] Connection refused. Is Logstash running on {LOGSTASH_HOST}:{LOGSTASH_PORT}?")
        print(f"    Run: docker compose up -d")
    except Exception as e:
        print(f"[✗] Error: {e}")


if __name__ == "__main__":
    events = generate_sample_events()
    send_events(events)
