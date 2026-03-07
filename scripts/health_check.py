"""
health_check.py — Verify all Phase 1 services are running correctly.

Usage:
    python scripts/health_check.py
"""

import os
import sys
import requests
import subprocess

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme123")


def check_elasticsearch():
    """Check Elasticsearch cluster health."""
    print("\n── Elasticsearch ──")
    try:
        r = requests.get(
            f"{ES_HOST}/_cluster/health",
            auth=("elastic", ELASTIC_PASSWORD),
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            status = data["status"]
            icon = {"green": "🟢", "yellow": "🟡", "red": "🔴"}.get(status, "⚪")
            print(f"  {icon} Cluster status: {status}")
            print(f"     Nodes: {data['number_of_nodes']}")
            print(f"     Active shards: {data['active_shards']}")
            return True
        else:
            print(f"  🔴 HTTP {r.status_code}")
            return False
    except Exception as e:
        print(f"  🔴 Not reachable: {e}")
        return False




def check_logstash():
    """Check Logstash by verifying the container is running."""
    print("\n── Logstash ──")
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", "threat-hunter-logstash"],
            capture_output=True, text=True, timeout=10
        )
        status = result.stdout.strip()
        if status == "running":
            print(f"  🟢 Container status: {status}")
            return True
        else:
            print(f"  🔴 Container status: {status}")
            return False
    except Exception as e:
        print(f"  🔴 Error: {e}")
        return False


def check_wazuh():
    """Check Wazuh Manager by verifying the container is running."""
    print("\n── Wazuh Manager ──")
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", "threat-hunter-wazuh"],
            capture_output=True, text=True, timeout=10
        )
        status = result.stdout.strip()
        if status == "running":
            print(f"  🟢 Container status: {status}")
            return True
        else:
            print(f"  🔴 Container status: {status}")
            return False
    except Exception as e:
        print(f"  🔴 Error: {e}")
        return False


def check_indexed_docs():
    """Check if security-onprem-* has any documents."""
    print("\n── Indexed Documents ──")
    try:
        r = requests.get(
            f"{ES_HOST}/security-onprem-*/_count",
            auth=("elastic", ELASTIC_PASSWORD),
            timeout=5
        )
        if r.status_code == 200:
            count = r.json().get("count", 0)
            icon = "🟢" if count > 0 else "🟡"
            print(f"  {icon} security-onprem-* doc count: {count}")
            return count > 0
        elif r.status_code == 404:
            print(f"  🟡 Index security-onprem-* does not exist yet (no logs ingested)")
            return False
        else:
            print(f"  🔴 HTTP {r.status_code}")
            return False
    except Exception as e:
        print(f"  🔴 Error: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("  Threat Hunter — Phase 1 Health Check")
    print("=" * 60)

    results = {
        "Elasticsearch": check_elasticsearch(),
        "Logstash": check_logstash(),
        "Wazuh Manager": check_wazuh(),
        "Indexed Docs": check_indexed_docs(),
    }

    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    all_ok = True
    for name, ok in results.items():
        icon = "✅" if ok else "❌"
        print(f"  {icon} {name}")
        if not ok and name != "Indexed Docs":
            all_ok = False

    if all_ok:
        print("\n  ✅ All core services are healthy!")
        if not results["Indexed Docs"]:
            print("  ℹ️  No docs yet — run: python tests/inject_logs.py")
    else:
        print("\n  ⚠️  Some services are not healthy. Check docker compose logs.")

    print("=" * 60)
