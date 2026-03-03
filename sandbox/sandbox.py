"""
sandbox.py — Phase 7: VirusTotal Sandbox Verification

Checks file hashes, IP addresses, and URLs against VirusTotal API.
Results are fed back to the AI agent to boost/reduce confidence.

Free tier: 4 requests/min — sufficient for development.
"""

import os
import time
import logging
from typing import Dict, Optional
import requests
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("sandbox")

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"
VT_MALICIOUS_THRESHOLD_IP = 5
VT_MALICIOUS_THRESHOLD_HASH = 3


class SandboxChecker:
    """
    Phase 7: VirusTotal integration for threat intelligence enrichment.
    """

    def __init__(self):
        self.headers = {"x-apikey": VT_API_KEY}
        self._last_call = 0.0

    def _rate_limit(self):
        """Enforce 4 req/min free tier limit (15s between calls)."""
        elapsed = time.time() - self._last_call
        if elapsed < 15:
            time.sleep(15 - elapsed)
        self._last_call = time.time()

    def _vt_get(self, endpoint: str) -> Optional[Dict]:
        if not VT_API_KEY:
            log.warning("[Sandbox] VT_API_KEY not set — skipping check")
            return None
        self._rate_limit()
        try:
            r = requests.get(f"{VT_BASE}/{endpoint}", headers=self.headers, timeout=15)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 404:
                return {"not_found": True}
            else:
                log.warning(f"[Sandbox] VT API error {r.status_code}: {r.text[:200]}")
                return None
        except Exception as e:
            log.error(f"[Sandbox] Request failed: {e}")
            return None

    def check_ip(self, ip: str) -> Dict:
        """Check an IP address reputation."""
        log.info(f"[Sandbox] Checking IP: {ip}")
        data = self._vt_get(f"ip_addresses/{ip}")
        if not data or data.get("not_found"):
            return {"ip": ip, "verdict": "unknown", "malicious_count": 0, "details": "Not in VT database"}

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        verdict = "malicious" if malicious >= VT_MALICIOUS_THRESHOLD_IP else (
            "suspicious" if malicious > 0 else "clean"
        )
        return {
            "ip": ip,
            "verdict": verdict,
            "malicious_count": malicious,
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "details": f"{malicious} AV engines flagged this IP",
        }

    def check_hash(self, file_hash: str) -> Dict:
        """Check a file hash (MD5/SHA1/SHA256)."""
        log.info(f"[Sandbox] Checking hash: {file_hash}")
        data = self._vt_get(f"files/{file_hash}")
        if not data or data.get("not_found"):
            return {"hash": file_hash, "verdict": "unknown", "malicious_count": 0, "details": "Not in VT database"}

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        verdict = "malicious" if malicious >= VT_MALICIOUS_THRESHOLD_HASH else (
            "suspicious" if malicious > 0 else "clean"
        )
        name = data.get("data", {}).get("attributes", {}).get("meaningful_name", "unknown")
        return {
            "hash": file_hash,
            "verdict": verdict,
            "malicious_count": malicious,
            "file_name": name,
            "details": f"{malicious} AV engines flagged this file",
        }

    def check_url(self, url: str) -> Dict:
        """Check a URL reputation."""
        import base64
        log.info(f"[Sandbox] Checking URL: {url}")
        # VT v3 uses URL-safe base64 encoding for URL lookups
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        data = self._vt_get(f"urls/{url_id}")
        if not data or data.get("not_found"):
            return {"url": url, "verdict": "unknown", "malicious_count": 0, "details": "Not in VT database"}

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        verdict = "malicious" if malicious >= 3 else ("suspicious" if malicious > 0 else "clean")
        return {
            "url": url,
            "verdict": verdict,
            "malicious_count": malicious,
            "details": f"{malicious} scanners flagged this URL",
        }

    def enrich_attack_chain(self, chain: list, source_ips: list) -> Dict:
        """
        Check all IPs in an attack chain against VT.
        Returns enrichment dict with verdicts and confidence boost.
        """
        results = {}
        confidence_boost = 0.0

        for ip in set(source_ips):
            if ip and ip not in ("unknown", "0.0.0.0"):
                result = self.check_ip(ip)
                results[ip] = result
                if result["verdict"] == "malicious":
                    confidence_boost += 0.15
                elif result["verdict"] == "suspicious":
                    confidence_boost += 0.05

        return {
            "ip_results": results,
            "confidence_boost": min(confidence_boost, 0.30),  # max +30%
            "any_malicious": any(r["verdict"] == "malicious" for r in results.values()),
        }
