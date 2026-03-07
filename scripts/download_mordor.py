"""
download_mordor.py — Download specific Mordor (OTRF Security Datasets) JSON files
for the 7 on-premise techniques we map in mitre_mapper.py.

Downloads only the targeted files — avoids GB-scale dataset bloat.

Usage:
    python scripts/download_mordor.py
"""

import os
import sys
import logging
import urllib.request

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("mordor_downloader")

SAVE_DIR = "data/mordor"

# Specific Mordor files mapped to the 7 on-prem techniques we care about.
# From: https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic
MORDOR_FILES = [
    # T1110 — Brute Force (Credential Access) — dcsync generates auth failures
    {
        "technique": "T1110",
        "filename": "T1110_brute_force.zip",
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip"
    },
    # T1552 — Unsecured Credentials (dump SAM registry hive)
    {
        "technique": "T1552",
        "filename": "T1552_credentials.zip",
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/cmd_sam_copy_esentutl.zip"
    },
    # T1078 — Valid Accounts (PSExec lateral movement = successful login after breach)
    {
        "technique": "T1078",
        "filename": "T1078_valid_accounts.zip",
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest.zip"
    },
    # T1021.002 — SMB/Windows Admin Shares (lateral movement via SMB)
    {
        "technique": "T1021.002",
        "filename": "T1021_smb_lateral.zip",
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_create_dcerpc_smb_svcctl.zip"
    },
    # T1059 — Command and Scripting Interpreter (VBS/PowerShell launcher)
    {
        "technique": "T1059",
        "filename": "T1059_powershell_exec.zip",
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip"
    },
    # T1041 — Exfiltration Over C2 (PSRemoting = C2 channel)
    {
        "technique": "T1041",
        "filename": "T1041_exfil_c2.zip",
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/covenant_psremoting_command.zip"
    },
]

def download_file(url: str, local_path: str, technique: str) -> bool:
    try:
        log.info(f"  Downloading {technique} from OTRF GitHub...")
        urllib.request.urlretrieve(url, local_path)
        size_kb = os.path.getsize(local_path) // 1024
        log.info(f"  ✓ Saved to {local_path} ({size_kb} KB)")
        return True
    except Exception as e:
        log.warning(f"  ✗ Failed to download {technique}: {e}")
        return False


def main():
    os.makedirs(SAVE_DIR, exist_ok=True)
    log.info(f"Downloading Mordor datasets for 7 on-prem techniques to {SAVE_DIR}/\n")
    
    ok, fail = 0, 0
    for item in MORDOR_FILES:
        local_path = os.path.join(SAVE_DIR, item["filename"])
        if os.path.exists(local_path):
            log.info(f"  [skip] {item['technique']} already downloaded: {item['filename']}")
            ok += 1
            continue
        
        success = download_file(item["url"], local_path, item["technique"])
        if not success and item.get("fallback_url"):
            log.info(f"  Trying fallback URL for {item['technique']}...")
            success = download_file(item["fallback_url"], local_path, item["technique"])

        if success:
            ok += 1
        else:
            fail += 1

    log.info(f"\nDone: {ok} downloaded, {fail} failed")
    log.info(f"Next step: python scripts/load_mordor.py")


if __name__ == "__main__":
    main()
