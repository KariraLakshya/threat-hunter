@echo off
echo ===================================================
echo   Autonomous Threat Hunter - Dynamic Attack Sandbox
echo ===================================================

echo [*] Generating new dynamic attack sequence...
python scripts\generate_attack.py

echo [*] Triggering Metasploit automated MITRE emulation script...
echo [*] Target: Ubuntu server (sandbox-net)
echo [*] Live logs recording to sandbox\metasploit\attack.log

:: Using -T to avoid TTY issues in redirection if needed, but for msfconsole -r it's usually fine.
:: We use > to overwrite the previous log file for each new run.
docker exec metasploit ./msfconsole -q -r /workspace/demo_attack.rc > sandbox\metasploit\attack.log 2>&1

echo.
echo [!] Attack Sequence Completed!
echo Check your Next.js SOC Dashboard for the live logs and final incident.
pause
