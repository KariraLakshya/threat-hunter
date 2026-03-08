import paramiko
import time

for i in range(7):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect('localhost', port=2222, username='hacker', password='bad', timeout=3)
    except Exception as e:
        print(f"Attempt {i+1} failed as expected")
        
import requests
import sqlite3

print("Waiting for logs to flow...")
time.sleep(10)
print("Triggering investigation...")
requests.post('http://localhost:8000/investigate', json={'lookback_minutes': 15, 'force_run': True})
time.sleep(5)

conn = sqlite3.connect('incidents/incidents.db')
cur = conn.cursor()
cur.execute("SELECT incident_id, severity, timestamp, summary FROM incidents ORDER BY timestamp DESC LIMIT 1")
print(cur.fetchone())
conn.close()
