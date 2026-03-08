#!/bin/bash

# Ensure Wazuh manager IP is set from environment variables (fallback: threat-hunter-wazuh)
MANAGER_IP=${WAZUH_MANAGER:-threat-hunter-wazuh}
sed -i "s/<address>.*<\/address>/<address>${MANAGER_IP}<\/address>/" /var/ossec/etc/ossec.conf

# Start Wazuh Agent
/etc/init.d/wazuh-agent start

# Start Cron (for T1053 Persistence checks)
cron

# Start SSH Daemon in foreground
/usr/sbin/sshd -D
