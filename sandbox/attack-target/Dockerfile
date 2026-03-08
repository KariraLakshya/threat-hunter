FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies, OpenSSH server, and Wazuh Agent 4.7.2
RUN apt-get update && apt-get install -y \
    curl apt-transport-https lsb-release gnupg2 openssh-server sudo cron \
    && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y wazuh-agent=4.7.2-1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Setup SSH and test user for credential access/brute force
RUN mkdir /var/run/sshd
RUN useradd -rm -d /home/jsmith -s /bin/bash -g root -G sudo -u 1000 jsmith
RUN echo 'jsmith:password123' | chpasswd
RUN echo 'root:root' | chpasswd

# Setup fake credentials file for T1552 (Credential Dumping)
RUN mkdir -p /opt/backup && echo "admin_password=supersecret99" > /opt/backup/creds.txt && chmod 600 /opt/backup/creds.txt

# Start script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
