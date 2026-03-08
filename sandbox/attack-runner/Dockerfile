FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install common attacker tools used in our demo
RUN apt-get update && apt-get install -y \
    nmap hydra netcat-traditional curl ssh sshpass \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Add hydra password list
RUN mkdir -p /usr/share/wordlists \
    && echo -e "admin123\npassword\nqwerty\njsmith\npassword123\nroot" > /usr/share/wordlists/passwords.txt

ENTRYPOINT ["tail", "-f", "/dev/null"]
