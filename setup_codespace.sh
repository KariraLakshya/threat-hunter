#!/bin/bash
# setup_codespace.sh — Rebuild .env from GitHub Codespaces secrets
#
# In Codespaces, secrets are injected as environment variables automatically.
# This script writes them into a .env file that docker compose and Python can read.
#
# Run once after Codespace creation:
#   bash setup_codespace.sh

set -e

ENV_FILE=".env"

echo "=== Threat Hunter — Codespace .env Setup ==="

cat > "$ENV_FILE" << EOF
# ── Elasticsearch ──
ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-changeme123}
KIBANA_PASSWORD=${KIBANA_PASSWORD:-changeme123}
ES_JAVA_OPTS=${ES_JAVA_OPTS:--Xms512m -Xmx512m}

# ── Wazuh ──
WAZUH_API_USER=${WAZUH_API_USER:-wazuh-wui}
WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD:-changeme123}

# ── VirusTotal (Phase 7) ──
VT_API_KEY=${VT_API_KEY:-}

# ── Groq API (Phase 6 — AI Agent, free) ──
GROQ_API_KEY=${GROQ_API_KEY:-}
GROQ_MODEL=${GROQ_MODEL:-llama-3.3-70b-versatile}

# ── Slack (Phase 8) ──
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-}

# ── Email (Phase 8) ──
SMTP_HOST=${SMTP_HOST:-smtp.gmail.com}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_USER=${SMTP_USER:-}
SMTP_PASSWORD=${SMTP_PASSWORD:-}
ALERT_EMAIL_TO=${ALERT_EMAIL_TO:-}

# ── AWS (Phase 2) ──
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}

# ── Codespaces: ES is localhost inside the container network ──
ES_HOST=http://localhost:9200
INCIDENTS_DB=incidents/incidents.db
REDIS_HOST=localhost
EOF

echo "✅ .env written from Codespaces secrets"
echo ""
echo "Keys detected:"
[ -n "$GROQ_API_KEY" ]   && echo "  ✅ GROQ_API_KEY"     || echo "  ⚠️  GROQ_API_KEY      (add in repo Settings → Codespaces → Secrets)"
[ -n "$VT_API_KEY" ]     && echo "  ✅ VT_API_KEY"       || echo "  ⚠️  VT_API_KEY        (optional)"
[ -n "$SLACK_WEBHOOK_URL" ] && echo "  ✅ SLACK_WEBHOOK_URL" || echo "  ⚠️  SLACK_WEBHOOK_URL  (optional)"
echo ""
echo "Next: docker compose up -d"
