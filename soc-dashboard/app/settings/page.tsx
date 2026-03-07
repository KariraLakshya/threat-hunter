"use client"

import { useState, useEffect, useCallback } from "react"
import {
  Settings, Mail, Bell, CheckCircle2, XCircle,
  Send, Eye, EyeOff, Save, AlertTriangle, Loader2,
  Shield, Zap, MessageSquare, AtSign, Info,
  RefreshCw, ExternalLink, Lock
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

// ── Types ──────────────────────────────────────────────────────

type TestStatus = "idle" | "loading" | "success" | "error"
const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const
type Severity = typeof SEVERITY_LEVELS[number]

interface Routing {
  slack: boolean
  email: boolean
}

const DEFAULT_ROUTING: Record<Severity, Routing> = {
  critical: { slack: true,  email: true  },
  high:     { slack: true,  email: true  },
  medium:   { slack: true,  email: false },
  low:      { slack: false, email: false },
}

const SEV_COLORS: Record<Severity, string> = {
  critical: "text-red-400    border-red-800/40    bg-red-950/20",
  high:     "text-orange-400 border-orange-800/40 bg-orange-950/20",
  medium:   "text-yellow-400 border-yellow-800/40 bg-yellow-950/20",
  low:      "text-emerald-400 border-emerald-800/40 bg-emerald-950/20",
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

// ── Sub-components ─────────────────────────────────────────────

function SectionCard({ title, icon, color, badge, children }: {
  title: string
  icon: React.ReactNode
  color: string
  badge?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
        <div className="flex items-center gap-2.5">
          <span className={color}>{icon}</span>
          <span className="text-sm font-semibold text-zinc-200">{title}</span>
        </div>
        {badge}
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

function PasswordInput({ value, onChange, placeholder, disabled }: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  disabled?: boolean
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <Input
        type={show ? "text" : "password"}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="h-8 bg-zinc-900 border-zinc-700 text-xs pr-8 text-zinc-300 placeholder:text-zinc-600 disabled:opacity-50"
      />
      <button
        type="button"
        onClick={() => setShow(v => !v)}
        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400"
      >
        {show ? <EyeOff size={13} /> : <Eye size={13} />}
      </button>
    </div>
  )
}

function TestBtn({ status, onClick, disabled }: {
  status: TestStatus
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <Button
      onClick={onClick}
      disabled={status === "loading" || disabled}
      variant="outline"
      size="sm"
      className={`gap-1.5 text-xs border-zinc-700 shrink-0 transition-all ${
        status === "success" ? "border-emerald-800/50 text-emerald-400" :
        status === "error"   ? "border-red-800/50 text-red-400" :
        "text-zinc-400 hover:text-zinc-100"
      }`}
    >
      {status === "loading" && <Loader2 size={11} className="animate-spin" />}
      {status === "success" && <CheckCircle2 size={11} />}
      {status === "error"   && <XCircle size={11} />}
      {status === "idle"    && <Send size={11} />}
      {status === "idle"    ? "Send Test"
       : status === "loading" ? "Sending…"
       : status === "success" ? "Delivered!"
       : "Failed"}
    </Button>
  )
}

function Toggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return (
    <button
      onClick={onChange}
      className={`relative w-9 h-5 rounded-full transition-colors shrink-0 ${on ? "bg-sky-600" : "bg-zinc-700"}`}
    >
      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${on ? "left-4" : "left-0.5"}`} />
    </button>
  )
}

function StatusPill({ connected }: { connected: boolean }) {
  return (
    <span className={`flex items-center gap-1.5 text-[11px] font-medium px-2 py-1 rounded-full border ${
      connected
        ? "text-emerald-400 border-emerald-800/50 bg-emerald-950/30"
        : "text-zinc-500 border-zinc-700/50 bg-zinc-800/30"
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-emerald-500" : "bg-zinc-600"}`} />
      {connected ? "Connected" : "Not configured"}
    </span>
  )
}

function InlineError({ msg }: { msg: string | null }) {
  if (!msg) return null
  return (
    <p className="flex items-center gap-1.5 text-[11px] text-red-400 mt-2">
      <XCircle size={11} className="shrink-0" /> {msg}
    </p>
  )
}

function InlineSuccess({ msg }: { msg: string | null }) {
  if (!msg) return null
  return (
    <p className="flex items-center gap-1.5 text-[11px] text-emerald-400 mt-2">
      <CheckCircle2 size={11} className="shrink-0" /> {msg}
    </p>
  )
}

// ── Main page ──────────────────────────────────────────────────

export default function IntegrationsPage() {

  // ── Slack state ──────────────────────────────────────────────
  const [slackUrl,    setSlackUrl]    = useState("")
  const [slackTest,   setSlackTest]   = useState<TestStatus>("idle")
  const [slackErr,    setSlackErr]    = useState<string | null>(null)
  const [slackOk,     setSlackOk]     = useState<string | null>(null)

  // ── Email state ──────────────────────────────────────────────
  const [smtpHost,    setSmtpHost]    = useState("smtp.gmail.com")
  const [smtpPort,    setSmtpPort]    = useState("587")
  const [smtpUser,    setSmtpUser]    = useState("")
  const [smtpPass,    setSmtpPass]    = useState("")
  const [alertEmail,  setAlertEmail]  = useState("")
  const [emailTest,   setEmailTest]   = useState<TestStatus>("idle")
  const [emailErr,    setEmailErr]    = useState<string | null>(null)
  const [emailOk,     setEmailOk]     = useState<string | null>(null)
  const [smtpPassSet, setSmtpPassSet] = useState(false)  // true if backend already has a password

  // ── Routing + save state ─────────────────────────────────────
  const [routing,     setRouting]     = useState<Record<Severity, Routing>>(DEFAULT_ROUTING)
  const [saveStatus,  setSaveStatus]  = useState<TestStatus>("idle")
  const [saveErr,     setSaveErr]     = useState<string | null>(null)
  const [configLoaded, setConfigLoaded] = useState(false)

  // ── Load existing config from backend on mount ───────────────
  const loadConfig = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/integrations/config`)
      if (!res.ok) return
      const data = await res.json()
      setSlackUrl(data.slack_webhook  ?? "")
      setSmtpHost(data.smtp_host      ?? "smtp.gmail.com")
      setSmtpPort(String(data.smtp_port ?? 587))
      setSmtpUser(data.smtp_user      ?? "")
      setAlertEmail(data.alert_email  ?? "")
      setSmtpPassSet(!!data.smtp_pass_set)
      if (data.routing && Object.keys(data.routing).length > 0) {
        setRouting({ ...DEFAULT_ROUTING, ...data.routing })
      }
      setConfigLoaded(true)
    } catch {
      // API might not be running — that's fine, page still works
      setConfigLoaded(true)
    }
  }, [])

  useEffect(() => { loadConfig() }, [loadConfig])

  // ── Test Slack ───────────────────────────────────────────────
  async function testSlack() {
    setSlackErr(null); setSlackOk(null)
    if (!slackUrl.startsWith("https://hooks.slack.com/")) {
      setSlackErr("Must start with https://hooks.slack.com/")
      return
    }
    setSlackTest("loading")
    try {
      const res = await fetch(`${API_BASE}/integrations/test-slack`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ webhook_url: slackUrl }),
      })
      const data = await res.json()
      if (res.ok) {
        setSlackTest("success")
        setSlackOk(data.detail ?? "Message sent!")
      } else {
        setSlackTest("error")
        setSlackErr(data.detail ?? "Slack test failed")
      }
    } catch {
      setSlackTest("error")
      setSlackErr("Cannot reach FastAPI — is it running on :8000?")
    }
    setTimeout(() => setSlackTest("idle"), 5000)
  }

  // ── Test Email ───────────────────────────────────────────────
  async function testEmail() {
    setEmailErr(null); setEmailOk(null)
    if (!smtpUser || !alertEmail) {
      setEmailErr("SMTP username and recipient email are required")
      return
    }
    if (!smtpPass && !smtpPassSet) {
      setEmailErr("SMTP password is required")
      return
    }
    setEmailTest("loading")
    try {
      const res = await fetch(`${API_BASE}/integrations/test-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          smtp_host:   smtpHost,
          smtp_port:   parseInt(smtpPort),
          smtp_user:   smtpUser,
          smtp_pass:   smtpPass,   // empty string = "use existing .env value"
          alert_email: alertEmail,
        }),
      })
      const data = await res.json()
      if (res.ok) {
        setEmailTest("success")
        setEmailOk(data.detail ?? "Email sent!")
      } else {
        setEmailTest("error")
        setEmailErr(data.detail ?? "Email test failed")
      }
    } catch {
      setEmailTest("error")
      setEmailErr("Cannot reach FastAPI — is it running on :8000?")
    }
    setTimeout(() => setEmailTest("idle"), 5000)
  }

  // ── Save ─────────────────────────────────────────────────────
  async function saveConfig() {
    setSaveErr(null)
    setSaveStatus("loading")
    try {
      const res = await fetch(`${API_BASE}/integrations/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          slack_webhook: slackUrl,
          smtp_host:     smtpHost,
          smtp_port:     parseInt(smtpPort),
          smtp_user:     smtpUser,
          smtp_pass:     smtpPass,
          alert_email:   alertEmail,
          routing,
        }),
      })
      const data = await res.json()
      if (res.ok) {
        setSaveStatus("success")
        if (smtpPass) setSmtpPassSet(true)   // backend now has the password
      } else {
        setSaveStatus("error")
        setSaveErr(data.detail ?? "Save failed")
      }
    } catch {
      setSaveStatus("error")
      setSaveErr("Cannot reach FastAPI — is it running on :8000?")
    }
    setTimeout(() => setSaveStatus("idle"), 4000)
  }

  function toggleRouting(sev: Severity, channel: "slack" | "email") {
    setRouting(r => ({ ...r, [sev]: { ...r[sev], [channel]: !r[sev][channel] } }))
  }

  const slackConfigured = slackUrl.startsWith("https://hooks.slack.com/")
  const emailConfigured = !!(smtpUser && (smtpPass || smtpPassSet) && alertEmail)

  return (
    <div className="flex flex-col h-full gap-0 -m-6">

      {/* ── Header ── */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/80">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-sky-950/50 border border-sky-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(14,165,233,0.15)]">
              <Settings size={16} className="text-sky-400" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">Integrations</h1>
              <p className="text-xs text-zinc-500 mt-0.5">Alert channels · Severity routing · Saved to .env</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Live channel indicators */}
            <div className="flex items-center gap-2">
              <StatusPill connected={slackConfigured} />
              <StatusPill connected={emailConfigured} />
            </div>

            <Button
              onClick={saveConfig}
              disabled={saveStatus === "loading"}
              className={`gap-2 text-xs transition-all ${
                saveStatus === "success" ? "bg-emerald-700 hover:bg-emerald-600" :
                saveStatus === "error"   ? "bg-red-800 hover:bg-red-700" :
                "bg-sky-700 hover:bg-sky-600"
              } text-white border-0`}
              size="sm"
            >
              {saveStatus === "loading" && <Loader2 size={12} className="animate-spin" />}
              {saveStatus === "success" && <CheckCircle2 size={12} />}
              {saveStatus === "error"   && <XCircle size={12} />}
              {saveStatus === "idle"    && <Save size={12} />}
              {saveStatus === "idle"    ? "Save to .env"
               : saveStatus === "loading" ? "Saving…"
               : saveStatus === "success" ? "Saved!"
               : "Save Failed"}
            </Button>
          </div>
        </div>
        {saveErr && (
          <p className="mt-2 text-[11px] text-red-400 flex items-center gap-1.5">
            <XCircle size={11} /> {saveErr}
          </p>
        )}
      </div>

      {/* ── Body ── */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-3xl space-y-5">

          {/* ── Slack ── */}
          <SectionCard
            title="Slack"
            icon={<MessageSquare size={16} />}
            color="text-[#7B3BA4]"
            badge={<StatusPill connected={slackConfigured} />}
          >
            <div className="space-y-4">
              <div>
                <label className="text-xs text-zinc-500 block mb-1.5">Incoming Webhook URL</label>
                <div className="flex gap-2">
                  <Input
                    value={slackUrl}
                    onChange={e => { setSlackUrl(e.target.value); setSlackErr(null); setSlackOk(null) }}
                    placeholder="https://hooks.slack.com/services/T.../B.../..."
                    className="h-8 bg-zinc-900 border-zinc-700 text-xs text-zinc-300 placeholder:text-zinc-600 flex-1 font-mono"
                  />
                  <TestBtn status={slackTest} onClick={testSlack} />
                </div>
                <InlineError   msg={slackErr} />
                <InlineSuccess msg={slackOk}  />
                <p className="text-[11px] text-zinc-600 mt-2 flex items-center gap-1.5">
                  <Info size={10} className="shrink-0" />
                  Create at{" "}
                  <a
                    href="https://api.slack.com/apps"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-500 hover:text-sky-400 flex items-center gap-0.5"
                  >
                    api.slack.com/apps <ExternalLink size={9} />
                  </a>
                  {" "}→ Incoming Webhooks → Add New
                </p>
              </div>

              {/* Preview card */}
              <div className="rounded-lg border-l-4 border-l-emerald-600 border border-zinc-700/50 bg-zinc-800/30 px-4 py-3 space-y-1">
                <p className="text-[11px] font-semibold text-zinc-300">🔐 [CRITICAL] Incident INC-A3F2B1</p>
                <p className="text-[11px] text-zinc-500">Cross-environment brute force → lateral movement → S3 exfil</p>
                <div className="flex gap-4 text-[10px] text-zinc-600 mt-1">
                  <span>Environments: on-premise, aws</span>
                  <span>Cross-Env: ⚠️ YES</span>
                </div>
                <p className="text-[10px] text-zinc-700 italic">← alert format preview</p>
              </div>
            </div>
          </SectionCard>

          {/* ── Gmail / SMTP ── */}
          <SectionCard
            title="Email (Gmail / SMTP)"
            icon={<Mail size={16} />}
            color="text-sky-400"
            badge={<StatusPill connected={emailConfigured} />}
          >
            <div className="space-y-4">

              {/* Gmail App Password callout */}
              <div className="flex items-start gap-3 p-3 rounded-lg bg-amber-950/20 border border-amber-800/40">
                <Lock size={13} className="text-amber-400 shrink-0 mt-0.5" />
                <div className="text-[11px] text-amber-300/80 leading-relaxed">
                  <span className="font-semibold text-amber-300">Gmail requires an App Password.</span>{" "}
                  Go to{" "}
                  <a
                    href="https://myaccount.google.com/apppasswords"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-400 hover:text-sky-300 underline"
                  >
                    myaccount.google.com/apppasswords
                  </a>{" "}
                  → create one for "Mail" → paste it below.
                  2-Step Verification must be enabled on your account.
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-zinc-500 block mb-1.5">SMTP Host</label>
                  <Input
                    value={smtpHost}
                    onChange={e => setSmtpHost(e.target.value)}
                    className="h-8 bg-zinc-900 border-zinc-700 text-xs text-zinc-300"
                  />
                </div>
                <div>
                  <label className="text-xs text-zinc-500 block mb-1.5">SMTP Port</label>
                  <Input
                    value={smtpPort}
                    onChange={e => setSmtpPort(e.target.value)}
                    className="h-8 bg-zinc-900 border-zinc-700 text-xs text-zinc-300"
                  />
                </div>
                <div>
                  <label className="text-xs text-zinc-500 block mb-1.5">Gmail Address</label>
                  <div className="relative">
                    <AtSign size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
                    <Input
                      value={smtpUser}
                      onChange={e => setSmtpUser(e.target.value)}
                      placeholder="you@gmail.com"
                      className="h-8 bg-zinc-900 border-zinc-700 text-xs pl-7 text-zinc-300 placeholder:text-zinc-600"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-xs text-zinc-500 block mb-1.5">
                    App Password
                    {smtpPassSet && !smtpPass && (
                      <span className="ml-2 text-emerald-500 text-[10px]">✓ saved</span>
                    )}
                  </label>
                  <PasswordInput
                    value={smtpPass}
                    onChange={setSmtpPass}
                    placeholder={smtpPassSet ? "••••••••••••••••" : "xxxx xxxx xxxx xxxx"}
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-zinc-500 block mb-1.5">Alert Recipient</label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <AtSign size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
                    <Input
                      value={alertEmail}
                      onChange={e => setAlertEmail(e.target.value)}
                      placeholder="soc-team@yourcompany.com"
                      className="h-8 bg-zinc-900 border-zinc-700 text-xs pl-7 text-zinc-300 placeholder:text-zinc-600"
                    />
                  </div>
                  <TestBtn status={emailTest} onClick={testEmail} />
                </div>
                <InlineError   msg={emailErr} />
                <InlineSuccess msg={emailOk}  />
              </div>
            </div>
          </SectionCard>

          {/* ── Severity routing ── */}
          <SectionCard
            title="Severity Routing Rules"
            icon={<Shield size={16} />}
            color="text-sky-400"
          >
            <div className="space-y-2">
              <p className="text-xs text-zinc-500 mb-4">
                Choose which channels fire for each severity level. These are saved to{" "}
                <span className="font-mono text-zinc-400">ALERT_ROUTING</span> in your .env.
              </p>

              <div className="grid grid-cols-[1fr_80px_80px] gap-2 mb-2 text-[11px] text-zinc-600 px-3">
                <span>Severity</span>
                <span className="text-center flex items-center justify-center gap-1"><MessageSquare size={10}/> Slack</span>
                <span className="text-center flex items-center justify-center gap-1"><Mail size={10}/> Email</span>
              </div>

              {SEVERITY_LEVELS.map(sev => (
                <div
                  key={sev}
                  className={`grid grid-cols-[1fr_80px_80px] gap-2 items-center px-3 py-3 rounded-lg border ${SEV_COLORS[sev]}`}
                >
                  <span className="text-xs font-semibold uppercase tracking-wide">{sev}</span>
                  <div className="flex justify-center">
                    <Toggle on={routing[sev].slack} onChange={() => toggleRouting(sev, "slack")} />
                  </div>
                  <div className="flex justify-center">
                    <Toggle on={routing[sev].email} onChange={() => toggleRouting(sev, "email")} />
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>

          {/* ── How it works note ── */}
          <div className="flex items-start gap-3 p-4 rounded-xl border border-zinc-700/50 bg-zinc-800/30">
            <Info size={14} className="text-sky-500 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="text-xs font-semibold text-zinc-300">How this works</p>
              <p className="text-xs text-zinc-500 leading-relaxed">
                Clicking <span className="text-zinc-400 font-medium">Save to .env</span> writes your config directly to
                the <span className="font-mono text-zinc-400">.env</span> file at the repo root and hot-reloads it into
                the running FastAPI process — no restart needed. The{" "}
                <span className="font-mono text-zinc-400">response_engine.py</span> reads{" "}
                <span className="font-mono text-zinc-400">SLACK_WEBHOOK</span>,{" "}
                <span className="font-mono text-zinc-400">SMTP_*</span>, and{" "}
                <span className="font-mono text-zinc-400">ALERT_EMAIL</span> on every incident response.
              </p>
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}