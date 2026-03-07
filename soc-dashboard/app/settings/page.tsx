"use client"

import { useState } from "react"
import {
  Settings, Slack, Mail, Bell, CheckCircle2, XCircle,
  Send, Eye, EyeOff, Save, AlertTriangle, Loader2,
  ChevronRight, Shield, Zap, MessageSquare, AtSign
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

type TestStatus = "idle" | "loading" | "success" | "error"

const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const
type Severity = typeof SEVERITY_LEVELS[number]

const SEV_COLORS: Record<Severity, string> = {
  critical: "text-red-400 border-red-800/40 bg-red-950/20",
  high: "text-orange-400 border-orange-800/40 bg-orange-950/20",
  medium: "text-yellow-400 border-yellow-800/40 bg-yellow-950/20",
  low: "text-emerald-400 border-emerald-800/40 bg-emerald-950/20",
}

function TestButton({ status, onClick }: { status: TestStatus; onClick: () => void }) {
  return (
    <Button
      onClick={onClick}
      disabled={status === "loading"}
      variant="outline"
      size="sm"
      className={`gap-1.5 text-xs border-zinc-700 transition-all ${
        status === "success" ? "border-emerald-800/50 text-emerald-400" :
        status === "error" ? "border-red-800/50 text-red-400" :
        "text-zinc-400 hover:text-zinc-100"
      }`}
    >
      {status === "loading" && <Loader2 size={11} className="animate-spin" />}
      {status === "success" && <CheckCircle2 size={11} />}
      {status === "error" && <XCircle size={11} />}
      {status === "idle" && <Send size={11} />}
      {status === "idle" ? "Test" : status === "loading" ? "Sending…" : status === "success" ? "Sent!" : "Failed"}
    </Button>
  )
}

function SectionCard({ title, icon, color, children }: {
  title: string
  icon: React.ReactNode
  color: string
  children: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden">
      <div className="flex items-center gap-2.5 px-5 py-4 border-b border-zinc-800">
        <span className={color}>{icon}</span>
        <span className="text-sm font-semibold text-zinc-200">{title}</span>
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

function PasswordInput({ value, onChange, placeholder }: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <Input
        type={show ? "text" : "password"}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="h-8 bg-zinc-900 border-zinc-700 text-xs pr-8 text-zinc-300 placeholder:text-zinc-600"
      />
      <button onClick={() => setShow(v => !v)} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400">
        {show ? <EyeOff size={13} /> : <Eye size={13} />}
      </button>
    </div>
  )
}

export default function IntegrationsPage() {
  // Slack
  const [slackUrl, setSlackUrl] = useState("")
  const [slackTest, setSlackTest] = useState<TestStatus>("idle")

  // Email
  const [smtpHost, setSmtpHost] = useState("smtp.gmail.com")
  const [smtpPort, setSmtpPort] = useState("587")
  const [smtpUser, setSmtpUser] = useState("")
  const [smtpPass, setSmtpPass] = useState("")
  const [alertEmail, setAlertEmail] = useState("")
  const [emailTest, setEmailTest] = useState<TestStatus>("idle")

  // Routing
  const [routing, setRouting] = useState<Record<Severity, { slack: boolean; email: boolean }>>({
    critical: { slack: true, email: true },
    high: { slack: true, email: true },
    medium: { slack: true, email: false },
    low: { slack: false, email: false },
  })

  const [saved, setSaved] = useState(false)

  function testSlack() {
    setSlackTest("loading")
    setTimeout(() => setSlackTest(slackUrl ? "success" : "error"), 1500)
    setTimeout(() => setSlackTest("idle"), 4000)
  }

  function testEmail() {
    setEmailTest("loading")
    setTimeout(() => setEmailTest(smtpUser && smtpPass ? "success" : "error"), 1500)
    setTimeout(() => setEmailTest("idle"), 4000)
  }

  function saveConfig() {
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  function toggleRouting(sev: Severity, channel: "slack" | "email") {
    setRouting(r => ({ ...r, [sev]: { ...r[sev], [channel]: !r[sev][channel] } }))
  }

  return (
    <div className="flex flex-col h-full gap-0 -m-6">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/80">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-sky-950/50 border border-sky-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(14,165,233,0.15)]">
              <Settings size={16} className="text-sky-400" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">Integrations</h1>
              <p className="text-xs text-zinc-500 mt-0.5">Alert channels · Severity routing · Webhook config</p>
            </div>
          </div>
          <Button
            onClick={saveConfig}
            className={`gap-2 text-xs transition-all ${saved ? "bg-emerald-700 hover:bg-emerald-600" : "bg-sky-700 hover:bg-sky-600"} text-white border-0`}
            size="sm"
          >
            {saved ? <CheckCircle2 size={12} /> : <Save size={12} />}
            {saved ? "Saved!" : "Save Config"}
          </Button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-3xl space-y-5">

          {/* Slack */}
          <SectionCard title="Slack" icon={<MessageSquare size={16} />} color="text-[#4A154B]" >
            <div className="space-y-4">
              <div>
                <label className="text-xs text-zinc-500 block mb-1.5">Webhook URL</label>
                <div className="flex gap-2">
                  <Input
                    value={slackUrl}
                    onChange={e => setSlackUrl(e.target.value)}
                    placeholder="https://hooks.slack.com/services/T.../B.../..."
                    className="h-8 bg-zinc-900 border-zinc-700 text-xs text-zinc-300 placeholder:text-zinc-600 flex-1"
                  />
                  <TestButton status={slackTest} onClick={testSlack} />
                </div>
                <p className="text-[11px] text-zinc-600 mt-1.5">
                  Create a webhook at <span className="text-sky-500">api.slack.com/apps</span> → Incoming Webhooks
                </p>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-zinc-800/40 border border-zinc-700/50">
                <div className="w-8 h-8 rounded-lg bg-[#4A154B]/30 border border-[#4A154B]/40 flex items-center justify-center">
                  <MessageSquare size={14} className="text-[#7B3BA4]" />
                </div>
                <div>
                  <p className="text-xs text-zinc-300 font-medium">Alert format</p>
                  <p className="text-[11px] text-zinc-500">Color-coded attachments with incident ID, severity, attack chain, and immediate actions</p>
                </div>
              </div>
            </div>
          </SectionCard>

          {/* Email */}
          <SectionCard title="Email (SMTP)" icon={<Mail size={16} />} color="text-sky-400">
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-zinc-500 block mb-1.5">SMTP Host</label>
                  <Input value={smtpHost} onChange={e => setSmtpHost(e.target.value)}
                    className="h-8 bg-zinc-900 border-zinc-700 text-xs text-zinc-300" />
                </div>
                <div>
                  <label className="text-xs text-zinc-500 block mb-1.5">SMTP Port</label>
                  <Input value={smtpPort} onChange={e => setSmtpPort(e.target.value)}
                    className="h-8 bg-zinc-900 border-zinc-700 text-xs text-zinc-300" />
                </div>
                <div>
                  <label className="text-xs text-zinc-500 block mb-1.5">SMTP Username</label>
                  <Input value={smtpUser} onChange={e => setSmtpUser(e.target.value)}
                    placeholder="your@email.com"
                    className="h-8 bg-zinc-900 border-zinc-700 text-xs text-zinc-300 placeholder:text-zinc-600" />
                </div>
                <div>
                  <label className="text-xs text-zinc-500 block mb-1.5">SMTP Password</label>
                  <PasswordInput value={smtpPass} onChange={setSmtpPass} placeholder="App password" />
                </div>
              </div>
              <div>
                <label className="text-xs text-zinc-500 block mb-1.5">Alert Recipients</label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <AtSign size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
                    <Input value={alertEmail} onChange={e => setAlertEmail(e.target.value)}
                      placeholder="soc-team@yourcompany.com"
                      className="h-8 bg-zinc-900 border-zinc-700 text-xs pl-7 text-zinc-300 placeholder:text-zinc-600" />
                  </div>
                  <TestButton status={emailTest} onClick={testEmail} />
                </div>
              </div>
            </div>
          </SectionCard>

          {/* Severity routing */}
          <SectionCard title="Severity Routing Rules" icon={<Shield size={16} />} color="text-sky-400">
            <div className="space-y-2">
              <p className="text-xs text-zinc-500 mb-3">Configure which channels receive alerts per severity level</p>
              <div className="grid grid-cols-3 gap-2 mb-2 text-[11px] text-zinc-600 px-1">
                <span>Severity</span>
                <span className="text-center">Slack</span>
                <span className="text-center">Email</span>
              </div>
              {SEVERITY_LEVELS.map(sev => (
                <div key={sev} className={`grid grid-cols-3 gap-2 items-center p-3 rounded-lg border ${SEV_COLORS[sev]}`}>
                  <span className="text-xs font-semibold uppercase">{sev}</span>
                  <div className="flex justify-center">
                    <button
                      onClick={() => toggleRouting(sev, "slack")}
                      className={`w-9 h-5 rounded-full transition-colors ${routing[sev].slack ? "bg-sky-600" : "bg-zinc-700"}`}
                    >
                      <span className={`block w-4 h-4 rounded-full bg-white shadow transition-all mx-auto ${routing[sev].slack ? "translate-x-2" : "-translate-x-2"}`} />
                    </button>
                  </div>
                  <div className="flex justify-center">
                    <button
                      onClick={() => toggleRouting(sev, "email")}
                      className={`w-9 h-5 rounded-full transition-colors ${routing[sev].email ? "bg-sky-600" : "bg-zinc-700"}`}
                    >
                      <span className={`block w-4 h-4 rounded-full bg-white shadow transition-all mx-auto ${routing[sev].email ? "translate-x-2" : "-translate-x-2"}`} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>

          {/* Info note */}
          <div className="flex items-start gap-3 p-4 rounded-xl border border-zinc-700/50 bg-zinc-800/30">
            <AlertTriangle size={14} className="text-yellow-500 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold text-zinc-300 mb-1">Phase 2 note</p>
              <p className="text-xs text-zinc-500 leading-relaxed">
                Configuration here will be persisted to your <span className="font-mono text-zinc-400">.env</span> file in Phase 2 backend integration. For now, settings are stored in component state only.
              </p>
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}