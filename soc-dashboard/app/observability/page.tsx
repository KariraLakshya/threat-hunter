"use client"

import { useState } from "react"
import { BarChart3, RefreshCw, ExternalLink, Activity, Shield, Wifi, Cloud, Database, Cpu, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { useHealth, useStats } from "@/hooks/useApi"

const GRAFANA_BASE = process.env.NEXT_PUBLIC_GRAFANA_URL ?? "http://localhost:3001"
const DASHBOARD_UID = "soc-overview"

const PANELS = [
  { id: 1, title: "Event Volume",      icon: <Activity size={13}/>, color: "text-amber-400",   border: "border-amber-800/30",  bg: "bg-amber-950/10",  span: "col-span-2", h: 240 },
  { id: 2, title: "Alert Counters",    icon: <Shield   size={13}/>, color: "text-red-400",     border: "border-red-800/30",    bg: "bg-red-950/10",    span: "col-span-1", h: 240 },
  { id: 3, title: "Auth Failures",     icon: <Wifi     size={13}/>, color: "text-amber-400",   border: "border-amber-800/30",  bg: "bg-amber-950/10",  span: "col-span-1", h: 240 },
  { id: 4, title: "Cloud Activity",    icon: <Cloud    size={13}/>, color: "text-sky-400",     border: "border-sky-800/30",    bg: "bg-sky-950/10",    span: "col-span-2", h: 240 },
  { id: 5, title: "Pipeline Health",   icon: <Database size={13}/>, color: "text-amber-400",   border: "border-amber-800/30",  bg: "bg-amber-950/10",  span: "col-span-1", h: 240 },
  { id: 6, title: "Network Anomalies", icon: <Cpu      size={13}/>, color: "text-orange-400",  border: "border-orange-800/30", bg: "bg-orange-950/10", span: "col-span-2", h: 240 },
]

function GrafanaPanel({ panel, theme = "dark" }: { panel: typeof PANELS[0]; theme?: string }) {
  const src = `${GRAFANA_BASE}/d-solo/${DASHBOARD_UID}?panelId=${panel.id}&theme=${theme}&kiosk&refresh=30s`
  return (
    <div className={`${panel.span} rounded-xl border ${panel.border} ${panel.bg} overflow-hidden flex flex-col`} style={{ height: panel.h }}>
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800/60 shrink-0">
        <div className="flex items-center gap-2">
          <span className={panel.color}>{panel.icon}</span>
          <span className={`text-xs font-semibold ${panel.color}`}>{panel.title}</span>
        </div>
        <a href={`${GRAFANA_BASE}/d/${DASHBOARD_UID}?viewPanel=${panel.id}`} target="_blank" rel="noopener noreferrer"
          className="p-1 rounded hover:bg-zinc-800 transition-colors">
          <ExternalLink size={11} className="text-zinc-600 hover:text-zinc-400"/>
        </a>
      </div>
      <iframe src={src} className="w-full flex-1 border-0" title={panel.title} />
    </div>
  )
}

function FallbackPanel({ panel }: { panel: typeof PANELS[0] }) {
  return (
    <div className={`${panel.span} rounded-xl border ${panel.border} ${panel.bg} overflow-hidden flex flex-col`} style={{ height: panel.h }}>
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800/60 shrink-0">
        <div className="flex items-center gap-2">
          <span className={panel.color}>{panel.icon}</span>
          <span className={`text-xs font-semibold ${panel.color}`}>{panel.title}</span>
        </div>
        <a href={GRAFANA_BASE} target="_blank" rel="noopener noreferrer"
          className="p-1 rounded hover:bg-zinc-800 transition-colors">
          <ExternalLink size={11} className="text-zinc-600 hover:text-zinc-400"/>
        </a>
      </div>
      <div className="flex-1 flex flex-col items-center justify-center gap-2">
        <BarChart3 size={22} className="text-zinc-700"/>
        <p className={`text-xs font-medium ${panel.color}`}>{panel.title}</p>
        <p className="text-[10px] font-mono text-zinc-700">Panel {panel.id}</p>
        <a href={GRAFANA_BASE} target="_blank" rel="noopener noreferrer"
          className="mt-1 text-[11px] text-amber-600 hover:text-amber-400 flex items-center gap-1 transition-colors">
          <ExternalLink size={10}/> Start Grafana
        </a>
      </div>
    </div>
  )
}

export default function ObservabilityPage() {
  const [grafanaLive, setGrafanaLive] = useState(false)
  const { data: stats } = useStats(15_000)
  const { data: health } = useHealth(30_000)

  const esOk = health?.services?.elasticsearch?.ok ?? false

  const liveStats = [
    { label: "Total Events",    value: stats?.total ?? 0,                      color: "text-amber-400" },
    { label: "Critical",        value: stats?.by_severity?.critical ?? 0,      color: "text-red-400" },
    { label: "High",            value: stats?.by_severity?.high ?? 0,          color: "text-orange-400" },
    { label: "Cross-Env",       value: stats?.cross_environment ?? 0,          color: "text-violet-400" },
    { label: "Elasticsearch",   value: esOk ? "GREEN" : "DEGRADED",            color: esOk ? "text-emerald-400" : "text-red-400" },
    { label: "Grafana",         value: grafanaLive ? "LIVE" : "OFFLINE",       color: grafanaLive ? "text-emerald-400" : "text-zinc-600" },
  ]

  return (
    <div className="flex flex-col h-full -m-6">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/90 shrink-0">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-amber-950/50 border border-amber-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(245,158,11,0.15)]">
              <BarChart3 size={16} className="text-amber-400"/>
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">Observability</h1>
              <p className="text-xs text-zinc-500 mt-0.5">Grafana · Elasticsearch · Live telemetry</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Grafana toggle */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-zinc-500">Grafana panels</span>
              <button onClick={() => setGrafanaLive(v => !v)}
                className={`relative w-10 h-5 rounded-full transition-colors ${grafanaLive ? "bg-amber-600" : "bg-zinc-700"}`}>
                <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${grafanaLive ? "left-5" : "left-0.5"}`}/>
              </button>
              <span className={`text-xs font-medium ${grafanaLive ? "text-amber-400" : "text-zinc-600"}`}>
                {grafanaLive ? "Live" : "Off"}
              </span>
            </div>
            <a href={GRAFANA_BASE} target="_blank" rel="noopener noreferrer">
              <Button variant="outline" size="sm" className="gap-1.5 text-xs border-amber-800/40 text-amber-400 hover:bg-amber-950/20">
                <ExternalLink size={12}/> Open Grafana
              </Button>
            </a>
          </div>
        </div>

        {/* Live stats strip */}
        <div className="grid grid-cols-6 gap-2">
          {liveStats.map(s => (
            <div key={s.label} className="px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 flex flex-col gap-0.5">
              <span className="text-[10px] text-zinc-600 leading-none">{s.label}</span>
              <span className={`text-sm font-bold font-mono ${s.color}`}>{s.value}</span>
            </div>
          ))}
        </div>

        {/* Setup note if Grafana not live */}
        {!grafanaLive && (
          <div className="flex items-center gap-2 mt-3 text-xs text-zinc-500 bg-zinc-900/60 border border-zinc-800 rounded-lg px-3 py-2">
            <AlertTriangle size={12} className="text-amber-500 shrink-0"/>
            Toggle "Grafana panels" on after running <span className="font-mono text-zinc-400 mx-1">docker-compose up -d grafana</span> on port 3001
          </div>
        )}
      </div>

      {/* Dashboard grid */}
      <div className="flex-1 overflow-y-auto p-5">
        <div className="grid grid-cols-3 gap-4">
          {PANELS.map(panel =>
            grafanaLive
              ? <GrafanaPanel key={panel.id} panel={panel}/>
              : <FallbackPanel key={panel.id} panel={panel}/>
          )}
        </div>
      </div>
    </div>
  )
}