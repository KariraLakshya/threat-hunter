"use client"

import { useState } from "react"
import {
  BarChart3, Maximize2, RefreshCw, ExternalLink,
  Activity, Shield, Wifi, Cloud, Database, Cpu
} from "lucide-react"
import { Button } from "@/components/ui/button"

const GRAFANA_BASE = process.env.NEXT_PUBLIC_GRAFANA_URL || "http://localhost:3001"

const PANELS = [
  {
    id: "event-volume",
    title: "Event Volume",
    icon: <Activity size={13} />,
    color: "text-amber-400",
    border: "border-amber-800/30",
    bg: "bg-amber-950/10",
    panelId: 1,
    span: "col-span-2",
  },
  {
    id: "alert-counters",
    title: "Alert Counters",
    icon: <Shield size={13} />,
    color: "text-red-400",
    border: "border-red-800/30",
    bg: "bg-red-950/10",
    panelId: 2,
    span: "col-span-1",
  },
  {
    id: "auth-failures",
    title: "Auth Failures",
    icon: <Wifi size={13} />,
    color: "text-amber-400",
    border: "border-amber-800/30",
    bg: "bg-amber-950/10",
    panelId: 3,
    span: "col-span-1",
  },
  {
    id: "cloud-activity",
    title: "Cloud Activity",
    icon: <Cloud size={13} />,
    color: "text-sky-400",
    border: "border-sky-800/30",
    bg: "bg-sky-950/10",
    panelId: 4,
    span: "col-span-2",
  },
  {
    id: "pipeline-health",
    title: "Pipeline Health",
    icon: <Database size={13} />,
    color: "text-amber-400",
    border: "border-amber-800/30",
    bg: "bg-amber-950/10",
    panelId: 5,
    span: "col-span-1",
  },
  {
    id: "network-anomalies",
    title: "Network Anomalies",
    icon: <Cpu size={13} />,
    color: "text-amber-400",
    border: "border-amber-800/30",
    bg: "bg-amber-950/10",
    panelId: 6,
    span: "col-span-1",
  },
]

const LIVE_STATS = [
  { label: "Events/sec", value: "1.4k", delta: "+12%", up: true },
  { label: "Active Alerts", value: "8", delta: "+2", up: true },
  { label: "Auth Failures (1h)", value: "47", delta: "-5%", up: false },
  { label: "ES Indexing Rate", value: "98%", delta: "stable", up: true },
  { label: "Pipeline Lag", value: "2.1s", delta: "-0.3s", up: false },
  { label: "ES Cluster", value: "GREEN", delta: "healthy", up: true },
]

function GrafanaPanel({ panel, dashboardUid = "soc-overview" }: {
  panel: typeof PANELS[0]
  dashboardUid?: string
}) {
  const src = `${GRAFANA_BASE}/d-solo/${dashboardUid}?panelId=${panel.panelId}&theme=dark&kiosk`

  return (
    <div className={`${panel.span} rounded-xl border ${panel.border} ${panel.bg} overflow-hidden flex flex-col`} style={{ height: 240 }}>
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800/60">
        <div className="flex items-center gap-2">
          <span className={panel.color}>{panel.icon}</span>
          <span className={`text-xs font-semibold ${panel.color}`}>{panel.title}</span>
        </div>
        <div className="flex items-center gap-1">
          <button className="p-1 rounded hover:bg-zinc-800 transition-colors">
            <Maximize2 size={11} className="text-zinc-600" />
          </button>
          <a href={GRAFANA_BASE} target="_blank" rel="noopener noreferrer"
            className="p-1 rounded hover:bg-zinc-800 transition-colors">
            <ExternalLink size={11} className="text-zinc-600" />
          </a>
        </div>
      </div>
      <div className="flex-1 relative">
        <iframe
          src={src}
          className="w-full h-full border-0"
          title={panel.title}
          onError={() => {}}
        />
        {/* Fallback overlay — shows when Grafana is not running */}
        <div className="absolute inset-0 flex flex-col items-center justify-center bg-zinc-950/80 backdrop-blur-sm pointer-events-none"
          style={{ display: "none" }} // remove this to show the fallback always
        >
          <BarChart3 size={24} className="text-zinc-700 mb-2" />
          <p className="text-xs text-zinc-600">Grafana panel</p>
          <p className="text-[10px] text-zinc-700 font-mono mt-1">{GRAFANA_BASE}</p>
        </div>
      </div>
    </div>
  )
}

function GrafanaFallback({ panel }: { panel: typeof PANELS[0] }) {
  const heights: Record<string, number> = {
    "col-span-2": 240,
    "col-span-1": 240,
  }
  return (
    <div
      className={`${panel.span} rounded-xl border ${panel.border} ${panel.bg} overflow-hidden flex flex-col`}
      style={{ height: heights[panel.span] }}
    >
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800/60">
        <div className="flex items-center gap-2">
          <span className={panel.color}>{panel.icon}</span>
          <span className={`text-xs font-semibold ${panel.color}`}>{panel.title}</span>
        </div>
        <a href={GRAFANA_BASE} target="_blank" rel="noopener noreferrer"
          className="p-1 rounded hover:bg-zinc-800 transition-colors">
          <ExternalLink size={11} className="text-zinc-600" />
        </a>
      </div>
      <div className="flex-1 flex flex-col items-center justify-center gap-2">
        <BarChart3 size={22} className="text-zinc-700" />
        <p className="text-xs text-zinc-500 font-medium">{panel.title}</p>
        <p className="text-[10px] font-mono text-zinc-700">{GRAFANA_BASE} · Panel {panel.panelId}</p>
        <a
          href={GRAFANA_BASE}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-1 text-[11px] text-amber-600 hover:text-amber-400 flex items-center gap-1 transition-colors"
        >
          <ExternalLink size={10} /> Open Grafana
        </a>
      </div>
    </div>
  )
}

export default function ObservabilityPage() {
  const [grafanaLive, setGrafanaLive] = useState(false)
  const [lastRefresh] = useState(new Date().toLocaleTimeString())

  return (
    <div className="flex flex-col h-full gap-0 -m-6">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/80">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-amber-950/50 border border-amber-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(245,158,11,0.15)]">
              <BarChart3 size={16} className="text-amber-400" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">Observability</h1>
              <p className="text-xs text-zinc-500 mt-0.5">Live telemetry · Grafana dashboards · SOC wallboard</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-zinc-500">Grafana</span>
              <button
                onClick={() => setGrafanaLive(v => !v)}
                className={`relative w-10 h-5 rounded-full transition-colors ${grafanaLive ? "bg-amber-600" : "bg-zinc-700"}`}
              >
                <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${grafanaLive ? "left-5" : "left-0.5"}`} />
              </button>
              <span className={`text-[11px] font-medium ${grafanaLive ? "text-amber-400" : "text-zinc-600"}`}>
                {grafanaLive ? "Live" : "Mock"}
              </span>
            </div>
            <Button variant="outline" size="sm" className="gap-1.5 text-xs border-zinc-700 text-zinc-400">
              <RefreshCw size={12} /> Refresh
            </Button>
            <a href={GRAFANA_BASE} target="_blank" rel="noopener noreferrer">
              <Button variant="outline" size="sm" className="gap-1.5 text-xs border-amber-800/40 text-amber-400 hover:bg-amber-950/20">
                <ExternalLink size={12} /> Open Grafana
              </Button>
            </a>
          </div>
        </div>

        {/* Live stats strip */}
        <div className="grid grid-cols-6 gap-2">
          {LIVE_STATS.map(stat => (
            <div key={stat.label} className="px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 flex flex-col gap-0.5">
              <span className="text-[10px] text-zinc-600 leading-none">{stat.label}</span>
              <span className={`text-sm font-bold font-mono ${stat.label === "ES Cluster" ? "text-emerald-400" : "text-amber-400"}`}>
                {stat.value}
              </span>
              <span className={`text-[10px] ${stat.up ? "text-red-400" : "text-emerald-400"}`}>{stat.delta}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Dashboard grid */}
      <div className="flex-1 overflow-y-auto p-5">
        <div className="grid grid-cols-3 gap-4 auto-rows-min">
          {PANELS.map(panel =>
            grafanaLive
              ? <GrafanaPanel key={panel.id} panel={panel} />
              : <GrafanaFallback key={panel.id} panel={panel} />
          )}
        </div>

        <p className="text-center text-[11px] text-zinc-700 mt-6">
          Toggle "Live" above to connect Grafana at <span className="font-mono">{GRAFANA_BASE}</span> · Last refresh: {lastRefresh}
        </p>
      </div>
    </div>
  )
}