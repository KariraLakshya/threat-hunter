"use client"

import { useHealth, useStats, useIncidents } from "@/hooks/useApi"
import { RefreshCw, AlertTriangle, ShieldAlert, Siren, Globe, Brain, Activity, CheckCircle2, XCircle } from "lucide-react"

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-zinc-800 ${className}`} />
}

function ApiError({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 text-xs text-yellow-400 bg-yellow-950/20 border border-yellow-800/40 rounded-lg px-3 py-2">
      <AlertTriangle size={13} className="shrink-0" />
      <span>FastAPI unreachable: <span className="font-mono">{message}</span></span>
    </div>
  )
}

export default function OverviewPage() {
  const { data: stats, loading: sl, error: se, refetch: sr } = useStats(15_000)
  const { data: health, loading: hl, error: he } = useHealth(30_000)
  const { data: recent, loading: rl, error: re, refetch: rr } = useIncidents(5, 15_000)

  const incidents = recent?.incidents ?? []

  const kpis = [
    { label: "Total Incidents", value: stats?.total, icon: ShieldAlert, color: "text-cyan-400", glow: "shadow-[0_0_12px_rgba(34,211,238,0.3)]" },
    { label: "Critical", value: stats?.by_severity?.critical ?? 0, icon: Siren, color: "text-red-400", glow: "shadow-[0_0_12px_rgba(239,68,68,0.3)]" },
    { label: "High", value: stats?.by_severity?.high ?? 0, icon: Brain, color: "text-orange-400", glow: "shadow-[0_0_12px_rgba(249,115,22,0.3)]" },
    { label: "Cross-Environment", value: stats?.cross_environment ?? 0, icon: Globe, color: "text-violet-400", glow: "shadow-[0_0_12px_rgba(167,139,250,0.3)]" },
  ]

  const sevColor: Record<string, string> = {
    critical: "text-red-400", high: "text-orange-400",
    medium: "text-yellow-400", low: "text-emerald-400",
  }

  const sevBars = [
    { label: "Critical", value: stats?.by_severity?.critical ?? 0, color: "bg-red-500" },
    { label: "High", value: stats?.by_severity?.high ?? 0, color: "bg-orange-500" },
    { label: "Medium", value: stats?.by_severity?.medium ?? 0, color: "bg-yellow-500" },
    { label: "Low", value: stats?.by_severity?.low ?? 0, color: "bg-emerald-500" },
  ]
  const maxBar = Math.max(...sevBars.map(b => b.value), 1)

  const svcs = health?.services
    ? [
      { name: "Elasticsearch", ok: health.services.elasticsearch.ok, status: health.services.elasticsearch.status },
      { name: "SQLite DB", ok: health.services.database.ok, status: health.services.database.status },
      { name: "Redis", ok: health.services.redis.ok, status: health.services.redis.status },
    ]
    : []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Overview</h1>
          <p className="text-xs text-zinc-500 mt-0.5">Security operations dashboard</p>
        </div>
        <button onClick={() => { sr(); rr() }} className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
          <RefreshCw size={12} className={sl || rl ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      {(se || re || he) && <ApiError message={se ?? re ?? he ?? ""} />}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        {kpis.map(kpi => {
          const Icon = kpi.icon
          return (
            <div key={kpi.label} className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 flex items-center justify-between">
              <div>
                <p className="text-xs text-zinc-500 mb-1">{kpi.label}</p>
                {sl ? <Skeleton className="h-8 w-10" /> : <p className={`text-3xl font-bold font-mono ${kpi.color}`}>{kpi.value ?? 0}</p>}
              </div>
              <div className={`w-10 h-10 rounded-lg bg-zinc-800 flex items-center justify-center ${kpi.glow}`}>
                <Icon size={20} className={kpi.color} />
              </div>
            </div>
          )
        })}
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Severity breakdown */}
        <div className="col-span-2 rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
          <p className="text-sm font-semibold text-zinc-300 mb-4">Incidents by Severity</p>
          {sl ? (
            <div className="space-y-3">{[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-4 w-full" />)}</div>
          ) : (
            <div className="space-y-3">
              {sevBars.map(bar => (
                <div key={bar.label} className="flex items-center gap-3">
                  <span className="text-xs text-zinc-400 w-14 shrink-0">{bar.label}</span>
                  <div className="flex-1 h-2.5 bg-zinc-800 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full transition-all duration-700 ${bar.color}`} style={{ width: `${(bar.value / maxBar) * 100}%` }} />
                  </div>
                  <span className="text-xs font-mono text-zinc-400 w-5 text-right">{bar.value}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* System health */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
          <p className="text-sm font-semibold text-zinc-300 mb-4 flex items-center gap-2">
            <Activity size={14} className="text-cyan-400" /> System Health
          </p>
          {hl ? (
            <div className="space-y-2">{[1, 2, 3].map(i => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : (
            <div className="space-y-2">
              {svcs.map(svc => (
                <div key={svc.name} className="flex items-center justify-between p-2.5 rounded-lg bg-zinc-800/60 border border-zinc-700/50">
                  <span className="text-xs text-zinc-300">{svc.name}</span>
                  <div className="flex items-center gap-1.5">
                    {svc.ok
                      ? <CheckCircle2 size={13} className="text-emerald-400" />
                      : <XCircle size={13} className="text-red-400" />
                    }
                    <span className={`text-[10px] font-mono ${svc.ok ? "text-emerald-400" : "text-red-400"}`}>{svc.status}</span>
                  </div>
                </div>
              ))}
              {svcs.length === 0 && <p className="text-xs text-zinc-600">Awaiting health data…</p>}
            </div>
          )}
        </div>
      </div>

      {/* Incidents Layout */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
        <div className="flex items-center justify-between mb-4">
          <p className="text-sm font-semibold text-zinc-300">Recent Incidents</p>
          <button onClick={rr} className="text-zinc-600 hover:text-zinc-400 transition-colors"><RefreshCw size={12} /></button>
        </div>
        {rl && <div className="space-y-2">{[1, 2, 3].map(i => <Skeleton key={i} className="h-10 w-full" />)}</div>}
        {!rl && incidents.length === 0 && (
          <p className="text-xs text-zinc-600">{re ? "API unreachable" : "No incidents yet. Run an investigation."}</p>
        )}
        {!rl && incidents.map(inc => (
          <div key={inc.incident_id} className="flex items-center justify-between py-2 border-b border-zinc-800/70 last:border-0">
            <div className="flex items-center gap-3 min-w-0">
              <span className={`text-[10px] font-bold font-mono ${sevColor[inc.severity] ?? "text-zinc-400"} w-14 shrink-0`}>{inc.severity.toUpperCase()}</span>
              <span className="text-xs text-zinc-300 truncate">{inc.summary}</span>
            </div>
            <span className="text-[10px] font-mono text-zinc-600 shrink-0 ml-3">{inc.incident_id}</span>
          </div>
        ))}
      </div>
    </div>
  )
}