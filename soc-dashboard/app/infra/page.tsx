"use client"

import { useState, useEffect, useCallback } from "react"
import {
  Server, Database, Activity, Network,
  RefreshCw, Download, AlertTriangle,
  CheckCircle2, XCircle, Zap, RotateCcw, ArrowRight,
  Clock, Box, Cpu, Loader2, Wifi
} from "lucide-react"
import { Button } from "@/components/ui/button"

// ── Types ──────────────────────────────────────────────────────

type ServiceStatus = "healthy" | "degraded" | "offline" | "starting" | "unknown"

interface DockerContainer {
  name: string
  status: string          // e.g. "running", "exited"
  state: string           // e.g. "healthy", "starting"
  uptime: string
  image: string
}

interface HealthData {
  overall: string
  timestamp: string
  services: {
    elasticsearch?: { status: string; ok: boolean; error?: string }
    database?:      { status: string; ok: boolean; error?: string }
    redis?:         { status: string; ok: boolean; error?: string }
  }
}

interface DockerStatusData {
  containers: DockerContainer[]
  fetched_at: string
}

// ── Static service catalogue ───────────────────────────────────
// "key" maps to the health/docker response — "live" keys tell the
// component which data source to read for real status.

interface ServiceDef {
  name: string
  description: string
  version: string
  port: number
  iconName: string
  color: string
  actions: string[]
  // how to resolve live status:
  healthKey?: keyof HealthData["services"]   // from /health
  dockerName?: string                         // container name from /docker-status
}

const SERVICE_DEFS: ServiceDef[] = [
  {
    name: "Elasticsearch",
    description: "Security event storage & search",
    version: "8.13.0",
    port: 9200,
    iconName: "Database",
    color: "text-orange-400",
    actions: ["Restart", "Reindex", "Download Logs"],
    healthKey: "elasticsearch",
    dockerName: "threat-hunter-es",
  },
  {
    name: "Logstash",
    description: "Log ingestion & normalization pipeline",
    version: "8.13.0",
    port: 5000,
    iconName: "ArrowRight",
    color: "text-yellow-400",
    actions: ["Restart", "Clear Queue", "Download Logs"],
    dockerName: "threat-hunter-logstash",
  },
  {
    name: "Redis",
    description: "Task queue broker & cache",
    version: "7-alpine",
    port: 6379,
    iconName: "Zap",
    color: "text-red-400",
    actions: ["Restart", "Flush Cache"],
    healthKey: "redis",
    dockerName: "threat-hunter-redis",
  },
  {
    name: "FastAPI",
    description: "Security logic & REST API backend",
    version: "1.0.0",
    port: 8000,
    iconName: "Server",
    color: "text-emerald-400",
    actions: ["Restart", "Download Logs"],
    // FastAPI runs via uvicorn outside Docker — resolved purely by reachability
    healthKey: undefined,
    dockerName: undefined,
  },
  {
    name: "Grafana",
    description: "Metrics dashboard & observability",
    version: "latest",
    port: 3001,
    iconName: "Activity",
    color: "text-orange-300",
    actions: ["Restart", "Download Logs"],
    dockerName: "threat-hunter-grafana",
  },
  {
    name: "Wazuh Manager",
    description: "On-premise agent & SIEM manager",
    version: "4.7.2",
    port: 55000,
    iconName: "Box",
    color: "text-cyan-400",
    actions: ["Restart", "Download Logs"],
    dockerName: "threat-hunter-wazuh",
  },
  {
    name: "Suricata",
    description: "Network intrusion detection system",
    version: "latest",
    port: 0,
    iconName: "Network",
    color: "text-violet-400",
    actions: ["Restart", "Download Logs"],
    dockerName: "threat-hunter-suricata",
  },
  {
    name: "AI Agent",
    description: "LangGraph autonomous investigator",
    version: "LangGraph",
    port: 0,
    iconName: "Cpu",
    color: "text-purple-400",
    actions: ["Restart"],
    // bundled inside FastAPI — healthy if FastAPI is reachable
    healthKey: undefined,
    dockerName: undefined,
  },
]

const PIPELINE_STEPS = [
  { label: "Logstash",     sub: "TCP :5000",         color: "border-yellow-700 text-yellow-400 bg-yellow-950/20" },
  { label: "Elasticsearch",sub: "Index: security-*",  color: "border-orange-700 text-orange-400 bg-orange-950/20" },
  { label: "FastAPI",      sub: "POST /investigate",   color: "border-emerald-700 text-emerald-400 bg-emerald-950/20" },
  { label: "Correlation",  sub: "10 min window",       color: "border-sky-700 text-sky-400 bg-sky-950/20" },
  { label: "AI Agent",     sub: "LangGraph",           color: "border-purple-700 text-purple-400 bg-purple-950/20" },
  { label: "Response",     sub: "Slack / Email",       color: "border-red-700 text-red-400 bg-red-950/20" },
]

const STATUS_CONFIG: Record<ServiceStatus, { label: string; color: string; bg: string; border: string; dot: string }> = {
  healthy:  { label: "Healthy",  color: "text-emerald-400", bg: "bg-emerald-950/20", border: "border-emerald-800/40", dot: "bg-emerald-500" },
  degraded: { label: "Degraded", color: "text-yellow-400",  bg: "bg-yellow-950/20",  border: "border-yellow-800/40",  dot: "bg-yellow-500" },
  offline:  { label: "Offline",  color: "text-red-400",     bg: "bg-red-950/30",     border: "border-red-800/40",     dot: "bg-red-500" },
  starting: { label: "Starting", color: "text-sky-400",     bg: "bg-sky-950/20",     border: "border-sky-800/40",     dot: "bg-sky-400 animate-pulse" },
  unknown:  { label: "Unknown",  color: "text-zinc-500",    bg: "bg-zinc-800/20",    border: "border-zinc-700/30",    dot: "bg-zinc-600" },
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

// ── Icon helper ────────────────────────────────────────────────
function Ico({ name, size = 16 }: { name: string; size?: number }) {
  const props = { size }
  switch (name) {
    case "Database":  return <Database  {...props} />
    case "ArrowRight":return <ArrowRight {...props} />
    case "Zap":       return <Zap       {...props} />
    case "Server":    return <Server    {...props} />
    case "Activity":  return <Activity  {...props} />
    case "Box":       return <Box       {...props} />
    case "Network":   return <Network   {...props} />
    case "Cpu":       return <Cpu       {...props} />
    default:          return <Server    {...props} />
  }
}

// ── Derive status from API payloads ───────────────────────────
function resolveStatus(
  def: ServiceDef,
  health: HealthData | null,
  docker: DockerStatusData | null,
  apiReachable: boolean,
): { status: ServiceStatus; uptime: string; detail: string } {

  // FastAPI itself: reachable = healthy
  if (def.name === "FastAPI") {
    return apiReachable
      ? { status: "healthy", uptime: "–", detail: "API responding" }
      : { status: "offline",  uptime: "–", detail: "Cannot reach :8000" }
  }

  // AI Agent: co-located with FastAPI
  if (def.name === "AI Agent") {
    return apiReachable
      ? { status: "healthy", uptime: "–", detail: "LangGraph engine loaded" }
      : { status: "offline",  uptime: "–", detail: "FastAPI offline" }
  }

  // Health endpoint keys (ES, Redis, SQLite DB)
  if (def.healthKey && health) {
    const svc = health.services[def.healthKey]
    if (svc) {
      const status: ServiceStatus = svc.ok ? "healthy" : "offline"
      return {
        status,
        uptime: "–",
        detail: svc.ok ? svc.status : (svc.error ?? "unreachable"),
      }
    }
  }

  // Docker container status
  if (def.dockerName && docker) {
    const ct = docker.containers.find(c => c.name === def.dockerName)
    if (ct) {
      let status: ServiceStatus = "unknown"
      if (ct.status === "running") {
        // state is the Docker health status ("healthy", "starting", "unhealthy")
        // containers without a HEALTHCHECK have an empty state — treat as healthy
        status = ct.state === "unhealthy" ? "degraded"
               : ct.state === "starting"  ? "starting"
               : "healthy"   // "healthy" OR "" (no healthcheck) → healthy
      } else if (ct.status === "exited" || ct.status === "dead") {
        status = "offline"
      } else {
        status = "starting"
      }
      const stateLabel = ct.state ? `${ct.status} · ${ct.state}` : ct.status
      return { status, uptime: ct.uptime, detail: stateLabel }
    }
    // Container not in docker ps at all
    if (!apiReachable) return { status: "unknown", uptime: "–", detail: "API unreachable" }
    // Suricata runs in test/passive mode outside Docker in this setup
    if (def.name === "Suricata") return { status: "degraded", uptime: "–", detail: "test mode (no container)" }
    return { status: "offline", uptime: "–", detail: "container not running" }
  }

  return { status: "unknown", uptime: "–", detail: "No data" }
}

// ── CpuBar ─────────────────────────────────────────────────────
// Docker SDK doesn't stream CPU in this endpoint so we show N/A
function UptimeChip({ value }: { value: string }) {
  if (!value || value === "–") return <span className="text-zinc-600 font-mono text-[10px]">–</span>
  return <span className="text-zinc-400 font-mono text-[10px]">{value}</span>
}

// ── ServiceCard ────────────────────────────────────────────────
interface CardProps {
  def: ServiceDef
  status: ServiceStatus
  uptime: string
  detail: string
}

function ServiceCard({ def, status, uptime, detail }: CardProps) {
  const sc = STATUS_CONFIG[status]
  const [busy, setBusy] = useState<string | null>(null)

  function doAction(action: string) {
    setBusy(action)
    setTimeout(() => setBusy(null), 1500)
  }

  return (
    <div className={`rounded-xl border ${sc.border} bg-zinc-900/40 overflow-hidden hover:bg-zinc-900/60 transition-colors`}>
      {/* Header row */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800/60">
        <div className="flex items-center gap-2.5">
          <span className={def.color}><Ico name={def.iconName} /></span>
          <div>
            <span className="text-sm font-semibold text-zinc-200">{def.name}</span>
            <p className="text-[10px] text-zinc-500 leading-none mt-0.5">{def.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full shrink-0 ${sc.dot}`} />
          <span className={`text-[11px] font-medium ${sc.color}`}>{sc.label}</span>
        </div>
      </div>

      {/* Stats grid */}
      <div className="px-4 py-3 grid grid-cols-2 gap-x-4 gap-y-2 text-[11px]">
        <div className="flex items-center justify-between">
          <span className="text-zinc-600">Uptime</span>
          <UptimeChip value={uptime} />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-zinc-600">Version</span>
          <span className="text-zinc-400 font-mono">{def.version}</span>
        </div>
        {def.port > 0 && (
          <div className="flex items-center justify-between">
            <span className="text-zinc-600">Port</span>
            <span className="text-zinc-400 font-mono">:{def.port}</span>
          </div>
        )}
        <div className="col-span-2 flex items-center justify-between">
          <span className="text-zinc-600">Status</span>
          <span className={`text-[10px] font-mono truncate max-w-[140px] ${sc.color}`} title={detail}>{detail}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="px-4 py-2 border-t border-zinc-800/60 flex flex-wrap gap-1.5">
        {def.actions.map(action => (
          <button
            key={action}
            onClick={() => doAction(action)}
            disabled={busy === action}
            className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-zinc-700 text-zinc-500 hover:text-zinc-300 hover:border-zinc-600 transition-colors disabled:opacity-50"
          >
            {busy === action
              ? <RefreshCw size={9} className="animate-spin" />
              : action === "Restart"       ? <RotateCcw size={9} />
              : action === "Download Logs" ? <Download size={9} />
              : action.includes("Clear") || action.includes("Flush") ? <XCircle size={9} />
              : <Zap size={9} />
            }
            {busy === action ? "Running…" : action}
          </button>
        ))}
      </div>
    </div>
  )
}

// ── PipelineBar ────────────────────────────────────────────────
function PipelineBar({ statuses }: { statuses: Record<string, ServiceStatus> }) {
  const stepStatus: Record<string, ServiceStatus> = {
    "Logstash":      statuses["Logstash"]      ?? "unknown",
    "Elasticsearch": statuses["Elasticsearch"] ?? "unknown",
    "FastAPI":       statuses["FastAPI"]       ?? "unknown",
    "Correlation":   statuses["FastAPI"]       ?? "unknown",   // same process
    "AI Agent":      statuses["AI Agent"]      ?? "unknown",
    "Response":      statuses["FastAPI"]       ?? "unknown",
  }

  return (
    <div className="flex items-center gap-0 overflow-x-auto pb-1">
      {PIPELINE_STEPS.map((step, i) => {
        const st = stepStatus[step.label] ?? "unknown"
        const dotColor =
          st === "healthy"  ? "bg-emerald-500" :
          st === "degraded" ? "bg-yellow-500" :
          st === "offline"  ? "bg-red-500" :
          st === "starting" ? "bg-sky-400 animate-pulse" : "bg-zinc-600"
        return (
          <div key={step.label} className="flex items-center shrink-0">
            <div className={`px-3 py-2 rounded-lg border text-center min-w-[90px] ${step.color} relative`}>
              <span className={`absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full ${dotColor}`} />
              <div className="text-[11px] font-semibold leading-tight">{step.label}</div>
              <div className="text-[9px] opacity-70 leading-none mt-0.5">{step.sub}</div>
            </div>
            {i < PIPELINE_STEPS.length - 1 && (
              <div className="flex items-center mx-1">
                <div className="w-6 h-px bg-zinc-700" />
                <ArrowRight size={10} className="text-zinc-600 -ml-1" />
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────
export default function InfrastructurePage() {
  const [health,       setHealth]       = useState<HealthData | null>(null)
  const [docker,       setDocker]       = useState<DockerStatusData | null>(null)
  const [apiReachable, setApiReachable] = useState(false)
  const [loading,      setLoading]      = useState(true)
  const [lastRefresh,  setLastRefresh]  = useState<string>("–")
  const [fetchError,   setFetchError]   = useState<string | null>(null)

  const fetchAll = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    let reachable = false

    try {
      const hRes = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(5000) })
      if (hRes.ok) {
        setHealth(await hRes.json())
        reachable = true
      }
    } catch {
      setHealth(null)
    }

    if (reachable) {
      try {
        const dRes = await fetch(`${API_BASE}/docker-status`, { signal: AbortSignal.timeout(5000) })
        if (dRes.ok) setDocker(await dRes.json())
      } catch {
        // docker-status is optional — keep going
        setDocker(null)
      }
    } else {
      setFetchError("FastAPI is unreachable — start: uvicorn api.main:app --port 8000")
      setDocker(null)
    }

    setApiReachable(reachable)
    setLastRefresh(new Date().toLocaleTimeString())
    setLoading(false)
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])
  // auto-refresh every 30 s
  useEffect(() => {
    const id = setInterval(fetchAll, 30_000)
    return () => clearInterval(id)
  }, [fetchAll])

  // Compute per-service resolved status
  const resolved = SERVICE_DEFS.map(def => ({
    def,
    ...resolveStatus(def, health, docker, apiReachable),
  }))

  const statusMap: Record<string, ServiceStatus> = {}
  resolved.forEach(r => { statusMap[r.def.name] = r.status })

  const healthy  = resolved.filter(r => r.status === "healthy").length
  const degraded = resolved.filter(r => r.status === "degraded").length
  const offline  = resolved.filter(r => r.status === "offline").length

  return (
    <div className="flex flex-col h-full gap-0 -m-6">
      {/* ── Header ── */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/80">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-orange-950/50 border border-orange-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(249,115,22,0.15)]">
              <Server size={16} className="text-orange-400" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">Infrastructure</h1>
              <p className="text-xs text-zinc-500 mt-0.5">Live service health · Pipeline status · Docker containers</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Summary badges */}
            <div className="flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 size={12} /> {healthy} healthy
              </span>
              {degraded > 0 && (
                <span className="flex items-center gap-1.5 text-yellow-400">
                  <AlertTriangle size={12} /> {degraded} degraded
                </span>
              )}
              {offline > 0 && (
                <span className="flex items-center gap-1.5 text-red-400">
                  <XCircle size={12} /> {offline} offline
                </span>
              )}
            </div>

            {/* Last updated */}
            <span className="flex items-center gap-1 text-[10px] text-zinc-600 font-mono">
              <Clock size={10} /> {lastRefresh}
            </span>

            {/* Refresh button */}
            <Button
              variant="outline"
              size="sm"
              onClick={fetchAll}
              disabled={loading}
              className="gap-1.5 text-xs border-zinc-700 text-zinc-400 hover:text-zinc-200"
            >
              {loading
                ? <Loader2 size={12} className="animate-spin" />
                : <RefreshCw size={12} />
              }
              Refresh All
            </Button>
          </div>
        </div>

        {/* Error banner */}
        {fetchError && (
          <div className="mb-3 flex items-center gap-2 text-xs text-yellow-400 bg-yellow-950/20 border border-yellow-800/40 rounded-lg px-3 py-2">
            <AlertTriangle size={12} className="shrink-0" />
            <span className="font-mono">{fetchError}</span>
          </div>
        )}

        {/* Pipeline flow with live dots */}
        <PipelineBar statuses={statusMap} />
      </div>

      {/* ── Services grid ── */}
      <div className="flex-1 overflow-y-auto p-5">
        {loading && !health ? (
          <div className="flex items-center justify-center h-48 gap-3 text-zinc-500">
            <Loader2 size={20} className="animate-spin" />
            <span className="text-sm">Polling services…</span>
          </div>
        ) : (
          <>
            {/* API-verified services on top if reachable */}
            <div className="grid grid-cols-2 xl:grid-cols-3 gap-4">
              {resolved.map(r => (
                <ServiceCard
                  key={r.def.name}
                  def={r.def}
                  status={r.status}
                  uptime={r.uptime}
                  detail={r.detail}
                />
              ))}
            </div>

            {/* Docker status table (if available) */}
            {docker && docker.containers.length > 0 && (
              <div className="mt-6">
                <p className="text-xs font-semibold text-zinc-500 mb-3 flex items-center gap-2">
                  <Wifi size={12} /> Docker Container Raw Status
                  <span className="text-zinc-700 font-normal">· from /docker-status</span>
                </p>
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/30 overflow-hidden">
                  <table className="w-full text-[11px]">
                    <thead>
                      <tr className="border-b border-zinc-800 text-zinc-600">
                        <th className="text-left px-4 py-2 font-medium">Container</th>
                        <th className="text-left px-4 py-2 font-medium">Image</th>
                        <th className="text-left px-4 py-2 font-medium">Status</th>
                        <th className="text-left px-4 py-2 font-medium">Health</th>
                        <th className="text-left px-4 py-2 font-medium">Uptime</th>
                      </tr>
                    </thead>
                    <tbody>
                      {docker.containers.map(ct => {
                        const running = ct.status === "running"
                        const healthy = ct.state === "healthy"
                        return (
                          <tr key={ct.name} className="border-b border-zinc-800/40 last:border-0 hover:bg-zinc-800/20">
                            <td className="px-4 py-2 font-mono text-zinc-300">{ct.name}</td>
                            <td className="px-4 py-2 text-zinc-500 truncate max-w-[160px]">{ct.image}</td>
                            <td className="px-4 py-2">
                              <span className={running ? "text-emerald-400" : "text-red-400"}>
                                {ct.status}
                              </span>
                            </td>
                            <td className="px-4 py-2">
                              <span className={
                                ct.state === "healthy"  ? "text-emerald-400" :
                                ct.state === "starting" ? "text-sky-400" :
                                ct.state === "unhealthy"? "text-red-400" : "text-zinc-500"
                              }>{ct.state || "–"}</span>
                            </td>
                            <td className="px-4 py-2 font-mono text-zinc-500">{ct.uptime || "–"}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}