"use client"

import { useState } from "react"
import {
  Server, Database, Activity, Cpu, HardDrive, Network,
  RefreshCw, Play, Square, Trash2, Download, AlertTriangle,
  CheckCircle2, XCircle, Zap, RotateCcw, ArrowRight,
  MemoryStick, Clock, Box
} from "lucide-react"
import { Button } from "@/components/ui/button"

type ServiceStatus = "healthy" | "degraded" | "offline" | "starting"

interface ServiceInfo {
  name: string
  description: string
  status: ServiceStatus
  uptime: string
  version: string
  port: number
  cpu: number
  memory: string
  icon: React.ReactNode
  color: string
  actions: string[]
}

const SERVICES: ServiceInfo[] = [
  {
    name: "Elasticsearch",
    description: "Security event storage & search",
    status: "healthy",
    uptime: "14d 6h 22m",
    version: "8.13.0",
    port: 9200,
    cpu: 22,
    memory: "1.2 GB",
    icon: <Database size={16} />,
    color: "text-orange-400",
    actions: ["Restart", "Reindex", "Download Logs"],
  },
  {
    name: "Kibana",
    description: "Visualization & management UI",
    status: "healthy",
    uptime: "14d 6h 20m",
    version: "8.13.0",
    port: 5601,
    cpu: 8,
    memory: "412 MB",
    icon: <Activity size={16} />,
    color: "text-pink-400",
    actions: ["Restart", "Download Logs"],
  },
  {
    name: "Logstash",
    description: "Log ingestion & normalization pipeline",
    status: "healthy",
    uptime: "14d 6h 18m",
    version: "8.13.0",
    port: 5000,
    cpu: 14,
    memory: "380 MB",
    icon: <ArrowRight size={16} />,
    color: "text-yellow-400",
    actions: ["Restart", "Clear Queue", "Download Logs"],
  },
  {
    name: "Redis",
    description: "Task queue broker & cache",
    status: "healthy",
    uptime: "14d 6h 18m",
    version: "7-alpine",
    port: 6379,
    cpu: 3,
    memory: "48 MB",
    icon: <Zap size={16} />,
    color: "text-red-400",
    actions: ["Restart", "Flush Cache"],
  },
  {
    name: "FastAPI",
    description: "Security logic & REST API backend",
    status: "healthy",
    uptime: "2h 14m",
    version: "1.0.0",
    port: 8000,
    cpu: 5,
    memory: "210 MB",
    icon: <Server size={16} />,
    color: "text-emerald-400",
    actions: ["Restart", "Download Logs"],
  },
  {
    name: "Wazuh Manager",
    description: "On-premise agent & SIEM manager",
    status: "healthy",
    uptime: "14d 6h 10m",
    version: "4.7.2",
    port: 55000,
    cpu: 18,
    memory: "720 MB",
    icon: <Box size={16} />,
    color: "text-cyan-400",
    actions: ["Restart", "Download Logs"],
  },
  {
    name: "Suricata",
    description: "Network intrusion detection system",
    status: "degraded",
    uptime: "0m (test mode)",
    version: "latest",
    port: 0,
    cpu: 0,
    memory: "—",
    icon: <Network size={16} />,
    color: "text-violet-400",
    actions: ["Restart", "Download Logs"],
  },
  {
    name: "AI Agent",
    description: "LangGraph autonomous investigator",
    status: "healthy",
    uptime: "2h 14m",
    version: "LangGraph",
    port: 0,
    cpu: 2,
    memory: "160 MB",
    icon: <Cpu size={16} />,
    color: "text-purple-400",
    actions: ["Restart"],
  },
]

const PIPELINE_STEPS = [
  { label: "Logstash", sub: "TCP :5000", color: "border-yellow-700 text-yellow-400 bg-yellow-950/20" },
  { label: "Elasticsearch", sub: "Index: security-*", color: "border-orange-700 text-orange-400 bg-orange-950/20" },
  { label: "FastAPI", sub: "POST /investigate", color: "border-emerald-700 text-emerald-400 bg-emerald-950/20" },
  { label: "Correlation", sub: "10min window", color: "border-sky-700 text-sky-400 bg-sky-950/20" },
  { label: "AI Agent", sub: "LangGraph", color: "border-purple-700 text-purple-400 bg-purple-950/20" },
  { label: "Response", sub: "Slack / Email", color: "border-red-700 text-red-400 bg-red-950/20" },
]

const STATUS_CONFIG: Record<ServiceStatus, { label: string; color: string; bg: string; border: string; dot: string }> = {
  healthy:  { label: "Healthy",  color: "text-emerald-400", bg: "bg-emerald-950/20", border: "border-emerald-800/40", dot: "bg-emerald-500" },
  degraded: { label: "Degraded", color: "text-yellow-400",  bg: "bg-yellow-950/20",  border: "border-yellow-800/40",  dot: "bg-yellow-500" },
  offline:  { label: "Offline",  color: "text-red-400",     bg: "bg-red-950/30",     border: "border-red-800/40",     dot: "bg-red-500" },
  starting: { label: "Starting", color: "text-sky-400",     bg: "bg-sky-950/20",     border: "border-sky-800/40",     dot: "bg-sky-400 animate-pulse" },
}

function CpuBar({ value }: { value: number }) {
  const color = value >= 80 ? "bg-red-500" : value >= 50 ? "bg-yellow-500" : "bg-emerald-500"
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-[10px] font-mono text-zinc-400">{value}%</span>
    </div>
  )
}

function ServiceCard({ svc }: { svc: ServiceInfo }) {
  const sc = STATUS_CONFIG[svc.status]
  const [busy, setBusy] = useState<string | null>(null)

  function doAction(action: string) {
    setBusy(action)
    setTimeout(() => setBusy(null), 1500)
  }

  return (
    <div className={`rounded-xl border ${sc.border} bg-zinc-900/40 overflow-hidden hover:bg-zinc-900/60 transition-colors`}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800/60">
        <div className="flex items-center gap-2.5">
          <span className={svc.color}>{svc.icon}</span>
          <div>
            <span className="text-sm font-semibold text-zinc-200">{svc.name}</span>
            <p className="text-[10px] text-zinc-500 leading-none mt-0.5">{svc.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full ${sc.dot} shrink-0`} />
          <span className={`text-[11px] font-medium ${sc.color}`}>{sc.label}</span>
        </div>
      </div>
      <div className="px-4 py-3 grid grid-cols-2 gap-x-4 gap-y-2 text-[11px]">
        <div className="flex items-center justify-between">
          <span className="text-zinc-600">Uptime</span>
          <span className="text-zinc-400 font-mono">{svc.uptime}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-zinc-600">Version</span>
          <span className="text-zinc-400 font-mono">{svc.version}</span>
        </div>
        {svc.port > 0 && (
          <div className="flex items-center justify-between">
            <span className="text-zinc-600">Port</span>
            <span className="text-zinc-400 font-mono">:{svc.port}</span>
          </div>
        )}
        <div className="flex items-center justify-between">
          <span className="text-zinc-600">Memory</span>
          <span className="text-zinc-400 font-mono">{svc.memory}</span>
        </div>
        <div className="col-span-2 flex items-center justify-between pt-1">
          <span className="text-zinc-600">CPU</span>
          <CpuBar value={svc.cpu} />
        </div>
      </div>
      <div className="px-4 py-2 border-t border-zinc-800/60 flex flex-wrap gap-1.5">
        {svc.actions.map(action => (
          <button
            key={action}
            onClick={() => doAction(action)}
            disabled={busy === action}
            className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-zinc-700 text-zinc-500 hover:text-zinc-300 hover:border-zinc-600 transition-colors disabled:opacity-50"
          >
            {busy === action
              ? <RefreshCw size={9} className="animate-spin" />
              : action === "Restart" ? <RotateCcw size={9} />
              : action === "Download Logs" ? <Download size={9} />
              : action.includes("Clear") || action.includes("Flush") ? <Trash2 size={9} />
              : <Zap size={9} />
            }
            {busy === action ? "Running…" : action}
          </button>
        ))}
      </div>
    </div>
  )
}

export default function InfrastructurePage() {
  const healthy = SERVICES.filter(s => s.status === "healthy").length
  const degraded = SERVICES.filter(s => s.status === "degraded").length
  const offline = SERVICES.filter(s => s.status === "offline").length

  return (
    <div className="flex flex-col h-full gap-0 -m-6">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/80">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-orange-950/50 border border-orange-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(249,115,22,0.15)]">
              <Server size={16} className="text-orange-400" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">Infrastructure</h1>
              <p className="text-xs text-zinc-500 mt-0.5">System health · Pipeline control · Service management</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1.5 text-emerald-400"><CheckCircle2 size={12} /> {healthy} healthy</span>
              {degraded > 0 && <span className="flex items-center gap-1.5 text-yellow-400"><AlertTriangle size={12} /> {degraded} degraded</span>}
              {offline > 0 && <span className="flex items-center gap-1.5 text-red-400"><XCircle size={12} /> {offline} offline</span>}
            </div>
            <Button variant="outline" size="sm" className="gap-1.5 text-xs border-zinc-700 text-zinc-400">
              <RefreshCw size={12} /> Refresh All
            </Button>
          </div>
        </div>

        {/* Pipeline flow */}
        <div className="flex items-center gap-0 overflow-x-auto pb-1">
          {PIPELINE_STEPS.map((step, i) => (
            <div key={step.label} className="flex items-center shrink-0">
              <div className={`px-3 py-2 rounded-lg border text-center min-w-[90px] ${step.color}`}>
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
          ))}
        </div>
      </div>

      {/* Services grid */}
      <div className="flex-1 overflow-y-auto p-5">
        <div className="grid grid-cols-2 xl:grid-cols-3 gap-4">
          {SERVICES.map(svc => <ServiceCard key={svc.name} svc={svc} />)}
        </div>
      </div>
    </div>
  )
}