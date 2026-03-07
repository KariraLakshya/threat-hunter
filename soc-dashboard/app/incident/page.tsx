"use client"

import { useState, useEffect } from "react"
import {
  ShieldAlert, Search, RefreshCw, Globe, User, Network,
  Brain, AlertTriangle, CheckCircle2, XCircle, Lock,
  ArrowUpRight, Wifi, Loader2, Eye
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { api, Incident, ChainStep, Conclusion } from "@/lib/api"
import { useIncidents } from "@/hooks/useApi"

type Sev    = "critical" | "high" | "medium" | "low"
type Status = "open" | "investigating" | "closed"

const SEV: Record<Sev, { label: string; color: string; bg: string; border: string; dot: string }> = {
  critical: { label: "CRITICAL", color: "text-red-400",     bg: "bg-red-950/40",     border: "border-red-800/60",     dot: "bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.8)]" },
  high:     { label: "HIGH",     color: "text-orange-400",  bg: "bg-orange-950/30",  border: "border-orange-800/50",  dot: "bg-orange-500" },
  medium:   { label: "MEDIUM",   color: "text-yellow-400",  bg: "bg-yellow-950/20",  border: "border-yellow-800/40",  dot: "bg-yellow-500" },
  low:      { label: "LOW",      color: "text-emerald-400", bg: "bg-emerald-950/20", border: "border-emerald-800/40", dot: "bg-emerald-500" },
}
const STA: Record<Status, { label: string; color: string; icon: React.ReactNode }> = {
  open:          { label: "Open",          color: "text-red-400",   icon: <AlertTriangle size={11}/> },
  investigating: { label: "Investigating", color: "text-amber-400", icon: <Eye size={11}/> },
  closed:        { label: "Closed",        color: "text-zinc-500",  icon: <CheckCircle2 size={11}/> },
}

const fmtTime = (ts: string) =>
  new Date(ts).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })

function Sk({ className = "" }) {
  return <div className={`animate-pulse rounded bg-zinc-800 ${className}`} />
}

function ConfBar({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  const col  = pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-orange-500" : "bg-yellow-500"
  const tcol = pct >= 90 ? "text-red-400" : pct >= 70 ? "text-orange-400" : "text-yellow-400"
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${col}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-mono font-bold ${tcol}`}>{pct}%</span>
    </div>
  )
}

function ChainView({ chain }: { chain: ChainStep[] }) {
  if (!chain?.length) return <p className="text-xs text-zinc-600">No chain data available.</p>
  return (
    <div>
      {chain.map((step, i) => {
        const sev = SEV[step.severity as Sev] ?? SEV.low
        const last = i === chain.length - 1
        return (
          <div key={step.step} className="flex gap-3">
            <div className="flex flex-col items-center">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold border shrink-0 ${sev.bg} ${sev.border} ${sev.color}`}>{step.step}</div>
              {!last && <div className="w-px flex-1 bg-zinc-700/50 my-1" />}
            </div>
            <div className="flex-1 pb-3">
              <div className="flex items-center justify-between gap-2 mb-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-zinc-200">{step.tactic}</span>
                  <span className="text-[10px] font-mono text-zinc-400 bg-zinc-800/80 px-1.5 py-0.5 rounded">{step.technique}</span>
                </div>
                <span className="text-[10px] text-zinc-600 font-mono shrink-0">
                  {new Date(step.timestamp).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 mb-1.5">{step.technique_name}</p>
              <div className="flex flex-wrap gap-2">
                <span className="flex items-center gap-1 text-[10px] text-zinc-500"><User size={9}/>{step.user}</span>
                <span className="flex items-center gap-1 text-[10px] text-zinc-500"><Network size={9}/>{step.source_ip}</span>
                {(step.environment ?? []).map(env => (
                  <span key={env} className={`text-[10px] px-1.5 py-0.5 rounded border
                    ${env === "aws" ? "bg-amber-950/30 border-amber-800/40 text-amber-400" : "bg-zinc-800 border-zinc-700 text-zinc-400"}`}>{env}</span>
                ))}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function IncidentRow({ inc, selected, onClick }: { inc: Incident; selected: boolean; onClick: () => void }) {
  const s = SEV[inc.severity] ?? SEV.low
  const t = STA[inc.status]   ?? STA.open
  return (
    <button onClick={onClick}
      className={`w-full text-left px-4 py-3.5 border-b border-zinc-800/60 transition-all
        ${selected ? "bg-red-950/20 border-l-2 border-l-red-500" : "hover:bg-zinc-800/30 border-l-2 border-l-transparent"}`}>
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full shrink-0 ${s.dot}`} />
          <span className="text-[11px] font-mono text-zinc-400">{inc.incident_id}</span>
          {!!inc.cross_env && (
            <span className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-violet-900/40 text-violet-300 border border-violet-700/40">
              <Globe size={9}/> CROSS-ENV
            </span>
          )}
        </div>
        <span className={`flex items-center gap-1 text-[10px] ${t.color}`}>{t.icon}{t.label}</span>
      </div>
      <p className="text-xs text-zinc-300 line-clamp-2 mb-2 leading-relaxed">{inc.summary}</p>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${s.bg} ${s.border} ${s.color}`}>{s.label}</span>
          <span className="flex items-center gap-1 text-[10px] text-zinc-500"><User size={9}/>{inc.user}</span>
        </div>
        <span className="text-[10px] text-zinc-600">{fmtTime(inc.timestamp)}</span>
      </div>
    </button>
  )
}

function Detail({ inc, onRefresh }: { inc: Incident; onRefresh: () => void }) {
  const [tab, setTab]       = useState<"chain"|"actions"|"conclusion">("chain")
  const [closing, setClose] = useState(false)

  const s   = SEV[inc.severity] ?? SEV.low
  const t   = STA[inc.status]   ?? STA.open
  const c   = (inc.conclusion ?? {}) as Partial<Conclusion>

  // confidence: prefer final_confidence, fall back to confidence
  const conf      = c.final_confidence ?? c.confidence ?? 0
  const isAttack  = c.is_real_attack ?? c.is_attack ?? !!inc.is_attack
  const actions   = inc.actions?.length ? inc.actions : (c.immediate_actions ?? [])

  async function close() {
    setClose(true)
    try { await api.closeIncident(inc.incident_id); onRefresh() }
    catch (e) { console.error(e) }
    finally  { setClose(false) }
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className={`px-5 py-4 border-b border-zinc-800 ${s.bg} shrink-0`}>
        <div className="flex items-start justify-between gap-3 mb-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`text-[11px] font-bold px-2 py-0.5 rounded border ${s.bg} ${s.border} ${s.color}`}>{s.label}</span>
            <span className="text-sm font-mono font-semibold text-zinc-200">{inc.incident_id}</span>
            {!!inc.cross_env && (
              <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-violet-900/40 text-violet-300 border border-violet-700/40">
                <Globe size={9}/> CROSS-ENVIRONMENT
              </span>
            )}
          </div>
          <span className={`flex items-center gap-1 text-xs shrink-0 ${t.color}`}>{t.icon}{t.label}</span>
        </div>
        <p className="text-sm text-zinc-200 leading-relaxed mb-3">{inc.summary}</p>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-[11px]">
          <span className="flex items-center gap-1.5 text-zinc-500"><User size={10}/>User: <span className="text-zinc-300 font-mono">{inc.user}</span></span>
          <span className="flex items-center gap-1.5 text-zinc-500"><Wifi size={10}/>Envs: <span className="text-zinc-300">{(inc.environments ?? []).join(", ")}</span></span>
          {c.kill_chain_stage && <span className="text-zinc-500">Stage: <span className="text-zinc-300">{c.kill_chain_stage}</span></span>}
          {c.business_impact  && <span className="text-zinc-500">Impact: <span className="text-zinc-300 capitalize">{c.business_impact}</span></span>}
        </div>
      </div>

      {/* AI verdict */}
      {conf > 0 && (
        <div className="px-5 py-3 border-b border-zinc-800 bg-zinc-900/50 shrink-0">
          <div className="flex items-center justify-between mb-2">
            <span className="flex items-center gap-1.5 text-xs font-semibold text-zinc-300"><Brain size={13} className="text-violet-400"/> AI Verdict</span>
            <span className={`flex items-center gap-1.5 text-[11px] font-bold px-2 py-0.5 rounded border
              ${isAttack ? "bg-red-950/50 text-red-400 border-red-800/40" : "bg-emerald-950/40 text-emerald-400 border-emerald-800/40"}`}>
              {isAttack ? <><XCircle size={11}/> CONFIRMED ATTACK</> : <><CheckCircle2 size={11}/> FALSE POSITIVE</>}
            </span>
          </div>
          <ConfBar value={conf} />
          {c.iterations_taken !== undefined && (
            <p className="text-[10px] text-zinc-600 mt-1">{c.iterations_taken} agent iteration{c.iterations_taken !== 1 ? "s" : ""} · FP check: {c.fp_check_recommendation ?? "N/A"}</p>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-zinc-800 shrink-0">
        {(["chain","actions","conclusion"] as const).map(tb => (
          <button key={tb} onClick={() => setTab(tb)}
            className={`px-4 py-2.5 text-xs font-medium capitalize border-b-2 transition-colors
              ${tab === tb ? "border-red-500 text-red-400 bg-red-950/10" : "border-transparent text-zinc-500 hover:text-zinc-300"}`}>
            {tb === "chain" ? "Attack Chain" : tb === "actions" ? "Response Actions" : "AI Conclusion"}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-5">
        {tab === "chain" && <ChainView chain={inc.chain} />}

        {tab === "actions" && (
          <div className="space-y-2">
            {!actions.length && <p className="text-xs text-zinc-600">No actions recorded.</p>}
            {actions.map((a, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/50 group hover:border-red-800/40 transition-colors">
                <span className="w-5 h-5 rounded-full bg-red-950/60 border border-red-800/40 flex items-center justify-center text-[10px] text-red-400 font-bold shrink-0">{i+1}</span>
                <span className="text-xs text-zinc-300 leading-relaxed">{a}</span>
                <ArrowUpRight size={12} className="text-zinc-600 group-hover:text-red-400 transition-colors shrink-0 ml-auto mt-0.5" />
              </div>
            ))}
          </div>
        )}

        {tab === "conclusion" && (
          <div className="space-y-3">
            {c.attack_narrative && (
              <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
                <p className="text-[10px] text-zinc-500 font-semibold uppercase tracking-wider mb-1.5">Attack Narrative</p>
                <p className="text-xs text-zinc-300 leading-relaxed">{c.attack_narrative}</p>
              </div>
            )}
            {c.attacker_objective && (
              <div className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700/50">
                <p className="text-[10px] text-zinc-500 font-semibold uppercase tracking-wider mb-1.5">Attacker Objective</p>
                <p className="text-xs text-zinc-300">{c.attacker_objective}</p>
              </div>
            )}
            {c.attacker_next_step && (
              <div className="p-3 rounded-lg bg-zinc-800/50 border border-red-900/30">
                <p className="text-[10px] text-red-500 font-semibold uppercase tracking-wider mb-1.5">Predicted Next Step</p>
                <p className="text-xs text-zinc-300">{c.attacker_next_step}</p>
              </div>
            )}
            {!c.attack_narrative && !c.attacker_objective && (
              <p className="text-xs text-zinc-600">No AI conclusion data available.</p>
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-5 py-3 border-t border-zinc-800 bg-zinc-900/80 flex items-center gap-2 shrink-0">
        {inc.status !== "closed" && (
          <Button onClick={close} disabled={closing} variant="outline" size="sm"
            className="text-xs border-zinc-700 text-zinc-400 hover:text-zinc-100 gap-1.5">
            {closing ? <Loader2 size={12} className="animate-spin"/> : <Lock size={12}/>}
            {closing ? "Closing…" : "Close Incident"}
          </Button>
        )}
        <div className="flex-1"/>
        <span className="text-[10px] text-zinc-600 font-mono">{fmtTime(inc.timestamp)}</span>
      </div>
    </div>
  )
}

export default function IncidentsPage() {
  const { data, loading, error, refetch } = useIncidents(100, 15_000)
  const [selected, setSelected] = useState<Incident | null>(null)
  const [search,   setSearch]   = useState("")
  const [sevF,     setSevF]     = useState<Sev | "all">("all")
  const [staF,     setStaF]     = useState<Status | "all">("all")

  const incidents = data?.incidents ?? []
  useEffect(() => { if (!selected && incidents.length) setSelected(incidents[0]) }, [incidents])

  const filtered = incidents.filter(inc =>
    (sevF === "all" || inc.severity === sevF) &&
    (staF === "all" || inc.status   === staF) &&
    (!search || [inc.summary, inc.incident_id, inc.user].some(f => f?.toLowerCase().includes(search.toLowerCase())))
  )

  const cnt = {
    critical: incidents.filter(i => i.severity === "critical").length,
    high:     incidents.filter(i => i.severity === "high").length,
    open:     incidents.filter(i => i.status   === "open").length,
    cross:    incidents.filter(i => !!i.cross_env).length,
  }

  return (
    <div className="flex flex-col h-full -m-6">
      {/* Toolbar */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/90 backdrop-blur shrink-0">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-red-950/60 border border-red-800/40 flex items-center justify-center">
              <ShieldAlert size={16} className="text-red-400"/>
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">Incident Feed</h1>
              <p className="text-xs text-zinc-500 mt-0.5">
                {loading ? "Loading…" : error ? "API unreachable — start FastAPI on :8000" : `${incidents.length} incidents`}
              </p>
            </div>
          </div>
          <Button onClick={refetch} variant="outline" size="sm" className="gap-1.5 text-xs border-zinc-700 text-zinc-400">
            <RefreshCw size={12} className={loading ? "animate-spin" : ""}/> Refresh
          </Button>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-xs text-yellow-400 bg-yellow-950/20 border border-yellow-800/40 rounded-lg px-3 py-2 mb-3">
            <AlertTriangle size={13}/> FastAPI not reachable at localhost:8000
          </div>
        )}

        {/* KPI chips */}
        <div className="grid grid-cols-4 gap-3 mb-4">
          {[
            { label: "Critical",  val: cnt.critical, col: "text-red-400",    bg: "bg-red-950/30 border-red-900/50",      fn: () => setSevF(v => v === "critical" ? "all" : "critical") },
            { label: "High",      val: cnt.high,     col: "text-orange-400", bg: "bg-orange-950/20 border-orange-900/40", fn: () => setSevF(v => v === "high" ? "all" : "high") },
            { label: "Open",      val: cnt.open,     col: "text-zinc-300",   bg: "bg-zinc-800/60 border-zinc-700/50",     fn: () => setStaF(v => v === "open" ? "all" : "open") },
            { label: "Cross-Env", val: cnt.cross,    col: "text-violet-400", bg: "bg-violet-950/30 border-violet-900/40", fn: () => {} },
          ].map(s => (
            <button key={s.label} onClick={s.fn}
              className={`px-3 py-2 rounded-lg border ${s.bg} flex items-center justify-between hover:brightness-125 transition-all`}>
              <span className="text-[11px] text-zinc-500">{s.label}</span>
              <span className={`text-xl font-bold font-mono ${s.col}`}>{s.val}</span>
            </button>
          ))}
        </div>

        {/* Search + filters */}
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500"/>
            <Input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search incidents, users, IDs…"
              className="pl-8 h-8 bg-zinc-900 border-zinc-700 text-xs placeholder:text-zinc-600"/>
          </div>
          <select value={sevF} onChange={e => setSevF(e.target.value as Sev | "all")}
            className="h-8 px-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-xs text-zinc-300 focus:outline-none">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option><option value="high">High</option>
            <option value="medium">Medium</option><option value="low">Low</option>
          </select>
          <select value={staF} onChange={e => setStaF(e.target.value as Status | "all")}
            className="h-8 px-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-xs text-zinc-300 focus:outline-none">
            <option value="all">All Status</option>
            <option value="open">Open</option><option value="investigating">Investigating</option><option value="closed">Closed</option>
          </select>
        </div>
      </div>

      {/* Split */}
      <div className="flex flex-1 overflow-hidden">
        <div className="w-[380px] shrink-0 border-r border-zinc-800 overflow-y-auto bg-zinc-950">
          {loading && [1,2,3,4].map(i => (
            <div key={i} className="px-4 py-4 border-b border-zinc-800/60 space-y-2">
              <Sk className="h-3 w-32"/><Sk className="h-3 w-full"/><Sk className="h-3 w-3/4"/>
            </div>
          ))}
          {!loading && !filtered.length && (
            <p className="text-center text-xs text-zinc-600 p-8">{error ? "API unreachable" : "No incidents match filters"}</p>
          )}
          {!loading && filtered.map(inc => (
            <IncidentRow key={inc.incident_id} inc={inc} selected={selected?.incident_id === inc.incident_id} onClick={() => setSelected(inc)}/>
          ))}
        </div>
        <div className="flex-1 overflow-hidden bg-zinc-900/20">
          {selected
            ? <Detail key={selected.incident_id} inc={selected} onRefresh={refetch}/>
            : <div className="flex flex-col items-center justify-center h-full gap-3 text-center">
                <ShieldAlert size={28} className="text-zinc-700"/>
                <p className="text-sm text-zinc-500">Select an incident to investigate</p>
              </div>
          }
        </div>
      </div>
    </div>
  )
}