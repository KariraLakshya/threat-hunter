"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import {
  FlaskConical, RefreshCw, Play, Shield, AlertTriangle,
  CheckCircle2, XCircle, Clock, Globe, Search, Loader2,
  Database, Wifi, ChevronRight, Lock, ExternalLink, Activity
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input }  from "@/components/ui/input"

// ── Types ──────────────────────────────────────────────────────

type Verdict = "malicious" | "suspicious" | "clean" | "unknown" | "pending" | "private"

interface IOC {
  ip:             string
  is_private:     boolean
  incident_ids:   string[]
  incident_count: number
  scanned:        boolean
  scanned_at:     string | null
  verdict:        Verdict
  malicious:      number
  suspicious:     number
  harmless:       number
  details:        string
}

interface IOCsResponse {
  iocs:            IOC[]
  total:           number
  scanned:         number
  pending:         number
  malicious:       number
  private_skipped: number
}

// ── Constants ──────────────────────────────────────────────────

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

const VC: Record<Verdict, { label: string; color: string; bg: string; border: string; dot: string; icon: React.ReactNode }> = {
  malicious:  { label: "MALICIOUS",  color: "text-red-400",     bg: "bg-red-950/30",     border: "border-red-800/50",     dot: "bg-red-500",     icon: <XCircle      size={12}/> },
  suspicious: { label: "SUSPICIOUS", color: "text-amber-400",   bg: "bg-amber-950/30",   border: "border-amber-800/50",   dot: "bg-amber-500",   icon: <AlertTriangle size={12}/> },
  clean:      { label: "CLEAN",      color: "text-emerald-400", bg: "bg-emerald-950/20", border: "border-emerald-800/40", dot: "bg-emerald-500", icon: <CheckCircle2  size={12}/> },
  unknown:    { label: "UNKNOWN",    color: "text-zinc-400",    bg: "bg-zinc-800/30",    border: "border-zinc-700/40",    dot: "bg-zinc-500",    icon: <Shield        size={12}/> },
  pending:    { label: "PENDING",    color: "text-blue-400",    bg: "bg-blue-950/20",    border: "border-blue-800/30",    dot: "bg-blue-500",    icon: <Clock         size={12}/> },
  private:    { label: "PRIVATE",    color: "text-zinc-600",    bg: "bg-zinc-900/40",    border: "border-zinc-800/40",    dot: "bg-zinc-700",    icon: <Lock          size={12}/> },
}

function fmtTime(iso: string | null) {
  if (!iso) return "–"
  try { return new Date(iso).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }) }
  catch { return "–" }
}

function fmtDate(iso: string | null) {
  if (!iso) return "–"
  try {
    const d = new Date(iso)
    const isToday = d.toDateString() === new Date().toDateString()
    return isToday ? `Today ${fmtTime(iso)}` : d.toLocaleDateString("en-US", { month: "short", day: "numeric" }) + " " + fmtTime(iso)
  } catch { return "–" }
}

// ── Score ring ─────────────────────────────────────────────────

function Ring({ malicious, total }: { malicious: number; total: number }) {
  const score = total > 0 ? Math.round((malicious / total) * 100) : 0
  const r = 20, c = 2 * Math.PI * r
  const col = score >= 50 ? "#ef4444" : score >= 20 ? "#f59e0b" : "#10b981"
  return (
    <div className="relative w-12 h-12 flex items-center justify-center shrink-0">
      <svg className="absolute -rotate-90" width="48" height="48">
        <circle cx="24" cy="24" r={r} fill="none" stroke="#27272a" strokeWidth="4"/>
        <circle cx="24" cy="24" r={r} fill="none" stroke={col} strokeWidth="4"
          strokeDasharray={c} strokeDashoffset={c - (score / 100) * c} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}/>
      </svg>
      <span className="text-[11px] font-bold font-mono" style={{ color: col }}>{score}</span>
    </div>
  )
}

// ── IOC row ────────────────────────────────────────────────────

function IOCRow({ ioc, selected, onClick }: { ioc: IOC; selected: boolean; onClick: () => void }) {
  const v = VC[ioc.verdict] ?? VC.unknown
  const total = ioc.malicious + ioc.suspicious + ioc.harmless
  return (
    <button onClick={onClick}
      className={`w-full text-left px-4 py-3 border-b border-zinc-800/60 transition-all flex items-center gap-3
        ${selected ? "bg-emerald-950/20 border-l-2 border-l-emerald-500" : "hover:bg-zinc-800/30 border-l-2 border-l-transparent"}`}>
      {/* verdict dot */}
      <span className={`w-2 h-2 rounded-full shrink-0 ${v.dot} ${ioc.verdict === "pending" ? "animate-pulse" : ""}`}/>

      {/* IP */}
      <span className="font-mono text-sm text-zinc-200 w-36 shrink-0">{ioc.ip}</span>

      {/* verdict badge */}
      <span className={`flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${v.bg} ${v.border} ${v.color} shrink-0`}>
        {v.icon}{v.label}
      </span>

      {/* incidents */}
      <span className="flex items-center gap-1 text-[10px] text-zinc-500 shrink-0">
        <Shield size={9}/>{ioc.incident_count} incident{ioc.incident_count !== 1 ? "s" : ""}
      </span>

      {/* engine counts */}
      {ioc.scanned && !ioc.is_private && total > 0 && (
        <span className="text-[10px] text-zinc-600 shrink-0">{ioc.malicious}/{total} engines</span>
      )}

      <div className="flex-1"/>

      {/* scanned time */}
      <span className="text-[10px] text-zinc-700 font-mono shrink-0">{ioc.scanned_at ? fmtDate(ioc.scanned_at) : "Not scanned"}</span>

      <ChevronRight size={12} className="text-zinc-700 shrink-0"/>
    </button>
  )
}

// ── Detail panel ───────────────────────────────────────────────

function IOCDetail({ ioc }: { ioc: IOC }) {
  const v = VC[ioc.verdict] ?? VC.unknown
  const total = ioc.malicious + ioc.suspicious + ioc.harmless

  return (
    <div className="h-full flex flex-col overflow-y-auto">
      {/* header */}
      <div className={`px-5 py-4 border-b border-zinc-800 ${v.bg} shrink-0`}>
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-3">
            {total > 0 && <Ring malicious={ioc.malicious} total={total}/>}
            <div>
              <p className="font-mono text-lg font-bold text-zinc-100">{ioc.ip}</p>
              <span className={`flex items-center gap-1.5 text-xs font-semibold mt-1 ${v.color}`}>
                {v.icon}{v.label}
              </span>
            </div>
          </div>
          <a href={`https://www.virustotal.com/gui/ip-address/${ioc.ip}`}
            target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1 text-[11px] text-zinc-500 hover:text-emerald-400 transition-colors mt-1">
            <ExternalLink size={11}/> VT
          </a>
        </div>
        {ioc.details && <p className="text-xs text-zinc-400">{ioc.details}</p>}
      </div>

      <div className="p-5 space-y-4">
        {/* Engine breakdown */}
        {ioc.scanned && !ioc.is_private && (
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
            <p className="text-xs font-semibold text-zinc-400 mb-3 flex items-center gap-2">
              <Activity size={12}/> Engine Results
            </p>
            <div className="space-y-2">
              {[
                { label: "Malicious",  val: ioc.malicious,  color: "bg-red-500",     text: "text-red-400"     },
                { label: "Suspicious", val: ioc.suspicious, color: "bg-amber-500",   text: "text-amber-400"   },
                { label: "Harmless",   val: ioc.harmless,   color: "bg-emerald-500", text: "text-emerald-400" },
              ].map(row => (
                <div key={row.label} className="flex items-center gap-3">
                  <span className="text-[11px] text-zinc-500 w-20 shrink-0">{row.label}</span>
                  <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${row.color} transition-all duration-500`}
                      style={{ width: total > 0 ? `${(row.val / total) * 100}%` : "0%" }}/>
                  </div>
                  <span className={`text-[11px] font-mono w-6 text-right ${row.text}`}>{row.val}</span>
                </div>
              ))}
              <p className="text-[10px] text-zinc-600 pt-1">{total} engines total</p>
            </div>
          </div>
        )}

        {ioc.is_private && (
          <div className="rounded-lg border border-zinc-800 bg-zinc-800/30 p-4 flex items-center gap-3">
            <Lock size={14} className="text-zinc-600 shrink-0"/>
            <div>
              <p className="text-xs font-semibold text-zinc-400">Private / Internal IP</p>
              <p className="text-[11px] text-zinc-600 mt-0.5">RFC 1918 range — not scanned by VirusTotal</p>
            </div>
          </div>
        )}

        {/* Incidents */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
          <p className="text-xs font-semibold text-zinc-400 mb-3 flex items-center gap-2">
            <Shield size={12}/> Seen In Incidents
          </p>
          <div className="space-y-1.5">
            {ioc.incident_ids.map(id => (
              <div key={id} className="flex items-center gap-2 text-[11px]">
                <span className="w-1.5 h-1.5 rounded-full bg-zinc-600 shrink-0"/>
                <span className="font-mono text-zinc-300">{id}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Scan info */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
          <p className="text-xs font-semibold text-zinc-400 mb-3 flex items-center gap-2">
            <Clock size={12}/> Scan Info
          </p>
          <div className="space-y-1.5 text-[11px]">
            <div className="flex justify-between">
              <span className="text-zinc-600">Last scanned</span>
              <span className="text-zinc-300">{fmtDate(ioc.scanned_at)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-zinc-600">Source</span>
              <span className="text-zinc-300">VirusTotal v3</span>
            </div>
            <div className="flex justify-between">
              <span className="text-zinc-600">Type</span>
              <span className="text-zinc-300">{ioc.is_private ? "Private IP" : "Public IP"}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────

export default function ThreatIntelPage() {
  const [data,      setData]    = useState<IOCsResponse | null>(null)
  const [loading,   setLoading] = useState(true)
  const [scanning,  setScanning]= useState(false)
  const [error,     setError]   = useState<string | null>(null)
  const [selected,  setSelected]= useState<IOC | null>(null)
  const [filter,    setFilter]  = useState<Verdict | "all">("all")
  const [search,    setSearch]  = useState("")
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchIOCs = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/intel/iocs`)
      if (!res.ok) throw new Error(`${res.status}`)
      const json: IOCsResponse = await res.json()
      setData(json)
      setError(null)
      // stop polling once all scannable IPs are done
      if (json.pending === 0 && pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
        setScanning(false)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load IOCs")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchIOCs()
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [fetchIOCs])

  async function startScan() {
    setScanning(true)
    try {
      const res = await fetch(`${API_BASE}/intel/scan`, { method: "POST" })
      const json = await res.json()
      if (json.status === "nothing_to_scan") {
        setScanning(false)
        return
      }
      // poll every 20s while scan is running
      pollRef.current = setInterval(fetchIOCs, 20_000)
    } catch (e) {
      setScanning(false)
      setError(e instanceof Error ? e.message : "Scan failed to start")
    }
  }

  async function clearCache() {
    await fetch(`${API_BASE}/intel/cache`, { method: "DELETE" })
    await fetchIOCs()
  }

  const iocs = data?.iocs ?? []
  const displayed = iocs.filter(ioc => {
    if (filter !== "all" && ioc.verdict !== filter) return false
    if (search && !ioc.ip.includes(search)) return false
    return true
  })

  const hasPending = (data?.pending ?? 0) > 0
  const allDone    = !hasPending && (data?.total ?? 0) > 0

  const FILTERS: { key: Verdict | "all"; label: string }[] = [
    { key: "all",       label: `All (${data?.total ?? 0})` },
    { key: "malicious", label: `Malicious (${data?.malicious ?? 0})` },
    { key: "suspicious",label: `Suspicious (${iocs.filter(i => i.verdict === "suspicious").length})` },
    { key: "pending",   label: `Pending (${data?.pending ?? 0})` },
    { key: "private",   label: `Private (${data?.private_skipped ?? 0})` },
  ]

  return (
    <div className="flex flex-col h-full -m-6">

      {/* ── Header ── */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/90 shrink-0">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-950/60 border border-emerald-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(16,185,129,0.15)]">
              <FlaskConical size={16} className="text-emerald-400"/>
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">Threat Intelligence</h1>
              <p className="text-xs text-zinc-500 mt-0.5">Auto-extracted IOCs from incidents · VirusTotal v3</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {scanning && (
              <span className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-800/40 px-3 py-1.5 rounded-lg">
                <Loader2 size={11} className="animate-spin"/> Scanning…
              </span>
            )}
            <button onClick={fetchIOCs}
              className="text-zinc-600 hover:text-zinc-400 transition-colors p-1.5 rounded-lg hover:bg-zinc-800">
              <RefreshCw size={13} className={loading ? "animate-spin" : ""}/>
            </button>
            <Button onClick={clearCache} variant="outline" size="sm"
              className="text-xs border-zinc-700 text-zinc-500 hover:text-zinc-300 gap-1.5">
              <Database size={11}/> Clear cache
            </Button>
            <Button onClick={startScan} disabled={scanning || !hasPending} size="sm"
              className="gap-2 bg-emerald-700 hover:bg-emerald-600 text-white border-0 shadow-[0_0_14px_rgba(16,185,129,0.2)] disabled:opacity-40">
              {scanning ? <Loader2 size={12} className="animate-spin"/> : <Play size={12}/>}
              {scanning ? "Scanning…" : hasPending ? `Scan ${data?.pending} IPs` : "Up to date"}
            </Button>
          </div>
        </div>

        {/* KPI strip */}
        <div className="grid grid-cols-5 gap-2 mb-3">
          {[
            { label: "Total IOCs",   val: data?.total           ?? 0, color: "text-zinc-300"   },
            { label: "Scanned",      val: data?.scanned         ?? 0, color: "text-blue-400"   },
            { label: "Malicious",    val: data?.malicious       ?? 0, color: "text-red-400"    },
            { label: "Pending",      val: data?.pending         ?? 0, color: "text-amber-400"  },
            { label: "Private (skip)",val: data?.private_skipped ?? 0, color: "text-zinc-600"  },
          ].map(s => (
            <div key={s.label} className="px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800">
              <p className="text-[10px] text-zinc-600">{s.label}</p>
              <p className={`text-lg font-bold font-mono ${s.color}`}>{s.val}</p>
            </div>
          ))}
        </div>

        {/* filter + search row */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex gap-1">
            {FILTERS.map(f => (
              <button key={f.key} onClick={() => setFilter(f.key)}
                className={`text-[11px] px-2.5 py-1 rounded-lg border transition-all ${
                  filter === f.key
                    ? "bg-emerald-950/40 border-emerald-800/50 text-emerald-400"
                    : "border-zinc-800 text-zinc-600 hover:text-zinc-400 hover:bg-zinc-800/50"
                }`}>
                {f.label}
              </button>
            ))}
          </div>
          <div className="relative ml-auto">
            <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600"/>
            <Input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Filter by IP…"
              className="h-7 pl-7 w-40 bg-zinc-900 border-zinc-700 text-xs placeholder:text-zinc-700"/>
          </div>
        </div>

        {error && (
          <div className="mt-2 flex items-center gap-2 text-xs text-red-400 bg-red-950/20 border border-red-900/40 rounded-lg px-3 py-2">
            <XCircle size={11}/> {error} — is FastAPI running?
          </div>
        )}
      </div>

      {/* ── Body ── */}
      <div className="flex flex-1 overflow-hidden">

        {/* IOC list */}
        <div className="w-[480px] shrink-0 border-r border-zinc-800 overflow-y-auto">
          {loading && (
            <div className="flex flex-col items-center justify-center h-48 gap-3">
              <Loader2 size={24} className="text-emerald-500 animate-spin"/>
              <p className="text-xs text-zinc-500">Loading IOCs from incidents…</p>
            </div>
          )}

          {!loading && displayed.length === 0 && (
            <div className="flex flex-col items-center justify-center h-64 gap-4 text-center p-6">
              <div className="w-14 h-14 rounded-2xl bg-emerald-950/30 border border-emerald-800/30 flex items-center justify-center">
                <FlaskConical size={24} className="text-emerald-700"/>
              </div>
              {data?.total === 0 ? (
                <div>
                  <p className="text-sm text-zinc-400">No IOCs yet</p>
                  <p className="text-xs text-zinc-600 mt-1">Run an investigation to generate incidents with IPs</p>
                </div>
              ) : (
                <div>
                  <p className="text-sm text-zinc-400">No IOCs match filter</p>
                  <button onClick={() => { setFilter("all"); setSearch("") }}
                    className="text-xs text-emerald-500 hover:text-emerald-400 mt-1">Clear filters</button>
                </div>
              )}
            </div>
          )}

          {!loading && displayed.map(ioc => (
            <IOCRow key={ioc.ip} ioc={ioc}
              selected={selected?.ip === ioc.ip}
              onClick={() => setSelected(ioc.ip === selected?.ip ? null : ioc)}
            />
          ))}
        </div>

        {/* Detail / empty state */}
        <div className="flex-1 overflow-hidden">
          {selected ? (
            <IOCDetail ioc={
              // always show the freshest version from data
              data?.iocs.find(i => i.ip === selected.ip) ?? selected
            }/>
          ) : (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-8">
              <div className="w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center">
                <Globe size={28} className="text-zinc-700"/>
              </div>
              <div>
                <p className="text-sm text-zinc-500">Select an IOC to see details</p>
                <p className="text-xs text-zinc-700 mt-1">Engine breakdown, affected incidents, scan timestamp</p>
              </div>
              {hasPending && !scanning && (
                <button onClick={startScan}
                  className="flex items-center gap-2 text-xs text-emerald-500 hover:text-emerald-400 transition-colors mt-2">
                  <Play size={11}/> Scan {data?.pending} unscanned IP{data!.pending > 1 ? "s" : ""}
                </button>
              )}
              {allDone && (
                <p className="text-xs text-zinc-700 flex items-center gap-1.5 mt-2">
                  <CheckCircle2 size={11} className="text-emerald-700"/> All IPs scanned
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}