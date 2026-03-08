"use client"

import { useState, useRef, useEffect, useCallback } from "react"
import {
  Bot, Play, Square, Brain, Zap, Shield,
  CheckCircle2, Terminal, Loader2, Search, XCircle,
  Clock, Trash2, RotateCcw, Wifi, WifiOff
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input }  from "@/components/ui/input"

// ── Types ──────────────────────────────────────────────────────

type Phase = "idle" | "observing" | "fp_check" | "rag" | "reasoning" | "concluding" | "done" | "error"

interface Log {
  id:   number
  text: string
  type: "info" | "warn" | "success" | "error" | "system"
}

interface RunRecord {
  id:         string
  startedAt:  string
  lookback:   string
  userFilter: string
  phase:      Phase
  logs:       Log[]
  incidentId: string | null
  error:      string | null
}

// ── Constants ──────────────────────────────────────────────────

const API_BASE    = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
const CACHE_KEY   = "ai-investigation-cache"
const MAX_RUNS    = 10

// Map backend phase strings → our Phase type
const PHASE_MAP: Record<string, Phase> = {
  observing:  "observing",
  fp_check:   "fp_check",
  rag:        "rag",
  reasoning:  "reasoning",
  concluding: "concluding",
  error:      "error",
}

const PHASE_ORDER: Phase[] = ["idle","observing","fp_check","rag","reasoning","concluding","done","error"]

const PHASES = [
  { key: "observing"   as Phase, label: "Observe",    icon: <Search      size={12}/> },
  { key: "fp_check"    as Phase, label: "FP Check",   icon: <Shield      size={12}/> },
  { key: "rag"         as Phase, label: "RAG Lookup", icon: <Brain       size={12}/> },
  { key: "reasoning"   as Phase, label: "Reason",     icon: <Zap         size={12}/> },
  { key: "concluding"  as Phase, label: "Conclude",   icon: <CheckCircle2 size={12}/> },
]

const LC: Record<Log["type"], string> = {
  system:  "text-purple-400 font-semibold mt-2 first:mt-0",
  info:    "text-zinc-300",
  warn:    "text-amber-400",
  success: "text-emerald-400 font-semibold",
  error:   "text-red-400 font-semibold",
}

// ── Cache helpers ──────────────────────────────────────────────

function loadCache(): RunRecord[] {
  try {
    const raw = sessionStorage.getItem(CACHE_KEY)
    return raw ? JSON.parse(raw) : []
  } catch { return [] }
}

function saveCache(runs: RunRecord[]) {
  try {
    sessionStorage.setItem(CACHE_KEY, JSON.stringify(runs.slice(-MAX_RUNS)))
  } catch {}
}

function fmtTime(iso: string) {
  try { return new Date(iso).toLocaleTimeString("en-US", { hour:"2-digit", minute:"2-digit", second:"2-digit" }) }
  catch { return "–" }
}

function fmtDate(iso: string) {
  try {
    const d = new Date(iso)
    const isToday = d.toDateString() === new Date().toDateString()
    return isToday ? `Today ${fmtTime(iso)}` : `${d.toLocaleDateString("en-US",{month:"short",day:"numeric"})} ${fmtTime(iso)}`
  } catch { return "–" }
}

function PhaseBadge({ phase }: { phase: Phase }) {
  if (phase === "done")  return <span className="text-[10px] text-emerald-400 flex items-center gap-1"><CheckCircle2 size={9}/>Done</span>
  if (phase === "error") return <span className="text-[10px] text-red-400 flex items-center gap-1"><XCircle size={9}/>Error</span>
  if (phase === "idle")  return <span className="text-[10px] text-zinc-600">Idle</span>
  return <span className="text-[10px] text-purple-400 flex items-center gap-1"><Loader2 size={9} className="animate-spin"/>Running</span>
}

// ── Main Page ──────────────────────────────────────────────────

export default function AIPage() {

  const [phase,      setPhase]    = useState<Phase>("idle")
  const [logs,       setLogs]     = useState<Log[]>([])
  const [lookback,   setLookback] = useState("30")
  const [userFilter, setUF]       = useState("")
  const [incidentId, setIncidentId] = useState<string | null>(null)
  const [streamErr,  setStreamErr]  = useState<string | null>(null)

  const [history,    setHistory]  = useState<RunRecord[]>([])
  const [activeRun,  setActiveRun]= useState<string | null>(null)

  const logRef    = useRef<HTMLDivElement>(null)
  const esRef     = useRef<EventSource | null>(null)
  const idRef     = useRef(0)
  const runIdRef  = useRef("")

  const running = phase !== "idle" && phase !== "done" && phase !== "error"

  // ── Load cache on mount ────────────────────────────────────
  useEffect(() => {
    const cached = loadCache()
    setHistory(cached)
    if (cached.length > 0) {
      const last = cached[cached.length - 1]
      if (last.phase === "done" || last.phase === "error") setActiveRun(last.id)
    }
  }, [])

  // ── Auto-scroll ────────────────────────────────────────────
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  // ── Cleanup on unmount ─────────────────────────────────────
  useEffect(() => () => { esRef.current?.close() }, [])

  // ── Add a log line and mirror to cache ─────────────────────
  const addLog = useCallback((text: string, type: Log["type"]) => {
    const entry: Log = { id: idRef.current++, text, type }
    setLogs(l => {
      const next = [...l, entry]
      setHistory(hist => {
        const updated = hist.map(r => r.id === runIdRef.current ? { ...r, logs: next } : r)
        saveCache(updated)
        return updated
      })
      return next
    })
  }, [])

  const updateRunPhase = useCallback((p: Phase) => {
    setPhase(p)
    setHistory(hist => {
      const updated = hist.map(r => r.id === runIdRef.current ? { ...r, phase: p } : r)
      saveCache(updated)
      return updated
    })
  }, [])

  // ── Run investigation via SSE stream ───────────────────────
  function run() {
    if (running) return
    esRef.current?.close()

    const runId = `run-${Date.now()}`
    runIdRef.current = runId

    setLogs([])
    setIncidentId(null)
    setStreamErr(null)
    setPhase("observing")
    setActiveRun(null)

    const newRun: RunRecord = {
      id: runId, startedAt: new Date().toISOString(),
      lookback, userFilter, phase: "observing", logs: [], incidentId: null, error: null,
    }
    setHistory(hist => { const u = [...hist, newRun]; saveCache(u); return u })

    const params = new URLSearchParams({ lookback_minutes: lookback })
    if (userFilter) params.set("user_filter", userFilter)
    const url = `${API_BASE}/investigate/stream?${params}`

    const es = new EventSource(url)
    esRef.current = es

    es.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)

        // keep-alive ping
        if (msg.ping) return

        // completion sentinel
        if (msg.done) {
          es.close()
          if (msg.error && msg.error !== "no_events" && msg.error !== "no_correlated_events") {
            setStreamErr(msg.error)
            updateRunPhase("error")
            addLog(`✗ Pipeline error: ${msg.error}`, "error")
          } else if (msg.error) {
            // graceful empty-result end
            updateRunPhase("done")
          } else {
            const iid = msg.incident_id || ""
            setIncidentId(iid)
            updateRunPhase("done")
            addLog(`✔ Incident ${iid} created — check the Incident Feed`, "success")
            setHistory(hist => {
              const updated = hist.map(r => r.id === runIdRef.current
                ? { ...r, phase: "done" as Phase, incidentId: iid }
                : r
              )
              saveCache(updated)
              return updated
            })
          }
          return
        }

        // regular log line
        const type    = (msg.type as Log["type"]) ?? "info"
        const msgPhase: Phase | undefined = PHASE_MAP[msg.phase as string]
        if (msgPhase) updateRunPhase(msgPhase)
        addLog(msg.text ?? "", type)

      } catch { /* malformed frame — ignore */ }
    }

    es.onerror = () => {
      es.close()
      if (runIdRef.current === runId) {
        updateRunPhase("error")
        setStreamErr("SSE connection failed")
        addLog("✗ Cannot reach FastAPI — is it running on localhost:8000?", "error")
        addLog("  Start with: uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload", "warn")
      }
    }
  }

  function stop() {
    esRef.current?.close()
    setPhase("idle")
    setLogs([])
    setHistory(hist => {
      const updated = hist.filter(r => r.id !== runIdRef.current)
      saveCache(updated)
      return updated
    })
  }

  function clearHistory() {
    setHistory([])
    sessionStorage.removeItem(CACHE_KEY)
    setActiveRun(null)
  }

  function deleteRun(id: string) {
    setHistory(hist => { const u = hist.filter(r => r.id !== id); saveCache(u); return u })
    if (activeRun === id) setActiveRun(null)
  }

  // ── Display: live vs history ───────────────────────────────
  const viewingRun    = activeRun ? history.find(r => r.id === activeRun) : null
  const displayLogs   = viewingRun ? viewingRun.logs  : logs
  const displayPhase  = viewingRun ? viewingRun.phase : phase
  const displayIncId  = viewingRun ? viewingRun.incidentId : incidentId
  const isHistoryView = !!viewingRun
  const phaseIdx      = PHASE_ORDER.indexOf(displayPhase)

  return (
    <div className="flex flex-col h-full -m-6">

      {/* ── Header ── */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/90 shrink-0">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-950/60 border border-purple-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(168,85,247,0.2)]">
              <Bot size={16} className="text-purple-400"/>
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">AI Investigation</h1>
              <p className="text-xs text-zinc-500 mt-0.5">
                GET /investigate/stream · SSE · LangGraph · Groq LLaMA-3.3-70B
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isHistoryView && (
              <span className="flex items-center gap-1.5 text-xs text-amber-400 bg-amber-950/30 border border-amber-800/40 px-3 py-1.5 rounded-lg">
                <Clock size={11}/> Viewing history
              </span>
            )}
            {!isHistoryView && running && (
              <span className="flex items-center gap-1.5 text-xs text-purple-400 bg-purple-950/30 border border-purple-800/40 px-3 py-1.5 rounded-lg">
                <Wifi size={11} className="animate-pulse"/> Live stream
              </span>
            )}
            {!isHistoryView && displayPhase === "done" && (
              <span className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-800/40 px-3 py-1.5 rounded-lg">
                <CheckCircle2 size={11}/> Complete
              </span>
            )}
            {!isHistoryView && displayPhase === "error" && (
              <span className="flex items-center gap-1.5 text-xs text-red-400 bg-red-950/30 border border-red-800/40 px-3 py-1.5 rounded-lg">
                <WifiOff size={11}/> Stream error
              </span>
            )}
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <label className="text-xs text-zinc-500 shrink-0">Lookback</label>
            <select value={lookback} onChange={e => setLookback(e.target.value)} disabled={running}
              className="h-8 px-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-xs text-zinc-300 focus:outline-none disabled:opacity-50">
              {["5","10","15","30","60","90"].map(v => <option key={v} value={v}>{v} min</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs text-zinc-500 shrink-0">User filter</label>
            <Input value={userFilter} onChange={e => setUF(e.target.value)} disabled={running}
              placeholder="e.g. jsmith"
              className="h-8 bg-zinc-900 border-zinc-700 text-xs placeholder:text-zinc-600 w-32 disabled:opacity-50"/>
          </div>
          {!running
            ? <Button onClick={run}
                className="gap-2 bg-purple-600 hover:bg-purple-500 text-white border-0 shadow-[0_0_20px_rgba(168,85,247,0.25)]"
                size="sm">
                <Play size={12}/> Run Investigation
              </Button>
            : <Button onClick={stop} variant="outline" size="sm"
                className="gap-2 border-red-800/50 text-red-400 hover:bg-red-950/30">
                <Square size={12}/> Stop
              </Button>
          }
          {isHistoryView && (
            <Button onClick={() => setActiveRun(null)} variant="outline" size="sm"
              className="gap-1.5 text-xs border-zinc-700 text-zinc-400 hover:text-zinc-200 ml-auto">
              <RotateCcw size={11}/> Back to live
            </Button>
          )}
        </div>
      </div>

      {/* ── Body ── */}
      <div className="flex flex-1 overflow-hidden">

        {/* ── Terminal panel ── */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* Phase stepper */}
          <div className="flex items-center px-6 py-3 border-b border-zinc-800 bg-zinc-900/40 shrink-0 gap-1 overflow-x-auto">
            {PHASES.map((p, i) => {
              const pidx = PHASE_ORDER.indexOf(p.key)
              const done   = phaseIdx > pidx && displayPhase !== "error"
              const active = displayPhase === p.key
              return (
                <div key={p.key} className="flex items-center shrink-0">
                  <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-medium transition-all
                    ${active  ? "bg-purple-950/60 text-purple-300 border border-purple-700/60 shadow-[0_0_8px_rgba(168,85,247,0.2)]"
                    : done   ? "text-emerald-400"
                              : "text-zinc-600"}`}>
                    {done ? <CheckCircle2 size={11}/> : p.icon}{p.label}
                  </div>
                  {i < PHASES.length - 1 && (
                    <div className={`w-6 h-px mx-0.5 ${phaseIdx > pidx && displayPhase !== "error" ? "bg-emerald-800" : "bg-zinc-800"}`}/>
                  )}
                </div>
              )
            })}
            {isHistoryView && viewingRun && (
              <span className="ml-auto shrink-0 text-[10px] text-zinc-600 font-mono flex items-center gap-1">
                <Clock size={9}/> {fmtDate(viewingRun.startedAt)}
                {viewingRun.userFilter && <span className="ml-1">· user:{viewingRun.userFilter}</span>}
                <span className="ml-1">· {viewingRun.lookback}m</span>
              </span>
            )}
          </div>

          {/* Log output — the real terminal */}
          <div ref={logRef}
            className="flex-1 overflow-y-auto bg-zinc-950 p-5 text-[12px] leading-relaxed"
            style={{ fontFamily: "'JetBrains Mono','Fira Code',monospace" }}>

            {!displayLogs.length && displayPhase === "idle" && !isHistoryView && (
              <div className="flex flex-col items-center justify-center h-full gap-4 text-center">
                <div className="w-16 h-16 rounded-2xl bg-purple-950/40 border border-purple-800/30 flex items-center justify-center">
                  <Terminal size={28} className="text-purple-700"/>
                </div>
                <div>
                  <p className="text-sm text-zinc-400">AI agent standing by</p>
                  <p className="text-xs text-zinc-600 mt-1">Logs stream live from the real pipeline via SSE</p>
                  <p className="text-xs text-zinc-700 mt-0.5">Requires FastAPI on localhost:8000</p>
                  {history.length > 0 && (
                    <p className="text-xs text-purple-700 mt-2">{history.length} past run{history.length > 1 ? "s" : ""} in history →</p>
                  )}
                </div>
              </div>
            )}

            {displayLogs.map(l => (
              <div key={l.id} className={LC[l.type]}>
                {l.type !== "system" && <span className="text-zinc-700 mr-2 select-none">$</span>}
                {l.text}
              </div>
            ))}

            {!isHistoryView && running && (
              <div className="flex items-center gap-1 mt-1 text-purple-400">
                <span className="text-zinc-700 select-none mr-2">$</span>
                <span className="w-2 h-4 bg-purple-400 animate-pulse inline-block"/>
              </div>
            )}
          </div>

          {/* Result strip */}
          {displayPhase === "done" && !streamErr && (
            <div className="px-6 py-3 border-t border-emerald-900/40 bg-emerald-950/10 flex items-center gap-4 shrink-0">
              <CheckCircle2 size={14} className="text-emerald-400 shrink-0"/>
              <span className="text-emerald-400 font-semibold text-sm">Investigation complete</span>
              {displayIncId && <>
                <div className="h-4 w-px bg-zinc-700"/>
                <span className="text-xs font-mono text-zinc-300">{displayIncId}</span>
              </>}
              <div className="flex-1"/>
              <span className="text-xs text-zinc-500 font-mono">View in Incident Feed</span>
            </div>
          )}

          {displayPhase === "error" && (
            <div className="px-6 py-3 border-t border-red-900/40 bg-red-950/10 flex items-center gap-3 shrink-0">
              <WifiOff size={14} className="text-red-400 shrink-0"/>
              <span className="text-red-400 font-semibold text-sm">Stream error</span>
              {streamErr && <span className="text-xs text-zinc-500 font-mono">{streamErr}</span>}
              <div className="flex-1"/>
              <Button onClick={run} size="sm" variant="outline"
                className="text-xs border-zinc-700 text-zinc-400 hover:text-white gap-1.5">
                <RotateCcw size={11}/> Retry
              </Button>
            </div>
          )}
        </div>

        {/* ── Sidebar ── */}
        <div className="w-64 shrink-0 border-l border-zinc-800 bg-zinc-900/20 flex flex-col overflow-hidden">

          {/* Pipeline steps */}
          <div className="p-4 space-y-1.5 border-b border-zinc-800">
            <p className="text-[11px] text-zinc-600 font-semibold uppercase tracking-wider mb-2">Agent Pipeline</p>
            {[
              { icon: <Search size={12}/>,        label:"Observe",    sub:"ES query + correlation",  col:"text-purple-400", bg:"bg-purple-950/20 border-purple-800/30" },
              { icon: <Shield size={12}/>,        label:"FP Check",   sub:"Devil's advocate LLM",   col:"text-blue-400",   bg:"bg-blue-950/20 border-blue-800/30"   },
              { icon: <Brain  size={12}/>,        label:"RAG Lookup", sub:"ChromaDB + VirusTotal",  col:"text-sky-400",    bg:"bg-sky-950/20 border-sky-800/30"     },
              { icon: <Zap    size={12}/>,        label:"Reason",     sub:"LLaMA-3.3-70B analysis", col:"text-violet-400", bg:"bg-violet-950/20 border-violet-800/30"},
              { icon: <CheckCircle2 size={12}/>,  label:"Conclude",   sub:"Verdict + incident",     col:"text-emerald-400",bg:"bg-emerald-950/20 border-emerald-800/30"},
            ].map(s => (
              <div key={s.label} className={`flex items-center gap-2.5 p-2 rounded-lg border ${s.bg}`}>
                <span className={s.col}>{s.icon}</span>
                <div>
                  <p className={`text-[11px] font-semibold ${s.col}`}>{s.label}</p>
                  <p className="text-[10px] text-zinc-600">{s.sub}</p>
                </div>
              </div>
            ))}
            <div className="mt-2 p-2.5 rounded-lg border border-zinc-700/50 bg-zinc-800/30">
              <p className="text-[10px] font-mono text-zinc-600">GET /investigate/stream</p>
              <p className="text-[10px] text-zinc-700 mt-0.5">Real logs via SSE. Results → Incident Feed.</p>
            </div>
          </div>

          {/* Run history */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-zinc-800 shrink-0">
              <p className="text-[11px] text-zinc-500 font-semibold uppercase tracking-wider flex items-center gap-1.5">
                <Clock size={10}/> History
                {history.length > 0 && <span className="text-zinc-700 font-normal">({history.length})</span>}
              </p>
              {history.length > 0 && (
                <button onClick={clearHistory} title="Clear all" className="text-zinc-700 hover:text-red-400 transition-colors">
                  <Trash2 size={11}/>
                </button>
              )}
            </div>

            <div className="flex-1 overflow-y-auto">
              {history.length === 0 && (
                <p className="text-[10px] text-zinc-700 text-center p-4">No runs yet this session</p>
              )}
              {[...history].reverse().map(run => {
                const isSelected = activeRun === run.id
                const isLive     = !activeRun && runIdRef.current === run.id && running
                return (
                  <div key={run.id}
                    className={`border-b border-zinc-800/60 last:border-0 transition-colors cursor-pointer
                      ${isSelected
                        ? "bg-purple-950/20 border-l-2 border-l-purple-500"
                        : "hover:bg-zinc-800/30 border-l-2 border-l-transparent"}`}
                    onClick={() => setActiveRun(isSelected ? null : run.id)}>
                    <div className="px-3 py-2.5">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] font-mono text-zinc-500">{fmtTime(run.startedAt)}</span>
                        <PhaseBadge phase={run.phase}/>
                      </div>
                      <div className="flex items-center gap-1.5 text-[10px] text-zinc-600">
                        <span className="text-zinc-500">{run.lookback}m</span>
                        {run.userFilter && <><span>·</span><span className="font-mono text-zinc-500">{run.userFilter}</span></>}
                        <span>·</span>
                        <span>{run.logs.length} lines</span>
                      </div>
                      {run.incidentId && (
                        <span className="text-[9px] font-mono text-emerald-600 mt-0.5 block">{run.incidentId}</span>
                      )}
                      {isLive && <span className="text-[9px] text-purple-500 mt-0.5 block">● streaming</span>}
                    </div>
                    <button
                      onClick={e => { e.stopPropagation(); deleteRun(run.id) }}
                      className="hidden group-hover:block absolute right-2 top-2 text-zinc-700 hover:text-red-400"
                    />
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}