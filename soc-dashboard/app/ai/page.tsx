"use client"

import { useState, useRef, useEffect } from "react"
import { Bot, Play, Square, Brain, ChevronRight, Zap, Shield, AlertTriangle, CheckCircle2, Terminal, Loader2, BarChart2, Search, XCircle, Globe } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input }  from "@/components/ui/input"
import { api }    from "@/lib/api"

type Phase = "idle" | "observing" | "fp_check" | "rag" | "reasoning" | "concluding" | "done" | "error"

interface Log { id: number; text: string; type: "info"|"warn"|"success"|"error"|"system" }

const PHASE_ORDER: Phase[] = ["idle","observing","fp_check","rag","reasoning","concluding","done"]
const PHASES = [
  { key: "observing"  as Phase, label: "Observe",    icon: <Search size={12}/> },
  { key: "fp_check"   as Phase, label: "FP Check",   icon: <Shield size={12}/> },
  { key: "rag"        as Phase, label: "RAG Lookup", icon: <Brain  size={12}/> },
  { key: "reasoning"  as Phase, label: "Reason",     icon: <Zap    size={12}/> },
  { key: "concluding" as Phase, label: "Conclude",   icon: <CheckCircle2 size={12}/> },
]

// Simulated log lines streamed while real /investigate runs in background
const SIM: { ms: number; phase: Phase; text: string; type: Log["type"] }[] = [
  { ms: 200,  phase:"observing",  type:"system", text:"▶ OBSERVE — Connecting to Elasticsearch (security-*)" },
  { ms: 700,  phase:"observing",  type:"info",   text:"  Pulling events from on-premise and cloud indices…" },
  { ms: 1300, phase:"observing",  type:"info",   text:"  Running correlation engine (window = lookback window)" },
  { ms: 1900, phase:"observing",  type:"info",   text:"  Mapping events to MITRE ATT&CK techniques…" },
  { ms: 2500, phase:"fp_check",   type:"system", text:"▶ FP CHECK — Challenging initial hypothesis" },
  { ms: 3000, phase:"fp_check",   type:"info",   text:"  Evaluating benign admin patterns and maintenance windows…" },
  { ms: 3600, phase:"fp_check",   type:"info",   text:"  Checking FP likelihood score…" },
  { ms: 4200, phase:"rag",        type:"system", text:"▶ RAG LOOKUP — ChromaDB semantic search" },
  { ms: 4800, phase:"rag",        type:"info",   text:"  Retrieving MITRE ATT&CK context for observed tactics…" },
  { ms: 5400, phase:"rag",        type:"info",   text:"  Loading similar resolved incidents from RAG store…" },
  { ms: 6100, phase:"reasoning",  type:"system", text:"▶ REASON — Groq LLaMA-3.3-70B deep analysis" },
  { ms: 6900, phase:"reasoning",  type:"info",   text:"  Weighing evidence for and against attack hypothesis…" },
  { ms: 7700, phase:"reasoning",  type:"info",   text:"  Assessing blast radius across environments…" },
  { ms: 8500, phase:"reasoning",  type:"warn",   text:"  Checking for cross-environment pivot signals…" },
  { ms: 9300, phase:"concluding", type:"system", text:"▶ CONCLUDE — Packaging final verdict and incident report" },
  { ms:10000, phase:"concluding", type:"info",   text:"  Calculating confidence score…" },
  { ms:10700, phase:"concluding", type:"info",   text:"  Generating immediate response actions…" },
  { ms:11400, phase:"concluding", type:"info",   text:"  Writing incident to SQLite database…" },
]

const LC: Record<Log["type"], string> = {
  system:"text-purple-400 font-semibold", info:"text-zinc-300",
  warn:"text-amber-400", success:"text-emerald-400", error:"text-red-400 font-semibold",
}

export default function AIPage() {
  const [phase,      setPhase]   = useState<Phase>("idle")
  const [logs,       setLogs]    = useState<Log[]>([])
  const [lookback,   setLookback]= useState("30")
  const [userFilter, setUF]      = useState("")
  const [apiResult,  setResult]  = useState<{ status: string } | null>(null)
  const logRef   = useRef<HTMLDivElement>(null)
  const timers   = useRef<ReturnType<typeof setTimeout>[]>([])
  const idRef    = useRef(0)

  const running = phase !== "idle" && phase !== "done" && phase !== "error"

  const addLog = (text: string, type: Log["type"]) =>
    setLogs(l => [...l, { id: idRef.current++, text, type }])

  function clearTimers() { timers.current.forEach(clearTimeout); timers.current = [] }

  async function run() {
    clearTimers(); setLogs([]); setResult(null); setPhase("observing")
    // stream sim logs
    SIM.forEach(({ ms, phase: p, text, type }) => {
      const t = setTimeout(() => { setPhase(p); addLog(text, type) }, ms)
      timers.current.push(t)
    })
    const finishMs = SIM[SIM.length - 1].ms + 900
    try {
      const res = await api.investigate({ lookback_minutes: parseInt(lookback), user_filter: userFilter || undefined })
      timers.current.push(setTimeout(() => {
        setPhase("done")
        addLog(`✔ Investigation queued — ${res.status}`, "success")
        addLog(`  Results appear in Incident Feed in ~30s`, "info")
        addLog(`  Lookback: ${res.lookback_minutes}m · Queued at: ${new Date(res.timestamp).toLocaleTimeString()}`, "info")
        setResult(res)
      }, finishMs))
    } catch (e) {
      timers.current.push(setTimeout(() => {
        setPhase("error")
        addLog(`✗ API Error: ${e instanceof Error ? e.message : "Unknown error"}`, "error")
        addLog(`  Is FastAPI running on localhost:8000?`, "warn")
      }, finishMs))
    }
  }

  function stop() { clearTimers(); setPhase("idle"); setLogs([]) }

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight }, [logs])
  useEffect(() => () => clearTimers(), [])

  const phaseIdx = PHASE_ORDER.indexOf(phase)

  return (
    <div className="flex flex-col h-full -m-6">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/90 shrink-0">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-950/60 border border-purple-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(168,85,247,0.2)]">
              <Bot size={16} className="text-purple-400"/>
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100 leading-none">AI Investigation</h1>
              <p className="text-xs text-zinc-500 mt-0.5">POST /investigate · LangGraph · Groq LLaMA-3.3-70B</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {running && <span className="flex items-center gap-1.5 text-xs text-purple-400 bg-purple-950/30 border border-purple-800/40 px-3 py-1.5 rounded-lg"><Loader2 size={11} className="animate-spin"/>Agent running…</span>}
            {phase === "done"  && <span className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-800/40 px-3 py-1.5 rounded-lg"><CheckCircle2 size={11}/>Queued successfully</span>}
            {phase === "error" && <span className="flex items-center gap-1.5 text-xs text-red-400 bg-red-950/30 border border-red-800/40 px-3 py-1.5 rounded-lg"><XCircle size={11}/>API unreachable</span>}
          </div>
        </div>
        <div className="flex items-center gap-3">
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
              placeholder="e.g. jsmith" className="h-8 bg-zinc-900 border-zinc-700 text-xs placeholder:text-zinc-600 w-32 disabled:opacity-50"/>
          </div>
          {!running
            ? <Button onClick={run} className="gap-2 bg-purple-600 hover:bg-purple-500 text-white border-0 shadow-[0_0_20px_rgba(168,85,247,0.25)]" size="sm"><Play size={12}/> Run Investigation</Button>
            : <Button onClick={stop} variant="outline" size="sm" className="gap-2 border-red-800/50 text-red-400 hover:bg-red-950/30"><Square size={12}/> Stop</Button>
          }
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Terminal */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Stepper */}
          <div className="flex items-center px-6 py-3 border-b border-zinc-800 bg-zinc-900/40 shrink-0">
            {PHASES.map((p, i) => {
              const pidx = PHASE_ORDER.indexOf(p.key)
              const done = phaseIdx > pidx && phase !== "error"
              const active = phase === p.key
              return (
                <div key={p.key} className="flex items-center">
                  <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-medium transition-all
                    ${active ? "bg-purple-950/60 text-purple-300 border border-purple-700/60 shadow-[0_0_8px_rgba(168,85,247,0.2)]"
                             : done ? "text-emerald-400" : "text-zinc-600"}`}>
                    {done ? <CheckCircle2 size={11}/> : p.icon}{p.label}
                  </div>
                  {i < PHASES.length - 1 && <div className={`w-8 h-px mx-1 ${phaseIdx > pidx && phase !== "error" ? "bg-emerald-800" : "bg-zinc-800"}`}/>}
                </div>
              )
            })}
          </div>

          {/* Log output */}
          <div ref={logRef} className="flex-1 overflow-y-auto bg-zinc-950 p-5 text-[12px] leading-relaxed"
            style={{ fontFamily: "'JetBrains Mono','Fira Code',monospace" }}>
            {!logs.length && phase === "idle" && (
              <div className="flex flex-col items-center justify-center h-full gap-4 text-center">
                <div className="w-16 h-16 rounded-2xl bg-purple-950/40 border border-purple-800/30 flex items-center justify-center">
                  <Terminal size={28} className="text-purple-700"/>
                </div>
                <div>
                  <p className="text-sm text-zinc-400">AI agent standing by</p>
                  <p className="text-xs text-zinc-600 mt-1">Configure lookback window and click Run Investigation</p>
                  <p className="text-xs text-zinc-700 mt-0.5">Requires FastAPI on localhost:8000</p>
                </div>
              </div>
            )}
            {logs.map(l => (
              <div key={l.id} className={LC[l.type]}>
                {l.type !== "system" && <span className="text-zinc-700 mr-2 select-none">$</span>}
                {l.text}
              </div>
            ))}
            {running && <div className="flex items-center gap-1 mt-1 text-purple-400"><span className="text-zinc-700 select-none mr-2">$</span><span className="w-2 h-4 bg-purple-400 animate-pulse inline-block"/></div>}
          </div>

          {/* Result strip */}
          {phase === "done" && apiResult && (
            <div className="px-6 py-3 border-t border-emerald-900/40 bg-emerald-950/10 flex items-center gap-4 shrink-0">
              <CheckCircle2 size={14} className="text-emerald-400 shrink-0"/>
              <span className="text-emerald-400 font-semibold text-sm">Investigation queued</span>
              <div className="h-4 w-px bg-zinc-700"/>
              <span className="text-xs text-zinc-400">{apiResult.status}</span>
              <div className="flex-1"/>
              <span className="text-xs text-zinc-500 font-mono">Check Incident Feed in ~30s</span>
            </div>
          )}
        </div>

        {/* Side info */}
        <div className="w-60 shrink-0 border-l border-zinc-800 bg-zinc-900/20 p-4 space-y-3 overflow-y-auto">
          <p className="text-[11px] text-zinc-600 font-semibold uppercase tracking-wider">Agent Pipeline</p>
          {[
            { icon: <Search size={12}/>,       label:"Observe",    sub:"Pull ES events",        col:"text-purple-400", bg:"bg-purple-950/20 border-purple-800/30" },
            { icon: <Shield size={12}/>,       label:"FP Check",   sub:"Devil's advocate",      col:"text-blue-400",   bg:"bg-blue-950/20 border-blue-800/30" },
            { icon: <Brain  size={12}/>,       label:"RAG Lookup", sub:"ChromaDB + MITRE",      col:"text-sky-400",    bg:"bg-sky-950/20 border-sky-800/30" },
            { icon: <Zap    size={12}/>,       label:"Reason",     sub:"LLM deep analysis",     col:"text-violet-400", bg:"bg-violet-950/20 border-violet-800/30" },
            { icon: <CheckCircle2 size={12}/>, label:"Conclude",   sub:"Verdict + actions",     col:"text-emerald-400",bg:"bg-emerald-950/20 border-emerald-800/30" },
          ].map(s => (
            <div key={s.label} className={`flex items-center gap-2.5 p-2.5 rounded-lg border ${s.bg}`}>
              <span className={s.col}>{s.icon}</span>
              <div><p className={`text-[11px] font-semibold ${s.col}`}>{s.label}</p><p className="text-[10px] text-zinc-600">{s.sub}</p></div>
            </div>
          ))}
          <div className="mt-3 p-3 rounded-lg border border-zinc-700/50 bg-zinc-800/30 space-y-1">
            <p className="text-[11px] text-zinc-500 font-semibold">Endpoint</p>
            <p className="text-[10px] font-mono text-zinc-600">POST /investigate</p>
            <p className="text-[10px] text-zinc-600">Runs in background.<br/>Results → Incident Feed.</p>
          </div>
        </div>
      </div>
    </div>
  )
}