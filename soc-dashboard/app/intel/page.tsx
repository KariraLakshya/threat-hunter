"use client"

import { useState } from "react"
import { FlaskConical, Search, Hash, Link2, Globe, Shield, AlertTriangle, CheckCircle2, XCircle, Loader2, Clock, Activity, ExternalLink } from "lucide-react"
import { Button }   from "@/components/ui/button"
import { Input }    from "@/components/ui/input"
import { api, SandboxResponse } from "@/lib/api"

type IndicatorType = "ip" | "hash" | "url"

const TABS: { key: IndicatorType; icon: React.ReactNode; label: string; placeholder: string }[] = [
  { key: "ip",   icon: <Globe    size={13}/>, label: "IP Address", placeholder: "e.g. 203.0.113.42" },
  { key: "hash", icon: <Hash     size={13}/>, label: "File Hash",  placeholder: "MD5 / SHA1 / SHA256" },
  { key: "url",  icon: <Link2   size={13}/>, label: "URL",         placeholder: "https://suspicious.example.com" },
]

const VC = {
  malicious:  { label:"MALICIOUS",  color:"text-red-400",     bg:"bg-red-950/40",     border:"border-red-800/60",     icon:<XCircle size={16}/> },
  suspicious: { label:"SUSPICIOUS", color:"text-yellow-400",  bg:"bg-yellow-950/30",  border:"border-yellow-800/50",  icon:<AlertTriangle size={16}/> },
  clean:      { label:"CLEAN",      color:"text-emerald-400", bg:"bg-emerald-950/20", border:"border-emerald-800/40", icon:<CheckCircle2 size={16}/> },
  unknown:    { label:"UNKNOWN",    color:"text-zinc-400",    bg:"bg-zinc-800/40",    border:"border-zinc-700/50",    icon:<Shield size={16}/> },
}

function Ring({ score }: { score: number }) {
  const r = 28, c = 2 * Math.PI * r
  const col = score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : "#10b981"
  return (
    <div className="relative w-20 h-20 flex items-center justify-center shrink-0">
      <svg className="absolute -rotate-90" width="80" height="80">
        <circle cx="40" cy="40" r={r} fill="none" stroke="#27272a" strokeWidth="6"/>
        <circle cx="40" cy="40" r={r} fill="none" stroke={col} strokeWidth="6"
          strokeDasharray={c} strokeDashoffset={c - (score / 100) * c} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.8s ease" }}/>
      </svg>
      <div className="text-center">
        <div className="text-xl font-bold font-mono" style={{ color: col }}>{score}</div>
        <div className="text-[9px] text-zinc-600">/100</div>
      </div>
    </div>
  )
}

export default function ThreatIntelPage() {
  const [tab,     setTab]    = useState<IndicatorType>("ip")
  const [query,   setQuery]  = useState("")
  const [loading, setLoad]   = useState(false)
  const [result,  setResult] = useState<SandboxResponse & { _scannedAt?: string } | null>(null)
  const [error,   setError]  = useState<string | null>(null)

  async function scan() {
    if (!query.trim()) return
    setLoad(true); setResult(null); setError(null)
    try {
      const res = await api.sandboxCheck({ type: tab, value: query.trim() })
      setResult({ ...res, _scannedAt: new Date().toLocaleTimeString() })
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed")
    } finally { setLoad(false) }
  }

  const vc = result ? VC[result.verdict] ?? VC.unknown : null
  const score = result ? Math.min(Math.round((result.malicious_count / 70) * 100), 100) : 0

  // derive label from whichever key is populated
  const indicator = result?.ip ?? result?.hash ?? result?.url ?? query

  return (
    <div className="flex flex-col h-full -m-6">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 border-b border-zinc-800 bg-zinc-950/90 shrink-0">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-lg bg-emerald-950/60 border border-emerald-800/40 flex items-center justify-center shadow-[0_0_16px_rgba(16,185,129,0.15)]">
            <FlaskConical size={16} className="text-emerald-400"/>
          </div>
          <div>
            <h1 className="text-lg font-semibold text-zinc-100 leading-none">Threat Intelligence</h1>
            <p className="text-xs text-zinc-500 mt-0.5">POST /sandbox/check · VirusTotal v3 API</p>
          </div>
        </div>

        {/* Type tabs */}
        <div className="flex gap-1 mb-3">
          {TABS.map(t => (
            <button key={t.key} onClick={() => { setTab(t.key); setResult(null); setError(null) }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all border
                ${tab === t.key ? "bg-emerald-950/40 border-emerald-800/50 text-emerald-400" : "border-zinc-800 text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50"}`}>
              {t.icon}{t.label}
            </button>
          ))}
        </div>

        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500"/>
            <Input value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && scan()}
              placeholder={TABS.find(t => t.key === tab)?.placeholder}
              className="pl-8 h-9 bg-zinc-900 border-zinc-700 text-sm text-zinc-300 placeholder:text-zinc-600 focus:border-emerald-700"/>
          </div>
          <Button onClick={scan} disabled={loading || !query.trim()} size="sm"
            className="gap-2 bg-emerald-700 hover:bg-emerald-600 text-white border-0 h-9 px-5 shadow-[0_0_14px_rgba(16,185,129,0.2)]">
            {loading ? <Loader2 size={13} className="animate-spin"/> : <Search size={13}/>} Scan
          </Button>
        </div>
        {error && <p className="text-xs text-red-400 mt-2 flex items-center gap-1.5"><XCircle size={11}/> {error}</p>}
      </div>

      {/* Results */}
      <div className="flex-1 overflow-y-auto p-6">
        {loading && (
          <div className="flex flex-col items-center justify-center h-48 gap-4">
            <Loader2 size={28} className="text-emerald-500 animate-spin"/>
            <p className="text-sm text-zinc-400">Querying VirusTotal…</p>
          </div>
        )}

        {!loading && !result && !error && (
          <div className="flex flex-col items-center justify-center h-64 gap-4 text-center">
            <div className="w-16 h-16 rounded-2xl bg-emerald-950/30 border border-emerald-800/30 flex items-center justify-center">
              <FlaskConical size={28} className="text-emerald-700"/>
            </div>
            <div>
              <p className="text-sm text-zinc-400">Enter an indicator to scan</p>
              <p className="text-xs text-zinc-600 mt-1">Supports IPs, file hashes, and URLs via VirusTotal</p>
              <p className="text-xs text-zinc-700 mt-0.5">Requires VT_API_KEY in backend .env</p>
            </div>
          </div>
        )}

        {!loading && result && vc && (
          <div className="space-y-4 max-w-3xl">
            {/* Verdict card */}
            <div className={`rounded-xl border ${vc.border} ${vc.bg} p-5 flex items-center gap-6`}>
              <Ring score={score}/>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-2">
                  <span className={`flex items-center gap-2 text-lg font-bold ${vc.color}`}>{vc.icon}{vc.label}</span>
                </div>
                <p className="font-mono text-sm text-zinc-300 mb-2 truncate">{indicator}</p>
                {result.file_name && <p className="text-xs text-zinc-500 mb-2">File: {result.file_name}</p>}
                <p className="text-xs text-zinc-400">{result.details}</p>
              </div>
              <div className="text-right space-y-1 text-xs shrink-0">
                <div className="flex items-center gap-1.5 justify-end text-zinc-400"><Activity size={11}/> Malicious: <span className={vc.color}>{result.malicious_count}</span></div>
                {result.suspicious_count !== undefined && <div className="text-zinc-500">Suspicious: {result.suspicious_count}</div>}
                {result.harmless_count   !== undefined && <div className="text-emerald-500">Harmless: {result.harmless_count}</div>}
              </div>
            </div>

            {/* Meta */}
            <div className="grid grid-cols-2 gap-4">
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
                <p className="text-xs font-semibold text-zinc-400 mb-3 flex items-center gap-2"><Clock size={12}/>Scan Info</p>
                <div className="space-y-2 text-[11px]">
                  <div className="flex justify-between"><span className="text-zinc-600">Scanned at</span><span className="text-zinc-300">{result._scannedAt}</span></div>
                  <div className="flex justify-between"><span className="text-zinc-600">Indicator type</span><span className="text-zinc-300 capitalize">{tab}</span></div>
                  <div className="flex justify-between"><span className="text-zinc-600">Verdict</span><span className={`font-semibold ${vc.color}`}>{vc.label}</span></div>
                </div>
              </div>
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 flex flex-col items-center justify-center gap-3">
                <FlaskConical size={20} className="text-emerald-600"/>
                <p className="text-xs text-zinc-400 text-center">Results powered by VirusTotal</p>
                <a href="https://www.virustotal.com" target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[11px] text-emerald-500 hover:text-emerald-400 transition-colors">
                  <ExternalLink size={11}/> Open VirusTotal
                </a>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}