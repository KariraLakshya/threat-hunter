"use client"

import { usePathname } from "next/navigation"
import { Shield } from "lucide-react"

const PAGE_META: Record<string, { label: string; sub: string; accent: string }> = {
  "/":              { label: "Overview",          sub: "Live threat intelligence across all environments",     accent: "text-sky-400"    },
  "/incident":      { label: "Incident Feed",     sub: "Real-time security incidents · AI-triaged",           accent: "text-red-400"    },
  "/ai":            { label: "AI Investigation",  sub: "Autonomous agent · LangGraph · Groq LLaMA-3.3-70B",  accent: "text-violet-400" },
  "/intel":         { label: "Threat Intel",      sub: "IOC enrichment · VirusTotal v3 · auto-extracted",     accent: "text-emerald-400"},
  "/observability": { label: "Observability",     sub: "Grafana dashboards · Elasticsearch telemetry",        accent: "text-amber-400"  },
  "/infra":         { label: "Infrastructure",    sub: "Docker containers · Service health · Uptime",         accent: "text-cyan-400"   },
  "/settings":      { label: "Integrations",      sub: "Slack · Email · Severity routing · .env hot-reload", accent: "text-zinc-400"   },
}

export default function Header() {
  const pathname = usePathname()

  const match = Object.entries(PAGE_META)
    .filter(([k]) => k === "/" ? pathname === "/" : pathname.startsWith(k))
    .sort((a, b) => b[0].length - a[0].length)[0]

  const page = match?.[1]

  return (
    <header className="h-14 border-b border-zinc-800/80 bg-zinc-950/95 backdrop-blur-sm flex items-center px-6 gap-4 shrink-0">

      {/* Page title + subtitle */}
      <div className="flex-1 flex items-baseline gap-3 min-w-0">
        {page ? (
          <>
            <span className={`text-sm font-bold tracking-tight ${page.accent}`}>
              {page.label}
            </span>
            <span className="text-[11px] text-zinc-600 truncate hidden md:block">
              {page.sub}
            </span>
          </>
        ) : (
          <span className="text-sm font-bold text-violet-400">CyberCortex</span>
        )}
      </div>

      {/* Threat level */}
      <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">
        <Shield size={10} className="text-emerald-500"/>
        <span className="text-[10px] font-semibold text-emerald-400 tracking-wider uppercase">Threat Level: Normal</span>
      </div>

      {/* Live ping */}
      <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-60"/>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-sky-500"/>
        </span>
        <span className="text-[10px] font-semibold text-sky-400 tracking-wider uppercase">Live</span>
      </div>

    </header>
  )
}