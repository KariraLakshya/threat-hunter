"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  LayoutDashboard, ShieldAlert, Bot, FlaskConical,
  BarChart3, Server, Settings, Brain
} from "lucide-react"

const navItems = [
  { name: "Overview",         href: "/",             icon: LayoutDashboard },
  { name: "Incidents",        href: "/incident",     icon: ShieldAlert     },
  { name: "AI Investigation", href: "/ai",           icon: Bot             },
  { name: "Threat Intel",     href: "/intel",        icon: FlaskConical    },
  { name: "Observability",    href: "/observability",icon: BarChart3       },
  { name: "Infrastructure",   href: "/infra",        icon: Server          },
  { name: "Integrations",     href: "/settings",     icon: Settings        },
]

export default function Sidebar() {
  const pathname = usePathname()

  function isActive(href: string) {
    if (href === "/") return pathname === "/"
    return pathname.startsWith(href)
  }

  return (
    <aside className="w-60 bg-zinc-950 border-r border-zinc-800/80 flex flex-col shrink-0">

      {/* ── Brand ── */}
      <div className="px-5 py-5 border-b border-zinc-800/80">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-violet-600 to-indigo-700 flex items-center justify-center shadow-[0_0_16px_rgba(139,92,246,0.5)]">
            <Brain size={15} className="text-white"/>
          </div>
          <div>
            <p className="text-sm font-bold leading-none tracking-tight">
              <span className="text-white">Cyber</span><span className="text-violet-400">Cortex</span>
            </p>
            <p className="text-[10px] text-zinc-500 mt-0.5 font-medium tracking-wider uppercase">AI · SOC Platform</p>
          </div>
        </div>
      </div>

      {/* ── Nav ── */}
      <nav className="flex-1 px-3 py-3 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon
          const active = isActive(item.href)
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-[13px] transition-all duration-150 group
                ${active
                  ? "bg-violet-950/60 text-white font-semibold border border-violet-700/40 shadow-[inset_0_1px_0_rgba(139,92,246,0.15)]"
                  : "text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/50 border border-transparent"
                }`}
            >
              {/* active left bar */}
              {active && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-full bg-violet-400 shadow-[0_0_8px_rgba(167,139,250,0.8)]"/>
              )}
              <Icon
                size={15}
                className={active
                  ? "text-violet-400"
                  : "text-zinc-600 group-hover:text-zinc-300 transition-colors"
                }
              />
              <span className="flex-1">{item.name}</span>
              {active && (
                <span className="w-1.5 h-1.5 rounded-full bg-violet-400 shadow-[0_0_6px_rgba(167,139,250,1)]"/>
              )}
            </Link>
          )
        })}
      </nav>

      {/* ── Footer ── */}
      <div className="px-5 py-3 border-t border-zinc-800/80">
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"/>
          <p className="text-[10px] text-zinc-600">v1.0 · LangGraph · Groq · VirusTotal</p>
        </div>
      </div>

    </aside>
  )
}