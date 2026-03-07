"use client"

import Link from "next/link"
import { LayoutDashboard, ShieldAlert, Bot, FlaskConical, BarChart3, Server, Settings } from "lucide-react"

const navItems = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  { name: "Incidents", href: "/incidents", icon: ShieldAlert },
  { name: "AI Investigation", href: "/ai", icon: Bot },
  { name: "Threat Intel", href: "/intel", icon: FlaskConical },
  { name: "Observability", href: "/observability", icon: BarChart3 },
  { name: "Infrastructure", href: "/infra", icon: Server },
  { name: "Integrations", href: "/settings", icon: Settings },
]

export default function Sidebar() {
  return (
    <aside className="w-64 bg-zinc-900 border-r border-zinc-800">
      <div className="p-6 font-semibold text-lg border-b border-zinc-800">
        Threat Hunter
      </div>
      <nav className="p-4 space-y-2">
        {navItems.map((item) => {
          const Icon = item.icon
          return (
            <Link
              key={item.name}
              href={item.href}
              className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-zinc-800 transition"
            >
              <Icon size={18} />
              {item.name}
            </Link>
          )
        })}
      </nav>
    </aside>
  )
}