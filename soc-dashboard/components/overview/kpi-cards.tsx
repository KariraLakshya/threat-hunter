import { Card, CardContent } from "@/components/ui/card"
import { ShieldAlert, Siren, Globe, Brain } from "lucide-react"

const cards = [
  {
    title: "Active Incidents",
    value: "12",
    icon: ShieldAlert,
  },
  {
    title: "Critical Alerts",
    value: "3",
    icon: Siren,
  },
  {
    title: "Cross-Env Attacks",
    value: "2",
    icon: Globe,
  },
  {
    title: "AI Confidence Avg",
    value: "86%",
    icon: Brain,
  },
]

export default function KPICards() {
  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => {
        const Icon = card.icon
        return (
          <Card key={card.title} className="bg-zinc-900 border-zinc-800">
            <CardContent className="p-6 flex items-center justify-between">
              <div>
                <p className="text-sm text-zinc-400">{card.title}</p>
                <p className="text-2xl font-semibold mt-1 text-cyan-400">{card.value}</p>
              </div>
              <Icon className="text-cyan-400 drop-shadow-[0_0_6px_#22d3ee]" size={28} />
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}