import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const services = [
  { name: "Elasticsearch", status: "healthy" },
  { name: "Logstash", status: "ingesting" },
  { name: "Redis", status: "healthy" },
  { name: "FastAPI", status: "online" },
  { name: "AI Agent", status: "processing" },
]

export default function HealthPanel() {
  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardHeader>
        <CardTitle className="text-sky-400">System Health</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        {services.map((svc) => (
          <div
            key={svc.name}
            className="p-4 rounded bg-zinc-800 flex justify-between items-center border border-zinc-700"
          >
            <span className="text-sm">{svc.name}</span>
            <StatusDot status={svc.status} />
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

function StatusDot({ status }: { status: string }) {
  const color =
    status === "healthy" || status === "online"
      ? "bg-green-500"
      : status === "processing" || status === "ingesting"
      ? "bg-yellow-500"
      : "bg-red-500"

  return <span className={`h-3 w-3 rounded-full ${color} shadow-[0_0_8px_currentColor]`} />
}