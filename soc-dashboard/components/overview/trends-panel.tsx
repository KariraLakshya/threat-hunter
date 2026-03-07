import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export default function TrendsPanel() {
  return (
    <div className="grid gap-6 xl:grid-cols-3">
      
      {/* Trends */}
      <Card className="xl:col-span-2 bg-zinc-900 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-sky-400">Attack Trends (24h)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-zinc-500">
            📊 Grafana Panel Placeholder
          </div>
        </CardContent>
      </Card>

      {/* Live Feed */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-sky-400">Live Activity</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <ActivityItem text="Failed login burst detected — jsmith" />
          <ActivityItem text="IAM privilege escalation — admin-user" />
          <ActivityItem text="Malicious IP detected — 203.0.113.42" />
          <ActivityItem text="Large S3 access spike — finance-bucket" />
        </CardContent>
      </Card>

    </div>
  )
}

function ActivityItem({ text }: { text: string }) {
  return (
    <div className="p-2 rounded bg-zinc-800 text-zinc-200 border border-zinc-700">
      {text}
    </div>
  )
}