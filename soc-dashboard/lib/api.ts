// lib/api.ts — typed client matching api/main.py exactly

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  })
  if (!res.ok) throw new Error(`${res.status} ${await res.text().catch(() => "")}`)
  return res.json() as Promise<T>
}

// ─── Exact shapes from api/main.py ────────────────────────────────────────────

export interface ChainStep {
  step: number
  timestamp: string
  event_type: string
  user: string
  source_ip: string
  environment: string[]
  tactic: string
  technique: string
  technique_name: string
  severity: string
  count: number
  cross_environment: boolean
  mitre_url: string
}

// conclusion fields come from agent/ai_agent.py ConclusionOutput + conclude()
export interface Conclusion {
  is_attack: boolean
  is_real_attack: boolean
  confidence: number
  final_confidence: number
  attack_narrative: string
  kill_chain_stage: string
  attacker_objective: string
  attacker_next_step: string
  business_impact: string
  immediate_actions: string[]
  summary: string
  severity: string
  investigation_complete: boolean
  iterations_taken: number
  fp_check_recommendation: string
  timestamp: string
}

export interface Incident {
  incident_id: string
  timestamp: string
  severity: "critical" | "high" | "medium" | "low"
  is_attack: number          // 0 | 1 (stored as SQLite int)
  user: string
  environments: string[]     // JSON-parsed by API
  cross_env: number          // 0 | 1
  summary: string
  actions: string[]          // JSON-parsed by API
  status: "open" | "investigating" | "closed"
  conclusion: Partial<Conclusion>
  chain: ChainStep[]
}

export interface HealthResponse {
  overall: "healthy" | "degraded"
  timestamp: string
  services: {
    elasticsearch: { status: string; ok: boolean; error?: string }
    database: { status: string; ok: boolean; error?: string }
    redis: { status: string; ok: boolean; error?: string }
  }
}

export interface StatsResponse {
  total: number
  by_severity: Record<string, number>
  cross_environment: number
}

// /investigate returns immediately; pipeline runs in background
export interface InvestigateResponse {
  status: string
  lookback_minutes: number
  timestamp: string
}

// /sandbox/check — shape differs per type (ip | hash | url)
export interface SandboxResponse {
  verdict: "malicious" | "suspicious" | "clean" | "unknown"
  malicious_count: number
  suspicious_count?: number
  harmless_count?: number
  details: string
  ip?: string
  hash?: string
  file_name?: string
  url?: string
}

// ─── API calls ────────────────────────────────────────────────────────────────

export const api = {
  health: () =>
    apiFetch<HealthResponse>("/health"),

  stats: () =>
    apiFetch<StatsResponse>("/stats"),

  incidents: (limit = 100, status?: string) => {
    const q = new URLSearchParams({ limit: String(limit) })
    if (status) q.set("status", status)
    return apiFetch<{ incidents: Incident[]; count: number }>(`/incidents?${q}`)
  },

  incident: (id: string) =>
    apiFetch<Incident>(`/incidents/${id}`),

  closeIncident: (id: string) =>
    apiFetch<{ incident_id: string; status: string }>(`/incidents/${id}/close`, { method: "POST" }),

  investigate: (body: { lookback_minutes: number; user_filter?: string }) =>
    apiFetch<InvestigateResponse>("/investigate", { method: "POST", body: JSON.stringify(body) }),

  sandboxCheck: (body: { type: "ip" | "hash" | "url"; value: string }) =>
    apiFetch<SandboxResponse>("/sandbox/check", { method: "POST", body: JSON.stringify(body) }),

  calderaOps: () =>
    apiFetch<CalderaTrackerResponse>("/caldera/operations"),
}

export interface CalderaTrackerResponse {
  active: boolean
  name?: string
  start?: string
  chain?: {
    id: string
    technique_id: string
    technique_name: string
    status: string
    command: string
    finish: string
  }[]
}