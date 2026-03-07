"use client"
import { useState, useEffect, useCallback, useRef } from "react"
import { api, Incident, HealthResponse, StatsResponse } from "@/lib/api"

export function useQuery<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  opts: { enabled?: boolean; refetchInterval?: number } = {}
) {
  const [data, setData]       = useState<T | null>(null)
  const [loading, setLoading] = useState(opts.enabled !== false)
  const [error, setError]     = useState<string | null>(null)

  const run = useCallback(async () => {
    if (opts.enabled === false) return
    setLoading(true); setError(null)
    try { setData(await fetcher()) }
    catch (e) { setError(e instanceof Error ? e.message : "Request failed") }
    finally { setLoading(false) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => { run() }, [run])

  useEffect(() => {
    if (!opts.refetchInterval) return
    const id = setInterval(run, opts.refetchInterval)
    return () => clearInterval(id)
  }, [run, opts.refetchInterval])

  return { data, loading, error, refetch: run }
}

export const useHealth    = (interval = 30_000) => useQuery(() => api.health(),           [], { refetchInterval: interval })
export const useStats     = (interval = 15_000) => useQuery(() => api.stats(),            [], { refetchInterval: interval })
export const useIncidents = (limit = 100, interval = 15_000) =>
  useQuery(() => api.incidents(limit), [limit], { refetchInterval: interval })