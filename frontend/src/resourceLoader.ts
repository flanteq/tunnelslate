export type Resource = 'panel-settings' | 'dashboard' | 'clients' | 'devices' | 'certificates' | 'operations' | 'settings' | 'audit' | 'connections' | 'admins'
export type Section = 'panel-settings' | 'overview' | 'clients' | 'certificates' | 'settings' | 'audit' | 'accounts'
export const resources: Resource[] = ['panel-settings', 'dashboard', 'clients', 'devices', 'certificates', 'operations', 'settings', 'audit', 'connections', 'admins']
export function sectionResources(section: Section): Resource[] {
  const common: Resource[] = ['dashboard', 'settings']
  switch (section) {
    case 'overview': return [...common, 'audit', 'connections']
    case 'clients': return [...common, 'clients', 'devices', 'operations']
    case 'certificates': return [...common, 'certificates', 'operations']
    case 'panel-settings': return [...common, 'panel-settings']
    case 'accounts': return [...common, 'admins']
    case 'audit': return [...common, 'audit']
    default: return common
  }
}

export function createResourceLoader(options: {
  needed: () => Resource[]
  enabled: () => boolean
  load: (name: Resource, signal: AbortSignal) => Promise<unknown>
  apply: (name: Resource, value: unknown) => void
  onError: (error: unknown) => void
}) {
  let dirty = new Set(resources)
  let generation = 0
  let running: { controller: AbortController; promise: Promise<void> } | undefined
  const retries = new Map<Resource, { attempts: number; after: number }>()
  let retryTimer: ReturnType<typeof setTimeout> | undefined

  function clearRetryTimer() {
    if (retryTimer !== undefined) clearTimeout(retryTimer)
    retryTimer = undefined
  }
  function scheduleRetry() {
    clearRetryTimer()
    if (!options.enabled()) return
    const next = Math.min(...options.needed().filter(name => dirty.has(name) && retries.has(name)).map(name => retries.get(name)!.after))
    if (!Number.isFinite(next)) return
    retryTimer = setTimeout(() => { retryTimer = undefined; void flush() }, Math.max(1, next - Date.now()))
  }
  function retryable(error: unknown) {
    const status = (error as { status?: number } | null)?.status
    return status === undefined || status === 408 || status === 429 || (status >= 500 && status < 600)
  }

  function invalidate(names: Resource[] = resources) { for (const name of names) dirty.add(name) }
  function reset() {
    generation++
    clearRetryTimer(); retries.clear()
    running?.controller.abort()
    running = undefined
    dirty = new Set(resources)
  }
  function flush(): Promise<void> {
    if (!options.enabled()) { clearRetryTimer(); return Promise.resolve() }
    if (running) return running.promise
    clearRetryTimer()
    const epoch = generation
    const job = { controller: new AbortController(), promise: Promise.resolve() }
    running = job
    job.promise = (async () => {
      const failed = new Set<Resource>()
      // Sequential, shared across page switches: no duplicate requests and no
      // full-dashboard fan-out. Invalidations during a request are kept dirty.
      while (epoch === generation && options.enabled()) {
        const name = options.needed().find(name => dirty.has(name) && !failed.has(name) && (retries.get(name)?.after ?? 0) <= Date.now())
        if (!name) break
        dirty.delete(name)
        try {
          const value = await options.load(name, job.controller.signal)
          if (epoch === generation && !job.controller.signal.aborted) {
            options.apply(name, value)
            retries.delete(name)
          }
        } catch (error) {
          if (epoch !== generation || job.controller.signal.aborted) break
          failed.add(name)
          if (retryable(error)) {
            const attempts = (retries.get(name)?.attempts ?? 0) + 1
            dirty.add(name)
            // Fresh SSE invalidations and fallback refreshes must respect the
            // same cooldown rather than starting another request immediately.
            retries.set(name, { attempts, after: Date.now() + Math.min(30_000, 2_000 * 2 ** Math.min(attempts - 1, 4)) })
            // One notification per failed resource until it recovers.
            if (attempts === 1) options.onError(error)
          } else {
            retries.delete(name)
            options.onError(error)
          }
        }
      }
    })().finally(() => {
      if (running === job) { running = undefined; scheduleRetry() }
    })
    return job.promise
  }
  return { invalidate, flush, reset }
}
