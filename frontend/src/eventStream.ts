import type { Dashboard } from './api'
import type { Resource } from './resourceLoader'

export interface EventState { revisions: Record<Resource | 'statistics', number>; vpn: Dashboard['vpn']; crl?: Dashboard['crl']; applied_revision: number }

export function createEventStream(options: {
  url: () => URL
  ready: (state: EventState) => void
  state: (state: EventState) => void
  expired: () => void
  connected: (value: boolean) => void
  checkSession: () => Promise<void>
  fallback: () => void
  connect?: (url: URL) => EventSource
}) {
  let source: EventSource | undefined
  let epoch = 0
  let online = false
  let lastMessage = 0
  let lastCheck = -Infinity
  let checking = false
  let watchdog: ReturnType<typeof setInterval> | undefined
  let fallback: ReturnType<typeof setInterval> | undefined

  function connection(value: boolean) { online = value; options.connected(value) }
  function checkSession(generation: number) {
    if (checking || Date.now() - lastCheck < 15_000) return
    checking = true; lastCheck = Date.now()
    void options.checkSession().catch((error: unknown) => {
      if (generation === epoch && (error as { status?: number })?.status === 401) options.expired()
    }).finally(() => { if (generation === epoch) checking = false })
  }
  function open(generation: number) {
    const stream = (options.connect ?? (url => new EventSource(url)))(options.url())
    source = stream; lastMessage = Date.now()
    const live = () => source === stream && epoch === generation
    const receive = (event: MessageEvent, ready: boolean) => {
      if (!live()) return
      try {
        const data = JSON.parse(event.data) as EventState
        if (!data.revisions || !data.vpn) throw new Error('Invalid event state')
        lastMessage = Date.now(); connection(true)
        if (ready) options.ready(data); else options.state(data)
      } catch { connection(false); checkSession(generation) }
    }
    stream.addEventListener('ready', event => receive(event as MessageEvent, true))
    stream.addEventListener('state', event => receive(event as MessageEvent, false))
    stream.addEventListener('heartbeat', () => { if (live()) lastMessage = Date.now() })
    stream.addEventListener('session-expired', () => { if (live()) options.expired() })
    stream.onerror = () => { if (live()) { connection(false); checkSession(generation) } }
  }
  function stop() {
    epoch++
    source?.close(); source = undefined
    if (watchdog) clearInterval(watchdog)
    if (fallback) clearInterval(fallback)
    watchdog = undefined; fallback = undefined; checking = false; lastCheck = -Infinity
    connection(false)
  }
  function start() {
    stop()
    const generation = epoch
    open(generation)
    watchdog = setInterval(() => {
      if (Date.now() - lastMessage > 40_000) {
        source?.close(); connection(false); checkSession(generation); open(generation)
      }
    }, 10_000)
    // Also works during a proxy outage or if SSE buffering was left enabled.
    fallback = setInterval(() => {
      if (!online) { checkSession(generation); options.fallback() }
    }, 30_000)
  }
  return { start, stop }
}
