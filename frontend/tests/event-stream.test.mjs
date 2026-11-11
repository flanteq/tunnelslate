import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createEventStream } from '../src/eventStream.ts'

function fixture(t, overrides = {}) {
  t.mock.timers.enable({ apis: ['setInterval', 'Date'], now: 100000 })
  const streams = [], events = [], connections = []
  const client = createEventStream({
    url: () => new URL('api/events', 'https://desk.test/ovpn/'),
    ready: data => events.push(['ready', data]), state: data => events.push(['state', data]),
    expired: () => events.push(['expired']), connected: value => connections.push(value),
    checkSession: async () => {}, fallback: () => events.push(['fallback']),
    connect: url => {
      const listeners = new Map()
      const stream = { url, addEventListener: (name, callback) => listeners.set(name, callback),
        close() { this.closed = true }, emit: (name, data) => listeners.get(name)?.({ data: JSON.stringify(data) }) }
      streams.push(stream); return stream
    }, ...overrides,
  })
  t.after(() => client.stop())
  client.start()
  return { client, streams, events, connections }
}
const state = { revisions: { clients: 1 }, vpn: { state: 'connected', connected_clients: 0 }, applied_revision: 1 }

test('uses base path, receives fresh state on reconnect, and ignores events from closed streams', t => {
  const f = fixture(t)
  assert.equal(f.streams[0].url.href, 'https://desk.test/ovpn/api/events')
  f.streams[0].emit('ready', state)
  f.streams[0].emit('state', state)
  assert.deepEqual(f.events.map(event => event[0]), ['ready', 'state'])
  f.client.start()
  assert.ok(f.streams[0].closed)
  f.streams[0].emit('session-expired')
  f.streams[1].emit('ready', state)
  assert.deepEqual(f.events.map(event => event[0]), ['ready', 'state', 'ready'])
})
test('falls back while disconnected and reopens a stalled stream', t => {
  const f = fixture(t)
  t.mock.timers.tick(30000)
  assert.ok(f.events.some(event => event[0] === 'fallback'))
  t.mock.timers.tick(20000)
  assert.ok(f.streams[0].closed)
  assert.equal(f.streams.length, 2)
})
test('heartbeat keeps a healthy stream alive without fallback requests', t => {
  const f = fixture(t)
  f.streams[0].emit('ready', state)
  for (let i = 0; i < 8; i++) { t.mock.timers.tick(15000); f.streams[0].emit('heartbeat') }
  assert.equal(f.streams.length, 1)
  assert.deepEqual(f.events.map(event => event[0]), ['ready'])
})
test('an authentication failure during reconnect ends the session', async t => {
  const f = fixture(t, { checkSession: async () => { throw { status: 401 } } })
  f.streams[0].onerror()
  await Promise.resolve(); await Promise.resolve()
  assert.ok(f.events.some(event => event[0] === 'expired'))
})
