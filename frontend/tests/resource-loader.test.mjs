import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createResourceLoader, sectionResources } from '../src/resourceLoader.ts'

test('loads only visible resources once, and loads a changed closed section when opened', async () => {
  let section = 'overview'
  const calls = []
  const loader = createResourceLoader({ needed: () => sectionResources(section), enabled: () => true,
    load: async name => { calls.push(name); return name }, apply() {}, onError: error => { throw error } })
  await loader.flush()
  assert.deepEqual(calls, ['dashboard', 'settings', 'audit', 'connections'])
  await loader.flush()
  assert.equal(calls.length, 4)
  loader.invalidate(['clients', 'devices'])
  await loader.flush()
  assert.equal(calls.length, 4)
  section = 'clients'
  await loader.flush()
  assert.deepEqual(calls.slice(4), ['clients', 'devices', 'operations'])
  loader.invalidate(['devices'])
  await loader.flush()
  assert.deepEqual(calls.slice(7), ['devices'])
})

test('coalesces simultaneous refreshes and repeats a resource invalidated during an in-flight fetch', async () => {
  let release
  let calls = 0
  const applied = []
  const loader = createResourceLoader({ needed: () => ['clients'], enabled: () => true,
    load: async () => { calls++; if (calls === 1) await new Promise(resolve => { release = resolve }); return calls },
    apply: (_, value) => applied.push(value), onError: error => { throw error } })
  const first = loader.flush()
  const second = loader.flush()
  assert.equal(calls, 1)
  loader.invalidate(['clients'])
  release()
  await Promise.all([first, second])
  assert.equal(calls, 2)
  assert.deepEqual(applied, [1, 2])
})

test('logout cancels pending work and stale responses cannot overwrite a new session', async () => {
  let release
  const applied = []
  let calls = 0
  const loader = createResourceLoader({ needed: () => ['clients'], enabled: () => true,
    load: async () => { if (++calls === 1) { await new Promise(resolve => { release = resolve }); return 'old' } return 'new' },
    apply: (_, value) => applied.push(value), onError: error => { throw error } })
  const old = loader.flush()
  loader.reset()
  await loader.flush()
  release(); await old
  assert.deepEqual(applied, ['new'])
})

const advance = async (t, milliseconds) => {
  t.mock.timers.tick(milliseconds)
  await new Promise(resolve => setImmediate(resolve))
}

test('transient failures retry without SSE events and successful resources stay cached', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100000 })
  const calls = [], applied = [], errors = []
  let unavailable = true
  const loader = createResourceLoader({ needed: () => ['clients', 'settings'], enabled: () => true,
    load: async name => { calls.push(name); if (name === 'clients' && unavailable) throw new Error('Offline'); return name },
    apply: name => applied.push(name), onError: error => errors.push(error) })
  t.after(() => loader.reset())
  await loader.flush()
  assert.deepEqual(calls, ['clients', 'settings'])
  assert.deepEqual(applied, ['settings'])
  await advance(t, 1999)
  assert.equal(calls.length, 2)
  unavailable = false
  await advance(t, 1)
  assert.deepEqual(calls, ['clients', 'settings', 'clients'])
  assert.deepEqual(applied, ['settings', 'clients'])
  assert.equal(errors.length, 1)
  await advance(t, 60000)
  assert.equal(calls.length, 3)
  // A later outage starts at the initial delay and can report a fresh error.
  unavailable = true
  loader.invalidate(['clients']); await loader.flush()
  assert.equal(errors.length, 2)
  unavailable = false
  await advance(t, 2000)
  assert.equal(calls.length, 5)
})

test('retries back off to 30 seconds and SSE or fallback invalidations cannot bypass the cooldown', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100000 })
  let calls = 0, errors = 0
  const loader = createResourceLoader({ needed: () => ['clients'], enabled: () => true,
    load: async () => { calls++; throw { status: 503 } }, apply() {}, onError: () => errors++ })
  t.after(() => loader.reset())
  await loader.flush()
  for (const delay of [2000, 4000, 8000, 16000, 30000, 30000]) {
    const before = calls
    for (let i = 0; i < 4; i++) { loader.invalidate(['clients']); await loader.flush() }
    assert.equal(calls, before)
    await advance(t, delay - 1)
    assert.equal(calls, before)
    await advance(t, 1)
    assert.equal(calls, before + 1)
  }
  assert.equal(errors, 1, 'persistent failure must not produce a toast on every retry')
})

test('hidden tabs and closed sections pause failed resources until they are needed again', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100000 })
  let enabled = false
  let needed = ['clients']
  let calls = 0
  let errors = 0
  const loader = createResourceLoader({ needed: () => needed, enabled: () => enabled,
    load: async () => { calls++; throw new Error('Offline') }, apply() {}, onError: () => { errors++ } })
  t.after(() => loader.reset())
  await loader.flush(); assert.equal(calls, 0)
  enabled = true
  await loader.flush(); assert.equal(calls, 1); assert.equal(errors, 1)
  enabled = false
  await advance(t, 30000)
  assert.equal(calls, 1)
  enabled = true; needed = []
  await loader.flush(); await advance(t, 30000)
  assert.equal(calls, 1)
  needed = ['clients']
  await loader.flush(); assert.equal(calls, 2)
  needed = []
  await loader.flush(); await advance(t, 30000)
  assert.equal(calls, 2)
  needed = ['clients']
  await loader.flush(); assert.equal(calls, 3)
})

test('logout cancels a queued retry and an old failed request cannot retry in a new session', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100000 })
  let calls = 0, errors = 0
  const applied = []
  let rejectOld
  const loader = createResourceLoader({ needed: () => ['clients'], enabled: () => true,
    load: async () => {
      calls++
      if (calls === 1) throw new Error('Offline')
      if (calls === 2) return new Promise((_, reject) => { rejectOld = reject })
      return 'new session'
    }, apply: (_, value) => applied.push(value), onError: () => errors++ })
  t.after(() => loader.reset())
  await loader.flush()
  loader.reset()
  await advance(t, 60000)
  assert.equal(calls, 1, 'queued retry survived logout')
  const old = loader.flush()
  loader.reset()
  await loader.flush()
  rejectOld(new Error('Late network failure')); await old
  await advance(t, 60000)
  assert.equal(calls, 3)
  assert.equal(errors, 1)
  assert.deepEqual(applied, ['new session'])
})

test('only transient HTTP failures are retried; authentication and other client errors stop', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100000 })
  const counts = new Map()
  for (const status of [400, 401, 403, 404, 408, 429, 500, 503]) {
    const loader = createResourceLoader({ needed: () => ['clients'], enabled: () => true,
      load: async () => { counts.set(status, (counts.get(status) ?? 0) + 1); throw { status } }, apply() {}, onError() {} })
    t.after(() => loader.reset())
    await loader.flush()
  }
  await advance(t, 2000)
  for (const status of [400, 401, 403, 404]) assert.equal(counts.get(status), 1)
  for (const status of [408, 429, 500, 503]) assert.equal(counts.get(status), 2)
})

test('a retry shares in-flight work with updates and keeps newer invalidations', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 100000 })
  let calls = 0, release
  const applied = []
  const loader = createResourceLoader({ needed: () => ['clients'], enabled: () => true,
    load: async () => {
      calls++
      if (calls === 1) throw new Error('Offline')
      if (calls === 2) await new Promise(resolve => { release = resolve })
      return calls
    }, apply: (_, value) => applied.push(value), onError() {} })
  t.after(() => loader.reset())
  await loader.flush()
  await advance(t, 2000)
  loader.invalidate(['clients'])
  const first = loader.flush(), second = loader.flush()
  assert.equal(calls, 2)
  release(); await Promise.all([first, second])
  assert.equal(calls, 3)
  assert.deepEqual(applied, [2, 3])
  await advance(t, 60000)
  assert.equal(calls, 3)
})

test('panel settings load on demand and do not add a request to the overview', async () => {
  assert.ok(!sectionResources('overview').includes('panel-settings'))
  assert.deepEqual(sectionResources('panel-settings'), ['dashboard', 'settings', 'panel-settings'])
  let section = 'overview'
  const calls = []
  const loader = createResourceLoader({ needed: () => sectionResources(section), enabled: () => true,
    load: async name => { calls.push(name); return name }, apply() {}, onError: error => { throw error } })
  await loader.flush()
  loader.invalidate(['panel-settings', 'dashboard'])
  await loader.flush()
  section = 'panel-settings'
  await loader.flush()
  assert.deepEqual(calls.slice(-2), ['dashboard', 'panel-settings'])
})
