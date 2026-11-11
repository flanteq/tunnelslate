import assert from 'node:assert/strict'
import { test } from 'node:test'
import { effectScope, ref } from 'vue'
import { useClientList } from '../src/useClientList.ts'

function fixture(t, names) {
  const clients = ref(names.map((name, index) => ({ id: String(index), name, disabled: false, created_at: index })))
  const query = ref('')
  const scope = effectScope()
  const list = scope.run(() => useClientList(() => clients.value, query))
  t.after(() => scope.stop())
  return { ...list, clients, query }
}

test('Russian alphabetical and natural ordering applies to pages and the owner selector', t => {
  const list = fixture(t, ['Яков', 'Клиент 10', 'борис', 'Клиент 2', 'Анна', 'александр'])
  assert.deepEqual(list.visibleClients.value.map(c => c.name), ['александр', 'Анна', 'борис', 'Клиент 2', 'Клиент 10', 'Яков'])
  assert.equal(list.clients.value[0].name, 'Яков', 'sorting must not mutate data from the parent')
  list.query.value = '  БОР  '
  assert.deepEqual(list.visibleClients.value.map(c => c.name), ['борис'])
  assert.equal(list.sortedClients.value.length, 6, 'owner selector must include clients outside the search')
})

test('pagination and search cover clients beyond the former 500-record limit', t => {
  const list = fixture(t, Array.from({ length: 521 }, (_, i) => `Клиент ${i + 1}`))
  assert.equal(list.pageCount.value, 53)
  assert.equal(list.visibleClients.value.length, 10)
  list.page.value = 53
  assert.deepEqual(list.visibleClients.value.map(c => c.name), ['Клиент 521'])
  assert.equal(list.rangeStart.value, 521)
  assert.equal(list.rangeEnd.value, 521)
  list.query.value = 'Клиент 520'
  assert.equal(list.page.value, 1)
  assert.equal(list.pageCount.value, 1)
  assert.deepEqual(list.visibleClients.value.map(c => c.name), ['Клиент 520'])
})

test('page size changes reset the page and unmatched search has an empty range', t => {
  const list = fixture(t, Array.from({ length: 61 }, (_, i) => `Клиент ${i + 1}`))
  list.page.value = 3
  list.pageSize.value = 25
  assert.equal(list.page.value, 1)
  assert.equal(list.pageCount.value, 3)
  assert.equal(list.visibleClients.value.length, 25)
  list.pageSize.value = 50
  assert.equal(list.pageCount.value, 2)
  assert.equal(list.visibleClients.value.length, 50)
  list.query.value = 'Нет такого клиента'
  assert.equal(list.page.value, 1)
  assert.equal(list.rangeStart.value, 0)
  assert.equal(list.rangeEnd.value, 0)
  assert.deepEqual(list.visibleClients.value, [])
})

test('refresh keeps the current page and deleting its last client returns to the previous page', t => {
  const list = fixture(t, Array.from({ length: 21 }, (_, i) => `Клиент ${i + 1}`))
  list.page.value = 3
  list.clients.value = list.clients.value.map(c => ({ ...c }))
  assert.equal(list.page.value, 3)
  list.clients.value = list.clients.value.slice(0, 20)
  assert.equal(list.page.value, 2)
  assert.equal(list.rangeStart.value, 11)
  assert.equal(list.rangeEnd.value, 20)
  list.clients.value = []
  assert.equal(list.page.value, 1)
  assert.equal(list.rangeStart.value, 0)
  assert.deepEqual(list.visibleClients.value, [])
})
