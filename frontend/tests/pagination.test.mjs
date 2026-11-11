import assert from 'node:assert/strict'
import { test } from 'node:test'
import { effectScope, ref } from 'vue'
import { usePagination } from '../src/usePagination.ts'

function fixture(t, count) {
  const rows = ref(Array.from({ length: count }, (_, id) => ({ id })))
  const query = ref('')
  const scope = effectScope()
  const pagination = scope.run(() => usePagination(() => rows.value, query))
  t.after(() => scope.stop())
  return { ...pagination, rows, query }
}

test('certificate and operation pagination are independent and reach old history', t => {
  const certificates = fixture(t, 521), operations = fixture(t, 137)
  certificates.page.value = 53
  operations.page.value = 14
  assert.deepEqual(certificates.items.value, [{ id: 520 }])
  assert.deepEqual(operations.items.value.map(row => row.id), [130, 131, 132, 133, 134, 135, 136])
  certificates.pageSize.value = 25
  assert.equal(certificates.page.value, 1)
  assert.equal(certificates.items.value.length, 25)
  assert.equal(operations.page.value, 14)
  operations.pageSize.value = 50
  assert.equal(operations.page.value, 1)
  assert.equal(operations.items.value.length, 50)
})

test('SSE refresh preserves the selected page and clamps it when the list shrinks', t => {
  const list = fixture(t, 21)
  list.page.value = 3
  list.rows.value = list.rows.value.map(row => ({ ...row }))
  assert.equal(list.page.value, 3)
  list.rows.value = list.rows.value.slice(0, 20)
  assert.equal(list.page.value, 2)
  assert.equal(list.items.value.length, 10)
  list.rows.value = []
  assert.equal(list.page.value, 1)
  assert.equal(list.pageCount.value, 1)
  assert.deepEqual(list.items.value, [])
})

test('a changed search resets pagination even when the page count stays the same', t => {
  const list = fixture(t, 51)
  list.page.value = 4
  list.query.value = 'новый поиск'
  assert.equal(list.page.value, 1)
})
