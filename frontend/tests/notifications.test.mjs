import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createNotifications } from '../src/notifications.ts'

function fixture(t) {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const notifications = createNotifications()
  t.after(() => notifications.clear())
  return notifications
}

test('each error closes after 12 seconds independently of subsequent errors', t => {
  const notifications = fixture(t)
  const first = notifications.error('Не удалось удалить клиента')
  t.mock.timers.tick(5000)
  const second = notifications.error('Не удалось скачать профиль')
  assert.deepEqual(notifications.items.value.map(item => item.id), [first, second])
  t.mock.timers.tick(6999)
  assert.equal(notifications.items.value.length, 2)
  t.mock.timers.tick(1)
  assert.deepEqual(notifications.items.value.map(item => item.id), [second])
  t.mock.timers.tick(5000)
  assert.equal(notifications.items.value.length, 0)
})

test('at most five errors remain visible and older ones are evicted first', t => {
  const notifications = fixture(t)
  for (let i = 1; i <= 7; i++) notifications.error(`Ошибка ${i}`)
  assert.deepEqual(notifications.items.value.map(item => item.message), ['Ошибка 3', 'Ошибка 4', 'Ошибка 5', 'Ошибка 6', 'Ошибка 7'])
  t.mock.timers.tick(12000)
  assert.equal(notifications.items.value.length, 0)
})

test('manual dismissal removes only the selected error and is safe to repeat', t => {
  const notifications = fixture(t)
  const first = notifications.error('Ошибка подключения')
  const second = notifications.error('Не удалось сохранить настройки')
  notifications.dismiss(first)
  notifications.dismiss(first)
  assert.deepEqual(notifications.items.value.map(item => item.id), [second])
  t.mock.timers.tick(12000)
  assert.equal(notifications.items.value.length, 0)
})

test('session cleanup clears all errors without leaving timers that affect later messages', t => {
  const notifications = fixture(t)
  notifications.error('Ошибка')
  notifications.clear()
  assert.equal(notifications.items.value.length, 0)
  t.mock.timers.tick(6000)
  const later = notifications.error('Другая ошибка')
  t.mock.timers.tick(6000)
  assert.deepEqual(notifications.items.value.map(item => item.id), [later])
  t.mock.timers.tick(6000)
  assert.equal(notifications.items.value.length, 0)
})

test('duplicate polling errors neither fill the stack nor prolong the timer and can reappear after expiry', t => {
  const notifications = fixture(t)
  const first = notifications.error('Сервер недоступен', 'refresh')
  t.mock.timers.tick(10000)
  assert.equal(notifications.error('Сервер недоступен', 'refresh'), first)
  assert.equal(notifications.items.value.length, 1)
  t.mock.timers.tick(2000)
  assert.equal(notifications.items.value.length, 0)
  assert.notEqual(notifications.error('Сервер недоступен', 'refresh'), first)
  assert.equal(notifications.items.value.length, 1)
})

test('separate user errors do not replace one another even when their text is identical', t => {
  const notifications = fixture(t)
  notifications.error('Не удалось создать клиента')
  notifications.error('Не удалось создать клиента')
  assert.equal(notifications.items.value.length, 2)
  assert.notEqual(notifications.items.value[0].id, notifications.items.value[1].id)
})
