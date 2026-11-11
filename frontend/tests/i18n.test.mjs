import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'
import ru from '../src/locales/ru.json' with { type: 'json' }
import en from '../src/locales/en.json' with { type: 'json' }
import { t, setLanguage, language, formatNumber, formatDateTime } from '../src/i18n.ts'
import { certificateDate, certificateTerm, defaultCertificateDate } from '../src/certificateDates.ts'
import { responseError, errorText } from '../src/api.ts'
import { createNotifications } from '../src/notifications.ts'

afterEach(() => setLanguage('ru'))

test('both languages cover the same keys and preserve interpolation parameters', () => {
  assert.deepEqual(Object.keys(en).sort(), Object.keys(ru).sort())
  const placeholders = value => [...new Set(Object.values(typeof value === 'string' ? { text: value } : value).flatMap(text => text.match(/\{\w+\}/g) ?? []))].sort()
  for (const key of Object.keys(ru)) {
    assert.deepEqual(placeholders(en[key]), placeholders(ru[key]), key)
    assert.ok(typeof en[key] === 'string' ? en[key].length : en[key].other, key)
  }
})

test('plural rules follow the selected language and preserve literal parameter values', () => {
  for (const count of [1, 21]) assert.match(t('clients.needAttention', { p0: count }), /требует завершения$/)
  for (const count of [2, 5, 11, 22]) assert.match(t('clients.needAttention', { p0: count }), /требуют завершения$/)
  setLanguage('en')
  assert.equal(t('clients.needAttention', { p0: 1 }), '1 needs attention')
  assert.equal(t('clients.needAttention', { p0: 21 }), '21 need attention')
  const value = '<script>{device}</script>'
  assert.ok(errorText(responseError(400, { code: 'vpn.static_ip_conflict', params: { device: value } })).includes(value))
  setLanguage('unsupported')
  assert.equal(language.value, 'en')
})

test('localized certificate dates retain UTC days, revocation semantics and the default expiry', () => {
  const expiry = Date.parse('2030-01-01T23:59:59Z') / 1000
  const revoked = Date.parse('2026-11-08T12:00:00Z') / 1000
  const original = process.env.TZ
  try {
    process.env.TZ = 'Pacific/Auckland'
    assert.equal(certificateDate(expiry), '01.01.2030')
    assert.equal(formatNumber(1234.5), new Intl.NumberFormat('ru-RU').format(1234.5))
    const defaultDate = defaultCertificateDate(new Date('2026-11-08T23:59:59Z'))
    setLanguage('en')
    assert.equal(certificateDate(expiry), '1/1/2030')
    assert.equal(certificateTerm({ status: 'revoked', not_after: expiry, revoked_at: revoked }), 'Revoked on 11/8/2026')
    assert.equal(defaultCertificateDate(new Date('2026-11-08T23:59:59Z')), defaultDate)
    assert.equal(formatNumber(1234.5), '1,234.5')
    assert.match(formatDateTime(revoked), /11\/09\/2026/)
  } finally { if (original === undefined) delete process.env.TZ; else process.env.TZ = original }
})

test('API error codes translate independently of server diagnostic text', () => {
  const error = responseError(409, { error: 'private server diagnostic', code: 'client.name_exists' })
  assert.equal(errorText(error), ru['errors.client.name_exists'])
  setLanguage('en')
  assert.equal(errorText(error), en['errors.client.name_exists'])
  assert.equal(error.message, 'private server diagnostic')
  assert.equal(errorText(responseError(400, { code: 'future.code', error: 'do not show me' })), en['errors.request_failed'])
  assert.equal(errorText(responseError(500, { error: 'database details' })), en['errors.internal_error'])
  assert.equal(errorText(new TypeError('Failed to fetch')), en['errors.network_error'])
  assert.match(errorText(responseError(400, { code: 'ccd.static_ip_range', params: { start: '10.8.0.128', end: '10.8.0.254' } })), /10\.8\.0\.128–10\.8\.0\.254/)
  assert.match(errorText(responseError(400, { code: 'certificate.ca_expiry', params: { expires_at: 1893456000 } })), /01\/01\/2030/)
})

test('an existing error notification changes language without duplication or resetting its lifetime', context => {
  context.mock.timers.enable({ apis: ['setTimeout'] })
  const notifications = createNotifications()
  context.after(() => notifications.clear())
  const message = () => errorText(responseError(409, { code: 'client.name_exists' }))
  const id = notifications.error(message, 'load')
  context.mock.timers.tick(6000)
  setLanguage('en')
  assert.equal(notifications.items.value[0].message(), en['errors.client.name_exists'])
  assert.equal(notifications.error(message, 'load'), id)
  context.mock.timers.tick(6000)
  assert.equal(notifications.items.value.length, 0)
})


test('IP lockout errors show a rounded wait in both languages', () => {
  const error = responseError(429, { code: 'auth.ip_blocked', params: { retry_after: 61, retry_at: 9999999999 } })
  setLanguage('en')
  assert.match(errorText(error), /2 min/)
  setLanguage('ru')
  assert.match(errorText(error), /2 мин/)
})
