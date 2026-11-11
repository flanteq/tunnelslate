// Run against an isolated Docker deployment. No credentials/tokens are printed.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const base = process.env.SMOKE_BASE_URL
const origin = process.env.SMOKE_ORIGIN
const password = process.env.SMOKE_ADMIN_PASSWORD
if (!base || !origin || !password) throw new Error('Set SMOKE_BASE_URL, SMOKE_ORIGIN and SMOKE_ADMIN_PASSWORD')
async function call(path, options = {}) {
  return fetch(`${base}${path}`, { ...options, signal: AbortSignal.timeout(10000) })
}
let healthy = false
for (let attempt = 0; attempt < 30; attempt++) {
  try { healthy = (await call('/healthz')).ok } catch { /* Wait for process startup. */ }
  if (healthy) break
  await new Promise(resolve => setTimeout(resolve, 500))
}
assert.ok(healthy, 'database readiness')
const page = await call('/')
assert.equal(page.status, 200)
const html = await page.text()
assert.match(html, /TunnelSlate/)
const asset = html.match(/src="([^"]+\.js)"/)
assert.ok(asset, 'production JS reference')
assert.equal((await fetch(new URL(asset[1], `${base}/`))).status, 200)
assert.equal((await call('/assets/missing.js')).status, 404)
assert.equal((await call('/api/dashboard')).status, 401)
const initialPassword = process.env.SMOKE_INITIAL_PASSWORD_FILE ? (await readFile(process.env.SMOKE_INITIAL_PASSWORD_FILE, 'utf8')).trim() : password
let loginBody = JSON.stringify({ username: 'admin', password: initialPassword })
const loginHeaders = { 'Content-Type': 'application/json', Origin: origin }
assert.equal((await call('/api/auth/login', { method: 'POST', headers: { ...loginHeaders, Origin: 'https://wrong-origin.invalid' }, body: loginBody })).status, 403)
let login = await call('/api/auth/login', { method: 'POST', headers: loginHeaders, body: loginBody })
assert.equal(login.status, 200, 'login')
let session = await login.json()
let cookie = login.headers.get('set-cookie')?.split(';')[0]
if (session.password_setup_required) {
  assert.equal((await call('/api/dashboard', { headers: { Cookie: cookie } })).status, 403, 'panel blocked before password setup')
  const setup = await call('/api/auth/setup-password', { method: 'POST', headers: { ...loginHeaders, Cookie: cookie, 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify({ new_password: password }) })
  assert.equal(setup.status, 200, 'mandatory password setup')
  loginBody = JSON.stringify({ username: 'admin', password })
  login = await call('/api/auth/login', { method: 'POST', headers: loginHeaders, body: loginBody })
  assert.equal(login.status, 200)
  session = await login.json(); cookie = login.headers.get('set-cookie')?.split(';')[0]
}
assert.equal(session.password_setup_required, false)
assert.ok(cookie, 'HttpOnly cookie received')
const headers = { Cookie: cookie }
assert.equal((await call('/api/auth/session', { headers })).status, 200)
const dashboardResponse = await call('/api/dashboard', { headers })
assert.equal(dashboardResponse.headers.get('cache-control'), 'no-store')
const dashboard = await dashboardResponse.json()
assert.ok(['not_configured', 'waiting_for_pki'].includes(dashboard.vpn.state))
assert.equal(dashboard.vpn.connected_clients, null)
assert.deepEqual(await (await call('/api/clients', { headers })).json(), [])
assert.deepEqual(await (await call('/api/certificates', { headers })).json(), [])
const audit = await (await call('/api/audit', { headers })).json()
assert.ok(audit.some(event => event.action === 'auth.login'))
const settings = await (await call('/api/settings', { headers })).json()
assert.equal(settings.editable, true)
assert.ok(!JSON.stringify(settings).includes(password), 'no secret in settings API')
assert.equal((await call('/api/auth/logout', { method: 'POST', headers: { ...headers, Origin: origin } })).status, 403)
assert.equal((await call('/api/auth/logout', { method: 'POST', headers: { ...headers, Origin: origin, 'X-CSRF-Token': session.csrf_token } })).status, 200)
assert.equal((await call('/api/auth/session', { headers })).status, 401)
console.log('HTTP smoke passed: frontend/assets, readiness, auth, CSRF, real empty data, audit, secret filtering and logout.')
