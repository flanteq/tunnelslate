// Destructive lifecycle checks: run ONLY against an isolated empty test deployment.
// State/profiles in /artifacts are private test data and are never printed.
import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
const base = process.env.SMOKE_BASE_URL
const origin = process.env.SMOKE_ORIGIN
const password = process.env.SMOKE_ADMIN_PASSWORD
if (!base || !origin || !password) throw new Error('Test URL, origin and password are required')
const phase = process.argv[2] ?? 'initialize'
const statePath = '/artifacts/state.json'
let state = {}
try { state = JSON.parse(await readFile(statePath, 'utf8')) } catch { /* New test installation. */ }
async function saveState() { await writeFile(statePath, JSON.stringify(state), { mode: 0o600 }) }
async function request(path, { method = 'GET', body, csrf = true, key, headers = {} } = {}) {
  return fetch(`${base}/api${path}`, {
    method, signal: AbortSignal.timeout(100000),
    headers: { 'Content-Type': 'application/json', Origin: origin, ...(state.cookie ? { Cookie: state.cookie } : {}), ...(csrf && state.csrf ? { 'X-CSRF-Token': state.csrf } : {}), ...(key ? { 'Idempotency-Key': key } : {}), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
async function json(path, options) {
  const response = await request(path, options)
  assert.ok(response.ok, `${path}: HTTP ${response.status}`)
  return response.json()
}
async function poll(check, message) {
  for (let attempt = 0; attempt < 35; attempt++) {
    try { if (await check()) return } catch { /* Allow process restarts. */ }
    await new Promise(resolve => setTimeout(resolve, 1000))
  }
  assert.fail(message)
}
async function applied(revision) {
  await poll(async () => (await json('/settings')).applied_revision === revision && (await json('/dashboard')).vpn.state === 'connected', 'VPN configuration not applied')
}
async function profile(target) {
  const response = await request(`/devices/${state.device}/profile`)
  assert.equal(response.status, 200, 'profile download')
  const data = await response.text()
  assert.match(data, /remote tunnelslate-vpn 1194/)
  await writeFile(`/artifacts/${target}`, data, { mode: 0o600 })
}

if (phase === 'initialize') {
  const html = await (await fetch(`${base}/`)).text()
  assert.ok(html.includes('<base href="/ovpn/">'))
  const js = html.match(/src="([^"]+\.js)"/)
  assert.ok(js)
  assert.equal((await fetch(new URL(js[1], `${base}/`))).status, 200, 'prefixed production JS')
  assert.equal((await fetch(new URL('favicon.svg', `${base}/`))).status, 200, 'prefixed favicon')
  const root = new URL(base)
  assert.equal((await fetch(`${root.origin}/api/settings`)).status, 404, 'no API outside prefix')
  const initialPassword = process.env.SMOKE_INITIAL_PASSWORD_FILE ? (await readFile(process.env.SMOKE_INITIAL_PASSWORD_FILE, 'utf8')).trim() : password
  let login = await request('/auth/login', { method: 'POST', body: { username: 'admin', password: initialPassword } })
  assert.equal(login.status, 200)
  assert.match(login.headers.get('set-cookie'), /Path=\/ovpn\//)
  state.cookie = login.headers.get('set-cookie').split(';')[0]
  let session = await login.json()
  state.csrf = session.csrf_token
  if (session.password_setup_required) {
    assert.equal((await request('/settings')).status, 403, 'panel blocked before password setup')
    await json('/auth/setup-password', { method: 'POST', body: { new_password: password } })
    login = await request('/auth/login', { method: 'POST', body: { username: 'admin', password } })
    assert.equal(login.status, 200)
    session = await login.json(); state.cookie = login.headers.get('set-cookie').split(';')[0]; state.csrf = session.csrf_token
  }
  assert.equal(session.password_setup_required, false)
  assert.equal((await json('/settings')).bootstrap.state, 'empty')
  assert.equal((await json('/dashboard')).vpn.state, 'waiting_for_pki')
  assert.equal((await request('/pki/initialize', { method:'POST', body:{}, csrf:false })).status,403)
  assert.equal((await json('/pki/initialize', { method:'POST', body:{} })).state,'ready')
  assert.equal((await request('/pki/initialize', { method:'POST', body:{} })).status,409)
  let settings = await json('/settings')
  await applied(settings.vpn.revision)
  const desired = { ...settings.vpn, endpoint:'tunnelslate-vpn', external_port:1194, network:'10.91.0.0/24', dns:['172.16.0.1'], routes:['192.168.99.0/24'] }
  assert.equal((await request('/settings/vpn',{method:'PUT',body:desired,csrf:false})).status,403)
  assert.equal((await request('/settings/vpn',{method:'PUT',body:{...desired,dns:['1.1.1.999']}})).status,400)
  const changed = await json('/settings/vpn',{method:'PUT',body:desired})
  await applied(changed.revision)
  assert.equal((await request('/settings/vpn',{method:'PUT',body:desired})).status,409)
  state.revision = changed.revision
  const client = await json('/clients',{method:'POST',body:{name:'Lifecycle client'}})
  const result = await json(`/clients/${client.id}/devices`,{method:'POST',body:{name:'Lifecycle laptop'},key:randomUUID()})
  state.client = client.id; state.device = result.operation.device_id; state.serial = result.operation.result_serial
  await profile('profile-old.ovpn'); await profile('client.ovpn')
  await saveState()
} else if (phase === 'connected') {
  await poll(async () => (await json('/connections')).some(c => c.device === 'Lifecycle laptop'), 'real VPN client did not connect')
} else if (phase === 'rotate') {
  const result = await json(`/devices/${state.device}/rotate`,{method:'POST',body:{},key:randomUUID()})
  assert.equal(result.operation.state,'succeeded')
  assert.notEqual(result.operation.result_serial,state.serial)
  state.oldSerial = state.serial; state.serial = result.operation.result_serial
  assert.equal((await json('/certificates')).find(c=>c.serial===state.oldSerial).status,'revoked')
  await profile('profile-new.ovpn')
  await saveState()
} else if (phase === 'rejected') {
  for (let i=0;i<9;i++) {
    assert.deepEqual(await json('/connections'),[], 'revoked profile reconnected')
    await new Promise(resolve=>setTimeout(resolve,1000))
  }
} else if (phase === 'activate-new') {
  await writeFile('/artifacts/client.ovpn',await readFile('/artifacts/profile-new.ovpn'),{mode:0o600})
} else if (phase === 'tcp') {
  const settings = await json('/settings')
  const changed = await json('/settings/vpn',{method:'PUT',body:{...settings.vpn,protocol:'tcp',network:'10.92.0.0/24',dns:['172.16.0.1','1.1.1.1'],redirect_gateway:true}})
  await applied(changed.revision)
  state.revision = changed.revision
  await profile('client.ovpn')
  assert.match(await readFile('/artifacts/client.ovpn','utf8'),/proto tcp-client/)
  await saveState()
} else if (phase === 'revoke') {
  const result = await json(`/certificates/${state.serial}/revoke`,{method:'POST',body:{},key:randomUUID()})
  assert.equal(result.operation.state,'succeeded')
  assert.equal((await request(`/devices/${state.device}/profile`)).status,409)
  await poll(async()=>(await json('/connections')).length===0,'revoked active session remained connected')
} else if (phase === 'restart') {
  assert.equal((await json('/auth/session')).username,'admin','session lost on restart')
  const settings = await json('/settings')
  assert.equal(settings.bootstrap.state,'ready')
  assert.equal(settings.vpn.revision,state.revision)
  assert.equal(settings.vpn.protocol,'tcp')
  assert.equal((await json('/certificates')).filter(c=>c.status==='revoked').length,2)
  await applied(state.revision)
} else { throw new Error('Unknown phase') }
console.log(`Isolated check passed: ${phase}`)
