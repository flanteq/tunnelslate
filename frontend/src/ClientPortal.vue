<script setup lang="ts">
import { PRODUCT_NAME } from './branding'
import { t } from './i18n'
import LanguageSwitcher from './LanguageSwitcher.vue'
import { onMounted, onUnmounted, ref } from 'vue'
import { api, ApiError, errorText, responseError } from './api'
import Icon from './Icon.vue'
import { certificateTerm } from './certificateDates'
import InfoNote from './InfoNote.vue'
import ErrorNotifications from './ErrorNotifications.vue'
import { notifications } from './notifications'
interface Profile { id: string; name: string; status: string; not_after: number; revoked_at?: number; downloadable: boolean }
const name = ref(''), csrf = ref(''), devices = ref<Profile[]>([])
const loading = ref(true), busy = ref(false), unavailable = ref(false), reported = ref(false)
const dialog = ref<HTMLDialogElement | null>(null)
let requestKey = crypto.randomUUID()
let generation = 0
let controller: AbortController | undefined
let observedHash = ''
let refreshing = false
const current = (epoch: number) => epoch === generation && !controller?.signal.aborted
function expired() { unavailable.value = true; devices.value = []; name.value = ''; csrf.value = '' }
function error(err: unknown) {
  if (err instanceof ApiError && err.status === 401) { expired(); return }
  notifications.error(() => errorText(err, t('portal.couldNotLoadProfiles')))
}
async function load(epoch = generation) {
  if (!current(epoch) || refreshing || busy.value || reported.value || unavailable.value) return
  refreshing = true
  const signal = controller?.signal
  try {
    const session = await api<{ name: string; csrf_token: string }>('/share/session', { signal })
    if (!current(epoch) || busy.value || reported.value) return
    const result = await api<{ devices: Profile[] }>('/share/devices', { signal })
    if (!current(epoch) || busy.value || reported.value) return
    name.value = session.name; csrf.value = session.csrf_token; devices.value = result.devices
  } catch (err) { if (current(epoch) && !reported.value && !busy.value) error(err) }
  finally { if (current(epoch)) refreshing = false }
}
async function start() {
  const epoch = ++generation
  controller?.abort(); controller = new AbortController()
  observedHash = location.hash; refreshing = false
  loading.value = true; busy.value = false; reported.value = false; unavailable.value = false
  name.value = ''; csrf.value = ''; devices.value = []; dialog.value?.close()
  requestKey = crypto.randomUUID()
  try {
    if (observedHash) {
      const token = observedHash.slice(1)
      if (!/^[0-9a-f]{64}$/.test(token)) { expired(); return }
      // A new URL always establishes its own session, even if an old cookie is
      // present. Never fall back to that cookie when the supplied token fails.
      await api('/share/exchange', { method: 'POST', body: JSON.stringify({ token }), signal: controller.signal })
    }
    if (current(epoch)) await load(epoch)
  } catch (err) { if (current(epoch)) error(err) }
  finally { if (current(epoch)) loading.value = false }
}
async function download(profile: Profile) {
  const epoch = generation
  busy.value = true
  try {
    const response = await fetch(new URL(`api/share/devices/${profile.id}/profile`, document.baseURI), { credentials: 'same-origin', signal: controller?.signal })
    if (!response.ok) { const body = await response.json().catch(() => ({})); throw responseError(response.status, body) }
    const disposition = response.headers.get('Content-Disposition') ?? ''
    const encoded = disposition.match(/filename\*=utf-8''([^;]+)/i)?.[1]
    const plain = disposition.match(/filename=(?:"([^"]+)"|([^;]+))/i)
    let filename = plain?.[1] ?? plain?.[2]?.trim() ?? 'openvpn.ovpn'
    if (encoded) { try { filename = decodeURIComponent(encoded) } catch { /* Plain fallback. */ } }
    const blob = await response.blob()
    if (!current(epoch)) return
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; anchor.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch (err) { if (current(epoch)) error(err) }
  finally {
    if (current(epoch)) { busy.value = false; if (!unavailable.value) await load(epoch) }
  }
}
async function compromise() {
  const epoch = generation
  busy.value = true
  try {
    await api('/share/compromised', { method: 'POST', headers: { 'X-CSRF-Token': csrf.value, 'Idempotency-Key': requestKey }, body: '{}', signal: controller?.signal })
    if (!current(epoch)) return
    // Retire all reads from the closed session before displaying the result.
    generation++; controller?.abort(); refreshing = false; busy.value = false
    expired(); reported.value = true; history.replaceState(null, '', location.pathname); observedHash = ''; dialog.value?.close()
  } catch (err) { if (current(epoch)) { error(err); if (unavailable.value) dialog.value?.close() } }
  finally { if (current(epoch)) busy.value = false }
}
function hashChanged() { if (location.hash !== observedHash) void start() }
function visible() {
  if (document.hidden) return
  if (location.hash !== observedHash) void start()
  else if (!loading.value) void load()
}
function restored(event: PageTransitionEvent) {
  if (event.persisted && !(reported.value && !location.hash)) void start()
}
onMounted(() => {
  void start()
  window.addEventListener('hashchange', hashChanged)
  window.addEventListener('pageshow', restored)
  document.addEventListener('visibilitychange', visible)
  window.addEventListener('focus', visible)
})
onUnmounted(() => {
  generation++; controller?.abort()
  window.removeEventListener('hashchange', hashChanged)
  window.removeEventListener('pageshow', restored)
  document.removeEventListener('visibilitychange', visible)
  window.removeEventListener('focus', visible)
})
</script>
<template>
  <main class="client-portal">
    <header class="portal-brand"><Icon name="shield" :size="30" /><span>{{ PRODUCT_NAME }}</span><LanguageSwitcher class="portal-language" /></header>
    <section class="card">
      <div class="card-heading"><h2>{{ name ? t('portal.openvpnProfiles', { p0: name }) : t('portal.openvpnProfiles301') }}</h2></div>
      <div v-if="loading" class="compact-empty" role="status">{{ t('portal.loading') }}</div>
      <div v-else-if="reported" class="card-body portal-message" role="status"><h3>{{ t('portal.linkAccessClosed') }}</h3><p>{{ t('portal.revocationOfAllCertificatesHasBeenRequested') }}</p></div>
      <template v-else-if="unavailable">
        <div class="card-body portal-message"><h3>{{ t('portal.linkUnavailable') }}</h3><p>{{ t('portal.itMayHaveBeenDeletedOrReplaced') }}</p></div>
        <footer class="card-actions portal-actions"><button class="button secondary" @click="start">{{ t('portal.tryAgain') }}</button></footer>
      </template>
      <template v-else>
        <InfoNote class="card-description">{{ t('portal.downloadYourDeviceSProfileAndImport') }}</InfoNote>
        <div v-if="!devices.length" class="compact-empty">{{ t('portal.noProfilesAreAvailableYetContactYour') }}</div>
        <div v-else class="portal-profiles"><article v-for="profile in devices" :key="profile.id" class="portal-profile"><div><strong>{{ profile.name }}</strong><span class="subtle">{{ certificateTerm(profile) }}</span></div><button class="button secondary" :disabled="busy || !profile.downloadable" @click="download(profile)">{{ t('common.downloadOvpn') }}</button></article></div>
        <div class="card-body card-stack portal-safety"><p>{{ t('portal.suspectThatSomeoneElseHasYourLink') }}</p><button class="button secondary danger" :disabled="busy || !csrf" @click="dialog?.showModal()">{{ t('common.linkCompromised') }}</button></div>
      </template>
    </section>
    <dialog ref="dialog" class="confirmation-dialog" @cancel.prevent="!busy && dialog?.close()"><div class="card-heading"><h2>{{ t('portal.revokeAccessForAllDevices') }}</h2></div><div class="card-body dialog-copy"><p>{{ t('portal.theLinkWillStopWorkingImmediatelyAll') }}</p></div><div class="card-actions"><button class="button secondary" :disabled="busy" @click="dialog?.close()">{{ t('common.cancel') }}</button><button class="button primary" :disabled="busy" @click="compromise">{{ t('portal.revokeAccess') }}</button></div></dialog>
    <ErrorNotifications />
  </main>
</template>
