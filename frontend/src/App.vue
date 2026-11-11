<script setup lang="ts">
import { BRAND_PARTS, PRODUCT_NAME, PRODUCT_ID } from './branding'
import FloatingField from './FloatingField.vue'
import { t, formatDate, formatDateTime, formatTime, formatNumber } from './i18n'
import LanguageSwitcher from './LanguageSwitcher.vue'
import InfoNote from './InfoNote.vue'
import { computed, nextTick, onMounted, onUnmounted, ref, watch, watchEffect } from 'vue'
import Icon from './Icon.vue'
import { passwordInputMaxLength } from './passwordPolicy'
import ClientManager from './ClientManager.vue'
import { formatBytes } from './statistics'
import AccountsPanel from './AccountsPanel.vue'
import ConnectionsPanel from './ConnectionsPanel.vue'
import BootstrapPanel from './BootstrapPanel.vue'
import VPNSettingsPanel from './VPNSettingsPanel.vue'
import PanelSettingsPanel from './PanelSettingsPanel.vue'
import { dcoLabel } from './dco'
import InitialPasswordPage from './InitialPasswordPage.vue'
import ErrorNotifications from './ErrorNotifications.vue'
import { notifications } from './notifications'
import { api, ApiError, errorText } from './api'
import type { PanelSettingsView, Session, TOTPChallenge, AdminAccount, Dashboard, Client, Certificate, AuditEvent, Settings, Device, Operation, Connection } from './api'

import { createResourceLoader, resources, sectionResources } from './resourceLoader'
import type { Resource, Section } from './resourceLoader'
import { createEventStream } from './eventStream'
import type { EventState } from './eventStream'
const nav = computed((): { id: Section; title: string; icon: string; description: string }[] => [
  { id: 'overview', title: t('app.overview'), icon: 'grid', description: t('app.everythingYouNeedToKnowAboutYour') },
  { id: 'clients', title: t('app.clients'), icon: 'users', description: t('app.usersAndDevicesOnYourNetwork') },
  { id: 'certificates', title: t('app.certificates'), icon: 'certificate', description: t('app.deviceCertificatesAndRevocationHistory') },
  { id: 'settings', title: t('app.openvpnSettings'), icon: 'settings', description: t('app.openvpnServerAndConnectionSettings') },
  { id: 'panel-settings', title: t('panel.title'), icon: 'server', description: t('panel.description') },
  { id: 'accounts', title: t('app.accounts'), icon: 'lock', description: t('app.administratorsAndPanelAccess') },
  { id: 'audit', title: t('app.activityLog'), icon: 'clock', description: t('app.historyOfAdministrativeActions') },
])
const sectionFromURL = (): Section => nav.value.find(item => location.hash === `#${item.id}`)?.id ?? 'overview'
const active = ref<Section>(sectionFromURL())
const page = computed(() => nav.value.find(item => item.id === active.value)!)
const session = ref<Session | null>(null)
const booting = ref(true)
const busy = ref(false)
const changingPassword = ref(false)
const username = ref('')
const password = ref('')
const totpChallenge = ref(''), totpCode = ref('')
const totpInput = ref<HTMLInputElement | null>(null)
const dashboard = ref<Dashboard | null>(null)
const panelSettings = ref<PanelSettingsView | null>(null)
const instanceName = computed(() => dashboard.value?.instance_name || t('app.myServer'))
const serverVersion = ref('')
const initialPasswordAvailable = ref(false)
let loginBootstrapRequest: AbortController | undefined
const appVersion = computed(() => dashboard.value?.version || serverVersion.value)
const versionRequest = new AbortController()
const clients = ref<Client[]>([])
const accounts = ref<AdminAccount[]>([])
const certificates = ref<Certificate[]>([])
const audit = ref<AuditEvent[]>([])
const settings = ref<Settings | null>(null)
const devices = ref<Device[]>([])
const operations = ref<Operation[]>([])
const connections = ref<Connection[]>([])
const lastRefresh = ref<Date | null>(null)
const eventsConnected = ref(false)
let expiredDuringPasswordChange = false
let pendingUpdate: ReturnType<typeof setTimeout> | undefined
const statisticsRevision = ref(0)
let statisticsRemoteRevision = 0
let remoteRevisions: Partial<Record<Resource, number>> = {}
let liveState: EventState | undefined
const dark = ref(false)
try { dark.value = localStorage.getItem(PRODUCT_ID + '-theme') === 'dark' } catch { /* Storage may be unavailable. */ }
watchEffect(() => {
  document.documentElement.dataset.theme = dark.value ? 'dark' : 'light'
  try { localStorage.setItem(PRODUCT_ID + '-theme', dark.value ? 'dark' : 'light') } catch { /* Optional preference. */ }
})
const eventLabels = computed((): Record<string, string> => ({ 'panel.settings.update': t('panel.nameUpdated'), 'panel.metrics.update': t('panel.metricsUpdated'), 'vpn.auth.provider.save':t('vpnAuth.providerSavedEvent'), 'vpn.auth.provider.delete':t('vpnAuth.providerDeletedEvent'), 'vpn.auth.binding.save':t('vpnAuth.bindingSavedEvent'), 'vpn.auth.accept':t('vpnAuth.acceptEvent'), 'vpn.auth.reject':t('vpnAuth.rejectEvent'), 'auth.totp.enabled': t('totp.enabledEvent'), 'auth.totp.disabled': t('totp.disabledEvent'), 'admin.totp.reset': t('totp.resetEvent'), 'pki.crl.renew': t('crl.renewedEvent'), 'pki.crl.renewal_failed': t('crl.failedEvent'), 'pki.crl.expired': t('crl.criticalEvent'), 'pki.crl.recovered': t('crl.recoveredEvent'), 'admin.sessions.end': t('app.administratorSessionsEnded'), 'admin.created': t('app.administratorCreated'), 'admin.rename': t('app.administratorRenamed'), 'admin.password.reset': t('app.administratorPasswordReset'), 'admin.delete': t('app.administratorDeleted'), 'auth.ip_blocked': t('app.signInIPBlocked'), 'auth.login': t('app.signedInToThePanel'), 'auth.logout': t('app.signedOutOfThePanel'), 'auth.password.change': t('app.administratorPasswordChanged'), 'auth.password.setup': t('app.administratorPasswordSet'), 'vpn.settings.update': t('app.vpnSettingsUpdated'), 'device.ccd.update': t('app.deviceSettingsUpdated'), 'client.create': t('app.clientCreated'), 'pki.initialize': t('app.pkiInitialized'), 'pki.runtime.prepare': t('app.pkiServerFilesChecked'), 'pki.issue': t('app.certificateIssued'), 'pki.rotate': t('app.profileReissued'), 'pki.revoke': t('app.certificateRevoked'), 'pki.delete': t('app.profileDeleted'), 'pki.delete_client': t('app.clientAndProfilesDeleted'), 'profile.download': t('app.profileDownloaded'), 'session.disconnect': t('app.sessionDisconnected'), 'session.expired': t('app.sessionDisconnectedCertificateExpired'), 'client.link.create': t('app.profileLinkCreated'), 'client.link.rotate': t('app.profileLinkRegenerated'), 'client.link.delete': t('app.profileLinkDeleted'), 'client.link.open': t('app.profileLinkOpened'), 'client.link.compromised': t('app.linkReportedCompromisedRevocationOfAllCertificates'), 'pki.revoke_client': t('app.emergencyCertificateRevocationCompleted') }))
const auditActor = (actor: string) => actor.startsWith('client-link:') ? t('app.clientViaLink') : actor === 'system' ? t('app.system') : actor
const statusLabels = computed((): Record<string, string> => ({ valid: t('common.valid'), revoked: t('common.revoked'), expired: t('common.expired') }))
const dateTime = formatDateTime
const crlLabels = computed((): Record<string, string> => ({ valid: t('crl.valid'), renewal_due: t('crl.renewalDue'), renewal_failed: t('crl.renewalFailed'), expired: t('crl.expired'), missing: t('crl.missing'), invalid: t('crl.invalid'), not_initialized: t('crl.notInitialized') }))
const crlState = computed(() => dashboard.value?.crl?.state ?? 'not_initialized')
const crlTone = computed(() => crlState.value === 'valid' ? 'success' : ['expired', 'missing', 'invalid'].includes(crlState.value) ? 'critical' : ['renewal_due', 'renewal_failed'].includes(crlState.value) ? 'warning' : 'neutral')
const crlDescription = computed(() => dashboard.value?.crl?.next_update ? t('crl.validUntil', { date: formatDate(dashboard.value.crl.next_update, { timeZone: 'UTC' }) }) : t('crl.automaticRenewal'))


function showError(err: unknown) {
  if (err instanceof ApiError && err.status === 401) { clearSession(); notifications.error(() => t('app.yourSessionHasEndedSignInAgain'), 'session-expired'); return }
  notifications.error(() => errorText(err, t('app.theRequestCouldNotBeCompleted')), 'app-request')
}
const loaders = createResourceLoader({
  needed: () => sectionResources(active.value),
  enabled: () => !!session.value && !session.value.password_setup_required && !changingPassword.value && !document.hidden,
  load: async (name, signal) => {
    try { return await api(`/${name}`, { signal }) }
    catch (err) { if (name === 'connections' && err instanceof ApiError && err.status === 503) return []; throw err }
  },
  apply: (name, value) => {
    switch (name) {
      case 'dashboard': dashboard.value = value as Dashboard; if (liveState) { dashboard.value.vpn = liveState.vpn; dashboard.value.crl = liveState.crl }; break
      case 'panel-settings': panelSettings.value = value as PanelSettingsView; break
      case 'settings': settings.value = value as Settings; if (liveState) { settings.value.applied_revision = liveState.applied_revision; settings.value.dco = liveState.vpn.dco }; break
      case 'admins': accounts.value = value as AdminAccount[]; break
      case 'clients': clients.value = value as Client[]; break
      case 'devices': devices.value = value as Device[]; break
      case 'certificates': certificates.value = value as Certificate[]; break
      case 'operations': operations.value = value as Operation[]; break
      case 'audit': audit.value = value as AuditEvent[]; break
      case 'connections': connections.value = value as Connection[]; break
    }
    lastRefresh.value = new Date()
  },
  onError: showError,
})
function scheduleUpdate() {
  if (pendingUpdate) return
  pendingUpdate = setTimeout(() => { pendingUpdate = undefined; void loaders.flush() }, 150)
}
function receiveState(data: EventState, ready = false) {
  liveState = data
  if (ready || statisticsRemoteRevision !== data.revisions.statistics) statisticsRevision.value++
  statisticsRemoteRevision = data.revisions.statistics
  const changed = resources.filter(name => remoteRevisions[name] !== data.revisions[name])
  remoteRevisions = { ...data.revisions }
  loaders.invalidate(ready ? resources : changed)
  if (dashboard.value) { dashboard.value.vpn = data.vpn; dashboard.value.crl = data.crl }
  if (settings.value) { settings.value.applied_revision = data.applied_revision; settings.value.dco = data.vpn.dco }
  scheduleUpdate()
}
function sessionExpired() {
  if (changingPassword.value) { expiredDuringPasswordChange = true; return }
  showError(new ApiError(401, 'Session expired'))
}
const events = createEventStream({
  url: () => new URL('api/events', document.baseURI),
  ready: data => receiveState(data, true),
  state: data => receiveState(data),
  expired: sessionExpired,
  connected: value => { eventsConnected.value = value },
  checkSession: () => api<void>('/auth/session'),
  fallback: () => { statisticsRevision.value++; loaders.invalidate(sectionResources(active.value)); scheduleUpdate() },
})
function refreshAfterMutation() {
  if (!eventsConnected.value) { loaders.invalidate(sectionResources(active.value)); scheduleUpdate() }
}
async function refreshLoginBootstrap() {
  initialPasswordAvailable.value = false
  loginBootstrapRequest?.abort()
  const request = new AbortController()
  loginBootstrapRequest = request
  try {
    const info = await api<{ initial_password_available: boolean }>('/auth/bootstrap', { signal: request.signal })
    if (!request.signal.aborted && !session.value) initialPasswordAvailable.value = info.initial_password_available === true
  } catch { /* Optional hint: keep sign-in available if this check fails. */ }
}
watch(session, value => {
  loginBootstrapRequest?.abort(); initialPasswordAvailable.value = false
  if (!value) void refreshLoginBootstrap()
  events.stop(); loaders.reset(); remoteRevisions = {}; liveState = undefined
  if (pendingUpdate) { clearTimeout(pendingUpdate); pendingUpdate = undefined }
  if (value && !value.password_setup_required) { events.start(); scheduleUpdate() }
}, { flush: 'sync' })
watch(active, scheduleUpdate)
watch(changingPassword, value => {
  if (!value) {
    if (expiredDuringPasswordChange && session.value) sessionExpired()
    expiredDuringPasswordChange = false
    scheduleUpdate()
  }
})
function visibilityChanged() {
  if (!document.hidden && !session.value) void refreshLoginBootstrap()
  if (!document.hidden && session.value && !session.value.password_setup_required) {
    if (!eventsConnected.value) loaders.invalidate(sectionResources(active.value))
    scheduleUpdate()
  }
}
async function login() {
  if (busy.value) return
  busy.value = true
  const secondFactor = Boolean(totpChallenge.value)
  try {
    const result = await api<Session | TOTPChallenge>(secondFactor ? '/auth/totp' : '/auth/login', { method: 'POST', body: JSON.stringify(secondFactor ? { challenge_token: totpChallenge.value, code: totpCode.value } : { username: username.value, password: password.value }) })
    notifications.clear()
    password.value = ''
    totpCode.value = ''
    if ('totp_required' in result) {
      totpChallenge.value = result.challenge_token
      await nextTick(); totpInput.value?.focus()
    } else {
      totpChallenge.value = ''; session.value = result
    }
  } catch (err) {
    if (secondFactor) {
      totpCode.value = ''
      if (err instanceof ApiError && ['auth.totp_challenge_expired', 'auth.ip_blocked'].includes(err.code)) resetTOTPLogin()
      notifications.error(() => errorText(err, t('totp.signInFailed')))
      await nextTick(); totpInput.value?.focus()
    }
    else if (err instanceof ApiError && err.status === 401) notifications.error(() => t('app.incorrectUsernameOrPassword'))
    else if (err instanceof ApiError && err.status === 429) notifications.error(() => errorText(err, t('app.tooManySignInAttemptsTryAgain')))
    else if (err instanceof ApiError && err.status === 403) notifications.error(() => t('app.thePanelAddressDoesNotMatchOVPN'))
    else showError(err)
  } finally { busy.value = false }
}
function resetTOTPLogin() { totpChallenge.value = ''; totpCode.value = ''; password.value = '' }
async function logout() {
  if (!session.value) return
  busy.value = true
  try {
    await api('/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': session.value.csrf_token } })
    clearSession()
  } catch (err) { showError(err) } finally { busy.value = false }
}
function clearSession() {
  notifications.clear()
  resetTOTPLogin()
  session.value = null; panelSettings.value = null; dashboard.value = null; settings.value = null; clients.value = []; accounts.value = []; certificates.value = []; audit.value = []; devices.value = []; operations.value = []; connections.value = []; lastRefresh.value = null
}
function passwordChanged() {
  if (session.value) username.value = session.value.username
  changingPassword.value = false
  clearSession(); password.value = ''
}
function accountSignedOut(name?: string) {
  username.value = name ?? ''
  clearSession(); changingPassword.value = false; password.value = ''
}
function select(section: Section) {
  if (changingPassword.value || (active.value === section && location.hash === `#${section}`)) return
  const url = new URL(location.href)
  url.hash = section
  history.pushState(null, '', url)
  active.value = section
}
function navigationChanged() {
  if (changingPassword.value) {
    const url = new URL(location.href)
    url.hash = active.value
    history.replaceState(null, '', url)
    return
  }
  active.value = sectionFromURL()
}
onMounted(async () => {
  try { session.value = await api<Session>('/auth/session') }
  catch (err) { if (!(err instanceof ApiError && err.status === 401)) showError(err) }
  finally { booting.value = false }
})
onMounted(() => {
  void refreshLoginBootstrap()
  void api<{ version: string }>('/version', { signal: versionRequest.signal })
    .then(info => { if (typeof info.version === 'string') serverVersion.value = info.version })
    .catch(() => { /* Version is optional decoration; login remains available. */ })
})
onMounted(() => document.addEventListener('visibilitychange', visibilityChanged))
onMounted(() => {
  window.addEventListener('popstate', navigationChanged)
  window.addEventListener('hashchange', navigationChanged)
})
onUnmounted(() => {
  versionRequest.abort(); loginBootstrapRequest?.abort()
  events.stop(); loaders.reset(); notifications.clear()
  if (pendingUpdate) clearTimeout(pendingUpdate)
  document.removeEventListener('visibilitychange', visibilityChanged)
  window.removeEventListener('popstate', navigationChanged)
  window.removeEventListener('hashchange', navigationChanged)
})
</script>

<template>
  <ErrorNotifications />
  <div v-if="booting" class="boot-screen" role="status"><span class="brand-mark"><Icon name="shield" :size="30" /></span><span>{{ t('app.loadingTunnelSlate') }}</span></div>
  <main v-else-if="!session" class="login-page">
    <section class="login-story">
      <a class="brand" href="./" :aria-label="PRODUCT_NAME"><span class="brand-mark"><Icon name="shield" :size="26" /></span><span>{{ BRAND_PARTS[0] }}<span class="brand-light">{{ BRAND_PARTS[1] }}</span></span></a>
      <div class="story-content"><span class="eyebrow">{{ t('app.yourNETWORKYOURCONTROL') }}</span><h1>{{ t('app.aPlace') }}<br>{{ t('app.forYourVPN') }}</h1><p>{{ t('app.clientsCertificatesAndServerSettingsManagedIn') }}</p><div class="network-art" aria-hidden="true"><span class="node node-a"><Icon name="users" :size="26" /></span><span class="node node-main"><Icon name="shield" :size="54" /></span><span class="node node-b"><Icon name="key" :size="26" /></span><span class="node node-c"><Icon name="server" :size="26" /></span><span class="network-line line-a"></span><span class="network-line line-b"></span><span class="network-line line-c"></span></div></div>
    </section>
    <section class="login-form-panel">
      <LanguageSwitcher class="language-login" />
      <button class="icon-button theme-login" :aria-label="dark ? t('app.lightTheme') : t('app.darkTheme')" @click="dark = !dark"><Icon name="sun" /></button>
      <form class="login-form" @submit.prevent="login">
        <span class="small-icon"><Icon name="lock" :size="24" /></span>
        <p class="eyebrow muted">{{ t('app.administrationPANEL') }}</p><h2>{{ totpChallenge ? t('totp.verifySignIn') : t('app.welcomeBack') }}</h2><p class="subtle">{{ totpChallenge ? t('totp.signInHint') : t('app.signInToManageYourNetwork') }}</p>
        <template v-if="!totpChallenge">
        <FloatingField id="username" :label="t('app.username')"><input id="username" v-model="username" autocomplete="username" required maxlength="64" autofocus :placeholder="t('app.administratorUsername')"></FloatingField>
        <FloatingField id="password" :label="t('app.password')"><input id="password" v-model="password" type="password" autocomplete="current-password" required :maxlength="passwordInputMaxLength" :placeholder="t('app.enterYourPassword')"></FloatingField>
        </template>
        <template v-else>
          <input type="hidden" name="username" :value="username" autocomplete="username">
          <FloatingField id="login-totp-code" :label="t('totp.code')"><input id="login-totp-code" ref="totpInput" v-model="totpCode" type="text" name="totp-code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" placeholder="000000" required :disabled="busy"></FloatingField>
        </template>
        <button class="button primary login-submit" type="submit" :disabled="busy">{{ busy ? t('app.signingIn') : totpChallenge ? t('totp.verify') : t('app.signIn') }}<Icon name="arrow" :size="18" /></button>
        <button v-if="totpChallenge" class="button secondary login-totp-back" type="button" :disabled="busy" @click="resetTOTPLogin">{{ t('totp.backToSignIn') }}</button>
        <InfoNote v-if="!totpChallenge && initialPasswordAvailable" class="login-note">{{ t('app.onFirstStartupAOneTimePassword') }} <code>/data/app/initial_admin_password</code> {{ t('app.insideThePanelContainerSignInAnd') }}</InfoNote>
      </form>
      <span class="login-version">{{ PRODUCT_NAME }} <span v-if="appVersion">v{{ appVersion }}</span></span>
    </section>
  </main>

  <InitialPasswordPage v-else-if="session.password_setup_required" :csrf="session.csrf_token" :username="session.username" :signing-out="busy" @changed="passwordChanged" @expired="showError(new ApiError(401, 'Session expired'))" @logout="logout" />

  <div v-else class="app-layout">
    <aside class="sidebar">
      <a class="brand" href="#overview" @click.prevent="select('overview')"><span class="brand-mark"><Icon name="shield" :size="25" /></span><span>{{ BRAND_PARTS[0] }}<span class="brand-light">{{ BRAND_PARTS[1] }}</span></span></a>
      <div class="workspace">
        <span class="workspace-icon"><Icon name="server" /></span>
        <div class="workspace-details"><strong :title="instanceName">{{ instanceName }}</strong></div>
        <span class="workspace-badge">01</span>
      </div>
      <p class="nav-caption">{{ t('app.management') }}</p>
      <nav :aria-label="t('app.mainNavigation')"><button v-for="item in nav" :key="item.id" :class="['nav-item', { active: active === item.id }]" :aria-current="active === item.id ? 'page' : undefined" :disabled="changingPassword" @click="select(item.id)"><Icon :name="item.icon" />{{ item.title }}<span v-if="item.id === 'clients' && dashboard" class="nav-count">{{ formatNumber(dashboard.clients) }}</span></button></nav>
      <div class="sidebar-bottom"><div class="edition"><Icon name="shield" :size="18" /><span>{{ t('app.yourInfrastructure') }}<br><strong>{{ t('app.underYourControl') }}</strong></span></div><div class="sidebar-version"><span class="dot"></span>{{ PRODUCT_NAME }} <span v-if="appVersion">v{{ appVersion }}</span></div></div>
    </aside>
    <div class="main-column">
      <header class="topbar">
        <div class="breadcrumb"><span class="breadcrumb-root">{{ instanceName }} <Icon name="chevron" :size="14" /></span><span class="breadcrumb-page">{{ page.title }}</span></div>
        <div class="topbar-actions">
          <span class="data-refresh" :title="lastRefresh ? t('app.dataUpdated', { p0: formatDateTime(lastRefresh) }) : t('app.dataHasNotLoadedYet')"><Icon name="clock" :size="14" /><span class="data-refresh-label">{{ t('app.dataUpdated129') }}</span><time :datetime="lastRefresh?.toISOString()">{{ lastRefresh ? formatTime(lastRefresh) : '—' }}</time></span>
          <LanguageSwitcher />
          <button class="icon-button" :aria-label="dark ? t('app.lightTheme') : t('app.darkTheme')" @click="dark = !dark"><Icon name="sun" /></button>
          <div class="user-avatar">{{ session.username.slice(0, 1).toUpperCase() }}</div><span class="user-name">{{ session.username }}</span>
          <button class="icon-button" :aria-label="t('common.signOut')" :title="t('common.signOut')" :disabled="busy || changingPassword" @click="logout"><Icon name="logout" :size="18" /></button>
        </div>
      </header>
      <main class="content" :aria-busy="busy">
        <div class="page-heading"><div><p class="eyebrow muted">{{ PRODUCT_NAME.toUpperCase() }}</p><h1>{{ page.title }}</h1><p class="subtle">{{ page.description }}</p></div></div>

        <BootstrapPanel v-if="settings" :status="settings.bootstrap" :csrf="session.csrf_token" @refresh="refreshAfterMutation" />

        <template v-if="active === 'overview'">
          <section v-if="settings && settings.bootstrap.state !== 'ready'" class="welcome-banner"><div><span class="eyebrow">{{ t('app.startWITHTHEBASICS') }}</span><h2>{{ t('app.yourVPNUnderControl') }}</h2><p>{{ t('app.createClientsAndDevicesIssueProfiles') }}<br class="desktop-break"> {{ t('app.revokeCertificatesAndManageConnections') }}</p><button class="banner-link" @click="select('settings')">{{ t('app.viewConfiguration') }} <Icon name="arrow" :size="17" /></button></div><div class="banner-shield" aria-hidden="true"><Icon name="shield" :size="92" /></div></section>
          <div class="stats-grid"><article class="stat-card"><span class="stat-label">{{ t('app.clients') }}<Icon name="users" /></span><strong>{{ dashboard?.clients == null ? '—' : formatNumber(dashboard?.clients) }}</strong><span>{{ t('app.usersOnYourNetwork') }}</span></article><article class="stat-card"><span class="stat-label">{{ t('app.devices') }}<Icon name="server" /></span><strong>{{ dashboard?.devices == null ? '—' : formatNumber(dashboard?.devices) }}</strong><span>{{ t('app.individualVPNProfiles') }}</span></article><article class="stat-card"><span class="stat-label">{{ t('app.validCertificates') }}<Icon name="certificate" /></span><strong>{{ dashboard?.valid_certificates == null ? '—' : formatNumber(dashboard?.valid_certificates) }}</strong><span>{{ t('app.revokedExpired', { p0: dashboard?.revoked_certificates ?? '—', p1: dashboard?.expired_certificates ?? '—' }) }}</span></article><article class="stat-card"><span class="stat-label">{{ t('app.connections') }}<Icon name="activity" /></span><strong>{{ dashboard?.vpn.connected_clients == null ? '—' : formatNumber(dashboard?.vpn.connected_clients) }}</strong><span>{{ dashboard?.vpn.state === 'connected' ? t('app.activeVPNSessions') : t('app.managementInterfaceUnavailable') }}</span></article><article class="stat-card traffic-card"><span class="stat-label">{{ t('statistics.traffic') }}<Icon name="traffic" /></span><div class="traffic-legend">{{ t('statistics.trafficLegend') }}</div><div class="traffic-values"><div :title="t('statistics.todayUTC')"><span>{{ t('statistics.today') }}</span><strong><template v-if="dashboard?.statistics?.today">{{ formatBytes(dashboard.statistics.today.bytes_received) }} / {{ formatBytes(dashboard.statistics.today.bytes_sent) }}</template><template v-else>— / —</template></strong></div><div><span>{{ t('statistics.allTime') }}</span><strong><template v-if="dashboard?.statistics">{{ formatBytes(dashboard.statistics.bytes_received) }} / {{ formatBytes(dashboard.statistics.bytes_sent) }}</template><template v-else>— / —</template></strong></div></div></article></div>
          <div class="overview-grid"><section class="card"><div class="card-heading"><h2>{{ t('app.systemStatus') }}</h2><span :class="['pill', dashboard?.vpn.state === 'connected' ? 'success' : 'neutral']">{{ dashboard?.vpn.state === 'connected' ? t('app.serverAvailable') : t('app.checkOpenVPN') }}</span></div><div class="system-row"><span class="system-icon"><Icon name="lock" /></span><div><strong>{{ t('app.authentication') }}</strong><span>{{ t('app.sessionsCSRFProtectionAndSignInRate') }}</span></div><span class="pill success"><span class="dot"></span>{{ t('app.running') }}</span></div><div class="system-row"><span class="system-icon"><Icon name="database" /></span><div><strong>{{ t('app.sqliteStorage') }}</strong><span>{{ t('app.databaseInABindMount') }}</span></div><span class="pill success"><span class="dot"></span>{{ t('app.running') }}</span></div><div class="system-row"><span class="system-icon"><Icon name="server" /></span><div><strong>{{ t('app.openvpnServer') }}</strong><span>{{ dashboard?.vpn.version ? t('app.openvpnVersion', { version: dashboard.vpn.version }) : t('app.statusViaManagementInterface') }}</span></div><span :class="['pill', dashboard?.vpn.state === 'connected' ? 'success' : 'neutral']">{{ dashboard?.vpn.state === 'connected' ? t('app.connected') : t('app.unavailable') }}</span></div><div class="system-row"><span class="system-icon"><Icon name="server" /></span><div><strong>{{ t('dco.title') }}</strong><span v-if="dashboard?.vpn.dco?.kernel_release">{{ t('dco.kernel', { version: dashboard.vpn.dco.kernel_release }) }}</span></div><span :class="['pill', dashboard?.vpn.dco?.state === 'active' ? 'success' : 'neutral']">{{ dcoLabel(dashboard?.vpn.dco) }}</span></div><div class="system-row"><span class="system-icon"><Icon name="key" /></span><div><strong>{{ t('app.pkiManagement') }}</strong><span>{{ t('app.issueRevokeAndReissueCertificates') }}</span></div><span :class="['pill', settings?.capabilities.pki ? 'success' : 'neutral']">{{ settings?.capabilities.pki ? t('app.available') : t('app.unavailable159') }}</span></div><div class="system-row crl-status-row"><span class="system-icon"><Icon name="shield" /></span><div><strong>{{ t('crl.title') }}</strong><span>{{ crlDescription }}</span></div><span :class="['pill', crlTone]">{{ crlLabels[crlState] ?? t('crl.invalid') }}</span></div></section>
          <section class="card"><div class="card-heading"><h2>{{ t('app.recentActivity') }}</h2><button class="text-button" @click="select('audit')">{{ t('app.all') }} <Icon name="arrow" :size="15" /></button></div><div v-if="audit.length" class="timeline"><div v-for="event in audit.slice(0, 7)" :key="event.id" :class="['timeline-item', { 'critical-event': event.severity === 'CRITICAL', 'warning-event': event.severity === 'WARNING' }]"><span class="timeline-dot"></span><div><strong>{{ eventLabels[event.action] ?? event.action }}</strong><span>{{ auditActor(event.actor) }} · {{ dateTime(event.created_at) }}</span></div></div></div><div v-else class="compact-empty">{{ t('app.noEventsYet') }}</div></section></div>
          <ConnectionsPanel :connections="connections" :state="dashboard?.vpn.state ?? 'unavailable'" :csrf="session.csrf_token" @refresh="refreshAfterMutation" />
        </template>

        <AccountsPanel v-else-if="active === 'accounts'" :accounts="accounts" :csrf="session.csrf_token" @refresh="refreshAfterMutation" @expired="sessionExpired" @pending="changingPassword = $event" @signed-out="accountSignedOut" />
        <ClientManager v-else-if="active === 'clients' || active === 'certificates'" :section="active" :statistics-revision="statisticsRevision" :clients="clients" :devices="devices" :certificates="certificates" :operations="operations" :external-auth-available="settings?.capabilities.external_vpn_auth ?? false" :certificate-max-date="settings?.certificate_max_date" :csrf="session.csrf_token" :ready="settings?.capabilities.pki ?? false" @refresh="refreshAfterMutation" />

        <template v-else-if="active === 'settings'">
          <div v-if="settings" class="settings-grid"><VPNSettingsPanel :settings="settings" :csrf="session.csrf_token" @refresh="refreshAfterMutation" /></div>
        </template>

        <template v-else-if="active === 'panel-settings'">
          <PanelSettingsPanel v-if="panelSettings" :view="panelSettings" :csrf="session.csrf_token" @refresh="refreshAfterMutation" @updated="panelSettings = $event; dashboard && (dashboard.instance_name = $event.settings.instance_name)" />
        </template>

        <section v-else class="card list-card"><div class="list-toolbar"><h2>{{ t('app.activityLog') }}</h2><span class="subtle">{{ t('app.last100Events') }}</span></div><div v-if="!audit.length" class="empty-state"><span class="empty-icon"><Icon name="clock" :size="34" /></span><h3>{{ t('app.noActivityYet') }}</h3><p>{{ t('app.signInsAndAdministrativeActionsWillAppear') }}</p></div><div v-else class="table-scroll"><table><thead><tr><th>{{ t('app.event') }}</th><th>{{ t('app.severity') }}</th><th>{{ t('app.actor') }}</th><th>{{ t('app.target') }}</th><th>{{ t('app.time') }}</th></tr></thead><tbody><tr v-for="event in audit" :key="event.id" :class="{ 'critical-event': event.severity === 'CRITICAL', 'warning-event': event.severity === 'WARNING' }"><td>{{ eventLabels[event.action] ?? event.action }}</td><td><span :class="['pill', event.severity === 'CRITICAL' ? 'critical' : event.severity === 'WARNING' ? 'warning' : 'neutral']">{{ event.severity ?? 'INFO' }}</span></td><td>{{ auditActor(event.actor) }}</td><td>{{ event.target_name || event.target || '—' }}</td><td>{{ dateTime(event.created_at) }}</td></tr></tbody></table></div></section>

      </main>
    </div>
  </div>
</template>
