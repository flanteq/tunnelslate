<script setup lang="ts">
import { t, dateLocale, formatNumber } from './i18n'
import InfoNote from './InfoNote.vue'
import FloatingField from './FloatingField.vue'
import CertificateExpiryInput from './CertificateExpiryInput.vue'
import { certificateDate, certificateTerm, defaultCertificateDate } from './certificateDates'
import { computed, ref, watch } from 'vue'
import { api, ApiError, errorText, responseError } from './api'
import type { Client, Device, Certificate, Operation } from './api'
import Icon from './Icon.vue'
import DeviceCCDDialog from './DeviceCCDDialog.vue'
import ClientLinkDialog from './ClientLinkDialog.vue'
import ClientStatisticsDialog from './ClientStatisticsDialog.vue'
import VPNAuthDialog from './VPNAuthDialog.vue'
import { useClientList } from './useClientList'
import { usePagination } from './usePagination'
import TablePagination from './TablePagination.vue'
import { notifications } from './notifications'

const props = defineProps<{ section: string; statisticsRevision: number; clients: Client[]; devices: Device[]; certificates: Certificate[]; operations: Operation[]; csrf: string; ready: boolean; externalAuthAvailable: boolean; certificateMaxDate?: string }>()
const emit = defineEmits<{ refresh: [] }>()
const clientName = ref(''), deviceName = ref(''), selected = ref(''), query = ref('')
const certificateQuery = ref('')
const pending = ref(false)
const defaultExpiry = computed(() => defaultCertificateDate(new Date(), props.certificateMaxDate))
const deviceExpiresOn = ref(defaultExpiry.value), rotateExpiresOn = ref(defaultExpiry.value)
watch(defaultExpiry, (value, previous) => {
  // Update untouched defaults when CA metadata arrives; keep a manually chosen date.
  if (deviceExpiresOn.value === previous) deviceExpiresOn.value = value
  if (rotateExpiresOn.value === previous) rotateExpiresOn.value = value
})
const rotating = computed(() => confirmation.value?.path.endsWith('/rotate') ?? false)
const viewingStatistics = ref<Client | null>(null)
const editingLink = ref<Client | null>(null)
const editingCCD = ref<Device | null>(null)
const editingAuth = ref<{id: string; name: string} | null>(null)
const dialog = ref<HTMLDialogElement | null>(null)
const confirmation = ref<{ path: string; title: () => string; message: () => string } | null>(null)
const keys = new Map<string, string>()
const { page, pageSize, sortedClients, matchingClients, pageCount, visibleClients } = useClientList(() => props.clients, query)
const listHeading = ref<HTMLElement | null>(null)
function goToPage(value: number) {
  page.value = Math.max(1, Math.min(value, pageCount.value))
  listHeading.value?.scrollIntoView({ block: 'start' })
}
function setClientPageSize(value: number) {
  pageSize.value = value
  listHeading.value?.scrollIntoView({ block: 'start' })
}
const matchingCerts = computed(() => props.certificates.filter(c => `${c.client} ${c.device} ${c.serial}`.toLocaleLowerCase(dateLocale.value).includes(certificateQuery.value.trim().toLocaleLowerCase(dateLocale.value))))
const certificatePages = usePagination(() => matchingCerts.value, certificateQuery)
const operationPages = usePagination(() => props.operations)
const certificateHeading = ref<HTMLElement | null>(null)
const operationHeading = ref<HTMLElement | null>(null)
function goToCertificatePage(value: number) {
  certificatePages.page.value = Math.max(1, Math.min(value, certificatePages.pageCount.value))
  certificateHeading.value?.scrollIntoView({ block: 'start' })
}
function goToOperationPage(value: number) {
  operationPages.page.value = Math.max(1, Math.min(value, operationPages.pageCount.value))
  operationHeading.value?.scrollIntoView({ block: 'start' })
}
function setCertificatePageSize(value: number) {
  certificatePages.pageSize.value = value
  certificateHeading.value?.scrollIntoView({ block: 'start' })
}
function setOperationPageSize(value: number) {
  operationPages.pageSize.value = value
  operationHeading.value?.scrollIntoView({ block: 'start' })
}
const unfinished = computed(() => props.operations.filter(op => ['pending', 'running', 'partial'].includes(op.state)))
const activeOperation = (op: Operation) => ['pending', 'running', 'partial'].includes(op.state)
const clientDeletion = (id: string) => props.operations.find(op => ['delete_client', 'revoke_client'].includes(op.kind) && op.client_id === id && activeOperation(op))
const clientDeleting = (id: string) => props.clients.some(c => c.id === id && c.revocation_pending) || !!clientDeletion(id) || props.devices.some(d => d.client_id === id && ['delete_client', 'revoke_client'].includes(d.operation_kind) && ['pending', 'running', 'partial'].includes(d.operation_state))
const clientBusy = (id: string) => clientDeleting(id) || props.operations.some(op => activeOperation(op) && (op.client_id === id || props.devices.some(d => d.id === op.device_id && d.client_id === id)))
watch(() => props.clients, values => { if (selected.value && !values.some(c => c.id === selected.value)) selected.value = '' })
watch(() => props.devices, values => { if (editingCCD.value && !values.some(d => d.id === editingCCD.value?.id)) editingCCD.value = null })
const stateLabels = computed((): Record<string, string> => ({ valid: t('common.valid'), revoked: t('common.revoked'), expired: t('common.expired'), pending: t('clients.pending'), running: t('clients.running'), partial: t('clients.needsAttention'), succeeded: t('clients.completed'), failed: t('clients.cancelled') }))
const stepLabels = computed((): Record<string, string> => ({ queued: t('clients.queued'), issue_certificate: t('clients.issuingCertificate'), revoke_certificate: t('clients.revokingCertificate'), publish_crl: t('clients.publishingCRL'), publish_ccd: t('clients.publishingDeviceSettings'), disconnect_sessions: t('clients.disconnectingSessions'), delete_profile: t('clients.deletingProfile'), delete_client: t('clients.deletingClientAndProfiles'), complete: t('clients.completed216'), certificate_expired: t('clients.issuanceDeadlineExpired'), cancelled: t('clients.cancelledAfterLinkCompromise') }))
const kindLabels = computed((): Record<string, string> => ({ issue: t('clients.issue'), rotate: t('clients.reissue'), revoke: t('clients.revoke'), delete: t('clients.deletingProfile'), delete_client: t('clients.deleteClient'), revoke_client: t('clients.emergencyClientRevocation') }))
const runningLabels = computed((): Record<string, string> => ({ issue: t('clients.issuing'), rotate: t('clients.reissuing'), revoke: t('clients.revoking'), delete: t('clients.deleting'), delete_client: t('clients.deletingClient'), revoke_client: t('clients.revokingAllProfiles') }))
const pendingLabels = computed((): Record<string, string> => ({ issue: t('common.awaitingIssuance'), rotate: t('clients.awaitingReissue'), revoke: t('clients.awaitingRevocation'), delete: t('clients.awaitingDeletion'), delete_client: t('clients.awaitingClientDeletion'), revoke_client: t('clients.awaitingEmergencyRevocation') }))
function operationStatus(kind: string, state: string) {
  if (state === 'running') return runningLabels.value[kind] ?? stateLabels.value[state]
  if (state === 'pending') return pendingLabels.value[kind] ?? stateLabels.value[state]
  return stateLabels.value[state] ?? state
}
function deviceStatus(device: Device) {
  if (['delete_client', 'revoke_client'].includes(device.operation_kind) && ['pending', 'running', 'partial'].includes(device.operation_state)) return operationStatus(device.operation_kind, device.operation_state)
  const parent = clientDeletion(device.client_id)
  if (parent) return operationStatus(parent.kind, parent.state)
  if (['pending', 'running', 'partial'].includes(device.operation_state)) return operationStatus(device.operation_kind, device.operation_state)
  return stateLabels.value[device.status] ?? device.status
}
const deviceBusy = (device: Device) => ['pending', 'running', 'partial'].includes(device.operation_state) || clientDeleting(device.client_id)
function ask(path: string, title: () => string, message: () => string) { rotateExpiresOn.value = defaultCertificateDate(new Date(), props.certificateMaxDate); confirmation.value = { path, title, message }; dialog.value?.showModal() }
async function mutate(path: string, body: unknown = {}) {
  pending.value = true
  const fingerprint = path + JSON.stringify(body)
  const key = keys.get(fingerprint) ?? crypto.randomUUID()
  keys.set(fingerprint, key)
  try {
    const response = await api(path, { method: 'POST', headers: { 'X-CSRF-Token': props.csrf, 'Idempotency-Key': key }, body: JSON.stringify(body) })
    keys.delete(fingerprint)
    return response
  } catch (err) {
    notifications.error(() => errorText(err, t('clients.theOperationCouldNotBeCompleted')))
    if (err instanceof ApiError && err.status < 500) keys.delete(fingerprint)
    return null
  } finally { pending.value = false; emit('refresh') }
}
async function createClient() {
  const result = await mutate('/clients', { name: clientName.value }) as Client | null
  if (result) { selected.value = result.id; clientName.value = '' }
}
async function createDevice() {
  if (!selected.value) return
  if (await mutate(`/clients/${selected.value}/devices`, { name: deviceName.value, expires_on: deviceExpiresOn.value || defaultCertificateDate(new Date(), props.certificateMaxDate) })) { deviceName.value = ''; deviceExpiresOn.value = defaultCertificateDate(new Date(), props.certificateMaxDate) }
}
async function confirm() {
  const action = confirmation.value
  const body = rotating.value ? { expires_on: rotateExpiresOn.value || defaultCertificateDate(new Date(), props.certificateMaxDate) } : {}
  dialog.value?.close(); confirmation.value = null
  if (action) await mutate(action.path, body)
}
async function download(device: Device) {
  pending.value = true
  try {
    const response = await fetch(new URL(`api/devices/${device.id}/profile`, document.baseURI), { credentials: 'same-origin' })
    if (!response.ok) { const body = await response.json().catch(() => ({})); throw responseError(response.status, body) }
    // Use metadata from the downloaded certificate, including after a reissue
    // that has not yet reached the device list through SSE.
    const disposition = response.headers.get('Content-Disposition') ?? ''
    const encodedName = disposition.match(/filename\*=utf-8''([^;]+)/i)?.[1]
    const plainName = disposition.match(/filename=(?:"([^"]+)"|([^;]+))/i)
    let filename = plainName?.[1] ?? plainName?.[2]?.trim() ?? 'openvpn.ovpn'
    if (encodedName) { try { filename = decodeURIComponent(encodedName) } catch { /* Use the plain fallback. */ } }
    const url = URL.createObjectURL(await response.blob())
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch (err) { notifications.error(() => errorText(err, t('clients.couldNotDownloadTheProfile'))) }
  finally { pending.value = false; emit('refresh') }
}
</script>

<template>
  <div class="client-manager" :aria-busy="pending">
    <div v-if="!ready" class="alert info"><Icon name="info" />{{ t('clients.pkiIsUnavailableCheckInitializationAndThe') }}</div>
    <template v-if="section === 'clients'">
      <div class="management-forms">
        <form class="card management-form client-create-form" @submit.prevent="createClient">
          <div class="card-heading"><h2>{{ t('clients.newClient') }}</h2></div>
          <InfoNote class="card-description">{{ t('clients.aClientCanHaveMultipleDevicesEach') }}</InfoNote>
          <div class="card-body form-fields">
            <div class="form-row"><FloatingField id="client-name" :label="t('clients.name')"><input id="client-name" v-model="clientName" required maxlength="128" :placeholder="t('clients.forExampleAlex')"></FloatingField><button class="button primary" :disabled="pending" type="submit">{{ t('clients.createClient') }}</button></div>
          </div>
        </form>
        <form class="card management-form device-create-form" @submit.prevent="createDevice">
          <div class="card-heading"><h2>{{ t('clients.newDevice') }}</h2></div>
          <div class="card-body form-fields">
            <FloatingField id="device-owner" :label="t('clients.client')" fixed><select id="device-owner" v-model="selected" required><option disabled value="">{{ t('clients.selectAClient') }}</option><option v-for="client in sortedClients" :key="client.id" :value="client.id" :disabled="clientDeleting(client.id)">{{ client.name }}</option></select></FloatingField>
            <div class="device-create-fields">
              <FloatingField id="device-name" :label="t('clients.deviceName')"><input id="device-name" v-model="deviceName" required maxlength="128" :placeholder="t('clients.forExampleMacBook')"></FloatingField>
              <CertificateExpiryInput id="device-expires-on" v-model="deviceExpiresOn" :max="certificateMaxDate" />
            </div>
            <button class="button primary" :disabled="pending || !ready || !selected || clientDeleting(selected)" type="submit">{{ t('clients.issueProfile') }}</button>
          </div>
        </form>
      </div>
      <div ref="listHeading" class="section-toolbar"><h2>{{ t('clients.clientsAndDevices') }} <span class="count-label">{{ formatNumber(clients.length) }}</span></h2><input v-model="query" type="search" :aria-label="t('clients.searchClients')" :placeholder="t('clients.findAClient')"></div>
      <div v-if="!clients.length" class="card empty-state"><span class="empty-icon"><Icon name="users" :size="34" /></span><h3>{{ t('clients.addYourFirstClient') }}</h3><p>{{ t('clients.thenCreateADeviceAndDownloadIts') }}</p></div>
      <section v-for="client in visibleClients" :key="client.id" class="card client-card"><div class="card-heading"><div class="client-heading"><h2>{{ client.name }}</h2><span v-if="client.external_auth" :class="['pill', client.auth_provider_enabled ? 'success' : 'warning']"><Icon name="lock" :size="12" />{{ client.auth_provider_enabled ? t('vpnAuth.clientExternalAuth') : t('vpnAuth.clientProviderDisabled') }}</span></div><div class="client-actions"><button class="text-button" @click="viewingStatistics = client">{{ t('statistics.button') }}</button><button v-if="externalAuthAvailable" class="text-button" :disabled="pending || clientBusy(client.id)" @click="editingAuth = {id:client.id, name:client.name}">{{ t('vpnAuth.accessButton') }}</button><button class="text-button" :disabled="pending || clientDeleting(client.id)" @click="editingLink = client">{{ client.link_created_at ? t('clients.profileLink') : t('common.createLink') }}</button><button class="text-button" :disabled="pending || clientDeleting(client.id)" @click="selected = client.id">{{ t('clients.addDevice') }} <Icon name="arrow" :size="15" /></button><button class="text-button danger" :disabled="pending || clientBusy(client.id)" @click="ask(`/clients/${client.id}/delete`, () => t('clients.deleteClient258'), () => t('clients.allCertificatesForWillBeRevokedAnd', { p0: client.name }))">{{ t('clients.deleteClient260') }}</button></div></div>
        <div v-if="!devices.some(d => d.client_id === client.id)" class="compact-empty">{{ t('clients.noDevicesYet') }}</div>
        <div v-else class="table-scroll"><table><thead><tr><th>{{ t('clients.device') }}</th><th>{{ t('clients.certificate') }}</th><th>{{ t('clients.expirationRevocation') }}</th><th>{{ t('common.actions') }}</th></tr></thead><tbody><tr v-for="device in devices.filter(d => d.client_id === client.id)" :key="device.id"><td><strong>{{ device.name }}</strong><span v-if="device.custom_ccd || device.ccd_pending" class="device-ccd-summary">{{ device.ccd_pending ? t('clients.ccdPublicationPending') : device.static_ip ? `IP: ${device.static_ip}` : t('clients.customSettings') }}</span></td><td><span :class="['pill', deviceBusy(device) ? 'neutral' : device.status === 'valid' ? 'success' : 'neutral']">{{ deviceStatus(device) }}</span></td><td>{{ certificateTerm(device) }}</td><td class="actions-cell"><button class="text-button" :disabled="pending || deviceBusy(device)" @click="editingCCD = device">{{ t('clients.vpnSettings') }}</button><button class="button secondary" :disabled="pending || deviceBusy(device) || device.status !== 'valid'" @click="download(device)">{{ t('common.downloadOvpn') }}</button><button class="text-button" :disabled="pending || deviceBusy(device) || !ready" @click="ask(`/devices/${device.id}/rotate`, () => t('clients.reissueProfile'), () => t('clients.theDeviceWillReceiveANewKey', { p0: device.name }))">{{ t('clients.reissue271') }}</button><button class="text-button danger" :disabled="pending || deviceBusy(device) || device.status === 'revoked' || !device.serial" @click="ask(`/certificates/${device.serial}/revoke`, () => t('clients.revokeCertificate'), () => t('clients.theDeviceWillLoseAccessANew', { p0: device.name }))">{{ t('clients.revoke274') }}</button><button class="text-button danger" :disabled="pending || deviceBusy(device) || !ready" @click="ask(`/devices/${device.id}/delete`, () => t('clients.deleteProfile'), () => t('clients.allCertificatesForWillBeRevokedAnd276', { p0: device.name }))">{{ t('common.delete') }}</button></td></tr></tbody></table></div>
      </section>
      <div v-if="clients.length && !visibleClients.length" class="compact-empty"><p>{{ t('clients.nothingFound') }}</p></div>
      <TablePagination v-if="clients.length" class="card" :page="page" :page-size="pageSize" :total="matchingClients.length" :label="t('clients.clientPages')" @update:page="goToPage" @update:page-size="setClientPageSize" />
    </template>
    <section v-else class="card"><div ref="certificateHeading" class="list-toolbar"><h2>{{ t('clients.certificateHistory') }} <span class="count-label">{{ formatNumber(certificates.length) }}</span></h2><input v-model="certificateQuery" type="search" :aria-label="t('clients.searchCertificates')" :placeholder="t('clients.clientDeviceOrSerial')"></div><div v-if="!certificates.length" class="empty-state"><span class="empty-icon"><Icon name="certificate" :size="34" /></span><h3>{{ t('clients.noCertificatesYet') }}</h3><p>{{ t('clients.createADeviceInTheClientsSection') }}</p></div><div v-else-if="!matchingCerts.length" class="compact-empty">{{ t('clients.nothingFound') }}</div><div v-else class="table-scroll"><table><thead><tr><th>{{ t('clients.client') }}</th><th>{{ t('clients.device') }}</th><th>Serial</th><th>{{ t('clients.status') }}</th><th>{{ t('clients.expiration') }}</th><th>{{ t('common.revoked') }}</th><th>{{ t('common.actions') }}</th></tr></thead><tbody><tr v-for="cert in certificatePages.items.value" :key="cert.serial"><td>{{ cert.client }}</td><td>{{ cert.device }}</td><td><code>{{ cert.serial }}</code></td><td><span :class="['pill', cert.status === 'valid' ? 'success' : 'neutral']">{{ stateLabels[cert.status] }}</span></td><td>{{ certificateDate(cert.not_after) }}</td><td>{{ certificateDate(cert.revoked_at) }}</td><td><button class="text-button danger" :disabled="pending || cert.status === 'revoked' || clientDeleting(cert.client_id)" @click="ask(`/certificates/${cert.serial}/revoke`, () => t('clients.revokeThisCertificate'), () => t('clients.thisCertificateWillBecomeInvalidOtherDevices'))">{{ t('clients.revoke274') }}</button></td></tr></tbody></table></div><TablePagination v-if="certificates.length" :page="certificatePages.page.value" :page-size="certificatePages.pageSize.value" :total="matchingCerts.length" :label="t('clients.certificateHistoryPages')" @update:page="goToCertificatePage" @update:page-size="setCertificatePageSize" /></section>
    <section v-if="section === 'certificates' && operations.length" class="card operations-card"><div ref="operationHeading" class="card-heading"><h2>{{ t('clients.certificateOperations') }}</h2><span :class="['pill', unfinished.length ? 'neutral' : 'success']">{{ unfinished.length ? t('clients.needAttention', { p0: unfinished.length }) : t('clients.allCompleted') }}</span></div><InfoNote class="card-description">{{ t('clients.unfinishedOperationsResumeAutomaticallyIncludingAfterThe') }}</InfoNote><div class="table-scroll"><table><thead><tr><th>{{ t('clients.operation') }}</th><th>{{ t('common.clientDevice') }}</th><th>{{ t('clients.statusStep') }}</th><th>{{ t('clients.action') }}</th></tr></thead><tbody><tr v-for="operation in operationPages.items.value" :key="operation.id"><td>{{ kindLabels[operation.kind] ?? operation.kind }}</td><td>{{ operation.device_name ?? operation.client_name ?? devices.find(d => d.id === operation.device_id)?.name ?? operation.device_id }}</td><td><strong>{{ operationStatus(operation.kind, operation.state) }}</strong><span class="operation-detail">{{ stepLabels[operation.step] ?? operation.step }}</span><details v-if="operation.error" class="technical-details operation-error"><summary>{{ t('diagnostics.details') }}</summary><pre>{{ operation.error }}</pre></details></td><td><button v-if="activeOperation(operation)" class="button secondary" :disabled="pending" @click="mutate(`/operations/${operation.id}/retry`)">{{ t('clients.retryOperation') }}</button><Icon v-else-if="operation.state === 'succeeded'" name="check" /></td></tr></tbody></table></div><TablePagination :page="operationPages.page.value" :page-size="operationPages.pageSize.value" :total="operations.length" :label="t('clients.certificateOperationPages')" @update:page="goToOperationPage" @update:page-size="setOperationPageSize" /></section>
    <ClientStatisticsDialog v-if="viewingStatistics" :client="viewingStatistics" :revision="statisticsRevision" @close="viewingStatistics = null" />
    <VPNAuthDialog v-if="editingAuth" :subject="editingAuth" :csrf="csrf" @close="editingAuth=null" @refresh="emit('refresh')" />
    <ClientLinkDialog v-if="editingLink" :client="clients.find(c => c.id === editingLink?.id) ?? editingLink" :csrf="csrf" @close="editingLink = null" @refresh="emit('refresh')" />
    <DeviceCCDDialog v-if="editingCCD" :key="editingCCD.id" :device="devices.find(d => d.id === editingCCD?.id) ?? editingCCD" :csrf="csrf" @close="editingCCD = null" @refresh="emit('refresh')" />
    <dialog ref="dialog" class="confirmation-dialog" @cancel="confirmation = null"><form @submit.prevent="confirm"><div class="card-heading"><h2>{{ confirmation?.title() }}</h2></div><div class="card-body form-fields dialog-copy"><p>{{ confirmation?.message() }}</p><CertificateExpiryInput v-if="rotating" id="rotate-expires-on" v-model="rotateExpiresOn" :max="certificateMaxDate" /></div><div class="card-actions"><button class="button secondary" type="button" @click="dialog?.close(); confirmation = null">{{ t('common.cancel') }}</button><button class="button primary" type="submit">{{ t('common.confirm') }}</button></div></form></dialog>
  </div>
</template>
