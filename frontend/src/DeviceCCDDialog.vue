<script setup lang="ts">
import FloatingField from './FloatingField.vue'
import { t } from './i18n'
import InfoNote from './InfoNote.vue'
import { computed, nextTick, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import { api, ApiError, errorText } from './api'
import type { CCDSettings, CCDView, Device } from './api'
import Icon from './Icon.vue'
import { notifications } from './notifications'

const props = defineProps<{ device: Pick<Device, 'id' | 'name' | 'ccd_pending'>; csrf: string }>()
const emit = defineEmits<{ close: []; refresh: [] }>()
const dialog = ref<HTMLDialogElement | null>(null)
const view = ref<CCDView | null>(null)
const form = ref<CCDSettings | null>(null)
type Tab = 'address' | 'dns' | 'routes' | 'access'
const tabs: Tab[] = ['address', 'dns', 'routes', 'access']
const tab = ref<Tab>('address')
const tabLabels = computed(() => ({ address: t('ccd.tabAddress'), dns: t('ccd.tabDNS'), routes: t('ccd.tabRoutes'), access: t('network.tab') }))
const formElement = ref<HTMLFormElement | null>(null)
const body = ref<HTMLElement | null>(null)
watch(tab, () => nextTick(() => body.value?.scrollTo(0, 0)))
function moveTab(event: KeyboardEvent) {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const direction = event.key === 'ArrowLeft' ? -1 : 1
  tab.value = event.key === 'Home' ? tabs[0]! : event.key === 'End' ? tabs[tabs.length - 1]! : tabs[(tabs.indexOf(tab.value) + direction + tabs.length) % tabs.length]!
  document.getElementById(`ccd-tab-${tab.value}`)?.focus()
}
const fixed = ref(false)
const dnsSearch = ref('')
const allowedNetworks = ref(''), siteNetworks = ref('')
const busy = ref(false)
const loading = ref(true)
const loadError = ref(false)
const conflict = ref(false)
const original = ref('')
const controller = new AbortController()
const dirty = computed(() => !!form.value && original.value !== JSON.stringify(payload()))
watch(() => props.device.ccd_pending, pending => {
  if (!pending && view.value && !view.value.published && !dirty.value && !busy.value && !loading.value) void load()
})

function payload(): CCDSettings {
  const value = form.value!
  return {
    ...value,
    allowed_networks: value.access_mode === 'restricted' ? allowedNetworks.value.split(/[\s,]+/).filter(Boolean) : [],
    site_networks: siteNetworks.value.split(/[\s,]+/).filter(Boolean),
    dns_domain: value.dns_domains_mode === 'custom' ? value.dns_domain.trim() : '',
    dns_search: value.dns_domains_mode === 'custom' ? dnsSearch.value.split(/[\s,]+/).filter(Boolean) : [],
    static_ip: fixed.value ? value.static_ip.trim() : '',
    dns: value.dns_mode === 'custom' ? value.dns.map(v => v.trim()) : [],
    routes: value.routes_mode === 'custom' ? value.routes.map(v => v.trim()) : [],
  }
}
function populate(value: CCDView) {
  view.value = value
  form.value = { ...value.settings, dns: [...value.settings.dns], routes: [...value.settings.routes] }
  allowedNetworks.value = value.settings.allowed_networks.join('\n'); siteNetworks.value = value.settings.site_networks.join('\n')
  dnsSearch.value = value.settings.dns_search.join('\n')
  fixed.value = !!value.settings.static_ip
  original.value = JSON.stringify(payload())
  if (!form.value.dns.length) form.value.dns = ['']
  conflict.value = false
}
async function load() {
  loading.value = true; loadError.value = false
  try { populate(await api<CCDView>(`/devices/${props.device.id}/ccd`, { signal: controller.signal })) }
  catch (err) {
    if (!controller.signal.aborted) {
      loadError.value = true
      notifications.error(() => errorText(err, t('ccd.couldNotLoadDeviceSettings')))
    }
  } finally { loading.value = false }
}
async function save() {
  if (!form.value || !view.value) return
  const invalid = formElement.value?.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>('input:invalid, select:invalid, textarea:invalid')
  if (invalid) {
    const target = invalid.closest<HTMLElement>('[role="tabpanel"]')?.dataset.tab as Tab | undefined
    if (target) tab.value = target
    await nextTick()
    invalid.focus(); invalid.reportValidity()
    return
  }
  busy.value = true
  try {
    populate(await api<CCDView>(`/devices/${props.device.id}/ccd`, {
      method: 'PUT', headers: { 'X-CSRF-Token': props.csrf },
      body: JSON.stringify({ settings: payload(), vpn_revision: view.value.vpn.revision }),
    }))
  } catch (err) {
    notifications.error(() => errorText(err, t('ccd.couldNotSaveDeviceSettings')))
    if (err instanceof ApiError && err.status === 409) conflict.value = true
    // A 503 can mean the desired settings were committed. Reload the saved
    // revision so the publication status and a subsequent save remain accurate.
    if (err instanceof ApiError && err.status === 503) await load()
  } finally { busy.value = false; emit('refresh') }
}
function reset() {
  if (!form.value) return
  fixed.value = false
  form.value.access_mode = 'all'; allowedNetworks.value = ''; siteNetworks.value = ''
  form.value.dns_domains_mode = 'inherit'; form.value.dns_mode = 'inherit'; form.value.routes_mode = 'inherit'; form.value.tunnel_mode = 'inherit'
}
function close() { if (!busy.value) { dialog.value?.close(); emit('close') } }
onMounted(() => { dialog.value?.showModal(); void load() })
onBeforeUnmount(() => controller.abort())
</script>

<template>
  <dialog ref="dialog" class="ccd-dialog device-ccd-dialog" aria-labelledby="ccd-title" @cancel.prevent="close">
    <div class="ccd-dialog-heading"><div><h2 id="ccd-title">{{ t('ccd.deviceSettings') }}</h2><p>{{ device.name }}</p></div><button class="icon-button" type="button" :aria-label="t('ccd.closeDeviceSettings')" :disabled="busy" @click="close"><Icon name="close" :size="18" /></button></div>
    <div v-if="loading" class="ccd-loading" role="status"><p>{{ t('ccd.loadingSettings') }}</p></div>
    <div v-else-if="loadError" class="ccd-loading"><p>{{ t('ccd.couldNotLoadSettings') }}</p><button class="button secondary" @click="load">{{ t('ccd.retry') }}</button></div>
    <form v-else-if="form && view" ref="formElement" novalidate @submit.prevent="save">
      <InfoNote class="card-description">{{ t('ccd.settingsTakeEffectAfterTheDeviceReconnects') }}</InfoNote>
      <div class="vpn-settings-tabs device-ccd-tabs" role="tablist" :aria-label="t('ccd.deviceSettings')" @keydown="moveTab">
        <button v-for="name in tabs" :id="`ccd-tab-${name}`" :key="name" class="vpn-settings-tab" type="button" role="tab" :aria-selected="tab === name" :aria-controls="`ccd-panel-${name}`" :tabindex="tab === name ? 0 : -1" :disabled="busy" @click="tab = name">{{ tabLabels[name] }}</button>
      </div>
      <fieldset :disabled="busy">
        <div ref="body" class="card-body form-fields device-ccd-body">
        <div v-if="!view.published" class="alert info"><Icon name="info" :size="16" /><div>{{ t('ccd.settingsWereSavedPublicationIsStillPending') }}<details v-if="view.publication_error" class="technical-details ccd-publication-error"><summary>{{ t('diagnostics.details') }}</summary><pre>{{ view.publication_error }}</pre></details></div></div>
        <div v-show="tab === 'address'" id="ccd-panel-address" data-tab="address" role="tabpanel" aria-labelledby="ccd-tab-address">
        <section class="ccd-section">
          <h3>{{ t('ccd.vpnAddress') }}</h3>
          <InfoNote class="field-help">{{ t('ccd.theLowerHalfOfTheSubnetIs') }}</InfoNote>
          <FloatingField id="ccd-address-mode" :label="t('ccd.addressAssignment')" fixed><select id="ccd-address-mode" v-model="fixed"><option :value="false">{{ t('ccd.automatic') }}</option><option :value="true">{{ t('ccd.staticAddress') }}</option></select></FloatingField>
          <template v-if="fixed"><FloatingField id="ccd-ip" :label="t('ccd.staticIPv4Address')"><input id="ccd-ip" v-model="form.static_ip" required maxlength="15" :placeholder="view.static_range.start" autocomplete="off"></FloatingField><InfoNote class="field-help">{{ t('ccd.availableRange', { p0: view.static_range.start, p1: view.static_range.end }) }}</InfoNote></template>
          <InfoNote v-else class="field-help">{{ t('ccd.dynamicRange', { p0: view.dynamic_range.start, p1: view.dynamic_range.end }) }}</InfoNote>
        </section>
        </div>
        <div v-show="tab === 'dns'" id="ccd-panel-dns" data-tab="dns" role="tabpanel" aria-labelledby="ccd-tab-dns">
        <section class="ccd-section">
          <h3>{{ t('ccd.dnsServers') }}</h3>
          <InfoNote class="field-help">{{ t('ccd.inheritServerDNSSettingsOrSpecifyUp') }}</InfoNote>
          <FloatingField id="ccd-dns-mode" :label="t('ccd.dnsSettings')" fixed><select id="ccd-dns-mode" v-model="form.dns_mode"><option value="inherit">{{ t('ccd.inheritServerSettings') }}</option><option value="custom">{{ t('ccd.customDNS') }}</option></select></FloatingField>
          <InfoNote v-if="form.dns_mode === 'inherit'" class="field-help">{{ t('ccd.current', { p0: view.vpn.dns.join(', ') }) }}</InfoNote>
          <template v-else>
            <div v-for="(_, i) in form.dns" :key="i" class="ccd-field-row"><FloatingField :id="`ccd-dns-${i}`" :label="t('ccd.dnsServer', { p0: i + 1 })"><input :id="`ccd-dns-${i}`" v-model="form.dns[i]" required maxlength="15" :placeholder="t('ccd.dnsIPv4Address')" autocomplete="off"></FloatingField><button class="icon-button" type="button" :disabled="form.dns.length === 1" :aria-label="t('ccd.removeDNSServer', { p0: i + 1 })" @click="form.dns.splice(i, 1)"><Icon name="close" :size="16" /></button></div>
            <button class="text-button" type="button" :disabled="form.dns.length >= 8" @click="form.dns.push('')">{{ t('ccd.addDNSServer') }}</button>
          </template>
        </section>
        <section class="ccd-section">
          <h3>{{ t('ccd.dnsDomainsMode') }}</h3>
          <FloatingField id="ccd-dns-domains-mode" :label="t('ccd.dnsDomainsMode')" fixed><select id="ccd-dns-domains-mode" v-model="form.dns_domains_mode"><option value="inherit">{{ t('ccd.inheritServerSettings') }}</option><option value="custom">{{ t('ccd.customDNSDomains') }}</option></select></FloatingField>
          <InfoNote v-if="form.dns_domains_mode === 'inherit'" class="field-help">{{ [view.vpn.dns_domain, ...view.vpn.dns_search].filter(Boolean).join(', ') || t('ccd.noDNSDomains') }}</InfoNote>
          <template v-else>
            <FloatingField id="ccd-dns-domain" :label="t('vpn.dnsDomain')"><input id="ccd-dns-domain" v-model="form.dns_domain" maxlength="253" placeholder="office.example.com" autocomplete="off"></FloatingField>
            <FloatingField id="ccd-dns-search" :label="t('vpn.dnsSearch')" fixed><textarea id="ccd-dns-search" v-model="dnsSearch" rows="2" placeholder="office.example.com"></textarea></FloatingField>
            <InfoNote class="field-help">{{ t('vpn.dnsDomainsHelp') }}</InfoNote>
          </template>
        </section>
        </div>
        <div v-show="tab === 'routes'" id="ccd-panel-routes" data-tab="routes" role="tabpanel" aria-labelledby="ccd-tab-routes">
        <section class="ccd-section">
          <h3>{{ t('common.routing') }}</h3>
          <InfoNote class="field-help">{{ t('ccd.inheritServerSettingsOrSpecifyUpTo') }}</InfoNote>
          <FloatingField id="ccd-tunnel-mode" :label="t('ccd.trafficThroughVPN')" fixed><select id="ccd-tunnel-mode" v-model="form.tunnel_mode"><option value="inherit">{{ t('ccd.inheritServerMode', { p0: view.vpn.redirect_gateway ? 'Full tunnel' : 'Split tunnel' }) }}</option><option value="split">{{ t('common.splitTunnelSelectedNetworks') }}</option><option value="full">{{ t('common.fullTunnelAllIPv4Traffic') }}</option></select></FloatingField>
          <FloatingField id="ccd-routes-mode" :label="t('ccd.additionalNetworks')" fixed><select id="ccd-routes-mode" v-model="form.routes_mode"><option value="inherit">{{ t('ccd.inheritServerRoutes') }}</option><option value="custom">{{ t('ccd.replaceSharedRoutesWithACustomList') }}</option></select></FloatingField>
          <InfoNote v-if="form.routes_mode === 'inherit'" class="field-help">{{ view.vpn.routes.length ? view.vpn.routes.join(', ') : t('ccd.noSharedAdditionalRoutesAreConfigured') }}</InfoNote>
          <template v-else>
            <div v-for="(_, i) in form.routes" :key="i" class="ccd-field-row"><FloatingField :id="`ccd-route-${i}`" :label="t('ccd.networkInCIDRNotation', { p0: i + 1 })"><input :id="`ccd-route-${i}`" v-model="form.routes[i]" required maxlength="18" placeholder="192.0.2.0/24" autocomplete="off"></FloatingField><button class="icon-button" type="button" :aria-label="t('ccd.removeRoute', { p0: i + 1 })" @click="form.routes.splice(i, 1)"><Icon name="close" :size="16" /></button></div>
            <button class="text-button" type="button" :disabled="form.routes.length >= 32" @click="form.routes.push('')">{{ t('ccd.addNetwork') }}</button>
          </template>
        </section>
        </div>
        <div v-show="tab === 'access'" id="ccd-panel-access" data-tab="access" role="tabpanel" aria-labelledby="ccd-tab-access">
        <section class="ccd-section">
          <h3>{{ t('network.tab') }}</h3>
          <InfoNote class="field-help">{{ t('network.deviceHelp') }}</InfoNote>
          <FloatingField id="ccd-access-mode" :label="t('network.accessMode')" fixed><select id="ccd-access-mode" v-model="form.access_mode"><option value="all">{{ t('network.unrestricted') }}</option><option value="restricted">{{ t('network.restricted') }}</option></select></FloatingField>
          <template v-if="form.access_mode === 'restricted'"><FloatingField id="ccd-allowed-networks" :label="t('network.allowedNetworks')" fixed><textarea id="ccd-allowed-networks" v-model="allowedNetworks" rows="3" placeholder="192.0.2.10/32&#10;198.51.100.0/24"></textarea></FloatingField><InfoNote class="field-help">{{ t('network.accessHelp') }}</InfoNote></template>
          <FloatingField id="ccd-site-networks" :label="t('network.siteNetworks')" fixed><textarea id="ccd-site-networks" v-model="siteNetworks" rows="3" placeholder="192.168.20.0/24"></textarea></FloatingField>
          <InfoNote class="field-help">{{ t('network.routerHelp') }}</InfoNote>
          <InfoNote v-if="siteNetworks.trim() && !view.vpn.site_to_site" class="field-help">{{ t('network.sitesDisabled') }}</InfoNote>
        </section>
        </div>
        <div v-if="conflict" class="alert info"><Icon name="info" :size="16" /><span>{{ t('ccd.settingsHaveChangedOrAnAddressConflict') }}<button class="text-button" type="button" @click="load">{{ t('ccd.reloadSettings') }}</button></span></div>
        </div>
        <div class="card-actions ccd-dialog-actions device-ccd-actions"><button class="text-button" type="button" @click="reset">{{ t('ccd.resetToSharedSettings') }}</button><div><button class="button secondary" type="button" @click="close">{{ t('common.close') }}</button><button class="button primary" type="submit" :disabled="!dirty">{{ busy ? t('common.saving') : t('ccd.save') }}</button></div></div>
      </fieldset>
    </form>
  </dialog>
</template>
