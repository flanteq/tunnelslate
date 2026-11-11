<script setup lang="ts">
import FloatingField from './FloatingField.vue'
import { t } from './i18n'
import InfoNote from './InfoNote.vue'
import VPNAuthProviders from './VPNAuthProviders.vue'
import { nextTick, ref, watch } from 'vue'
import { api, errorText } from './api'
import { notifications } from './notifications'
import type { Settings } from './api'
import { dcoLabel } from './dco'
const props = defineProps<{ settings: Settings; csrf: string }>()
const emit = defineEmits<{ refresh: [] }>()
const form = ref<Settings['vpn']>({ ...props.settings.vpn })
const dns = ref(props.settings.vpn.dns.join(', '))
const dnsSearch = ref(props.settings.vpn.dns_search.join('\n'))
const customMTU = ref(props.settings.vpn.tun_mtu !== 0)
const routes = ref(props.settings.vpn.routes.join('\n'))
const busy = ref(false)
const dirty = ref(false)
const formElement = ref<HTMLFormElement>()
type Tab = 'basic' | 'advanced' | 'network' | 'auth'
const tabs: Tab[] = ['basic', 'advanced', 'network', 'auth']
const tab = ref<Tab>('basic')
function selectTab(value: Tab) { tab.value = value }
function moveTab(event: KeyboardEvent) {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const direction=event.key==='ArrowLeft'?-1:1
  tab.value = event.key === 'Home' ? tabs[0]! : event.key === 'End' ? tabs[tabs.length-1]! : tabs[(tabs.indexOf(tab.value)+direction+tabs.length)%tabs.length]!
  document.getElementById(`vpn-tab-${tab.value}`)?.focus()
}
watch(() => props.settings.vpn.revision, () => {
  if (dirty.value || busy.value) return
  form.value = { ...props.settings.vpn }; dns.value = form.value.dns.join(', '); routes.value = form.value.routes.join('\n'); dnsSearch.value = form.value.dns_search.join('\n'); customMTU.value = form.value.tun_mtu !== 0
})
async function save() {
  if (formElement.value && !formElement.value.checkValidity()) {
    const invalid = formElement.value.querySelector('input:invalid, select:invalid, textarea:invalid')
    tab.value = invalid?.closest('#vpn-panel-network') ? 'network' : invalid?.closest('#vpn-panel-advanced') ? 'advanced' : 'basic'
    await nextTick()
    formElement.value.reportValidity()
    return
  }
  busy.value = true
  try {
    const result = await api<Settings['vpn']>('/settings/vpn', { method: 'PUT', headers: { 'X-CSRF-Token': props.csrf }, body: JSON.stringify({ ...form.value, dns_search: dnsSearch.value.split(/[\s,]+/).filter(Boolean), dns: dns.value.split(',').map(v => v.trim()), routes: routes.value.split(/[\s,]+/).filter(Boolean) }) })
    form.value = result; dirty.value = false
    dns.value = result.dns.join(', '); routes.value = result.routes.join('\n'); dnsSearch.value = result.dns_search.join('\n'); customMTU.value = result.tun_mtu !== 0
  } catch (err) { notifications.error(() => errorText(err, t('vpn.couldNotSaveSettings'))) }
  finally { busy.value = false; emit('refresh') }
}
</script>

<template>
  <section class="card vpn-settings-form">
    <div class="card-heading"><h2>{{ t('vpn.openvpnParameters') }}</h2><span :class="['pill', settings.applied_revision === settings.vpn.revision && !settings.network_status?.pending ? 'success' : 'neutral']">{{ settings.applied_revision === settings.vpn.revision && !settings.network_status?.pending ? t('vpn.applied') : t('vpn.pendingApplication') }}</span></div>
    <div class="vpn-settings-tabs" role="tablist" :aria-label="t('vpn.settingsTabs')" @keydown="moveTab">
      <button id="vpn-tab-basic" class="vpn-settings-tab" type="button" role="tab" :aria-selected="tab === 'basic'" :tabindex="tab === 'basic' ? 0 : -1" aria-controls="vpn-panel-basic" @click="selectTab('basic')">{{ t('vpn.basicSettings') }}</button>
      <button id="vpn-tab-advanced" class="vpn-settings-tab" type="button" role="tab" :aria-selected="tab === 'advanced'" :tabindex="tab === 'advanced' ? 0 : -1" aria-controls="vpn-panel-advanced" @click="selectTab('advanced')">{{ t('vpn.advancedSettings') }}</button>
      <button id="vpn-tab-network" class="vpn-settings-tab" type="button" role="tab" :aria-selected="tab === 'network'" :tabindex="tab === 'network' ? 0 : -1" aria-controls="vpn-panel-network" @click="selectTab('network')">{{ t('network.tab') }}</button>
      <button id="vpn-tab-auth" class="vpn-settings-tab" type="button" role="tab" :aria-selected="tab === 'auth'" :tabindex="tab === 'auth' ? 0 : -1" aria-controls="vpn-panel-auth" @click="selectTab('auth')">{{ t('vpnAuth.tab') }}</button>
    </div>
    <InfoNote class="card-description">{{ t(tab === 'auth' ? 'vpnAuth.providersHelp' : 'vpn.applyingSettingsRestartsOpenVPNAndDisconnectsCurrent') }}</InfoNote>
    <form ref="formElement" v-show="tab !== 'auth'" novalidate @submit.prevent="save" @input="dirty = true" @change="dirty = true">
    <div class="card-body form-fields">
      <fieldset :disabled="busy">
        <div id="vpn-panel-basic" role="tabpanel" aria-labelledby="vpn-tab-basic" v-show="tab === 'basic'">
        <FloatingField id="vpn-endpoint" :label="t('vpn.publicVPNAddress')"><input id="vpn-endpoint" v-model="form.endpoint" required maxlength="253" placeholder="vpn.example.com"></FloatingField>
        <div class="vpn-form-columns"><div><FloatingField id="vpn-port" :label="t('vpn.externalPortInProfiles')"><input id="vpn-port" aria-describedby="vpn-port-help" v-model.number="form.external_port" type="number" min="1" max="65535" required placeholder=" "></FloatingField><InfoNote class="field-help" id="vpn-port-help">{{ t('vpn.theExternalPortMustMatchTheCompose') }}</InfoNote></div><div><FloatingField id="vpn-protocol" :label="t('vpn.protocol')" fixed><select id="vpn-protocol" v-model="form.protocol"><option value="udp">UDP</option><option value="tcp">TCP</option></select></FloatingField></div></div>
        <FloatingField id="vpn-network" :label="t('vpn.vpnSubnet')"><input id="vpn-network" v-model="form.network" required placeholder="10.8.0.0/24"></FloatingField>
        <FloatingField id="vpn-dns" :label="t('vpn.clientDNS')"><input id="vpn-dns" aria-describedby="vpn-dns-help" v-model="dns" required placeholder="172.16.0.1, 1.1.1.1"></FloatingField><InfoNote class="field-help" id="vpn-dns-help">{{ t('vpn.enterCommaSeparatedIPv4AddressesDNSOutside') }}</InfoNote>
        <FloatingField id="vpn-mode" :label="t('common.routing')" fixed><select id="vpn-mode" v-model="form.redirect_gateway"><option :value="false">{{ t('common.splitTunnelSelectedNetworks') }}</option><option :value="true">{{ t('common.fullTunnelAllIPv4Traffic') }}</option></select></FloatingField>
        <FloatingField id="vpn-routes" :label="t('vpn.additionalNetworksThroughVPN')" fixed><textarea id="vpn-routes" aria-describedby="vpn-routes-help" v-model="routes" rows="3" placeholder="192.168.1.0/24&#10;172.20.0.0/16"></textarea></FloatingField><InfoNote class="field-help" id="vpn-routes-help">{{ t('vpn.enterOneIPv4CIDRNetworkPerLine') }}</InfoNote>
        </div>
        <div id="vpn-panel-advanced" role="tabpanel" aria-labelledby="vpn-tab-advanced" v-show="tab === 'advanced'">
          <section class="vpn-options-section vpn-form-columns">
            <div>
              <FloatingField id="vpn-mtu-mode" :label="t('vpn.tunMTU')" fixed><select id="vpn-mtu-mode" v-model="customMTU" @change="form.tun_mtu = customMTU ? 1400 : 0"><option :value="false">{{ t('vpn.defaultMTU') }}</option><option :value="true">{{ t('vpn.customValue') }}</option></select></FloatingField>
              <template v-if="customMTU"><FloatingField id="vpn-tun-mtu" :label="t('vpn.mtuBytes')"><input id="vpn-tun-mtu" v-model.number="form.tun_mtu" type="number" min="576" max="1500" required placeholder=" "></FloatingField></template>
              <InfoNote class="field-help">{{ t('vpn.mtuHelp') }}</InfoNote>
            </div>
            <div>
              <FloatingField id="vpn-mss-mode" :label="t('vpn.mssMode')" fixed><select id="vpn-mss-mode" v-model="form.mss_mode" @change="form.mss = form.mss_mode === 'custom' ? Math.min(1360, (form.tun_mtu || 1500) - 40) : 0"><option value="default">{{ t('vpn.mssDefault') }}</option><option value="custom">{{ t('vpn.customValue') }}</option><option value="off">{{ t('vpn.mssOff') }}</option></select></FloatingField>
              <template v-if="form.mss_mode === 'custom'"><FloatingField id="vpn-mss" :label="t('vpn.mssBytes')"><input id="vpn-mss" v-model.number="form.mss" type="number" min="536" :max="(form.tun_mtu || 1500) - 40" required placeholder=" "></FloatingField></template>
              <InfoNote class="field-help">{{ t('vpn.mssHelp') }}</InfoNote>
              <InfoNote v-if="form.protocol === 'tcp'" class="field-help">{{ t('vpn.mssTCP') }}</InfoNote>
            </div>
          </section>
          <section class="vpn-options-section">
            <FloatingField id="vpn-dns-domain" :label="t('vpn.dnsDomain')"><input id="vpn-dns-domain" v-model="form.dns_domain" maxlength="253" placeholder="office.example.com" autocomplete="off"></FloatingField>
            <FloatingField id="vpn-dns-search" :label="t('vpn.dnsSearch')" fixed><textarea id="vpn-dns-search" v-model="dnsSearch" rows="2" placeholder="office.example.com&#10;dev.example.com"></textarea></FloatingField>
            <InfoNote class="field-help">{{ t('vpn.dnsDomainsHelp') }}</InfoNote>
          </section>
          <section class="vpn-options-section">
            <div class="dco-control">
              <label class="dco-switch" for="vpn-dco">
                <input id="vpn-dco" class="dco-switch-input" type="checkbox" role="switch" v-model="form.dco" true-value="auto" false-value="off" aria-describedby="vpn-dco-mode vpn-dco-help">
                <span class="dco-switch-track" aria-hidden="true"></span>
                <span>{{ t('dco.title') }}</span>
              </label>
              <span id="vpn-dco-mode" class="dco-switch-value">{{ form.dco === 'auto' ? t('dco.automatic') : t('dco.off') }}</span>
            </div>
            <InfoNote class="field-help" id="vpn-dco-help">{{ t('dco.help') }}</InfoNote>
            <div class="vpn-dco-status" role="status"><span :class="['pill', settings.dco?.state === 'active' ? 'success' : 'neutral']">{{ dcoLabel(settings.dco) }}</span></div>
          </section>
          <FloatingField id="vpn-max-clients" :label="t('vpn.maxClients')"><input id="vpn-max-clients" v-model.number="form.max_clients" type="number" min="1" max="65535" required aria-describedby="vpn-max-clients-help" placeholder=" "></FloatingField><InfoNote class="field-help" id="vpn-max-clients-help">{{ t('vpn.maxClientsHelp') }}</InfoNote>
          <div class="vpn-form-columns"><div><FloatingField id="vpn-keepalive-interval" :label="t('vpn.keepaliveInterval')"><input id="vpn-keepalive-interval" v-model.number="form.keepalive_interval" type="number" min="1" max="3600" required placeholder=" "></FloatingField></div><div><FloatingField id="vpn-keepalive-timeout" :label="t('vpn.keepaliveTimeout')"><input id="vpn-keepalive-timeout" v-model.number="form.keepalive_timeout" type="number" :min="2 * form.keepalive_interval" max="86400" required placeholder=" "></FloatingField></div></div>
          <InfoNote class="field-help">{{ t('vpn.keepaliveHelp') }}</InfoNote>
        </div>
        <div id="vpn-panel-network" role="tabpanel" aria-labelledby="vpn-tab-network" v-show="tab === 'network'">
          <InfoNote v-if="settings.network_status?.error" class="field-help">{{ t('network.applyError') }}<details class="technical-details"><summary>{{ t('diagnostics.details') }}</summary><pre>{{ settings.network_status.error }}</pre></details></InfoNote>
          <section class="vpn-options-section">
            <div class="dco-control">
              <label class="dco-switch" for="vpn-isolation">
                <input id="vpn-isolation" class="dco-switch-input" type="checkbox" role="switch" v-model="form.isolate_clients" :true-value="false" :false-value="true" aria-describedby="vpn-isolation-mode vpn-isolation-help">
                <span class="dco-switch-track" aria-hidden="true"></span>
                <span>{{ t('network.isolation') }}</span>
              </label>
              <span id="vpn-isolation-mode" class="dco-switch-value">{{ form.isolate_clients ? t('network.communicationBlocked') : t('network.communicationAllowed') }}</span>
            </div>
            <InfoNote class="field-help" id="vpn-isolation-help">{{ t('network.isolationHelp') }}</InfoNote>
          </section>
          <section class="vpn-options-section">
            <div class="dco-control">
              <label class="dco-switch" for="vpn-site-to-site">
                <input id="vpn-site-to-site" class="dco-switch-input" type="checkbox" role="switch" v-model="form.site_to_site" aria-describedby="vpn-site-mode vpn-site-help">
                <span class="dco-switch-track" aria-hidden="true"></span>
                <span>{{ t('network.siteToSite') }}</span>
              </label>
              <span id="vpn-site-mode" class="dco-switch-value">{{ form.site_to_site ? t('network.enabled') : t('network.disabled') }}</span>
            </div>
            <InfoNote class="field-help" id="vpn-site-help">{{ t('network.siteHelp') }}</InfoNote>
            <InfoNote v-if="form.site_to_site && form.isolate_clients" class="field-help">{{ t('network.isolatedSites') }}</InfoNote>
            <FloatingField id="vpn-site-nat" :label="t('network.siteNAT')" fixed><select id="vpn-site-nat" v-model="form.site_nat" :disabled="!form.site_to_site"><option :value="false">{{ t('network.preserveAddresses') }}</option><option :value="true">{{ t('network.masquerade') }}</option></select></FloatingField>
            <InfoNote class="field-help">{{ t('network.natHelp') }}</InfoNote>
          </section>
        </div>
        <button class="button primary" type="submit">{{ busy ? t('common.saving') : t('vpn.saveAndApply') }}</button>
      </fieldset>
    </div>
    </form>
    <div v-if="tab === 'auth'" id="vpn-panel-auth" role="tabpanel" aria-labelledby="vpn-tab-auth"><VPNAuthProviders :csrf="csrf" :refresh-key="settings" @refresh="emit('refresh')" /></div>
  </section>
</template>
