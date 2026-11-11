<script setup lang="ts">
import { ref, watch } from 'vue'
import { api, errorText, type PanelSettingsView } from './api'
import { t, formatDateTime, hasMessage } from './i18n'
import { notifications } from './notifications'
import FloatingField from './FloatingField.vue'
import InfoNote from './InfoNote.vue'
const props = defineProps<{ view: PanelSettingsView; csrf: string }>()
const emit = defineEmits<{ refresh: []; updated: [view: PanelSettingsView] }>()
const tab = ref<'general' | 'metrics'>('general')
const form = ref({ ...props.view.settings })
const runtime = ref(props.view.runtime)
const key = ref(''), busy = ref(false), generalDirty = ref(false), metricsDirty = ref(false)
watch(() => props.view, value => { runtime.value = value.runtime; if (!generalDirty.value && !metricsDirty.value && !busy.value) form.value = { ...value.settings } })
function moveTab(event: KeyboardEvent) {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  tab.value = event.key === 'Home' ? 'general' : event.key === 'End' ? 'metrics' : tab.value === 'general' ? 'metrics' : 'general'
  document.getElementById(`panel-tab-${tab.value}`)?.focus()
}
function runtimeError() { const value = `errors.${runtime.value.error}`; return hasMessage(value) ? t(value) : t('panel.runtimeError') }
async function save(section: 'general' | 'metrics') {
  busy.value = true
  try {
    const body = section === 'general' ? { instance_name: form.value.instance_name, revision: form.value.revision } : {
      enabled: form.value.metrics_enabled, mtls: form.value.metrics_mtls, source: form.value.metrics_source,
      server_cert_pem: form.value.server_cert_pem, client_ca_pem: form.value.client_ca_pem, private_key_pem: key.value, revision: form.value.revision,
    }
    const result = await api<PanelSettingsView>(`/panel-settings/${section}`, { method: 'PUT', headers: { 'X-CSRF-Token': props.csrf }, body: JSON.stringify(body) })
    // Preserve unsaved fields from the other tab while advancing the shared revision.
    if (section === 'general') form.value.instance_name = result.settings.instance_name
    else { key.value = ''; form.value.key_configured = result.settings.key_configured }
    form.value.revision = result.settings.revision; runtime.value = result.runtime; if (section === 'general') generalDirty.value = false; else metricsDirty.value = false
    emit('updated', result)
  } catch (error) { notifications.error(() => errorText(error)) }
  finally { busy.value = false; emit('refresh') }
}
</script>

<template>
  <section class="card panel-settings">
    <div class="card-heading"><h2>{{ t('panel.title') }}</h2></div>
    <div class="vpn-settings-tabs" role="tablist" :aria-label="t('panel.title')" @keydown="moveTab">
      <button v-for="value in (['general', 'metrics'] as const)" :id="`panel-tab-${value}`" :key="value" class="vpn-settings-tab" type="button" role="tab" :aria-controls="`panel-content-${value}`" :aria-selected="tab === value" :tabindex="tab === value ? 0 : -1" @click="tab = value">{{ t(value === 'general' ? 'panel.general' : 'panel.metrics') }}</button>
    </div>
    <form v-show="tab === 'general'" id="panel-content-general" role="tabpanel" aria-labelledby="panel-tab-general" @submit.prevent="save('general')" @input="generalDirty = true" @change="generalDirty = true">
      <InfoNote class="card-description">{{ t('panel.nameHelp') }}</InfoNote>
      <div class="card-body form-fields">
        <FloatingField id="instance-name" :label="t('panel.instanceName')"><input id="instance-name" v-model="form.instance_name" maxlength="64" :placeholder="t('app.myServer')" :disabled="busy" /></FloatingField>
      </div>
      <div class="card-actions"><button class="button primary" :disabled="busy">{{ t('panel.save') }}</button></div>
    </form>
    <form v-show="tab === 'metrics'" id="panel-content-metrics" role="tabpanel" aria-labelledby="panel-tab-metrics" @submit.prevent="save('metrics')" @input="metricsDirty = true" @change="metricsDirty = true">
      <InfoNote class="card-description">{{ t('panel.metricsHelp') }}</InfoNote>
      <div class="card-body form-fields">
        <div class="metrics-head dco-control"><div class="dco-control"><label class="dco-switch"><input v-model="form.metrics_enabled" class="dco-switch-input" type="checkbox" role="switch" :disabled="busy" /><span class="dco-switch-track" aria-hidden="true"></span><span>{{ t('panel.enableMetrics') }}</span></label></div>
        <div class="metrics-state"><span :class="['pill', runtime.state === 'running' ? 'success' : runtime.state === 'error' ? 'critical' : 'neutral']">{{ t(runtime.state === 'running' ? 'panel.running' : runtime.state === 'error' ? 'panel.error' : 'panel.disabled') }}</span><code>{{ view.settings.metrics_mtls ? 'https' : 'http' }}://&lt;host&gt;:9090/metrics</code></div></div>
        <InfoNote v-if="runtime.state === 'error'" class="field-help">{{ runtimeError() }}</InfoNote>
        <div class="metrics-security"><div class="dco-control"><label class="dco-switch"><input v-model="form.metrics_mtls" class="dco-switch-input" type="checkbox" role="switch" :disabled="busy" /><span class="dco-switch-track" aria-hidden="true"></span><span>{{ t('panel.mtls') }}</span></label></div>
        <InfoNote class="field-help">{{ t(form.metrics_mtls ? 'panel.mtlsHelp' : 'panel.plainHelp') }}</InfoNote>
        <div v-if="form.metrics_mtls" class="metrics-material">
          <FloatingField id="metrics-source" :label="t('panel.source')" fixed><select id="metrics-source" v-model="form.metrics_source" :disabled="busy"><option value="files">{{ t('panel.files') }}</option><option value="pem">{{ t('panel.pem') }}</option></select></FloatingField>
          <div v-if="form.metrics_source === 'files'" class="metrics-files">
            <InfoNote class="field-help">{{ t('panel.filesHelp') }}</InfoNote>
            <ul><li><code>/data/app/certs/metrics/server.crt</code></li><li><code>/data/app/certs/metrics/server.key</code></li><li><code>/data/app/certs/metrics/client-ca.crt</code></li></ul>
          </div>
          <template v-else>
            <FloatingField id="metrics-cert" :label="t('panel.serverCert')" fixed><textarea id="metrics-cert" v-model="form.server_cert_pem" rows="6" maxlength="131072" spellcheck="false" :disabled="busy" /></FloatingField>
            <FloatingField id="metrics-key" :label="t(form.key_configured ? 'panel.replaceKey' : 'panel.serverKey')" fixed><textarea id="metrics-key" v-model="key" rows="5" maxlength="131072" spellcheck="false" autocomplete="off" :disabled="busy" /></FloatingField>
            <InfoNote class="field-help">{{ t('panel.keyHelp') }}</InfoNote>
            <FloatingField id="metrics-ca" :label="t('panel.clientCA')" fixed><textarea id="metrics-ca" v-model="form.client_ca_pem" rows="6" maxlength="131072" spellcheck="false" :disabled="busy" /></FloatingField>
          </template>
          <div v-if="runtime.certificate_expires" class="field-help">{{ t('panel.expires', { date: formatDateTime(runtime.certificate_expires) }) }}</div>
        </div></div>
      </div>
      <div class="card-actions"><button class="button primary" :disabled="busy">{{ t('panel.apply') }}</button></div>
    </form>
  </section>
</template>

<style scoped>
.panel-settings { width: 100%; }
.metrics-security { border-top:1px solid var(--border); margin-top:20px; padding-top:20px; }
.metrics-material { display:flex; flex-direction:column; gap:16px; margin-top:16px; }
.metrics-material > .floating-field, .metrics-material > .field-help, .metrics-files > .field-help { margin-top:0; }
.metrics-state { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.metrics-state code, .metrics-files code { overflow-wrap:anywhere; font-size:12px; }
.metrics-files ul { padding-left:20px; margin:12px 0 0; line-height:1.9; }
textarea { font-family:ui-monospace,monospace !important; }
</style>
