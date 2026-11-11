<script setup lang="ts">
import { t } from './i18n'
import InfoNote from './InfoNote.vue'
import { computed, ref } from 'vue'
import Icon from './Icon.vue'
import { api, errorText } from './api'
import { notifications } from './notifications'
import type { Settings } from './api'

const props = defineProps<{ status: Settings['bootstrap']; csrf: string }>()
const emit = defineEmits<{ refresh: [] }>()
const busy = ref(false)
const stages = computed((): Record<string, string> => ({
  verify_existing: t('pki.checkingData'), create_pki: t('pki.creatingPKI'), create_ca: t('pki.creatingCertificateAuthority'),
  create_server: t('pki.issuingServerCertificate'), validate_pki: t('pki.checkingCertificatesAndKeys'), publish_runtime: t('pki.preparingServerFiles'),
}))
async function initialize() {
  busy.value = true
  try { await api('/pki/initialize', { method: 'POST', headers: { 'X-CSRF-Token': props.csrf }, body: '{}' }) }
  catch (err) { notifications.error(() => errorText(err, t('pki.couldNotPreparePKI'))) }
  finally { busy.value = false; emit('refresh') }
}
</script>

<template>
  <section v-if="status.state !== 'ready'" class="card pki-setup" aria-labelledby="pki-setup-title" :aria-busy="busy || status.state === 'running'">
    <div class="card-heading"><h2 id="pki-setup-title">{{ status.state === 'empty' ? t('pki.initialVPNSetup') : t('pki.pkiPreparation') }}</h2><Icon name="key" /></div>
    <InfoNote class="card-description">{{ t('pki.initializationCreatesACertificateAuthorityAndA') }}</InfoNote>
    <div class="card-body card-stack pki-setup-body">
      <div v-if="status.state === 'running'" role="status"><p>{{ stages[status.step] ?? t('pki.preparingPKI') }}…</p></div>
      <div v-else-if="status.state !== 'empty'"><p>{{ t('pki.setupIsIncompleteCheckTheSavedData') }}</p></div>
      <details v-if="status.error" class="alert error technical-details"><summary>{{ t('diagnostics.details') }}</summary><pre>{{ status.error }}</pre></details>
      <button class="button primary" :disabled="busy || status.state === 'running'" @click="initialize"><Icon name="key" :size="17" />{{ busy || status.state === 'running' ? t('pki.preparing') : status.state === 'empty' ? t('pki.initializePKI') : t('pki.runCheckAgain') }}</button>
    </div>
  </section>
</template>
