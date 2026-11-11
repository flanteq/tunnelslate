<script setup lang="ts">
import FloatingField from './FloatingField.vue'
import { onUnmounted, ref } from 'vue'
import { api, ApiError, errorText } from './api'
import { t } from './i18n'
import InfoNote from './InfoNote.vue'
import { notifications } from './notifications'
import { passwordInputMaxLength } from './passwordPolicy'

const props = defineProps<{ csrf: string; username: string; mode: 'setup' | 'disable' }>()
const emit = defineEmits<{ changed: []; expired: []; pending: [value: boolean]; cancel: [] }>()
const password = ref(''), code = ref(''), busy = ref(false)
const setup = ref<{ setup_token: string; secret: string; qr_code: string; expires_at: number } | null>(null)

async function submit() {
  if (busy.value) return
  busy.value = true; emit('pending', true)
  try {
    const path = props.mode === 'disable' ? '/auth/totp/disable' : setup.value ? '/auth/totp/enable' : '/auth/totp/setup'
    const body = props.mode === 'disable' ? { current_password: password.value, code: code.value }
      : setup.value ? { setup_token: setup.value.setup_token, code: code.value } : { current_password: password.value }
    const result = await api<NonNullable<typeof setup.value>>(path, { method: 'POST', headers: { 'X-CSRF-Token': props.csrf }, body: JSON.stringify(body) })
    password.value = ''; code.value = ''
    if (path === '/auth/totp/setup') setup.value = result
    else { setup.value = null; emit('changed') }
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) emit('expired')
    else {
      if (err instanceof ApiError && err.code === 'auth.totp_setup_expired') setup.value = null
      notifications.error(() => errorText(err, t('totp.updateFailed')))
      code.value = ''
    }
  } finally { busy.value = false; emit('pending', false) }
}
async function copyKey() {
  if (!setup.value) return
  try { await navigator.clipboard.writeText(setup.value.secret) }
  catch { notifications.error(() => t('totp.copyFailed')) }
}
onUnmounted(() => { password.value = ''; code.value = ''; setup.value = null; emit('pending', false) })
</script>

<template>
  <form class="totp-form" @submit.prevent="submit" :aria-busy="busy">
    <div class="card-heading"><h2>{{ mode === 'disable' ? t('totp.disable') : t('totp.setup') }}</h2></div>
    <InfoNote class="card-description">{{ mode === 'disable' ? t('totp.disableHint') : setup ? t('totp.scanHint') : t('totp.setupHint') }}</InfoNote>
    <div class="card-body form-fields totp-body">
      <fieldset :disabled="busy">
        <input type="hidden" name="username" :value="username" autocomplete="username">
        <template v-if="!setup">
          <FloatingField id="totp-password" :label="t('password.currentPassword')"><input id="totp-password" v-model="password" type="password" name="current-password" autocomplete="current-password" required :maxlength="passwordInputMaxLength" autofocus placeholder=" "></FloatingField>
        </template>
        <template v-else>
          <img class="totp-qr" :src="setup.qr_code" :alt="t('totp.qrAlt')" width="256" height="256">
          <div class="totp-key"><FloatingField id="totp-secret" :label="t('totp.manualKey')" fixed><input id="totp-secret" :value="setup.secret" readonly autocomplete="off" spellcheck="false" placeholder=" "></FloatingField><button class="button secondary" type="button" @click="copyKey">{{ t('common.copy') }}</button></div>
          <InfoNote class="field-help">{{ t('totp.secretHint') }}</InfoNote>
        </template>
        <template v-if="setup || mode === 'disable'">
          <FloatingField id="totp-settings-code" :label="t('totp.code')"><input id="totp-settings-code" v-model="code" type="text" name="totp-code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" placeholder="000000" required></FloatingField>
        </template>
      </fieldset>
    </div>
    <div class="card-actions totp-actions"><button class="button secondary" type="button" :disabled="busy" @click="emit('cancel')">{{ t('common.cancel') }}</button><button :class="['button', mode === 'disable' ? 'secondary danger' : 'primary']" type="submit" :disabled="busy">{{ busy ? t('common.saving') : mode === 'disable' ? t('totp.disable') : setup ? t('totp.enable') : t('totp.continue') }}</button></div>
  </form>
</template>

<style scoped>
.totp-form { display: flex; flex-direction: column; max-height: calc(100dvh - 34px); }
.totp-form > .card-heading, .totp-form > .card-description, .totp-actions { flex-shrink: 0; }
.totp-body { overflow-y: auto; min-height: 0; }
.totp-body fieldset { border: 0; padding: 0; margin: 0; min-width: 0; }
.totp-body input { width: 100%; }
.totp-qr { display: block; max-width: 100%; height: auto; margin: 0 auto 20px; padding: 20px; background: #fff; border-radius: 10px; }
.totp-key { display: flex; gap: 10px; align-items: stretch; }
.totp-key input { min-width: 0; font-family: ui-monospace, monospace; font-size: 12px; }
.totp-key button { flex-shrink: 0; }
@media(max-width:600px) { .totp-key { align-items: stretch; flex-direction: column; } }
</style>
