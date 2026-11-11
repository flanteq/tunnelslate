<script setup lang="ts">
import { PRODUCT_NAME } from './branding'
import FloatingField from './FloatingField.vue'
import { t } from './i18n'
import LanguageSwitcher from './LanguageSwitcher.vue'
import InfoNote from './InfoNote.vue'
import { ref } from 'vue'
import Icon from './Icon.vue'
import { validNewPassword, passwordInputMaxLength } from './passwordPolicy'
import { api, ApiError } from './api'
import { notifications } from './notifications'

const props = defineProps<{ csrf: string; username: string; signingOut: boolean }>()
const emit = defineEmits<{ changed: []; expired: []; logout: [] }>()
const password = ref('')
const confirmation = ref('')
const busy = ref(false)

async function setPassword() {
  if (busy.value) return
  if (password.value !== confirmation.value) { notifications.error(() => t('setup.thePasswordAndConfirmationDoNotMatch')); return }
  if (!validNewPassword(password.value)) { notifications.error(() => t('setup.thePasswordMustContain1272Characters')); return }
  busy.value = true
  try {
    await api('/auth/setup-password', { method: 'POST', headers: { 'X-CSRF-Token': props.csrf }, body: JSON.stringify({ new_password: password.value }) })
    password.value = ''; confirmation.value = ''
    emit('changed')
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { emit('expired'); return }
    if (err instanceof ApiError && err.code === 'auth.password_unchanged') notifications.error(() => t('setup.thePermanentPasswordMustDifferFromThe'))
    else if (err instanceof ApiError && err.status === 429) notifications.error(() => t('common.tooManyAttemptsOrTheServerIs'))
    else notifications.error(() => t('setup.couldNotConfirmPasswordSetupTryAgain'))
  } finally { busy.value = false }
}
</script>

<template>
  <main class="initial-password-page">
    <section class="initial-password-card card" aria-labelledby="initial-password-title">
      <div class="initial-password-brand"><span class="brand-mark"><Icon name="shield" :size="25" /></span><span>{{ PRODUCT_NAME }}</span><LanguageSwitcher class="initial-password-language" /></div>
      <form class="login-form" @submit.prevent="setPassword" :aria-busy="busy">
        <p class="eyebrow muted">{{ t('setup.firstSIGNIN', { p0: username }) }}</p>
        <h1 id="initial-password-title">{{ t('setup.setYourPassword') }}</h1>
        <InfoNote class="subtle">{{ t('setup.youSignedInWithAOneTime') }}</InfoNote>
        <fieldset :disabled="busy || signingOut">
          <input type="hidden" name="username" :value="username" autocomplete="username">
          <FloatingField id="initial-password" :label="t('common.newPassword')"><input id="initial-password" aria-describedby="initial-password-help" v-model="password" type="password" name="new-password" autocomplete="new-password" required :maxlength="passwordInputMaxLength" autofocus placeholder=" "></FloatingField>
          <InfoNote id="initial-password-help" class="field-help">{{ t('setup.1272CharactersDifferentFromTheOne') }}</InfoNote>
          <FloatingField id="initial-password-confirmation" :label="t('setup.confirmPassword')"><input id="initial-password-confirmation" v-model="confirmation" type="password" name="confirm-password" autocomplete="new-password" required :maxlength="passwordInputMaxLength" placeholder=" "></FloatingField>
          <button class="button primary login-submit" type="submit">{{ busy ? t('common.saving') : t('setup.setPassword') }}<Icon name="arrow" :size="18" /></button>
          <InfoNote class="initial-password-next subtle">{{ t('setup.theOneTimePasswordWillStopWorking') }}</InfoNote>
        </fieldset>
      </form>
      <button class="button secondary initial-password-logout" :disabled="busy || signingOut" @click="emit('logout')"><Icon name="logout" :size="16" />{{ t('common.signOut') }}</button>
    </section>
  </main>
</template>

<style scoped>
.initial-password-language{margin-left:auto}
.initial-password-page{min-height:100dvh;display:grid;place-items:center;padding:32px 20px;background:var(--bg)}
.initial-password-card{width:100%;max-width:460px;padding:36px}
.initial-password-brand{display:flex;align-items:center;gap:12px;font-size:18px;font-weight:650;margin-bottom:34px}
.login-form{max-width:none}
.login-form fieldset{border:0;padding:0;margin:0;min-width:0}
.eyebrow{overflow-wrap:anywhere}
h1{font-size:28px;letter-spacing:-.7px;line-height:1.2;margin:12px 0}
.login-form>.subtle{line-height:1.7;margin-bottom:24px}
.initial-password-next{margin:14px 0 0;font-size:12px;line-height:1.6}
.initial-password-logout{margin-top:24px}
@media(max-width:480px){.initial-password-card{padding:26px 22px}.initial-password-page{padding:20px 14px}h1{font-size:25px}}
</style>
