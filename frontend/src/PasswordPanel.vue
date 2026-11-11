<script setup lang="ts">
import FloatingField from './FloatingField.vue'
import { t } from './i18n'
import InfoNote from './InfoNote.vue'
import { onUnmounted, ref } from 'vue'
import Icon from './Icon.vue'
import { validNewPassword, passwordInputMaxLength } from './passwordPolicy'
import { api, ApiError } from './api'
import { notifications } from './notifications'

const props = defineProps<{ csrf: string; username: string }>()
const emit = defineEmits<{ changed: []; expired: []; pending: [value: boolean]; cancel: [] }>()
const currentPassword = ref('')
const newPassword = ref('')
const confirmation = ref('')
const busy = ref(false)

async function changePassword() {
  if (newPassword.value !== confirmation.value) { notifications.error(() => t('password.theNewPasswordAndConfirmationDoNot')); return }
  if (!validNewPassword(newPassword.value)) { notifications.error(() => t('password.theNewPasswordMustContain1272')); return }
  if (newPassword.value === currentPassword.value) { notifications.error(() => t('password.theNewPasswordMustDifferFromThe')); return }
  busy.value = true
  emit('pending', true)
  try {
    await api('/auth/password', { method: 'POST', headers: { 'X-CSRF-Token': props.csrf }, body: JSON.stringify({ current_password: currentPassword.value, new_password: newPassword.value }) })
    currentPassword.value = ''; newPassword.value = ''; confirmation.value = ''
    emit('changed')
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { emit('expired'); return }
    if (err instanceof ApiError && err.code === 'auth.current_password_invalid') { notifications.error(() => t('password.theCurrentPasswordIsIncorrect')); currentPassword.value = '' }
    else if (err instanceof ApiError && err.status === 429) notifications.error(() => t('common.tooManyAttemptsOrTheServerIs'))
    else if (err instanceof ApiError && err.status === 403) notifications.error(() => t('password.couldNotVerifyTheRequestRefreshThe'))
    else notifications.error(() => t('password.couldNotConfirmThePasswordChangeIf'))
  } finally { busy.value = false; emit('pending', false) }
}
onUnmounted(() => emit('pending', false))
</script>

<template>
  <form class="password-form" @submit.prevent="changePassword" :aria-busy="busy">
    <div class="card-heading"><h2>{{ t('password.changePassword') }}</h2><Icon name="lock" /></div>
    <InfoNote class="card-description">{{ t('password.theNewPasswordMustContain1272395') }}</InfoNote>
    <div class="card-body form-fields">
      <fieldset :disabled="busy">
        <input type="hidden" name="username" :value="username" autocomplete="username">
        <FloatingField id="current-password" :label="t('password.currentPassword')"><input id="current-password" v-model="currentPassword" type="password" name="current-password" autocomplete="current-password" required :maxlength="passwordInputMaxLength" placeholder=" "></FloatingField>
        <FloatingField id="new-password" :label="t('common.newPassword')"><input id="new-password" v-model="newPassword" type="password" name="new-password" autocomplete="new-password" required :maxlength="passwordInputMaxLength" placeholder=" "></FloatingField>
        <FloatingField id="confirm-password" :label="t('password.confirmNewPassword')"><input id="confirm-password" v-model="confirmation" type="password" name="confirm-password" autocomplete="new-password" required :maxlength="passwordInputMaxLength" placeholder=" "></FloatingField>
      </fieldset>
    </div>
    <div class="card-actions"><button class="button secondary" type="button" :disabled="busy" @click="emit('cancel')">{{ t('common.cancel') }}</button><button class="button primary" type="submit" :disabled="busy">{{ busy ? t('common.saving') : t('common.changePassword') }}</button></div>
  </form>
</template>

