<script setup lang="ts">
import FloatingField from './FloatingField.vue'
import { t, formatDate, formatDateTime, formatNumber } from './i18n'
import { computed, ref } from 'vue'
import { api, ApiError, errorText } from './api'
import type { AdminAccount } from './api'
import InfoNote from './InfoNote.vue'
import PasswordPanel from './PasswordPanel.vue'
import TOTPPanel from './TOTPPanel.vue'
import { notifications } from './notifications'
const props = defineProps<{ accounts: AdminAccount[]; csrf: string }>()
const emit = defineEmits<{ refresh: []; expired: []; pending: [value: boolean]; signedOut: [username?: string] }>()
const username = ref(''), editedName = ref(''), busy = ref(false), showPassword = ref(false)
const dialog = ref<HTMLDialogElement | null>(null)
type AccountAction = 'rename' | 'reset' | 'delete' | 'password' | 'sessions' | 'end-sessions' | 'totp-setup' | 'totp-disable'
const mode = ref<AccountAction | 'credentials'>('rename')
const target = ref<AdminAccount | null>(null)
const credentials = ref<{ username: string; temporary_password: string } | null>(null)
const selectedAccount = computed(() => props.accounts.find(a => a.id === target.value?.id))
const dateTime = (unix: number) => unix ? formatDateTime(unix) : t('accounts.unknown')
const date = (unix: number) => formatDate(unix)
const canDelete = (account: AdminAccount) => props.accounts.some(a => a.id !== account.id && !a.password_setup_required)
function close() { dialog.value?.close(); credentials.value = null; target.value = null; showPassword.value = false; mode.value = 'rename' }
function ask(account: AdminAccount, action: AccountAction) { target.value = account; editedName.value = account.username; mode.value = action; dialog.value?.showModal() }
function passwordPending(value: boolean) { busy.value = value; emit('pending', value) }
function passwordChanged() { const name = target.value?.username; close(); emit('signedOut', name) }
function totpChanged() { close(); emit('refresh') }
type MutationResult = { username?: string; temporary_password?: string; signed_out?: boolean }
async function mutate(path: string, body: unknown, success: (result: MutationResult) => void) {
  busy.value = true; emit('pending', true)
  try {
    const result = await api<MutationResult>(path, { method: 'POST', headers: { 'X-CSRF-Token': props.csrf }, body: JSON.stringify(body) })
    success(result)
  }
  catch (err) {
    if (err instanceof ApiError && err.status === 401) emit('expired')
    else notifications.error(() => errorText(err, t('accounts.couldNotUpdateTheAccount')))
    return null
  } finally { busy.value = false; emit('pending', false); emit('refresh') }
}
function showCredentials(result: { username?: string; temporary_password?: string }) {
  if (!result.username || !result.temporary_password) return
  credentials.value = { username: result.username, temporary_password: result.temporary_password }
  showPassword.value = false; mode.value = 'credentials'; dialog.value?.showModal()
}
async function create() {
  await mutate('/admins', { username: username.value }, result => { username.value = ''; showCredentials(result) })
}
async function confirm() {
  const account = target.value; if (!account || busy.value) return
  const action = mode.value
  await mutate(`/admins/${account.id}/${action === 'reset' ? 'reset-password' : action}`, action === 'rename' ? { username: editedName.value } : {}, result => {
    if (result.signed_out) { close(); emit('signedOut', result.username); return }
    if (action === 'reset') { dialog.value?.close(); showCredentials(result) }
    else close()
  })
}
async function copy() {
  if (!credentials.value) return
  try { await navigator.clipboard.writeText(t('accounts.usernameOneTimePassword', { p0: credentials.value.username, p1: credentials.value.temporary_password })) }
  catch { notifications.error(() => t('accounts.couldNotCopyRevealThePasswordAnd')) }
}
</script>
<template>
  <div class="accounts-panel" :aria-busy="busy">
    <form class="card account-create" @submit.prevent="create">
      <div class="card-heading"><h2>{{ t('accounts.newAdministrator') }}</h2></div>
      <InfoNote class="card-description">{{ t('accounts.aOneTimePasswordWillBeGenerated') }}</InfoNote>
      <div class="card-body form-fields account-body"><div class="form-row"><FloatingField id="admin-username" :label="t('accounts.signInName')"><input id="admin-username" v-model="username" required minlength="3" maxlength="64" pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}" autocomplete="off" :placeholder="t('accounts.forExampleVpnOperator')"></FloatingField><button class="button primary" :disabled="busy" type="submit">{{ t('accounts.createAdministrator') }}</button></div><InfoNote class="field-help">{{ t('accounts.364CharactersLatinLettersNumbersPeriods') }}</InfoNote></div>
    </form>
    <section class="card"><div class="card-heading"><h2>{{ t('accounts.administrators') }} <span class="count-label">{{ formatNumber(accounts.length) }}</span></h2></div>
      <div v-if="!accounts.length" class="compact-empty">{{ t('accounts.loadingAccounts') }}</div>
      <div v-else class="table-scroll"><table><thead><tr><th>{{ t('accounts.name') }}</th><th>{{ t('accounts.state') }}</th><th>{{ t('accounts.created') }}</th><th>{{ t('accounts.unexpiredSessions') }}</th><th>{{ t('common.actions') }}</th></tr></thead><tbody><tr v-for="account in accounts" :key="account.id"><td><strong>{{ account.username }}</strong><span v-if="account.current" class="pill neutral account-self">{{ t('accounts.you') }}</span></td><td><span :class="['pill', account.password_setup_required ? 'neutral' : 'success']">{{ account.password_setup_required ? t('accounts.passwordSetupRequired') : t('accounts.ready') }}</span><span v-if="account.totp_enabled" class="pill success account-totp">{{ t('totp.enabled') }}</span></td><td>{{ date(account.created_at) }}</td><td><button class="button secondary" :disabled="busy || !account.sessions" :aria-label="t('accounts.viewSessions', { p0: account.username, p1: account.sessions })" @click="ask(account, 'sessions')">{{ formatNumber(account.sessions) }}</button></td><td class="actions-cell"><div class="account-row-actions"><button class="button secondary" :disabled="busy" @click="ask(account, 'rename')">{{ t('accounts.rename') }}</button><button v-if="account.current" class="button secondary" :disabled="busy" @click="ask(account, 'password')">{{ t('common.changePassword') }}</button><button v-else class="button secondary" :disabled="busy" @click="ask(account, 'reset')">{{ t('accounts.resetPassword') }}</button><button v-if="account.current" class="button secondary" :disabled="busy" @click="ask(account, account.totp_enabled ? 'totp-disable' : 'totp-setup')">{{ account.totp_enabled ? t('totp.disable') : t('totp.setup') }}</button><button class="button secondary danger" :disabled="busy || !canDelete(account)" @click="ask(account, 'delete')">{{ t('common.delete') }}</button></div></td></tr></tbody></table></div>
    </section>
    <dialog ref="dialog" class="account-dialog" @cancel.prevent="!busy && close()">
      <PasswordPanel v-if="mode === 'password' && target" :csrf="csrf" :username="target.username" @pending="passwordPending" @changed="passwordChanged" @expired="emit('expired')" @cancel="close" />
      <TOTPPanel v-else-if="(mode === 'totp-setup' || mode === 'totp-disable') && target" :csrf="csrf" :username="target.username" :mode="mode === 'totp-setup' ? 'setup' : 'disable'" @pending="passwordPending" @changed="totpChanged" @expired="emit('expired')" @cancel="close" />
      <template v-else>
        <div class="card-heading"><h2>{{ mode === 'sessions' ? t('accounts.sessions', { p0: target?.username }) : mode === 'end-sessions' ? t('accounts.endSessions') : mode === 'credentials' ? t('accounts.firstSignInCredentials') : mode === 'rename' ? t('accounts.renameAdministrator') : mode === 'reset' ? t('accounts.resetPassword30') : t('accounts.deleteAdministrator') }}</h2></div>
        <template v-if="mode === 'sessions'">
          <InfoNote class="card-description">{{ t('accounts.theseSignInsHaveNotExpiredClosing') }}</InfoNote>
          <div class="card-body form-fields account-body">
            <div v-if="!selectedAccount?.session_details?.length" class="session-empty">{{ t('accounts.noUnexpiredSessions') }}</div>
            <ul v-else class="account-sessions">
              <li v-for="(entry, index) in selectedAccount.session_details" :key="index">
                <div class="session-address"><strong>{{ entry.ip_address || t('accounts.unknownIP') }}</strong><span v-if="entry.current" class="pill neutral">{{ t('accounts.current') }}</span></div>
                <dl><div><dt>{{ t('accounts.signedIn') }}</dt><dd>{{ dateTime(entry.created_at) }}</dd></div><div><dt>{{ t('accounts.expires') }}</dt><dd>{{ dateTime(entry.expires_at) }}</dd></div></dl>
              </li>
            </ul>
          </div>
          <div class="card-actions"><button class="button secondary" :disabled="busy || !selectedAccount?.sessions" @click="target && ask(target, 'end-sessions')">{{ t('accounts.endSessions38') }}</button><button class="button secondary" :disabled="busy" @click="close">{{ t('common.close') }}</button></div>
        </template>
        <template v-else-if="mode === 'credentials' && credentials">
          <InfoNote class="card-description">{{ t('accounts.copyThePasswordNowItCannotBe') }}</InfoNote>
          <div class="card-body form-fields account-body"><FloatingField id="created-admin-name" :label="t('accounts.username')" fixed><input id="created-admin-name" :value="credentials.username" readonly placeholder=" "></FloatingField><FloatingField id="created-admin-password" :label="t('accounts.oneTimePassword')" fixed><input id="created-admin-password" :value="credentials.temporary_password" :type="showPassword ? 'text' : 'password'" readonly autocomplete="off" placeholder=" "></FloatingField><button class="button secondary account-reveal" @click="showPassword = !showPassword">{{ showPassword ? t('accounts.hidePassword') : t('accounts.showPassword') }}</button></div>
          <div class="card-actions"><button class="button primary" @click="copy">{{ t('common.copy') }}</button><button class="button secondary" @click="close">{{ t('common.close') }}</button></div>
        </template>
        <form v-else @submit.prevent="confirm">
          <div class="card-body form-fields account-body">
            <template v-if="mode === 'rename'"><p>{{ t('accounts.thisAccountSSessionsWillEndSign') }}</p><FloatingField id="edit-admin-name" :label="t('accounts.signInName')"><input id="edit-admin-name" v-model="editedName" required minlength="3" maxlength="64" pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}" placeholder=" "></FloatingField></template>
            <div v-else-if="mode === 'reset'"><p>{{ t('accounts.thePreviousPasswordForWillStopWorking', { p0: target?.username }) }}</p></div>
            <div v-else-if="mode === 'end-sessions'"><p>{{ t('accounts.allSessionsForWillEndThePassword', { p0: target?.username }) }}<template v-if="target?.current"> {{ t('accounts.youWillAlsoBeSignedOutIn') }}</template></p></div>
            <div v-else><p>{{ t('accounts.theAccountWillBeDeletedAndIts', { p0: target?.username }) }}<template v-if="target?.current"> {{ t('accounts.youWillBeSignedOut') }}</template></p></div>
          </div>
          <div class="card-actions"><button class="button secondary" type="button" :disabled="busy" @click="close">{{ t('common.cancel') }}</button><button class="button primary" type="submit" :disabled="busy">{{ mode === 'end-sessions' ? t('accounts.endSessions38') : t('common.confirm') }}</button></div>
        </form>
      </template>
    </dialog>
  </div>
</template>
<style scoped>
td { vertical-align: middle; }
td.actions-cell { display: table-cell; }
td .button { font-size: 10px; padding: 7px 9px; }
.account-row-actions { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; }
.account-sessions { list-style: none; margin: 0; padding: 0; }
.account-sessions li + li { border-top: 1px solid var(--border); margin-top: 18px; padding-top: 18px; }
.session-address { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; overflow-wrap: anywhere; font-size: 13px; }
.account-sessions dl { margin: 12px 0 0; }
.account-sessions dl > div { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px 16px; margin-top: 8px; }
.session-empty { font-size: 13px; color: var(--muted); }
.account-create { margin-bottom: 24px; }
.account-body > input { width: 100%; }
.account-body p:not(.field-help) { font-size: 13px; line-height: 1.7; color: var(--muted); overflow-wrap: anywhere; }
.account-self, .account-totp { margin-left: 8px; }
.account-reveal { margin-top: 12px; }
</style>
