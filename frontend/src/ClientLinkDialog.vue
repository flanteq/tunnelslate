<script setup lang="ts">
import FloatingField from './FloatingField.vue'
import { t } from './i18n'
import { onMounted, ref } from 'vue'
import type { Client } from './api'
import { api, errorText } from './api'
import InfoNote from './InfoNote.vue'
import { notifications } from './notifications'
const props = defineProps<{ client: Client; csrf: string }>()
const emit = defineEmits<{ close: []; refresh: [] }>()
const dialog = ref<HTMLDialogElement | null>(null)
const action = ref('')
const url = ref(''), busy = ref(false), active = ref(!!props.client.link_created_at)
let requestKey = crypto.randomUUID()
onMounted(() => dialog.value?.showModal())
async function save(kind: string) {
  busy.value = true
  try {
    const suffix = kind === 'create' || kind === 'rotate' ? '' : `/${kind}`
    const body = suffix ? {} : { replace: kind === 'rotate' }
    const result = await api<{ url?: string }>(`/clients/${props.client.id}/link${suffix}`, { method: 'POST', headers: { 'X-CSRF-Token': props.csrf, 'Idempotency-Key': requestKey }, body: JSON.stringify(body) })
    requestKey = crypto.randomUUID()
    url.value = result.url ?? ''; active.value = !!result.url; action.value = ''; emit('refresh')
    if (kind === 'compromised') emit('close')
  } catch (err) { notifications.error(() => errorText(err, t('links.couldNotUpdateTheLink'))) }
  finally { busy.value = false }
}
async function copy() {
  try { await navigator.clipboard.writeText(url.value) }
  catch { notifications.error(() => t('links.couldNotCopyTheLinkSelectAnd')) }
}
</script>
<template>
  <dialog ref="dialog" class="client-link-dialog" @cancel.prevent="!busy && emit('close')">
    <div class="card-heading"><h2>{{ t('links.profileLink', { p0: client.name }) }}</h2></div>
    <template v-if="action">
      <div class="card-body client-link-body">
        <div v-if="action === 'compromised'"><p>{{ t('links.theLinkWillBeDeletedImmediatelyAll') }}</p></div>
        <div v-else-if="action === 'rotate'"><p>{{ t('links.thePreviousLinkAndItsSessionsWill') }}</p></div>
        <div v-else><p>{{ t('links.theLinkAndItsSessionsWillStop') }}</p></div>
      </div>
      <div class="card-actions client-link-actions"><button class="button secondary" :disabled="busy" @click="action = ''">{{ t('common.cancel') }}</button><button class="button primary" :disabled="busy" @click="save(action)">{{ t('common.confirm') }}</button></div>
    </template>
    <template v-else>
      <InfoNote class="card-description">{{ t('links.anyoneWithThisLinkCanDownloadAll') }}</InfoNote>
      <div class="card-body client-link-body">
        <template v-if="url"><p>{{ t('links.copyTheLinkNowItCannotBe') }}</p><FloatingField id="client-share-url" :label="t('links.clientLink')" fixed><textarea id="client-share-url" :value="url" readonly rows="4" spellcheck="false" @focus="($event.target as HTMLTextAreaElement).select()"></textarea></FloatingField></template>
        <div v-else><p>{{ active ? t('links.theLinkIsActiveRegenerateItTo') : t('links.noLinkHasBeenCreatedYouCan') }}</p></div>
      </div>
      <div :class="['card-actions', 'client-link-actions', { 'fresh-link-actions': !!url }]">
        <template v-if="url"><button class="button primary" :disabled="busy" @click="copy">{{ t('common.copy') }}</button><button class="button secondary" :disabled="busy" @click="action = 'rotate'">{{ t('links.regenerate') }}</button></template>
        <button v-else-if="!active" class="button primary" :disabled="busy" @click="save('create')">{{ t('common.createLink') }}</button>
        <template v-else><button class="button secondary" :disabled="busy" @click="action = 'rotate'">{{ t('links.regenerateLink') }}</button><button class="button secondary danger" :disabled="busy" @click="action = 'delete'">{{ t('links.deleteLink') }}</button><button class="button secondary danger" :disabled="busy" @click="action = 'compromised'">{{ t('common.linkCompromised') }}</button></template>
        <button class="button secondary" :disabled="busy" @click="emit('close')">{{ t('common.close') }}</button>
      </div>
    </template>
  </dialog>
</template>
