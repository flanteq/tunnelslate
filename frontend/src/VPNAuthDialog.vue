<script setup lang="ts">
import FloatingField from './FloatingField.vue'
import { onMounted, onBeforeUnmount, ref } from 'vue'
import { api, errorText } from './api'
import type { VPNAuthBinding, VPNAuthView } from './api'
import { t } from './i18n'
import { notifications } from './notifications'
import InfoNote from './InfoNote.vue'
import Icon from './Icon.vue'

const props=defineProps<{subject:{id:string;name:string};csrf:string}>()
const emit=defineEmits<{close:[];refresh:[]}>()
const dialog=ref<HTMLDialogElement>(),view=ref<VPNAuthView>(),form=ref<VPNAuthBinding>(),busy=ref(false),loading=ref(true)
const controller=new AbortController()
const path=`/clients/${props.subject.id}/vpn-auth`
function populate(v:VPNAuthView){view.value=v;form.value={...v.binding}}
async function load(){loading.value=true;try{populate(await api<VPNAuthView>(path,{signal:controller.signal}))}catch(e){if(!controller.signal.aborted)notifications.error(()=>errorText(e))}finally{loading.value=false}}
async function save(){if(!form.value)return;busy.value=true;try{populate(await api<VPNAuthView>(path,{method:'PUT',headers:{'X-CSRF-Token':props.csrf},body:JSON.stringify(form.value)}));emit('refresh');close(true)}catch(e){notifications.error(()=>errorText(e));await load()}finally{busy.value=false;emit('refresh')}}
function close(force=false){if(busy.value&&!force)return;dialog.value?.close();emit('close')}

onMounted(()=>{dialog.value?.showModal();void load()});onBeforeUnmount(()=>controller.abort())
</script>
<template>
  <dialog ref="dialog" class="ccd-dialog" aria-labelledby="vpn-auth-binding-title" @cancel.prevent="close()">
    <div class="ccd-dialog-heading"><div><h2 id="vpn-auth-binding-title">{{ t('vpnAuth.accessTitle') }}</h2><p>{{ subject.name }}</p></div><button class="icon-button" type="button" :aria-label="t('common.close')" :disabled="busy" @click="close()"><Icon name="close" :size="18" /></button></div>
    <div v-if="loading" class="ccd-loading">{{ t('vpnAuth.loading') }}</div>
    <form v-else-if="form && view" @submit.prevent="save">
      <InfoNote class="card-description">{{ t('vpnAuth.bindingHelp') }}</InfoNote>
      <div class="card-body form-fields"><fieldset :disabled="busy"><section class="ccd-section">
        <FloatingField id="vpn-auth-mode" :label="t('vpnAuth.method')" fixed><select id="vpn-auth-mode" v-model="form.mode"><option value="certificate">{{ t('vpnAuth.certificate') }}</option><option value="external">{{ t('vpnAuth.external') }}</option></select></FloatingField>
        <template v-if="form.mode==='external'">
          <FloatingField id="vpn-auth-provider" :label="t('vpnAuth.provider')" fixed><select id="vpn-auth-provider" v-model="form.provider_id" required><option disabled value="">{{ t('vpnAuth.chooseProvider') }}</option><option v-for="provider in view.providers" :key="provider.id" :value="provider.id" :disabled="!provider.enabled">{{ provider.name }} · {{ provider.kind.toUpperCase() }}{{ provider.enabled?'':` · ${t('network.disabled')}` }}</option></select></FloatingField>
          <InfoNote v-if="!view.providers.length" class="field-help">{{ t('vpnAuth.noProvidersHelp') }}</InfoNote>
          <FloatingField id="vpn-auth-username" :label="t('vpnAuth.username')"><input id="vpn-auth-username" v-model="form.username" required maxlength="128" pattern="[A-Za-z0-9_.@\-]+" autocomplete="off" placeholder="user@example.com"></FloatingField>
        </template>
        <InfoNote v-if="view.disconnect_pending" class="field-help">{{ t('vpnAuth.disconnectPending') }}</InfoNote>
      </section></fieldset></div>
      <div class="card-actions"><button class="button secondary" type="button" :disabled="busy" @click="close()">{{ t('common.close') }}</button><button class="button primary" type="submit" :disabled="busy || (form.mode==='external' && (!form.provider_id || !form.username))">{{ busy?t('common.saving'):t('vpnAuth.save') }}</button></div>
    </form>
    <div v-else class="ccd-loading"><button class="button secondary" @click="load">{{ t('ccd.retry') }}</button></div>
  </dialog>
</template>
