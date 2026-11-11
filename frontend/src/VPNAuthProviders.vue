<script setup lang="ts">
import FloatingField from './FloatingField.vue'
import { computed, nextTick, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import { api, errorText } from './api'
import type { VPNAuthProvider, Settings } from './api'
import { t } from './i18n'
import { notifications } from './notifications'
import InfoNote from './InfoNote.vue'
import Icon from './Icon.vue'

const props=defineProps<{csrf:string;refreshKey:Settings}>(),emit=defineEmits<{refresh:[]}>()
const loaded=ref(false)
const providers=ref<VPNAuthProvider[]>([]),loading=ref(true),loadFailed=ref(false),busy=ref(false)
const editing=ref<VPNAuthProvider>(),removing=ref<VPNAuthProvider>(),dialog=ref<HTMLDialogElement>(),confirmation=ref<HTMLDialogElement>()
const testUsername=ref(''),testPassword=ref(''),tested=ref(false),original=ref('')
const controller=new AbortController()
const dirty=computed(()=>JSON.stringify(editing.value)!==original.value)
const headers=()=>({'X-CSRF-Token':props.csrf})
async function load(){loading.value=!loaded.value;loadFailed.value=false;try{providers.value=await api<VPNAuthProvider[]>('/vpn-auth/providers',{signal:controller.signal});loaded.value=true}catch(e){if(!controller.signal.aborted){loadFailed.value=true;notifications.error(()=>errorText(e))}}finally{loading.value=false}}
async function edit(provider?:VPNAuthProvider){
 editing.value=provider?JSON.parse(JSON.stringify(provider)):{id:'',name:'',kind:'ldap',enabled:true,revision:0,has_secret:false,secret:'',config:{address:'ldaps://ldap.example.com:636',bind_dn:'',base_dn:'',user_filter:'(uid={username})',group_dn:'',group_filter:'(member={dn})',ca_pem:'',nas_identifier:'tunnelslate',timeout_seconds:90}}
 if(editing.value){editing.value.secret='';editing.value.config.timeout_seconds ||= 90;}original.value=JSON.stringify(editing.value);testPassword.value='';testUsername.value='';tested.value=false
 await nextTick();dialog.value?.showModal()
}
function changeKind(){const p=editing.value;if(!p||p.id)return;p.config.address=p.kind==='ldap'?'ldaps://ldap.example.com:636':'radius.example.com:1812'}
function close(){if(busy.value)return;dialog.value?.close();editing.value=undefined;testPassword.value=''}
async function save(){if(!editing.value)return;busy.value=true;try{
 const p=editing.value;const result=await api<VPNAuthProvider>(p.id?`/vpn-auth/providers/${p.id}`:'/vpn-auth/providers',{method:p.id?'PUT':'POST',headers:headers(),body:JSON.stringify(p)})
 editing.value={...result,secret:''};original.value=JSON.stringify(editing.value);tested.value=false;await load();emit('refresh')
}catch(e){notifications.error(()=>errorText(e))}finally{busy.value=false}}
async function askDelete(provider:VPNAuthProvider){removing.value=provider;await nextTick();confirmation.value?.showModal()}
async function remove(){if(!removing.value)return;busy.value=true;try{await api(`/vpn-auth/providers/${removing.value.id}/delete`,{method:'POST',headers:headers(),body:JSON.stringify({revision:removing.value.revision})});confirmation.value?.close();removing.value=undefined;await load();emit('refresh')}catch(e){notifications.error(()=>errorText(e))}finally{busy.value=false}}
async function test(){if(!editing.value?.id)return;busy.value=true;tested.value=false;try{await api(`/vpn-auth/providers/${editing.value.id}/test`,{method:'POST',headers:headers(),body:JSON.stringify({username:testUsername.value,password:testPassword.value})});tested.value=true}catch(e){notifications.error(()=>errorText(e))}finally{testPassword.value='';busy.value=false}}
watch(()=>props.refreshKey,()=>{if(!loading.value&&!busy.value)void load()});
onMounted(()=>void load());onBeforeUnmount(()=>controller.abort())
</script>
<template>
  <div class="card-heading"><h2>{{ t('vpnAuth.providers') }}</h2><button class="button secondary" type="button" :disabled="loading || busy" @click="edit()">{{ t('vpnAuth.addProvider') }}</button></div>
  <div v-if="loading" class="compact-empty">{{ t('vpnAuth.loading') }}</div>
  <div v-else-if="loadFailed" class="compact-empty"><button class="button secondary" @click="load">{{ t('ccd.retry') }}</button></div>
  <div v-else-if="!providers.length" class="compact-empty">{{ t('vpnAuth.noProviders') }}</div>
  <div v-else class="table-scroll"><table><thead><tr><th>{{ t('clients.name') }}</th><th>{{ t('vpnAuth.type') }}</th><th>{{ t('vpnAuth.address') }}</th><th>{{ t('clients.status') }}</th><th>{{ t('common.actions') }}</th></tr></thead><tbody><tr v-for="provider in providers" :key="provider.id"><td><strong>{{ provider.name }}</strong></td><td>{{ provider.kind.toUpperCase() }}</td><td>{{ provider.config.address }}</td><td><span :class="['pill',provider.enabled?'success':'neutral']">{{ provider.enabled?t('network.enabled'):t('network.disabled') }}</span></td><td class="actions-cell"><button class="button secondary" :disabled="busy" @click="edit(provider)">{{ t('vpnAuth.edit') }}</button><button class="button secondary danger" :disabled="busy" @click="askDelete(provider)">{{ t('common.delete') }}</button></td></tr></tbody></table></div>
  <dialog ref="dialog" class="ccd-dialog" aria-labelledby="vpn-provider-title" @cancel.prevent="close">
    <template v-if="editing">
    <div class="ccd-dialog-heading"><h2 id="vpn-provider-title">{{ editing.id?t('vpnAuth.editProvider'):t('vpnAuth.addProvider') }}</h2><button class="icon-button" type="button" :disabled="busy" :aria-label="t('common.close')" @click="close"><Icon name="close" :size="18" /></button></div>
    <form @submit.prevent="save"><div class="card-body form-fields"><fieldset :disabled="busy"><section class="ccd-section">
      <FloatingField id="provider-name" :label="t('clients.name')"><input id="provider-name" v-model="editing.name" required maxlength="128" autocomplete="off" placeholder=" "></FloatingField>
      <FloatingField id="provider-kind" :label="t('vpnAuth.type')" fixed><select id="provider-kind" v-model="editing.kind" :disabled="!!editing.id" @change="changeKind"><option value="ldap">LDAP</option><option value="radius">RADIUS</option></select></FloatingField>
      <FloatingField id="provider-address" :label="t('vpnAuth.address')"><input id="provider-address" v-model="editing.config.address" required autocomplete="off" placeholder=" "></FloatingField>
      <template v-if="editing.kind==='ldap'">
        <InfoNote class="field-help">{{ t('vpnAuth.ldapHelp') }}</InfoNote>
        <FloatingField id="provider-bind-dn" :label="t('vpnAuth.bindDN')"><input id="provider-bind-dn" v-model="editing.config.bind_dn" required maxlength="1024" placeholder="cn=reader,dc=example,dc=com" autocomplete="off"></FloatingField>
        <FloatingField id="provider-secret" :label="t('vpnAuth.bindPassword')"><input id="provider-secret" v-model="editing.secret" type="password" :required="!editing.has_secret" minlength="1" maxlength="4096" autocomplete="new-password" :placeholder="editing.has_secret?t('vpnAuth.keepSecret'):' '"></FloatingField>
        <FloatingField id="provider-base-dn" :label="t('vpnAuth.baseDN')"><input id="provider-base-dn" v-model="editing.config.base_dn" required maxlength="1024" placeholder="ou=people,dc=example,dc=com" autocomplete="off"></FloatingField>
        <FloatingField id="provider-user-filter" :label="t('vpnAuth.userFilter')"><input id="provider-user-filter" v-model="editing.config.user_filter" required maxlength="2048" autocomplete="off" placeholder=" "></FloatingField><InfoNote class="field-help">{{ t('vpnAuth.filterHelp') }}</InfoNote>
        <FloatingField id="provider-group-dn" :label="t('vpnAuth.groupDN')"><input id="provider-group-dn" v-model="editing.config.group_dn" maxlength="1024" autocomplete="off" placeholder=" "></FloatingField>
        <template v-if="editing.config.group_dn"><FloatingField id="provider-group-filter" :label="t('vpnAuth.groupFilter')"><input id="provider-group-filter" v-model="editing.config.group_filter" required maxlength="2048" autocomplete="off" placeholder=" "></FloatingField><InfoNote class="field-help">{{ t('vpnAuth.groupHelp') }}</InfoNote></template>
        <FloatingField id="provider-ca" :label="t('vpnAuth.ca')" fixed><textarea id="provider-ca" v-model="editing.config.ca_pem" rows="3" placeholder="-----BEGIN CERTIFICATE-----" spellcheck="false"></textarea></FloatingField>
      </template>
      <template v-else>
        <InfoNote class="field-help">{{ t('vpnAuth.radiusHelp') }}</InfoNote>
        <FloatingField id="provider-nas" label="NAS-Identifier"><input id="provider-nas" v-model="editing.config.nas_identifier" maxlength="128" autocomplete="off" placeholder=" "></FloatingField>
        <FloatingField id="provider-secret" :label="t('vpnAuth.sharedSecret')"><input id="provider-secret" v-model="editing.secret" type="password" :required="!editing.has_secret" minlength="16" maxlength="4096" autocomplete="new-password" :placeholder="editing.has_secret?t('vpnAuth.keepSecret'):' '"></FloatingField>
        <FloatingField id="provider-timeout" :label="t('vpnAuth.timeout')"><input id="provider-timeout" v-model.number="editing.config.timeout_seconds" type="number" required min="5" max="300" step="1" aria-describedby="provider-timeout-help" placeholder=" "></FloatingField><InfoNote id="provider-timeout-help" class="field-help">{{ t('vpnAuth.timeoutHelp') }}</InfoNote>
      </template>
      <div class="dco-control vpn-auth-enabled"><label class="dco-switch" for="provider-enabled"><input id="provider-enabled" class="dco-switch-input" type="checkbox" role="switch" v-model="editing.enabled"><span class="dco-switch-track" aria-hidden="true"></span><span>{{ t('vpnAuth.providerEnabled') }}</span></label></div>
      <InfoNote class="field-help">{{ t('vpnAuth.providerChangesHelp') }}</InfoNote>
    </section>
    <section v-if="editing.id" class="ccd-section"><h3>{{ t('vpnAuth.testTitle') }}</h3><InfoNote class="field-help">{{ t('vpnAuth.testHelp') }}</InfoNote><FloatingField id="provider-test-username" :label="t('vpnAuth.username')"><input id="provider-test-username" v-model="testUsername" autocomplete="off" maxlength="128" placeholder=" "></FloatingField><FloatingField id="provider-test-password" :label="t('vpnAuth.testPassword')"><input id="provider-test-password" v-model="testPassword" type="password" autocomplete="off" maxlength="4096" placeholder=" "></FloatingField><div class="vpn-auth-test-actions"><button class="button secondary" type="button" :disabled="dirty || !testUsername || !testPassword" @click="test">{{ t('vpnAuth.test') }}</button><span v-if="tested && !dirty" class="pill success" role="status">{{ t('vpnAuth.testPassed') }}</span></div></section>
    </fieldset></div><div class="card-actions"><button class="button secondary" type="button" :disabled="busy" @click="close">{{ t('common.close') }}</button><button class="button primary" type="submit" :disabled="busy || !dirty">{{ busy?t('common.saving'):t('vpnAuth.save') }}</button></div></form>
    </template>
  </dialog>
  <dialog ref="confirmation" class="confirmation-dialog" @cancel="removing=undefined"><form @submit.prevent="remove"><div class="card-heading"><h2>{{ t('vpnAuth.deleteTitle') }}</h2></div><div class="card-body dialog-copy"><p>{{ t('vpnAuth.deleteHelp',{name:removing?.name??''}) }}</p></div><div class="card-actions"><button class="button secondary" type="button" :disabled="busy" @click="confirmation?.close();removing=undefined">{{ t('common.cancel') }}</button><button class="button primary danger" type="submit" :disabled="busy">{{ t('common.delete') }}</button></div></form></dialog>
</template>

<style scoped>
.vpn-auth-enabled{margin-top:20px}.vpn-auth-test-actions{display:flex;align-items:center;gap:12px;margin-top:16px}
</style>
