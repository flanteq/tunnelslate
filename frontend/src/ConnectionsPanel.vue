<script setup lang="ts">
import { t, formatNumber, formatDateTime } from './i18n'
import { ref } from 'vue'
import { api, errorText } from './api'
import { notifications } from './notifications'
import type { Connection } from './api'
const props = defineProps<{ connections: Connection[]; state: string; csrf: string }>()
const emit = defineEmits<{ refresh: [] }>()
const pending = ref('')
const bytes = (value: number) => value < 1048576 ? t('connections.kb', { p0: formatNumber(value / 1024, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) }) : t('connections.mb', { p0: formatNumber(value / 1048576, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) })
async function disconnect(cn: string) {
  pending.value = cn
  try {
    await api('/connections/disconnect', { method: 'POST', headers: { 'X-CSRF-Token': props.csrf }, body: JSON.stringify({ common_name: cn }) })
  }
  catch (err) { notifications.error(() => errorText(err, t('connections.couldNotDisconnectTheSession'))) }
  finally { pending.value = ''; emit('refresh') }
}
</script>
<template>
  <section class="card connections-card"><div class="card-heading"><h2>{{ t('connections.activeConnections') }}</h2><span :class="['pill', state === 'connected' ? 'success' : 'neutral']">{{ state === 'connected' ? t('connections.online', { p0: connections.length }) : t('connections.openvpnUnavailable') }}</span></div><div v-if="state !== 'connected'" class="compact-empty">{{ t('connections.checkTheVPNContainerAndManagementInterface') }}</div><div v-else-if="!connections.length" class="compact-empty">{{ t('connections.theServerIsAvailableNoClientsAre') }}</div><div v-else class="table-scroll"><table><thead><tr><th>{{ t('common.clientDevice') }}</th><th>{{ t('connections.address') }}</th><th>VPN IP</th><th>{{ t('connections.receivedSent') }}</th><th>{{ t('connections.connectedSince') }}</th><th></th></tr></thead><tbody><tr v-for="connection in connections" :key="connection.common_name"><td>{{ connection.client || t('connections.unknownClient') }} / {{ connection.device || connection.common_name }}</td><td>{{ connection.real_address }}</td><td>{{ connection.virtual_address }}</td><td>{{ bytes(connection.bytes_received) }} / {{ bytes(connection.bytes_sent) }}</td><td>{{ formatDateTime(connection.connected_since) }}</td><td><button class="button secondary" :disabled="!!pending || !connection.device" @click="disconnect(connection.common_name)">{{ pending === connection.common_name ? t('connections.disconnecting') : t('connections.disconnect') }}</button></td></tr></tbody></table></div></section>
</template>
