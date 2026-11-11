<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { t, formatNumber, formatDate } from './i18n'
import { api, errorText } from './api'
import type { Client } from './api'
import type { ClientStatistics, DailyStatistics } from './statistics'
import { formatBytes, formatDuration } from './statistics'
import { notifications } from './notifications'
import StatisticsSummary from './StatisticsSummary.vue'
import TablePagination from './TablePagination.vue'
import InfoNote from './InfoNote.vue'
import Icon from './Icon.vue'
const props = defineProps<{ client: Client; revision: number }>()
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement | null>(null), statistics = ref<ClientStatistics | null>(null)
const expanded = reactive(new Set<string>())
const daily = reactive<Record<string, DailyStatistics>>({})
const requests = new Map<string, AbortController>()
const retries = new Map<string, ReturnType<typeof setTimeout>>()
let stopped = false
function cancel(key: string) { requests.get(key)?.abort(); requests.delete(key); clearTimeout(retries.get(key)); retries.delete(key) }
async function load(key: string, path: string, apply: (data: unknown) => void, attempt = 0) {
  if (stopped || requests.has(key) || retries.has(key)) return
  cancel(key)
  const controller = new AbortController(); requests.set(key, controller)
  try {
    const data = await api(path, { signal: controller.signal })
    if (!stopped && !controller.signal.aborted) apply(data)
  } catch (error) {
    if (stopped || controller.signal.aborted) return
    const status = (error as { status?: number }).status
    const retryable = status === undefined || status === 408 || status === 429 || status >= 500
    if (!attempt) notifications.error(() => errorText(error))
    if (retryable) retries.set(key, setTimeout(() => { retries.delete(key); void load(key, path, apply, attempt + 1) }, Math.min(30_000, 2000 * 2 ** Math.min(attempt, 4))))
  } finally { if (requests.get(key) === controller) requests.delete(key) }
}
function loadDays(id: string, page = daily[id]?.page ?? 1, size = daily[id]?.page_size ?? 10) {
  if (daily[id] && (daily[id].page !== page || daily[id].page_size !== size)) cancel(id)
  void load(id, `/clients/${props.client.id}/statistics/devices/${id}/days?page=${page}&page_size=${size}`, data => { daily[id] = data as DailyStatistics })
}
function refresh() {
  void load('client', `/clients/${props.client.id}/statistics`, data => {
    statistics.value = data as ClientStatistics
    for (const id of expanded) {
      if (statistics.value.devices.some(device => device.id === id)) loadDays(id)
      else { expanded.delete(id); cancel(id); delete daily[id] }
    }
  })
}
function toggle(id: string) { if (expanded.has(id)) { expanded.delete(id); cancel(id) } else { expanded.add(id); loadDays(id) } }
onMounted(() => { dialog.value?.showModal(); refresh() })
watch(() => props.revision, refresh)
onUnmounted(() => { stopped = true; for (const key of requests.keys()) cancel(key); for (const timer of retries.values()) clearTimeout(timer) })
const dayLabel = (value: string) => formatDate(new Date(`${value}T00:00:00Z`), { timeZone: 'UTC' })
</script>
<template>
  <dialog ref="dialog" class="statistics-dialog account-dialog" :aria-label="t('statistics.clientTitle', { name: client.name })" @cancel.prevent="emit('close')">
    <div class="card-heading"><h2>{{ t('statistics.clientTitle', { name: client.name }) }}</h2><button class="icon-button" :aria-label="t('common.close')" @click="emit('close')"><Icon name="close" :size="18" /></button></div>
    <InfoNote class="card-description">{{ t('statistics.description', { days: statistics?.retention_days ?? 90 }) }}</InfoNote>
    <template v-if="statistics">
      <div class="card-body"><StatisticsSummary :totals="statistics.totals" /></div>
      <section v-for="device in statistics.devices" :key="device.id" class="statistics-device">
        <div class="card-heading"><h3>{{ device.name }}</h3><button class="button secondary" :aria-expanded="expanded.has(device.id)" :aria-controls="`statistics-${device.id}`" @click="toggle(device.id)">{{ expanded.has(device.id) ? t('statistics.hideDays') : t('statistics.showDays') }}</button></div>
        <div class="card-body"><StatisticsSummary :totals="device.totals" /></div>
        <div v-if="expanded.has(device.id)" :id="`statistics-${device.id}`">
          <template v-if="daily[device.id]">
            <div v-if="daily[device.id].days.length" class="table-scroll"><table><thead><tr><th>{{ t('statistics.dayUTC') }}</th><th>{{ t('statistics.sessions') }}</th><th>{{ t('statistics.duration') }}</th><th>{{ t('statistics.received') }}</th><th>{{ t('statistics.sent') }}</th></tr></thead><tbody><tr v-for="day in daily[device.id].days" :key="day.date"><td>{{ dayLabel(day.date) }}</td><td>{{ formatNumber(day.sessions) }}</td><td>{{ formatDuration(day.duration_seconds) }}</td><td>{{ formatBytes(day.bytes_received) }}</td><td>{{ formatBytes(day.bytes_sent) }}</td></tr></tbody></table></div>
            <div v-else class="card-body"><p>{{ t('statistics.noDays') }}</p></div>
            <TablePagination v-if="daily[device.id].total" :page="daily[device.id].page" :page-size="daily[device.id].page_size" :total="daily[device.id].total" :label="t('statistics.dailyPages', { name: device.name })" @update:page="loadDays(device.id, $event)" @update:page-size="loadDays(device.id, 1, $event)" />
          </template>
          <div v-else class="card-body" role="status"><p>{{ t('common.loading') }}</p></div>
        </div>
      </section>
      <div v-if="!statistics.devices.length" class="card-body"><p>{{ t('clients.noDevicesYet') }}</p></div>
    </template>
    <div v-else class="card-body" role="status"><p>{{ t('common.loading') }}</p></div>
    <div class="card-actions"><button class="button secondary" @click="emit('close')">{{ t('common.close') }}</button></div>
  </dialog>
</template>
<style scoped>
.statistics-dialog { width: min(900px,calc(100% - 32px)); }
.statistics-dialog > .card-heading { position: sticky; top: 0; z-index: 2; background: var(--surface); }
.statistics-dialog > .card-actions { position: sticky; bottom: 0; z-index: 2; background: var(--surface); }
.statistics-device { border-top: 1px solid var(--border); }
.statistics-device .card-heading { border-bottom: 0; }
.statistics-device h3 { font-size: 14px; margin: 0; }
.statistics-device .card-heading .button { font-size: 12px; }
.statistics-device .card-body { padding-top: 0; }
.statistics-device table { min-width: 560px; }
</style>
