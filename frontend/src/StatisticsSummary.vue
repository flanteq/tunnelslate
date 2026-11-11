<script setup lang="ts">
import { t, formatNumber } from './i18n'
import { formatBytes, formatDuration } from './statistics'
import type { StatisticsTotals } from './statistics'
defineProps<{ totals: StatisticsTotals }>()
</script>
<template>
  <dl class="statistics-summary">
    <div><dt>{{ t('statistics.sessions') }}</dt><dd>{{ formatNumber(totals.sessions) }}</dd></div>
    <div><dt>{{ t('statistics.duration') }}</dt><dd>{{ formatDuration(totals.duration_seconds) }}</dd></div>
    <div><dt>{{ t('statistics.received') }}</dt><dd>{{ formatBytes(totals.bytes_received) }}</dd></div>
    <div><dt>{{ t('statistics.sent') }}</dt><dd>{{ formatBytes(totals.bytes_sent) }}</dd></div>
  </dl>
</template>
<style scoped>
.statistics-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 20px; margin: 0; }
dt { color: var(--muted); font-size: 12px; line-height: 1.6; }
dd { text-align: left; margin: 6px 0 0; font-size: 18px; font-weight: 600; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
@media(max-width:600px) { .statistics-summary { grid-template-columns: repeat(2,minmax(0,1fr)); gap: 16px; } dd { font-size: 16px; } }
</style>
