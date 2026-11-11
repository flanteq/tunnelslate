<script setup lang="ts">
import { t } from './i18n'
import { computed } from 'vue'

const props = defineProps<{ page: number; pageSize: number; total: number; label: string }>()
const emit = defineEmits<{ 'update:page': [page: number]; 'update:pageSize': [size: number] }>()
const pageCount = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))
const start = computed(() => props.total ? (props.page - 1) * props.pageSize + 1 : 0)
const end = computed(() => Math.min(props.page * props.pageSize, props.total))
</script>

<template>
  <nav class="table-pagination" :aria-label="label">
    <span role="status" aria-live="polite">{{ t('pagination.of', { p0: start, p1: end, p2: total }) }}</span>
    <label>{{ t('pagination.perPage') }} <select :value="pageSize" :aria-label="t('pagination.recordsPerPage', { p0: label })" @change="emit('update:pageSize', Number(($event.target as HTMLSelectElement).value))"><option :value="10">10</option><option :value="25">25</option><option :value="50">50</option></select></label>
    <div class="page-navigation">
      <div class="pagination-buttons">
        <button class="button secondary" type="button" :disabled="page === 1" :aria-label="t('pagination.firstPage')" @click="emit('update:page', 1)">«</button>
        <button class="button secondary" type="button" :disabled="page === 1" @click="emit('update:page', page - 1)">{{ t('pagination.previous') }}</button>
        <span class="button secondary page-indicator" role="status" :aria-label="t('pagination.pageOf', { p0: page, p1: pageCount })">{{ page }} / {{ pageCount }}</span>
        <button class="button secondary" type="button" :disabled="page >= pageCount" @click="emit('update:page', page + 1)">{{ t('pagination.next') }}</button>
        <button class="button secondary" type="button" :disabled="page >= pageCount" :aria-label="t('pagination.lastPage')" @click="emit('update:page', pageCount)">»</button>
      </div>
    </div>
  </nav>
</template>

<style scoped>
.table-pagination { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px 20px; padding: 16px 23px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }
.table-pagination label, .page-navigation { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; }
.table-pagination select { padding: 7px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); font: inherit; }
.table-pagination .button { padding: 8px 12px; font-size: 12px; }
.pagination-buttons { align-items: center; justify-content: center; flex-wrap: wrap; }
.page-indicator, .page-indicator:hover { min-width: 7ch; background: var(--bg); color: var(--muted); font-variant-numeric: tabular-nums; cursor: default; }
@media(max-width:600px) {
  .table-pagination { padding: 16px 18px; }
  .page-navigation { width: 100%; justify-content: center; }
  .pagination-buttons { gap: 6px; }
  .table-pagination .button { padding: 8px; }
}
</style>
