import { computed, ref, watch } from 'vue'
import type { Ref } from 'vue'

export function usePagination<T>(source: () => T[], query?: Ref<string>) {
  const page = ref(1)
  const pageSize = ref(10)
  const total = computed(() => source().length)
  const pageCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))
  watch(query ? [query, pageSize] : [pageSize], () => { page.value = 1 }, { flush: 'sync' })
  watch(pageCount, count => { page.value = Math.min(page.value, count) }, { flush: 'sync' })
  const items = computed(() => source().slice((page.value - 1) * pageSize.value, page.value * pageSize.value))
  return { page, pageSize, total, pageCount, items }
}
