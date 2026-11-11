import { computed, ref, watch } from 'vue'
import type { Ref } from 'vue'
import { dateLocale } from './i18n.ts'
import type { Client } from './api'

export function useClientList(source: () => Client[], query: Ref<string>) {
  const page = ref(1)
  const pageSize = ref(10)
  const collator = computed(() => new Intl.Collator(dateLocale.value, { sensitivity: 'base', numeric: true }))
  const sortedClients = computed(() => [...source()].sort((a, b) => collator.value.compare(a.name, b.name) || a.id.localeCompare(b.id)))
  const matchingClients = computed(() => {
    const search = query.value.trim().toLocaleLowerCase(dateLocale.value)
    return sortedClients.value.filter(client => client.name.toLocaleLowerCase(dateLocale.value).includes(search))
  })
  const pageCount = computed(() => Math.max(1, Math.ceil(matchingClients.value.length / pageSize.value)))
  watch([query, pageSize], () => { page.value = 1 }, { flush: 'sync' })
  watch(pageCount, count => { page.value = Math.min(page.value, count) }, { flush: 'sync' })
  const visibleClients = computed(() => matchingClients.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value))
  const rangeStart = computed(() => matchingClients.value.length ? (page.value - 1) * pageSize.value + 1 : 0)
  const rangeEnd = computed(() => Math.min(page.value * pageSize.value, matchingClients.value.length))

  return { page, pageSize, sortedClients, matchingClients, pageCount, visibleClients, rangeStart, rangeEnd }
}
