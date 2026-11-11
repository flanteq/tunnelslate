<script setup lang="ts">
defineProps<{ name: string; size?: number }>()
const paths: Record<string, string> = {
  traffic: 'M7 3v18 M3 7l4-4 4 4 M17 21V3 M13 17l4 4 4-4',
  globe: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z M3 12h18 M12 3c5 5 5 13 0 18 M12 3c-5 5-5 13 0 18',
  shield: 'M12 3 3 7v6c0 5 6 8 9 9 3-1 9-4 9-9V7l-9-4Z M8 12l3 3 5-6',
  grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M16 3a4 4 0 0 1 0 8 M22 21v-2a4 4 0 0 0-3-3.87 M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z',
  key: 'M15 7a5 5 0 1 1-4.5 7L3 21H1v-3l7.5-7A5 5 0 0 1 15 7Z M17 7h.01',
  certificate: 'M14 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v6 M7 7h10 M7 11h4 M7 15h3 M21 15a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z M16 17.25V22l2-1 2 1v-4.75',
  settings: 'M4 7h16 M4 17h16 M8 4v6 M16 14v6',
  clock: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z M12 7v5l3 2',
  arrow: 'M5 12h14 M14 7l5 5-5 5',
  logout: 'M9 21H4V3h5 M9 12h12 M17 8l4 4-4 4',
  server: 'M3 3h18v7H3z M3 14h18v7H3z M7 6.5h.01 M7 17.5h.01 M12 6.5h5 M12 17.5h5',
  refresh: 'M3 12a9 9 0 0 1 15.36-6.36L21 8 M21 3v5h-5 M21 12a9 9 0 0 1-15.36 6.36L3 16 M3 21v-5h5',
  lock: 'M5 10h14v11H5z M8 10V6a4 4 0 0 1 8 0v4 M12 15v2',
  check: 'M5 12l4 4L19 6',
  close: 'M6 6l12 12 M18 6 6 18',
  chevron: 'm9 5 7 7-7 7',
  info: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z M12 11v6 M12 7h.01',
  database: 'M20 6c0 2-4 3-8 3S4 8 4 6s4-3 8-3 8 1 8 3Z M4 6v12c0 2 4 3 8 3s8-1 8-3V6 M4 12c0 2 4 3 8 3s8-1 8-3',
  activity: 'M2 12h5l3-9 4 18 3-9h5',
  sun: 'M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z M12 2v2 M12 20v2 M2 12h2 M20 12h2 M5 5l1 1 M18 18l1 1 M5 19l1-1 M18 6l1-1',
}
</script>
<template>
  <svg :width="size ?? 20" :height="size ?? 20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path :d="paths[name] ?? paths.info" /></svg>
</template>
