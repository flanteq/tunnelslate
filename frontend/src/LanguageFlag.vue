<script setup lang="ts">
import type { Language } from './i18n'
defineProps<{ language: Language }>()
</script>

<template>
  <svg class="language-flag" width="24" height="16" viewBox="0 0 60 40" aria-hidden="true">
    <template v-if="language === 'ru'">
      <path fill="#fff" d="M0 0h60v40H0z" /><path fill="#0039a6" d="M0 13.333h60v13.334H0z" /><path fill="#d52b1e" d="M0 26.667h60V40H0z" />
    </template>
    <template v-else>
      <path fill="#012169" d="M0 0h60v40H0z" />
      <path stroke="#fff" stroke-width="10" d="m0 0 60 40M60 0 0 40" />
      <path fill="#c8102e" d="m0 0 30 20h-6L0 4Zm60 0L30 20v-4L54 0ZM0 40l30-20v4L6 40Zm60 0L30 20h6l24 16Z" />
      <path stroke="#fff" stroke-width="14" d="M30 0v40M0 20h60" /><path stroke="#c8102e" stroke-width="8" d="M30 0v40M0 20h60" />
    </template>
  </svg>
</template>

<style scoped>
.language-flag { display: block; flex-shrink: 0; border-radius: 3px; overflow: hidden; box-shadow: 0 0 0 1px #0002; }
</style>
