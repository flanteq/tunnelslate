<script setup lang="ts">
import Icon from './Icon.vue'
</script>

<template>
  <div class="info-note"><Icon name="info" :size="16" /><div class="info-note-content"><slot /></div></div>
</template>

<style scoped>
.info-note { display: flex; align-items: flex-start; gap: 8px; }
.info-note > svg { flex-shrink: 0; margin-top: 2px; }
.info-note-content { min-width: 0; flex: 1; }
.info-note-content :deep(p) { margin: 0; }
</style>
