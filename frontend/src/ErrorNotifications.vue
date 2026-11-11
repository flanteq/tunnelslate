<script setup lang="ts">
import { t } from './i18n'
import Icon from './Icon.vue'
import { notifications } from './notifications'

const { items, dismiss } = notifications
</script>

<template>
  <Teleport to="body">
    <TransitionGroup name="error-toast" tag="div" class="error-notifications" role="region" :aria-label="t('notifications.errors')">
      <div v-for="item in items" :key="item.id" class="error-toast" role="alert" aria-atomic="true">
        <Icon name="info" :size="20" />
        <p>{{ typeof item.message === 'function' ? item.message() : item.message }}</p>
        <button class="icon-button error-toast-close" :aria-label="t('notifications.dismissErrorMessage')" @click="dismiss(item.id)"><Icon name="close" :size="18" /></button>
      </div>
    </TransitionGroup>
  </Teleport>
</template>

<style>
.error-notifications { position: fixed; z-index: 2000; bottom: max(16px, env(safe-area-inset-bottom)); right: max(16px, env(safe-area-inset-right)); left: max(16px, env(safe-area-inset-left)); width: min(380px, calc(100% - 32px)); max-height: calc(100dvh - 32px); margin-left: auto; display: flex; flex-direction: column; gap: 10px; overflow-y: auto; overscroll-behavior: contain; pointer-events: none; }
.error-toast { display: grid; grid-template-columns: 20px minmax(0, 1fr) 28px; align-items: center; flex-shrink: 0; gap: 12px; padding: 12px 16px; border: 1px solid var(--border-strong); border-left: 3px solid var(--error); border-radius: 10px; background: var(--surface); color: var(--text); box-shadow: 0 6px 20px #0002; pointer-events: auto; }
.error-toast > svg { display: block; margin: 0; color: var(--error); }
.error-toast p { min-width: 0; margin: 0; padding: 0; font-size: 13px; line-height: 20px; overflow-wrap: anywhere; }
.error-toast-close { width: 28px; height: 28px; margin: 0; padding: 0; }
.error-toast-enter-active { transition: opacity .15s ease; }
.error-toast-enter-from { opacity: 0; }
@media(max-width:600px) { .error-notifications { width: auto; margin-left: 0; } }
@media(prefers-reduced-motion:reduce) { .error-toast-enter-active { transition: none; } }
</style>
