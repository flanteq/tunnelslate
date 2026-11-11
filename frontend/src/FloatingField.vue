<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref } from 'vue'
defineProps<{ id: string; label: string; fixed?: boolean }>()
const measure = ref<HTMLElement>()
const extra = ref(0)
let observer: ResizeObserver | undefined
onMounted(() => {
  // Measure the compact label, independent of focus, so wrapping never moves the form.
  observer = new ResizeObserver(() => {
    if (measure.value?.getClientRects().length) extra.value = Math.max(0, Math.ceil(measure.value.getBoundingClientRect().height) - 15)
  })
  if (measure.value) observer.observe(measure.value)
})
onBeforeUnmount(() => observer?.disconnect())
</script>

<template>
  <div :class="['floating-field', { 'floating-field-fixed': fixed }]" :style="{ '--floating-extra': `${extra}px` }">
    <slot />
    <label :for="id" class="floating-label" :title="label">{{ label }}</label>
    <span ref="measure" class="floating-measure" aria-hidden="true">{{ label }}</span>
  </div>
</template>

<style scoped>
.floating-field { position: relative; flex: 1; min-width: 0; width: 100%; }
.floating-field :deep(input:not([type="hidden"])), .floating-field :deep(select:not([multiple])) {
  width: 100%; height: calc(56px + var(--floating-extra)); padding: calc(23px + var(--floating-extra)) 12px 7px; font-size: 13px; line-height: 24px;
}
.floating-field :deep(textarea) {
  display: block; width: 100%; height: auto; min-height: calc(96px + var(--floating-extra));
  margin: 0; padding: calc(29px + var(--floating-extra)) 12px 10px; border: 1px solid var(--border);
  border-radius: 8px; background: var(--surface); color: var(--text); font: inherit; font-size: 13px; line-height: 20px; resize: vertical;
}
.floating-field :deep(select) { border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); }
.floating-field :deep(select:focus), .floating-field :deep(textarea:focus) { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
.floating-field > .floating-label {
  position: absolute; top: 50%; left: 12px; max-width: calc(100% - 24px);
  margin: 0; color: var(--muted); font-size: 13px; line-height: 20px;
  transform: translateY(-50%); overflow-wrap: anywhere;
  cursor: text;
}
.floating-field :deep(input::placeholder) { opacity: 0; }
.floating-field:focus-within :deep(input::placeholder) { opacity: 1; }
.floating-field-fixed > .floating-label,
.floating-field:focus-within > .floating-label,
.floating-field:has(input:not(:placeholder-shown)) > .floating-label,
.floating-field:has(input:autofill) > .floating-label {
  top: 7px; transform: none; font-size: 11px; line-height: 15px;
}
.floating-field:focus-within > .floating-label { color: var(--accent); }
.floating-field:has(select) > .floating-label { max-width: calc(100% - 40px); cursor: pointer; }
.floating-measure { position: absolute; top: 7px; left: 12px; right: 12px; visibility: hidden; pointer-events: none; font-size: 11px; line-height: 15px; overflow-wrap: anywhere; }
.floating-field:has(select) > .floating-measure { right: 28px; }
.floating-field:has(textarea) > .floating-label {
  top: 1px; left: 1px; max-width: calc(100% - 2px); width: calc(100% - 2px); padding: 6px 11px 0;
  border-radius: 7px 7px 0 0; background: var(--surface);
}
.floating-field:has(:disabled) > .floating-label { opacity: .6; cursor: not-allowed; }
.floating-field :deep(select:disabled) { background: var(--hover); color: var(--muted); opacity: .6; cursor: not-allowed; }
@media (prefers-reduced-motion: no-preference) {
  .floating-label { transition: top .15s, transform .15s, font-size .15s, color .15s; }
}
</style>
