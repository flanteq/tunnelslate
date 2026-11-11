<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref, useId } from 'vue'
import Icon from './Icon.vue'
import LanguageFlag from './LanguageFlag.vue'
import { language, setLanguage, t } from './i18n'
import type { Language } from './i18n'

const choices: { value: Language; name: string }[] = [
  { value: 'ru', name: 'Русский' },
  { value: 'en', name: 'English' },
]
const open = ref(false)
const root = ref<HTMLElement | null>(null)
const trigger = ref<HTMLButtonElement | null>(null)
const menuId = useId()

function close(restoreFocus = false) {
  open.value = false
  if (restoreFocus) trigger.value?.focus()
}
function choose(value: Language) {
  setLanguage(value)
  close(true)
}
function outside(event: PointerEvent) {
  if (!root.value?.contains(event.target as Node)) close()
}
function focusLeft(event: FocusEvent) {
  if (!root.value?.contains(event.relatedTarget as Node | null)) close()
}
async function keyboard(event: KeyboardEvent) {
  if (event.key === 'Escape' && open.value) {
    event.preventDefault(); event.stopPropagation(); close(true)
    return
  }
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
  if (!open.value && ['Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const wasOpen = open.value
  open.value = true
  await nextTick()
  if (!root.value || !open.value) return
  const options = [...root.value.querySelectorAll<HTMLButtonElement>('[role="menuitemradio"]')]
  const current = options.indexOf(document.activeElement as HTMLButtonElement)
  const index = event.key === 'Home' ? 0 : event.key === 'End' ? options.length - 1
    : !wasOpen || current < 0 ? event.key === 'ArrowUp' ? options.length - 1 : 0
      : (current + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length
  options[index]?.focus()
}
onMounted(() => document.addEventListener('pointerdown', outside))
onUnmounted(() => document.removeEventListener('pointerdown', outside))
</script>
<template>
  <div ref="root" class="language-switcher" @keydown="keyboard" @focusout="focusLeft">
    <button ref="trigger" type="button" class="icon-button language-trigger" :class="{ 'is-open': open }" :title="t('language.select')" :aria-label="`${t('language.select')}: ${t(language === 'ru' ? 'language.ru' : 'language.en')}`" aria-haspopup="menu" :aria-expanded="open" :aria-controls="menuId" @click="open = !open">
      <LanguageFlag :language="language" />
    </button>
    <div v-if="open" :id="menuId" class="language-menu" role="menu" :aria-label="t('language.select')">
      <button v-for="choice in choices" :key="choice.value" type="button" class="language-option" role="menuitemradio" :aria-checked="language === choice.value" tabindex="-1" @click="choose(choice.value)">
        <LanguageFlag :language="choice.value" /><span :lang="choice.value">{{ choice.name }}</span><Icon v-if="language === choice.value" name="check" :size="15" />
      </button>
    </div>
  </div>
</template>
<style scoped>
.language-switcher { position: relative; display: inline-flex; flex-shrink: 0; }
.language-trigger { padding: 5px; }
.language-trigger.is-open { background: var(--hover); color: var(--text); }
.language-menu { position: absolute; top: calc(100% + 8px); right: 0; z-index: 30; width: 164px; padding: 5px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); color: var(--text); box-shadow: 0 8px 24px #0002; }
.language-option { display: flex; align-items: center; gap: 10px; width: 100%; padding: 9px 10px; border: 0; border-radius: 6px; background: transparent; color: inherit; font-size: 12px; text-align: left; }
.language-option:hover, .language-option:focus-visible { background: var(--hover); outline: none; }
.language-option[aria-checked="true"] { color: var(--accent); }
.language-option > svg:last-child:not(:first-child) { margin-left: auto; }
</style>
