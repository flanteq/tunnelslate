import { PRODUCT_ID } from './branding.ts'
import { computed, ref, watch } from 'vue'
import ru from './locales/ru.json' with { type: 'json' }
import en from './locales/en.json' with { type: 'json' }

export type Language = 'ru' | 'en'
export type MessageKey = keyof typeof ru
type Message = string | Partial<Record<Intl.LDMLPluralRule, string>>
const dictionaries: Record<Language, Record<MessageKey, Message>> = { ru, en }
const storageKey = PRODUCT_ID + '-language'
const supported = (value: string | null): value is Language => value === 'ru' || value === 'en'
function initialLanguage(): Language {
  if (typeof window === 'undefined') return 'ru'
  try { const saved = localStorage.getItem(storageKey); if (supported(saved)) return saved } catch { /* Optional preference. */ }
  return navigator.language.toLowerCase().startsWith('en') ? 'en' : 'ru'
}
export const language = ref<Language>(initialLanguage())
export const dateLocale = computed(() => language.value === 'ru' ? 'ru-RU' : 'en-US')
export function setLanguage(value: string) { if (supported(value)) language.value = value }
watch(language, value => {
  if (typeof document !== 'undefined') document.documentElement.lang = value
  try { if (typeof localStorage !== 'undefined') localStorage.setItem(storageKey, value) } catch { /* Optional preference. */ }
}, { immediate: true, flush: 'sync' })

export function hasMessage(key: string): key is MessageKey { return Object.hasOwn(ru, key) }
export function formatNumber(value: number, options?: Intl.NumberFormatOptions) { return new Intl.NumberFormat(dateLocale.value, options).format(value) }
export function formatDate(value: number | Date, options?: Intl.DateTimeFormatOptions) { return new Intl.DateTimeFormat(dateLocale.value, options).format(value instanceof Date ? value : new Date(value * 1000)) }
export function formatDateTime(value: number | Date) { return formatDate(value, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }) }
export function formatTime(value: Date) { return new Intl.DateTimeFormat(dateLocale.value, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(value) }

export function t(key: MessageKey, params: Record<string, unknown> = {}): string {
  const message = dictionaries[language.value][key]
  const text = typeof message === 'string' ? message : message[new Intl.PluralRules(dateLocale.value).select(Number(params.count ?? params.p0 ?? 0))] ?? message.other ?? key
  return text.replace(/\{(\w+)\}/g, (placeholder, name: string) => Object.hasOwn(params, name)
    ? typeof params[name] === 'number' ? formatNumber(params[name] as number) : String(params[name] ?? '')
    : placeholder)
}
