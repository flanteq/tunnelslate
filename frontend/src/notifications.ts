import { readonly, ref } from 'vue'

type NotificationMessage = string | (() => string)
interface ErrorNotification { id: number; message: NotificationMessage; key?: string }
const resolve = (message: NotificationMessage) => typeof message === 'function' ? message() : message

const lifetime = 12_000
const limit = 5

export function createNotifications() {
  const items = ref<ErrorNotification[]>([])
  const timers = new Map<number, ReturnType<typeof setTimeout>>()
  let nextID = 0

  function dismiss(id: number) {
    clearTimeout(timers.get(id))
    timers.delete(id)
    items.value = items.value.filter(item => item.id !== id)
  }

  function error(message: NotificationMessage, key?: string) {
    const duplicate = key ? items.value.find(item => item.key === key && resolve(item.message) === resolve(message)) : undefined
    if (duplicate) return duplicate.id
    const id = ++nextID
    items.value.push({ id, message, key })
    while (items.value.length > limit) dismiss(items.value[0]!.id)
    timers.set(id, setTimeout(() => dismiss(id), lifetime))
    return id
  }

  function clear() {
    for (const timer of timers.values()) clearTimeout(timer)
    timers.clear()
    items.value = []
  }

  return { items: readonly(items), error, dismiss, clear }
}

export const notifications = createNotifications()
