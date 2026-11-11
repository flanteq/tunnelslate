import type { DCOStatus } from './api'
import { t } from './i18n.ts'

export function dcoLabel(status?: DCOStatus): string {
  switch (status?.state) {
    case 'active': return t('dco.active')
    case 'disabled': return t('dco.disabled')
    case 'unavailable': return t('dco.unavailable')
    default: return t('dco.unknown')
  }
}
