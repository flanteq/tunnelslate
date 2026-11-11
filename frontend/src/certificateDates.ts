import { t, formatDate } from './i18n.ts'
export function defaultCertificateDate(now = new Date(), max?: string) {
  const date = new Date(now)
  date.setUTCDate(date.getUTCDate() + 825)
  const value = date.toISOString().slice(0, 10)
  return max && max < value ? max : value
}

export const utcToday = () => new Date().toISOString().slice(0, 10)
export const certificateDate = (unix: number | null | undefined) => unix
  ? formatDate(unix, { timeZone: 'UTC' }) : '—'

export function certificateTerm(cert: { status: string; not_after: number; revoked_at?: number | null }) {
  if (cert.status === 'revoked') return cert.revoked_at ? t('certificate.revoked', { p0: certificateDate(cert.revoked_at) }) : t('common.revoked')
  if (cert.status === 'expired') return t('certificate.expired', { p0: certificateDate(cert.not_after) })
  if (cert.status === 'valid') return t('certificate.validUntil', { p0: certificateDate(cert.not_after) })
  return t('common.awaitingIssuance')
}
