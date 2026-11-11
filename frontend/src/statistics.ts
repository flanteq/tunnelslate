import { formatNumber, t } from './i18n.ts'
export interface StatisticsTotals { sessions: number; duration_seconds: number; bytes_received: number; bytes_sent: number }
export interface Traffic { bytes_received: number; bytes_sent: number }
export interface ServerStatistics extends StatisticsTotals { today: Traffic; date: string; time_zone: string }
export interface DeviceStatistics { id: string; name: string; totals: StatisticsTotals }
export interface ClientStatistics { totals: StatisticsTotals; devices: DeviceStatistics[]; retention_days: number }
export interface StatisticsDay extends StatisticsTotals { date: string }
export interface DailyStatistics { days: StatisticsDay[]; total: number; page: number; page_size: number }
export function formatBytes(value: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++ }
  return `${formatNumber(value, { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`
}
export function formatDuration(value: number): string {
  const seconds = Math.max(0, Math.floor(value))
  const days = Math.floor(seconds / 86400), hours = Math.floor(seconds / 3600) % 24, minutes = Math.floor(seconds / 60) % 60
  return days ? t('statistics.durationDays', { days, hours, minutes }) : hours ? t('statistics.durationHours', { hours, minutes }) : t('statistics.durationMinutes', { minutes, seconds: seconds % 60 })
}
