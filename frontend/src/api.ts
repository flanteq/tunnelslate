import { t, hasMessage, formatDate } from './i18n.ts'
export class ApiError extends Error {
  status: number
  code: string
  params: Record<string, unknown>
  constructor(status: number, message: string, code = status === 401 ? 'auth.expired' : 'request_failed', params: Record<string, unknown> = {}) {
    super(message)
    this.status = status; this.code = code; this.params = params
  }
}

export function responseError(status: number, body: { error?: string; code?: string; params?: Record<string, unknown> | null }) {
  return new ApiError(status, body.error ?? 'Request failed', body.code ?? (status >= 500 ? 'internal_error' : status === 401 ? 'auth.expired' : 'request_failed'), body.params ?? {})
}

export function errorText(error: unknown, fallback = t('errors.request_failed')): string {
  if (error instanceof ApiError) {
    const key = `errors.${error.code}`
    const params = { ...error.params }
    if (error.code === 'certificate.ca_expiry' && typeof params.expires_at === 'number') {
      params.date = formatDate(params.expires_at, { timeZone: 'UTC', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' })
    }
    if (error.code === 'auth.ip_blocked' && typeof params.retry_after === 'number') {
      params.minutes = Math.max(1, Math.ceil(params.retry_after / 60))
    }
    return hasMessage(key) ? t(key, params) : fallback
  }
  return error instanceof TypeError ? t('errors.network_error') : fallback
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(new URL(`api${path}`, document.baseURI), {
    ...options,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...options.headers },
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw responseError(response.status, body)
  return body as T
}

export interface AdminSession { ip_address: string; created_at: number; expires_at: number; current: boolean }
export interface AdminAccount { id: number; username: string; created_at: number; password_setup_required: boolean; totp_enabled: boolean; current: boolean; sessions: number; session_details: AdminSession[] }
export interface Session { id: number; username: string; csrf_token: string; password_setup_required: boolean }
export interface TOTPChallenge { totp_required: true; challenge_token: string; expires_at: number }
export interface DCOStatus { state: 'active' | 'disabled' | 'unavailable' | 'unknown'; reason: string; kernel_release?: string; module_loaded?: boolean }
export interface Dashboard {
  instance_name?: string
  statistics?: import('./statistics').ServerStatistics
  clients: number; devices: number; valid_certificates: number
  revoked_certificates: number; expired_certificates: number; version: string
  vpn: { state: string; connected_clients: number | null; version?: string; dco?: DCOStatus }
  crl?: { state: string; this_update?: number; next_update?: number }
}
export interface Client { id: string; name: string; disabled: boolean; created_at: number; link_created_at?: number; revocation_pending?: boolean; external_auth: boolean; auth_provider_enabled: boolean }
export interface Certificate { serial: string; client: string; device: string; device_id: string; client_id: string; status: string; not_after: number; revoked_at: number | null; common_name: string; operation_state: string }
export interface Device { id: string; client_id: string; name: string; created_at: number; serial: string; status: string; not_after: number; revoked_at?: number; common_name: string; operation_state: string; operation_id: string; operation_kind: string; custom_ccd: boolean; static_ip: string; ccd_pending: boolean }
export interface CCDSettings { access_mode: 'all' | 'restricted'; allowed_networks: string[]; site_networks: string[]; static_ip: string; dns_mode: 'inherit' | 'custom'; dns: string[]; dns_domains_mode: 'inherit' | 'custom'; dns_domain: string; dns_search: string[]; routes_mode: 'inherit' | 'custom'; routes: string[]; tunnel_mode: 'inherit' | 'split' | 'full'; revision: number }
export interface CCDView {
  settings: CCDSettings
  vpn: { site_to_site: boolean; isolate_clients: boolean; site_nat: boolean; network: string; dns: string[]; dns_domain: string; dns_search: string[]; routes: string[]; redirect_gateway: boolean; revision: number }
  dynamic_range: { start: string; end: string }; static_range: { start: string; end: string }
  published: boolean; publication_error: string
}
export interface Operation { id: string; kind: string; state: string; step: string; device_id: string; device_name?: string; client_id?: string; client_name?: string; actor: string; result_serial: string; error: string; created_at: number; updated_at: number }
export interface Connection { common_name: string; real_address: string; virtual_address: string; bytes_received: number; bytes_sent: number; connected_since: number; device: string; client: string }
export interface AuditEvent { id: number; actor: string; action: string; target: string; created_at: number; severity?: string; target_name?: string }
export interface Settings {
	certificate_max_date: string
	bootstrap: { state: string; step: string; error: string; updated_at: number }
  applied_revision: number
  network_status: { pending: boolean; error: string }
  dco?: DCOStatus
  editable: boolean; source: string
  vpn: { isolate_clients: boolean; site_to_site: boolean; site_nat: boolean; endpoint: string; port: number; external_port: number; protocol: string; network: string; dns: string[]; dns_domain: string; dns_search: string[]; redirect_gateway: boolean; routes: string[]; dco: 'auto' | 'off'; max_clients: number; keepalive_interval: number; keepalive_timeout: number; tun_mtu: number; mss_mode: 'default' | 'custom' | 'off'; mss: number; revision: number }
  storage: Record<string, string>
  auth: { cookie_secure: boolean; session_ttl: string }
  capabilities: Record<string, boolean>
}

export interface VPNAuthProviderConfig { address: string; bind_dn: string; base_dn: string; user_filter: string; group_dn: string; group_filter: string; ca_pem: string; nas_identifier: string; timeout_seconds: number }
export interface VPNAuthProvider { id: string; name: string; kind: 'ldap' | 'radius'; enabled: boolean; config: VPNAuthProviderConfig; secret?: string; has_secret: boolean; revision: number }
export interface VPNAuthBinding { mode: 'certificate' | 'external' | 'inherit'; provider_id: string; username: string; revision: number }
export interface VPNAuthView { binding: VPNAuthBinding; providers: VPNAuthProvider[]; disconnect_pending: boolean }

export interface PanelSettingsView {
  settings: { instance_name: string; metrics_enabled: boolean; metrics_mtls: boolean; metrics_source: 'files' | 'pem'; server_cert_pem: string; client_ca_pem: string; key_configured: boolean; revision: number }
  runtime: { state: 'disabled' | 'running' | 'error'; error?: string; address: string; certificate_expires?: number }
}
