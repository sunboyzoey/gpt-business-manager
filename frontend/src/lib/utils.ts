export const API = '/api'
export const API_BASE = '/api'

export function getToken(): string {
  return ''
}

export function setToken(_token: string): void {
  // Browser sessions use an HttpOnly same-site cookie. API clients may still
  // use the bearer token returned by the login endpoint.
  localStorage.removeItem('gmail_business_auth_token')
}

export function clearToken(): void {
  localStorage.removeItem('gmail_business_auth_token')
}

function stringifyErrorDetail(detail: unknown): string {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const messages = detail.map((item) => {
      if (!item || typeof item !== 'object') return String(item)
      const record = item as Record<string, unknown>
      const loc = Array.isArray(record.loc) ? record.loc.join('.') : ''
      const msg = typeof record.msg === 'string' ? record.msg : ''
      if (loc && msg) return `${loc}: ${msg}`
      if (msg) return msg
      return JSON.stringify(record)
    })
    return messages.filter(Boolean).join('; ')
  }
  if (detail && typeof detail === 'object') {
    const record = detail as Record<string, unknown>
    if (typeof record.message === 'string') return record.message
    if (typeof record.error === 'string') return record.error
    if (typeof record.msg === 'string') return record.msg
    return JSON.stringify(record)
  }
  return String(detail || '')
}

/**
 * API errors keep the parsed response payload so a page can render a
 * structured, operation-specific explanation.  Existing callers can continue
 * treating this as a normal Error and reading `message` only.
 */
export class ApiFetchError extends Error {
  readonly status: number
  readonly payload: unknown

  constructor(message: string, status: number, payload: unknown) {
    super(message)
    this.name = 'ApiFetchError'
    this.status = status
    this.payload = payload
  }
}

export async function apiFetch(path: string, opts?: RequestInit) {
  const token = getToken()
  const baseHeaders: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) baseHeaders['Authorization'] = `Bearer ${token}`
  const res = await fetch(API + path, {
    ...opts,
    headers: { ...baseHeaders, ...(opts?.headers as Record<string, string> || {}) },
  })
  if (res.status === 401) {
    clearToken()
    if (window.location.pathname !== '/login') {
      window.location.href = '/login'
    }
    throw new Error('未认证，请重新登录')
  }
  if (!res.ok) {
    const text = await res.text()
    try {
      const json = JSON.parse(text)
      throw new ApiFetchError(
        stringifyErrorDetail(json.detail || json.error || json.message || json) || text,
        res.status,
        json,
      )
    } catch (e) {
      if (e instanceof SyntaxError) throw new ApiFetchError(text, res.status, text)
      throw e
    }
  }
  return res.json()
}
