import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export const API = import.meta.env.VITE_API_BASE || '/api'
export const API_BASE = API

export class ApiRequestError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiRequestError'
    this.status = status
  }
}

export function apiErrorStatus(error: unknown): number | null {
  return error instanceof ApiRequestError ? error.status : null
}

async function responseError(res: Response) {
  const contentType = (res.headers.get('content-type') || '').toLowerCase()
  const raw = await res.text()
  if (contentType.includes('application/json') || raw.trim().startsWith('{')) {
    try {
      const payload = JSON.parse(raw)
      const message = payload?.detail || payload?.error || payload?.message
      if (typeof message === 'string' && message.trim()) return new ApiRequestError(message.trim(), res.status)
    } catch {
      // Fall through to the sanitized HTTP error below.
    }
  }
  const normalized = raw.toLowerCase()
  if (res.status === 502 || normalized.includes('bad gateway') || normalized.includes('error code 502')) {
    return new ApiRequestError('服务网关暂时不可用，请检查 SunnyRegister 后端与 Python Worker 状态', res.status)
  }
  if (res.status === 504 || normalized.includes('gateway timeout') || normalized.includes('error code 504')) {
    return new ApiRequestError('服务响应超时，请稍后重试或检查邮箱网络链路', res.status)
  }
  return new ApiRequestError(`请求失败（HTTP ${res.status}），服务器返回了非 JSON 响应`, res.status)
}

export async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(API + path, {
    ...opts,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(opts?.headers || {}) },
  })
  if (res.status === 401 && !path.startsWith('/auth/')) {
    window.location.reload()
    throw new Error('Unauthorized')
  }
  if (!res.ok) throw await responseError(res)
  return res.json()
}

export async function apiDownload(path: string, opts?: RequestInit) {
  const res = await fetch(API + path, {
    ...opts,
    credentials: 'include',
    headers: {
      ...(opts?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(opts?.headers || {}),
    },
  })
  if (res.status === 401) {
    window.location.reload()
    throw new Error('Unauthorized')
  }
  if (!res.ok) throw await responseError(res)
  const blob = await res.blob()
  const disposition = res.headers.get('Content-Disposition') || ''
  const match = disposition.match(/filename\*=UTF-8''([^;]+)|filename="?([^"]+)"?/)
  const filename = decodeURIComponent(match?.[1] || match?.[2] || 'download')
  return { blob, filename }
}

export function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}
