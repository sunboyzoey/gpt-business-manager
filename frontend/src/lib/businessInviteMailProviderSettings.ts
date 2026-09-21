import { readBusinessInviteMailProviderDefaults } from './businessInviteMailProvider.ts'
import type { BusinessInviteMailProviderDefaults } from './businessInviteMailProvider.ts'

type Request = (path: string, options?: RequestInit) => Promise<unknown>
export interface BusinessInviteMailProviderSettingsState {
  defaults: BusinessInviteMailProviderDefaults | null
  loading: boolean
  saving: boolean
  error: string
  revision: number
}

// One snapshot for every mounted invitation/settings view. Generations prevent
// an older GET from overwriting a newer save (including an unsuccessful save).
export function createBusinessInviteMailProviderSettings(request: Request, timeoutMs = 15000) {
  const path = '/config/business-invite-mail-providers'
  let state: BusinessInviteMailProviderSettingsState = { defaults: null, loading: false, saving: false, error: '', revision: 0 }
  let generation = 0
  let readPromise: Promise<void> | null = null
  const subscribers = new Set<() => void>()
  const boundedRequest = async (options?: RequestInit) => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      return await Promise.race([
        request(path, { ...options, signal: controller.signal }),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            controller.abort()
            reject(new Error('席位默认邮箱请求超时，请重新读取配置'))
          }, timeoutMs)
        }),
      ])
    } finally {
      clearTimeout(timer)
    }
  }
  const publish = (patch: Partial<BusinessInviteMailProviderSettingsState>) => {
    state = { ...state, ...patch }
    subscribers.forEach(listener => listener())
  }
  const load = (force = false): Promise<void> => {
    if (state.saving) return Promise.resolve()
    if (!force && readPromise) return readPromise
    if (!force && (state.defaults || state.error)) return Promise.resolve()
    const current = ++generation
    publish({ loading: true, defaults: null, error: '' })
    const result = (async () => {
      try {
        const defaults = readBusinessInviteMailProviderDefaults(await boundedRequest())
        if (current === generation) publish({ defaults, revision: state.revision + 1 })
      } catch (error) {
        if (current === generation) publish({ defaults: null, error: error instanceof Error ? error.message : '读取席位默认邮箱失败' })
      } finally {
        if (current === generation) { readPromise = null; publish({ loading: false }) }
      }
    })()
    readPromise = result
    return result
  }
  const save = async (value: BusinessInviteMailProviderDefaults) => {
    const defaults = readBusinessInviteMailProviderDefaults(value)
    if (state.saving) throw new Error('正在保存席位默认邮箱，请稍候')
    const current = ++generation
    readPromise = null
    publish({ saving: true, loading: false, error: '' })
    try {
      const saved = readBusinessInviteMailProviderDefaults(await boundedRequest({ method: 'PUT', body: JSON.stringify(defaults) }))
      if (current === generation) publish({ defaults: saved, revision: state.revision + 1 })
    } catch (error) {
      // A failed response can be ambiguous; reload before presenting a policy.
      if (current === generation) publish({ defaults: null, error: error instanceof Error ? error.message : '保存席位默认邮箱失败' })
      throw error
    } finally {
      if (current === generation) publish({ saving: false })
    }
  }
  return {
    getSnapshot: () => state,
    subscribe: (listener: () => void) => { subscribers.add(listener); return () => { subscribers.delete(listener) } },
    load,
    save,
  }
}
