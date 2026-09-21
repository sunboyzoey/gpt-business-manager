import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '@/lib/utils'

export type UpgradeBrowserBackend = 'local' | 'roxybrowser'

export interface UpgradeBrowserConfig {
  browserBackend: UpgradeBrowserBackend
  roxyProxyId?: number
}

interface UpgradeBrowserConfigResponse {
  use_roxy?: boolean
  browser_backend?: string
  roxy_proxy_id?: number | null
}

const DEFAULT_ENDPOINT = '/gpt-plans/upgrade-browser-config'

function normalizeConfig(value: UpgradeBrowserConfigResponse | null | undefined): UpgradeBrowserConfig {
  const browserBackend: UpgradeBrowserBackend = value?.browser_backend === 'roxybrowser' || value?.use_roxy === true
    ? 'roxybrowser'
    : 'local'
  const rawProxyId = value?.roxy_proxy_id
  const roxyProxyId = browserBackend === 'roxybrowser' && rawProxyId != null && Number.isFinite(Number(rawProxyId))
    ? Number(rawProxyId)
    : undefined
  return { browserBackend, roxyProxyId }
}

/** 读取调用方自己的升级浏览器配置入口；套餐管理为默认入口。 */
export function useUpgradeBrowserConfig(endpoint = DEFAULT_ENDPOINT) {
  const [config, setConfig] = useState<UpgradeBrowserConfig>({ browserBackend: 'local' })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const result = await apiFetch(endpoint) as UpgradeBrowserConfigResponse
      const normalized = normalizeConfig(result)
      setConfig(normalized)
      return normalized
    } finally {
      setLoading(false)
    }
  }, [endpoint])

  useEffect(() => {
    void reload().catch(() => {
      // 页面仍可展示本地浏览器默认值；具体错误由用户保存时反馈。
    })
  }, [reload])

  const save = useCallback(async (next: UpgradeBrowserConfig) => {
    const previous = config
    setConfig(next)
    setSaving(true)
    try {
      const result = await apiFetch(endpoint, {
        method: 'PUT',
        body: JSON.stringify({
          use_roxy: next.browserBackend === 'roxybrowser',
          browser_backend: next.browserBackend,
          roxy_proxy_id: next.browserBackend === 'roxybrowser' ? (next.roxyProxyId ?? null) : null,
        }),
      }) as UpgradeBrowserConfigResponse
      const normalized = normalizeConfig(result)
      setConfig(normalized)
      return normalized
    } catch (error) {
      setConfig(previous)
      throw error
    } finally {
      setSaving(false)
    }
  }, [config, endpoint])

  return { config, loading, saving, reload, save }
}
