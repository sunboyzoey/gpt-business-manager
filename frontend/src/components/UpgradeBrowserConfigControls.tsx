import { Button, Select, Space, Switch, Tooltip } from 'antd'
import { LinkOutlined, ReloadOutlined, SafetyOutlined } from '@ant-design/icons'
import type { UpgradeBrowserConfig } from '@/hooks/useUpgradeBrowserConfig'

export interface UpgradeBrowserProxyOption {
  id: number
  host: string
  port: string
  protocol: string
  note?: string
  last_country?: string
  check_status?: number
  enabled?: boolean
}

interface Props {
  config: UpgradeBrowserConfig
  loading?: boolean
  saving?: boolean
  proxyLoading?: boolean
  proxies: UpgradeBrowserProxyOption[]
  disabled?: boolean
  onChange: (next: UpgradeBrowserConfig) => void
  onRefreshProxies: () => void
  onManageProxies?: () => void
}

export default function UpgradeBrowserConfigControls({
  config,
  loading = false,
  saving = false,
  proxyLoading = false,
  proxies,
  disabled = false,
  onChange,
  onRefreshProxies,
  onManageProxies,
}: Props) {
  const useRoxy = config.browserBackend === 'roxybrowser'
  const controlsDisabled = disabled || loading || saving

  return (
    <Space size={6} wrap>
      <Tooltip title="GPT 套餐管理统一使用此配置。保存后，所有后续“升级 PRO”都会直接使用该浏览器模式和代理，不再逐次询问。">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <SafetyOutlined style={{ color: useRoxy ? '#7C3AED' : undefined }} />
          <span style={{ fontSize: 13 }}>指纹浏览器</span>
          <Switch
            size="small"
            checked={useRoxy}
            loading={loading || saving}
            disabled={disabled}
            onChange={(checked) => onChange({
              browserBackend: checked ? 'roxybrowser' : 'local',
              roxyProxyId: checked ? config.roxyProxyId : undefined,
            })}
          />
        </span>
      </Tooltip>

      {useRoxy && (
        <Select
          allowClear
          showSearch
          optionFilterProp="label"
          size="middle"
          style={{ width: 270 }}
          placeholder={proxyLoading ? '正在读取 Roxy 代理…' : 'Roxy 代理：未指定'}
          loading={proxyLoading}
          disabled={controlsDisabled}
          value={config.roxyProxyId}
          onChange={(value) => onChange({ browserBackend: 'roxybrowser', roxyProxyId: value as number | undefined })}
          options={proxies
            .filter((proxy) => proxy.enabled !== false)
            .map((proxy) => ({
              value: proxy.id,
              label: `${proxy.check_status === 1 ? '✅ ' : proxy.check_status === 0 ? '❌ ' : ''}${proxy.note ? `${proxy.note} · ` : ''}${proxy.protocol} ${proxy.host}:${proxy.port}${proxy.last_country ? ` [${proxy.last_country}]` : ''}`,
            }))}
        />
      )}

      {useRoxy && (
        <Tooltip title="刷新 Roxy 代理清单">
          <Button
            size="small"
            icon={<ReloadOutlined />}
            loading={proxyLoading}
            disabled={controlsDisabled}
            onClick={onRefreshProxies}
          />
        </Tooltip>
      )}

      {useRoxy && onManageProxies && (
        <Button size="small" icon={<LinkOutlined />} disabled={controlsDisabled} onClick={onManageProxies}>
          代理管理
        </Button>
      )}
    </Space>
  )
}
