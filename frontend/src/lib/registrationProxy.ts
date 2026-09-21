export interface RegistrationProxyOption {
  key: string
  label: string
  kind: 'manual' | 'subscription'
  region?: string
  latency_ms?: number | null
  last_check_at?: string | null
}

export function parseRegistrationProxyOptions(payload: unknown): RegistrationProxyOption[] {
  const items = payload && typeof payload === 'object' && 'items' in payload ? payload.items : undefined
  if (!Array.isArray(items) || items.some(item => !item || typeof item.key !== 'string' || !item.key
    || typeof item.label !== 'string' || !['manual', 'subscription'].includes(item.kind))) {
    throw new Error('服务端返回的可用代理列表格式无效，请刷新后重试')
  }
  return items
}

export function registrationProxyError(items: RegistrationProxyOption[], key: string | undefined, loadError: string, loaded: boolean): string {
  if (loadError) return `可用代理读取失败：${loadError}`
  if (!loaded) return '正在读取已验证代理…'
  if (key && !items.some(item => item.key === key)) return '所选代理已不可用或检测结果已失效，请重新检测并选择可用代理。'
  if (!items.length) return '暂无检测通过的可用代理，请先前往代理管理添加并检测。'
  if (!key) return '请选择一个检测通过的可用代理。'
  return ''
}
