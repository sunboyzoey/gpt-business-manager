import { useEffect, useState, useCallback } from 'react'
import { Alert, App, Card, Table, Button, Input, Tag, Space, Popconfirm, Tabs, Progress, Badge, Typography } from 'antd'
import PageHeader from '@/components/PageHeader'
import {
  PlusOutlined,
  DeleteOutlined,
  ReloadOutlined,
  CheckCircleOutlined,
  SwapRightOutlined,
  SwapLeftOutlined,
  CloudDownloadOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { apiFetch } from '@/lib/utils'

const errorText = (error: unknown) => error instanceof Error ? error.message : String(error)
const formatCheckTime = (value?: string | number | null) => {
  if (!value) return '尚未检测'
  const date = new Date(typeof value === 'number' ? value * 1000 : /(?:Z|[+-]\d{2}:\d{2})$/.test(value) ? value : `${value}Z`)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false })
}

interface ManualProxy {
  id: number
  url: string
  region: string
  is_active: boolean
  is_usable: boolean
  last_check_at?: string | null
  last_check_ok?: boolean | null
  last_check_error?: string
  latency_ms?: number | null
  success_count: number
  fail_count: number
}
interface ManualCheckStatus {
  running: boolean
  total: number
  completed: number
  ok: number
  fail: number
  error?: string
  started_at?: string
  finished_at?: string
}

function ManualProxies() {
  const { message } = App.useApp()
  const [proxies, setProxies] = useState<ManualProxy[]>([])
  const [newProxy, setNewProxy] = useState('')
  const [region, setRegion] = useState('')
  const [checking, setChecking] = useState(false)
  const [checkStatus, setCheckStatus] = useState<ManualCheckStatus>()
  const [loading, setLoading] = useState(false)
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState('')
  const [statusError, setStatusError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try { setProxies(await apiFetch('/proxies')); setError('') }
    catch (reason) { setError(errorText(reason)) }
    finally { setLoading(false) }
  }, [])
  const loadCheckStatus = useCallback(async () => {
    try {
      const data: ManualCheckStatus = await apiFetch('/proxies/check-status')
      setCheckStatus(data); setChecking(data.running); setStatusError('')
      return data
    } catch (reason) { setStatusError(errorText(reason)) }
  }, [])

  useEffect(() => { void load(); void loadCheckStatus() }, [load, loadCheckStatus])
  useEffect(() => {
    if (!checking) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>
    const poll = async () => {
      const data = await loadCheckStatus()
      if (cancelled) return
      if (data && !data.running) { void load(); return }
      timer = setTimeout(() => void poll(), 1000)
    }
    timer = setTimeout(() => void poll(), 1000)
    return () => { cancelled = true; clearTimeout(timer) }
  }, [checking, load, loadCheckStatus])

  const add = async () => {
    if (!newProxy.trim() || adding) return
    const lines = newProxy.trim().split('\n').map(line => line.trim()).filter(Boolean)
    setAdding(true)
    try {
      await apiFetch(lines.length > 1 ? '/proxies/bulk' : '/proxies', {
        method: 'POST', body: JSON.stringify(lines.length > 1 ? { proxies: lines, region } : { url: lines[0], region }),
      })
      message.success('添加成功，请检测后再用于注册')
      setNewProxy(''); setRegion(''); await load()
    } catch (reason) { message.error(`添加失败：${errorText(reason)}`) }
    finally { setAdding(false) }
  }
  const mutateProxy = async (id: number, action: 'delete' | 'toggle') => {
    try {
      await apiFetch(action === 'delete' ? `/proxies/${id}` : `/proxies/${id}/toggle`, { method: action === 'delete' ? 'DELETE' : 'PATCH' })
      await load()
    } catch (reason) { message.error(errorText(reason)) }
  }
  const check = async () => {
    setChecking(true); setStatusError('')
    try {
      const data: ManualCheckStatus = await apiFetch('/proxies/check', { method: 'POST' })
      setCheckStatus(data); setChecking(data.running)
      if (!data.running) await load()
    } catch (reason) {
      setStatusError(`启动检测失败：${errorText(reason)}`)
      setChecking(false)
    }
  }

  return <>
    <Alert showIcon type="info" message="只有已启用且最近一次 ChatGPT 检测通过的代理才能用于注册" description="新增代理需要先检测；检测失败、已禁用或检测结果失效的代理不会出现在注册选项中。" style={{ marginBottom: 16 }} />
    <Card title="添加代理（每行一个）" style={{ marginBottom: 16 }}>
      <Space direction="vertical" style={{ width: '100%' }}>
        <Input.TextArea aria-label="代理地址" value={newProxy} onChange={event => setNewProxy(event.target.value)} placeholder={['http://user:pass@host:port', 'user:pass@host:port', 'host:port:user:pass'].join('\n')} rows={3} style={{ fontFamily: 'monospace' }} />
        <Space wrap>
          <Input aria-label="地区标签" value={region} onChange={event => setRegion(event.target.value)} placeholder="地区标签（如 US, SG）" style={{ width: 200 }} />
          <Button type="primary" icon={<PlusOutlined />} onClick={() => void add()} loading={adding} disabled={!newProxy.trim() || checking}>添加</Button>
          <Button icon={<ReloadOutlined spin={checking} />} onClick={() => void check()} loading={checking} disabled={loading || checking || !proxies.length}>检测全部（ChatGPT CSRF）</Button>
          <Button icon={<ReloadOutlined />} onClick={() => { void load(); void loadCheckStatus() }} loading={loading}>刷新状态</Button>
        </Space>
      </Space>
    </Card>
    {(error || statusError || checkStatus?.error) && <Alert showIcon type="error" message={error || statusError || checkStatus?.error} style={{ marginBottom: 16 }} />}
    {checkStatus && (checking || checkStatus.started_at || checkStatus.finished_at) && <Card size="small" style={{ marginBottom: 16 }}>
      <Space wrap><Tag color={checking ? 'processing' : 'default'}>{checking ? '检测进行中' : '检测已结束'}</Tag><span>{checkStatus.completed} / {checkStatus.total}</span><Tag color="success">通过 {checkStatus.ok}</Tag><Tag color="error">失败 {checkStatus.fail}</Tag>{checkStatus.finished_at && <Typography.Text type="secondary">完成于 {formatCheckTime(checkStatus.finished_at)}</Typography.Text>}</Space>
      {checking && <Progress percent={checkStatus.total ? Math.round(checkStatus.completed / checkStatus.total * 100) : 0} status="active" size="small" />}
    </Card>}
    <Card><Table<ManualProxy> rowKey="id" dataSource={proxies} loading={loading} pagination={false} scroll={{ x: 1100 }} columns={[
      { title: '代理地址', dataIndex: 'url', render: (value: string) => <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{value}</Typography.Text> },
      { title: '地区', dataIndex: 'region', render: (value: string) => value || '—' },
      { title: '上次检测', render: (_, proxy) => <Space direction="vertical" size={3}>
        <Tag color={proxy.last_check_ok == null ? 'default' : proxy.last_check_ok ? 'success' : 'error'}>{proxy.last_check_ok == null ? '未检测' : proxy.last_check_ok ? '通过' : '失败'}</Tag>
        <Typography.Text type="secondary">{formatCheckTime(proxy.last_check_at)}</Typography.Text>
        {proxy.last_check_error && <Typography.Text type="danger">{proxy.last_check_error}</Typography.Text>}
      </Space> },
      { title: '延迟', dataIndex: 'latency_ms', render: (value?: number | null) => value == null ? '—' : `${value} ms` },
      { title: '累计成功 / 失败', render: (_, proxy) => <Space><Tag color="success">{proxy.success_count}</Tag><span>/</span><Tag color="error">{proxy.fail_count}</Tag></Space> },
      { title: '注册可用性', render: (_, proxy) => <Tag color={proxy.is_usable ? 'success' : 'default'}>{proxy.is_usable ? '可选用' : !proxy.is_active ? '已禁用' : proxy.last_check_ok === true ? '检测结果已失效' : '待检测通过'}</Tag> },
      { title: '操作', render: (_, proxy) => <Space>
        <Button size="small" disabled={checking} icon={proxy.is_active ? <SwapLeftOutlined /> : <SwapRightOutlined />} onClick={() => void mutateProxy(proxy.id, 'toggle')}>{proxy.is_active ? '禁用' : '启用'}</Button>
        <Popconfirm title="确认删除此代理？" onConfirm={() => mutateProxy(proxy.id, 'delete')}><Button aria-label="删除代理" size="small" danger disabled={checking} icon={<DeleteOutlined />} /></Popconfirm>
      </Space> },
    ]} /></Card>
  </>
}

function SubscriptionProxies() {
  const { message } = App.useApp()
  const [subUrl, setSubUrl] = useState('')
  const [status, setStatus] = useState<any>(null)
  const [updating, setUpdating] = useState(false)
  const [settingUp, setSettingUp] = useState(false)
  const [testing, setTesting] = useState(false)
  const [protocolTesting, setProtocolTesting] = useState(false)
  const [loading, setLoading] = useState(false)
  const [protocolStatus, setProtocolStatus] = useState<any>(null)
  const [statusError, setStatusError] = useState('')
  const [configError, setConfigError] = useState('')
  const [protocolError, setProtocolError] = useState('')

  const loadStatus = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiFetch('/proxies/subscription/status')
      setStatus(data)
      setTesting(Boolean(data?.test?.running))
      setStatusError('')
    } catch (reason) {
      setStatusError(errorText(reason))
    } finally {
      setLoading(false)
    }
  }, [])

  const loadConfig = useCallback(async () => {
    try {
      const cfg = await apiFetch('/config')
      setSubUrl(cfg.proxy_subscription_url || '')
      setConfigError('')
    } catch (reason) {
      setConfigError(errorText(reason))
    }
  }, [])

  const loadProtocolStatus = useCallback(async () => {
    try {
      const data = await apiFetch('/proxies/subscription/chatgpt-protocol-status')
      setProtocolStatus(data)
      setProtocolTesting(Boolean(data?.running))
      setProtocolError('')
    } catch (reason) {
      setProtocolError(errorText(reason))
    }
  }, [])

  useEffect(() => {
    loadStatus()
    loadConfig()
    loadProtocolStatus()
  }, [loadStatus, loadConfig, loadProtocolStatus])

  useEffect(() => {
    if (!testing) return
    const timer = setInterval(async () => {
      try {
        const ts = await apiFetch('/proxies/subscription/test-status')
        setStatus((prev: any) => ({ ...prev, test: ts }))
        setStatusError('')
        if (!ts.running) {
          setTesting(false)
          loadStatus()
        }
      } catch (reason) {
        setStatusError(`节点检测状态读取失败，正在重试：${errorText(reason)}`)
      }
    }, 2000)
    return () => clearInterval(timer)
  }, [testing, loadStatus])

  useEffect(() => {
    if (!protocolTesting) return
    const timer = setInterval(async () => {
      try {
        const ps = await apiFetch('/proxies/subscription/chatgpt-protocol-status')
        setProtocolStatus(ps)
        setProtocolError('')
        if (!ps.running) {
          setProtocolTesting(false)
          loadProtocolStatus()
        }
      } catch (reason) {
        setProtocolError(`ChatGPT 检测状态读取失败，正在重试：${errorText(reason)}`)
      }
    }, 2000)
    return () => clearInterval(timer)
  }, [protocolTesting, loadProtocolStatus])

  const handleUpdate = async () => {
    if (!subUrl.trim()) {
      message.error('请输入订阅地址')
      return
    }
    setUpdating(true); setConfigError('')
    try {
      const res = await apiFetch('/proxies/subscription/update', {
        method: 'POST',
        body: JSON.stringify({ url: subUrl.trim() }),
      })
      if (res.ok) {
        message.success(res.msg || '更新成功')
        loadStatus()
        loadProtocolStatus()
      } else {
        setConfigError(res.msg || '更新失败')
      }
    } catch (e: any) {
      setConfigError(`更新失败: ${e.message}`)
    } finally {
      setUpdating(false)
    }
  }

  const handleTestNodes = async () => {
    setTesting(true)
    try {
      const result = await apiFetch('/proxies/subscription/test-nodes', { method: 'POST' })
      if (result.ok === false) throw new Error(result.msg || '无法启动节点测试')
      message.info('节点测试已启动')
    } catch (e: any) {
      message.error(`启动失败: ${e.message}`)
      setTesting(false)
    }
  }

  const handleSetup = async () => {
    setSettingUp(true); setConfigError('')
    try {
      const result = await apiFetch('/proxies/subscription/setup', { method: 'POST' })
      if (result.ok === false) throw new Error(result.msg || '代理服务启动失败')
      message.success(result.msg || '代理服务已启动')
      await loadStatus()
    } catch (reason) { setConfigError(errorText(reason)) }
    finally { setSettingUp(false) }
  }

  const handleTestChatGPTProtocol = async () => {
    setProtocolTesting(true)
    try {
      const result = await apiFetch('/proxies/subscription/test-chatgpt-protocol-nodes', { method: 'POST' })
      if (result.ok === false) throw new Error(result.msg || '无法启动 ChatGPT 检测')
      message.info('ChatGPT 协议预检已启动')
    } catch (e: any) {
      message.error(`启动失败: ${e.message}`)
      setProtocolTesting(false)
    }
  }

  const testResults = status?.test?.results || []
  const pool = status?.pool || []
  const protocolResults = protocolStatus?.results || []
  const protocolPool = protocolStatus?.pool || []

  const nodeColumns: any[] = [
    {
      title: '节点名称',
      dataIndex: 'name',
      key: 'name',
      ellipsis: true,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 80,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (s: string) => {
        if (!s) return <Tag>未检测</Tag>
        const colorMap: any = { ok: 'success', fail: 'error', blocked: 'warning', skip: 'default' }
        const labelMap: any = { ok: '可用', fail: '不可用', blocked: '封锁', skip: '跳过' }
        return <Tag color={colorMap[s] || 'default'}>{labelMap[s] || s}</Tag>
      },
    },
    {
      title: '延迟',
      dataIndex: 'latency',
      key: 'latency',
      width: 80,
      render: (v: number) => v ? `${v}ms` : '-',
    },
    {
      title: '地区',
      dataIndex: 'region',
      key: 'region',
      width: 60,
      render: (v: string) => v || '-',
    },
    {
      title: '错误',
      dataIndex: 'error',
      key: 'error',
      ellipsis: true,
      render: (v: string) => v ? <span style={{ color: '#999', fontSize: 12 }}>{v}</span> : '-',
    },
  ]

  return (
    <>
      <Alert showIcon type="info" message="更新订阅后请测试节点，建议再运行 ChatGPT 协议预检" description="只有当前有效且最近一次检测通过的订阅节点才会进入注册代理选项；检测期间暂时不可选用。" style={{ marginBottom: 16 }} />
      {(statusError || configError || protocolError) && <Alert showIcon type="error" message="订阅代理状态异常" description={[configError, statusError, protocolError].filter(Boolean).join('；')} style={{ marginBottom: 16 }} />}
      <Card title="订阅配置" style={{ marginBottom: 16 }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          {status && <Space wrap><Tag color={status.installed ? 'success' : 'warning'}>{status.installed ? 'mihomo 已安装' : 'mihomo 未安装'}</Tag><Tag color={status.running ? 'success' : 'warning'}>{status.running ? '代理服务运行中' : '代理服务未运行'}</Tag></Space>}
          <Input
            value={subUrl}
            onChange={(e) => setSubUrl(e.target.value)}
            placeholder="Clash 订阅地址 (https://example.com/subscribe?token=xxx)"
            style={{ fontFamily: 'monospace' }}
          />
          <Space wrap>
            <Button
              type="primary"
              icon={<CloudDownloadOutlined />}
              onClick={handleUpdate}
              loading={updating}
              disabled={settingUp || testing || protocolTesting}
            >
              更新订阅
            </Button>
            <Button onClick={() => void handleSetup()} loading={settingUp} disabled={updating || testing || protocolTesting}>安装 / 启动代理服务</Button>
            <Button
              icon={<ThunderboltOutlined />}
              onClick={handleTestNodes}
              loading={testing}
              disabled={settingUp || updating || protocolTesting}
            >
              测试节点
            </Button>
            <Button
              icon={<CheckCircleOutlined />}
              onClick={handleTestChatGPTProtocol}
              loading={protocolTesting}
              disabled={settingUp || updating || testing}
            >
              ChatGPT 协议预检
            </Button>
            <Button icon={<ReloadOutlined />} onClick={() => { void loadStatus(); void loadProtocolStatus() }} loading={loading}>
              刷新状态
            </Button>
          </Space>
        </Space>
      </Card>

      <Card
        title={
          <Space>
            <span>代理池</span>
            <Badge count={pool.length} style={{ backgroundColor: pool.length > 0 ? '#52c41a' : '#999' }} />
            {status?.test?.progress && (
              <span style={{ fontSize: 12, color: '#999', fontWeight: 'normal' }}>
                {status.test.progress}
              </span>
            )}
          </Space>
        }
        style={{ marginBottom: 16 }}
      >
        {testing && status?.test?.progress && (
          <div style={{ marginBottom: 12 }}>
            <Progress
              percent={(() => {
                const m = status.test.progress.match(/(\d+)\/(\d+)/)
                return m ? Math.round((parseInt(m[1]) / parseInt(m[2])) * 100) : 0
              })()}
              status="active"
              size="small"
            />
          </div>
        )}
        <Table
          rowKey={(r: any) => r.name + r.port}
          columns={nodeColumns}
          dataSource={testResults.length > 0 ? testResults : (status?.nodes || [])}
          loading={loading}
          pagination={{ pageSize: 20, size: 'small' }}
          size="small"
        />
      </Card>

      <Card
        title={
          <Space>
            <span>ChatGPT 协议预检池</span>
            <Badge count={protocolPool.length} style={{ backgroundColor: protocolPool.length > 0 ? '#52c41a' : '#999' }} />
            {protocolStatus?.progress && (
              <span style={{ fontSize: 12, color: '#999', fontWeight: 'normal' }}>
                {protocolStatus.progress}
              </span>
            )}
          </Space>
        }
      >
        <Space wrap style={{ marginBottom: 12 }}><Typography.Text type="secondary">最近检测：{formatCheckTime(protocolStatus?.updated_at)}</Typography.Text><Tag color="success">通过 {protocolResults.filter((result: any) => result.status === 'ok').length}</Tag><Tag color="error">失败 {protocolResults.filter((result: any) => result.status === 'fail' || result.status === 'blocked').length}</Tag></Space>
        {protocolTesting && protocolStatus?.progress && (
          <div style={{ marginBottom: 12 }}>
            <Progress
              percent={(() => {
                const m = protocolStatus.progress.match(/(\d+)\/(\d+)/)
                return m ? Math.round((parseInt(m[1]) / parseInt(m[2])) * 100) : 0
              })()}
              status="active"
              size="small"
            />
          </div>
        )}
        <Table
          rowKey={(r: any) => `${r.name || ''}-${r.addr || r.port || r._index || ''}`}
          columns={nodeColumns}
          dataSource={protocolResults.length > 0 ? protocolResults : protocolPool}
          loading={loading}
          pagination={{ pageSize: 20, size: 'small' }}
          size="small"
        />
      </Card>
    </>
  )
}

export default function Proxies() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader title="代理管理" subtitle="管理注册用的代理节点" />
      <Tabs
        defaultActiveKey="subscription"
        items={[
          {
            key: 'subscription',
            label: '订阅代理池',
            children: <SubscriptionProxies />,
          },
          {
            key: 'manual',
            label: '手动代理',
            children: <ManualProxies />,
          },
        ]}
      />
    </div>
  )
}
