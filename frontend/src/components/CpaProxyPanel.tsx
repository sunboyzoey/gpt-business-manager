import { useCallback, useEffect, useState } from 'react'
import {
  Table, Button, Space, Tag, Modal, Input, Card, Row, Col, Statistic,
  Popconfirm, App, Tooltip, Switch, InputNumber,
} from 'antd'
import {
  ReloadOutlined, PlusOutlined, DeleteOutlined, CloudServerOutlined,
} from '@ant-design/icons'
import { apiFetch } from '@/lib/utils'

interface CpaProxy {
  id: number
  proxy_url: string
  max_accounts: number
  used: number
  available: number
  enabled: boolean
  note: string
  created_at: string
}

interface ProxyStats {
  total: number
  enabled: number
  capacity: number
  used: number
  available: number
}

interface CpaProxyPanelProps {
  /** 空值=旧 GPT PRO 代理池；/gpt-plans=套餐管理专属代理池。 */
  apiPrefix?: '' | '/gpt-plans'
}

export default function CpaProxyPanel({ apiPrefix = '' }: CpaProxyPanelProps) {
  const { message } = App.useApp()
  const [items, setItems] = useState<CpaProxy[]>([])
  const [stats, setStats] = useState<ProxyStats | null>(null)
  const [loading, setLoading] = useState(false)

  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [importing, setImporting] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = (await apiFetch(`${apiPrefix}/cpa-proxy/proxies`)) as { items: CpaProxy[]; stats: ProxyStats }
      setItems(data.items || [])
      setStats(data.stats || null)
    } catch (e: any) {
      message.error(`加载代理失败: ${e?.message || e}`)
    } finally {
      setLoading(false)
    }
  }, [apiPrefix, message])

  useEffect(() => { load() }, [load])

  const doImport = async () => {
    if (!importText.trim()) return message.warning('请输入代理，每行一个')
    setImporting(true)
    try {
      const res = (await apiFetch(`${apiPrefix}/cpa-proxy/proxies/import`, {
        method: 'POST',
        body: JSON.stringify({ data: importText }),
      })) as { added: number; skipped_duplicate: number; invalid: number }
      message.success(`导入完成：新增 ${res.added}，重复跳过 ${res.skipped_duplicate}，非法 ${res.invalid}`)
      setImportOpen(false)
      setImportText('')
      load()
    } catch (e: any) {
      message.error(`导入失败: ${e?.message || e}`)
    } finally {
      setImporting(false)
    }
  }

  const toggleEnabled = async (row: CpaProxy, enabled: boolean) => {
    try {
      await apiFetch(`${apiPrefix}/cpa-proxy/proxies/${row.id}`, {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      })
      load()
    } catch (e: any) {
      message.error(`更新失败: ${e?.message || e}`)
    }
  }

  const saveMax = async (row: CpaProxy, max_accounts: number) => {
    if (max_accounts === row.max_accounts) return
    try {
      await apiFetch(`${apiPrefix}/cpa-proxy/proxies/${row.id}`, {
        method: 'PUT',
        body: JSON.stringify({ max_accounts }),
      })
      message.success('名额上限已更新')
      load()
    } catch (e: any) {
      message.error(`更新失败: ${e?.message || e}`)
    }
  }

  const del = async (id: number) => {
    try {
      await apiFetch(`${apiPrefix}/cpa-proxy/proxies/${id}`, { method: 'DELETE' })
      message.success('已删除')
      load()
    } catch (e: any) {
      message.error(`删除失败: ${e?.message || e}`)
    }
  }

  const columns = [
    {
      title: '代理 URL',
      dataIndex: 'proxy_url',
      key: 'proxy_url',
      ellipsis: true,
      render: (v: string) => <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</span>,
    },
    {
      title: '名额使用',
      key: 'usage',
      width: 160,
      render: (_: unknown, row: CpaProxy) => {
        const full = row.used >= row.max_accounts
        return (
          <Space size={6}>
            <Tag color={full ? 'error' : row.used > 0 ? 'processing' : 'default'} style={{ margin: 0 }}>
              {row.used} / {row.max_accounts}
            </Tag>
            {full && <span style={{ fontSize: 11, color: '#999' }}>已满</span>}
          </Space>
        )
      },
    },
    {
      title: '上限',
      dataIndex: 'max_accounts',
      key: 'max_accounts',
      width: 90,
      render: (_: unknown, row: CpaProxy) => (
        <InputNumber
          size="small"
          min={1}
          max={100}
          defaultValue={row.max_accounts}
          style={{ width: 64 }}
          onBlur={(e) => saveMax(row, Number((e.target as HTMLInputElement).value) || row.max_accounts)}
          onPressEnter={(e) => saveMax(row, Number((e.target as HTMLInputElement).value) || row.max_accounts)}
        />
      ),
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 80,
      render: (v: boolean, row: CpaProxy) => (
        <Switch size="small" checked={v} onChange={(c) => toggleEnabled(row, c)} />
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 90,
      render: (_: unknown, row: CpaProxy) => (
        <Popconfirm title="确认删除该代理？" onConfirm={() => del(row.id)} okType="danger">
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ]

  return (
    <div>
      <Card size="small" style={{ marginBottom: 12, borderRadius: 12 }}>
        <Row gutter={16}>
          <Col span={5}><Statistic title="代理总数" value={stats?.total ?? 0} /></Col>
          <Col span={5}><Statistic title="启用" value={stats?.enabled ?? 0} /></Col>
          <Col span={5}><Statistic title="总名额" value={stats?.capacity ?? 0} /></Col>
          <Col span={5}><Statistic title="已用名额" value={stats?.used ?? 0} /></Col>
          <Col span={4}><Statistic title="剩余名额" value={stats?.available ?? 0} /></Col>
        </Row>
      </Card>

      <Card
        title={<Space><CloudServerOutlined /><span>CPA 代理 IP 池</span><Tag>仅写入 CPA 文件 proxy_url，不做实际请求</Tag></Space>}
        style={{ borderRadius: 12 }}
        extra={
          <Space>
            <Button icon={<PlusOutlined />} type="primary" onClick={() => setImportOpen(true)}>导入代理</Button>
            <Tooltip title="刷新">
              <Button icon={<ReloadOutlined />} loading={loading} onClick={load} />
            </Tooltip>
          </Space>
        }
      >
        <Table<CpaProxy>
          rowKey="id"
          columns={columns}
          dataSource={items}
          loading={loading}
          size="small"
          pagination={{
            ...(apiPrefix === '/gpt-plans' ? { defaultPageSize: 10 } : { pageSize: 50 }),
            showTotal: (t) => `共 ${t} 个`,
          }}
        />
      </Card>

      <Modal
        title="导入代理 IP"
        open={importOpen}
        onCancel={() => setImportOpen(false)}
        onOk={doImport}
        confirmLoading={importing}
        okText="导入"
        width={620}
      >
        <p style={{ color: '#888', fontSize: 12 }}>
          每行一个，格式：<code>socks5://用户名:密码@IP:端口</code>。重复/非法行会自动跳过。
        </p>
        <Input.TextArea
          rows={12}
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          placeholder="socks5://user:pass@198.65.6.78:443"
          style={{ fontFamily: 'monospace', fontSize: 12 }}
        />
      </Modal>
    </div>
  )
}
