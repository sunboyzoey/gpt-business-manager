import { useEffect, useState } from 'react'
import { Alert, Button, Drawer, Input, Space, Table, Tag, Tooltip, Typography, theme } from 'antd'
import type { TableColumnsType } from 'antd'
import { apiFetch } from '@/lib/utils'
import './BusinessMotherAudit.css'

const { Text } = Typography

function timeLabel(value?: string | null): string {
  if (!value) return '未记录'
  const date = new Date(/[Zz]$|[+-]\d{2}:\d{2}$/.test(value) ? value : `${value}Z`)
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : '未记录'
}

export function BusinessDeadStamp({ dead, detectedAt }: { dead?: boolean; detectedAt?: string | null }) {
  if (dead !== true) return null
  return <Tooltip title={`已标记账号停用 · 记录时间：${timeLabel(detectedAt)}（非远端精确封控时间）`}>
    <span className="business-dead-stamp" role="img" aria-label="DEAD · 已停用" tabIndex={0}>DEAD</span>
  </Tooltip>
}

interface AuditItem {
  record_id: string
  record_kind: string
  membership_id: number | null
  child_id: number | null
  email: string
  seat_type: string
  source: string
  invited_at: string | null
  invited_at_source: string
  ended_at: string | null
  end_reason: string
  removed_at: string | null
  removed_at_source: string | null
  removal_observed_at: string | null
  sale_status: string
  sold_at: string | null
}
interface AuditSnapshot {
  mother: { parent_account_id: number; parent_email: string; parent_note: string; is_dead: boolean; dead_detected_at?: string | null }
  finance: { recorded_revenue_yuan: string; cost_yuan: string | null; profit_yuan: string | null; order_count: number; received_count: number; unpriced_count: number }
  rotation_revenue?: { rotation_blocked?: boolean; blocked_tiers?: string[]; tiers?: Record<string, { current_yuan?: string; threshold_yuan?: string | null; exceeded?: boolean }> }
  summary: { membership_count: number; active_count: number; ended_count: number; confirmed_removal_count: number; unknown_removal_time_count: number }
  items: AuditItem[]
  total: number
  page: number
  page_size: number
  notes: string[]
}

function readAudit(value: unknown, motherId: number, page: number): AuditSnapshot {
  if (!value || typeof value !== 'object') throw new Error('母号记录响应无效')
  const data = value as AuditSnapshot & { ok?: boolean }
  const money = (item: unknown, nullable = false) => (nullable && item === null)
    || (typeof item === 'string' && /^-?\d+(\.\d{1,2})?$/.test(item))
  if (data.ok !== true || data.mother?.parent_account_id !== motherId || data.page !== page
    || typeof data.mother.parent_email !== 'string' || typeof data.mother.parent_note !== 'string'
    || typeof data.mother.is_dead !== 'boolean'
    || !Number.isSafeInteger(data.total) || data.total < 0 || data.page_size !== 10
    || !Array.isArray(data.items) || !data.items.every(item => item && typeof item.record_id === 'string'
      && (item.membership_id === null || Number.isSafeInteger(item.membership_id))
      && typeof item.email === 'string' && typeof item.seat_type === 'string'
      && [item.invited_at, item.ended_at, item.removed_at, item.removal_observed_at].every(date => date === null || typeof date === 'string'))
    || !money(data.finance?.recorded_revenue_yuan) || !money(data.finance?.cost_yuan, true) || !money(data.finance?.profit_yuan, true)
    || !['order_count', 'received_count', 'unpriced_count'].every(key => Number.isSafeInteger((data.finance as unknown as Record<string, number>)?.[key]))
    || !data.summary || !['membership_count', 'active_count', 'ended_count', 'confirmed_removal_count', 'unknown_removal_time_count']
      .every(key => Number.isSafeInteger((data.summary as unknown as Record<string, number>)[key]))
    || !Array.isArray(data.notes) || !data.notes.every(note => typeof note === 'string')) {
    throw new Error('母号记录不完整或归属不一致，请重新读取')
  }
  return data
}

const endLabels: Record<string, string> = {
  removed: '已移除', revoked: '已撤邀', replaced: '已替换', parent_deleted: '母号已删除',
  account_deactivated: '账号停用后清理',
  remote_absent_on_refresh: '远端已不在空间', remote_member_missing: '远端未发现成员',
}
const columns: TableColumnsType<AuditItem> = [
  { title: '子号', key: 'email', width: 245, render: (_, item) => <Space direction="vertical" size={3}>
    <Text copyable>{item.email}</Text><Text type="secondary">{item.membership_id ? `成员 #${item.membership_id}` : '历史记录'} · {item.seat_type === 'prolite' ? '高级席位' : item.seat_type === 'default' ? '普通席位' : '席位未记录'}</Text>
  </Space> },
  { title: '邀请 / 归属记录时间', key: 'invited', width: 200, render: (_, item) => <Space direction="vertical" size={2}>
    <Text>{timeLabel(item.invited_at)}</Text><Text type="secondary" style={{ fontSize: 12 }}>{item.record_kind === 'legacy_invitation' ? '历史邀请成功记录' : item.record_kind === 'sale_history' ? '销售流水补充 · 邀请时间未记录' : '本地邀请 / 归属记录'}</Text>
  </Space> },
  { title: '移除 / 结束记录时间', key: 'removed', width: 240, render: (_, item) => <Space direction="vertical" size={2}>
    <Text>{timeLabel(item.removed_at || item.removal_observed_at || item.ended_at)}</Text>
    <Text type="secondary" style={{ fontSize: 12 }}>{item.removed_at ? '移除确认记录时间' : item.removal_observed_at
      ? '远端缺失观察时间 · 非实际移除时间' : item.ended_at ? '仅有本地归属结束记录' : '尚无结束记录'}</Text>
  </Space> },
  { title: '状态', key: 'status', width: 160, render: (_, item) => <Space direction="vertical" size={3}>
    <Tag color={item.ended_at ? 'default' : 'blue'}>{item.ended_at ? endLabels[item.end_reason] || '归属已结束' : item.record_kind === 'membership' ? '归属未结束' : '归属状态未记录'}</Tag>
    <Text type="secondary">{{ listed: '已上架', sold: '已出售', unlisted: '未上架' }[item.sale_status] || '销售状态未记录'}</Text>
  </Space> },
]

export default function BusinessMotherAudit({ motherId, onClose }: { motherId: number | null; onClose: () => void }) {
  const { token } = theme.useToken()
  const [page, setPage] = useState(1)
  const [query, setQuery] = useState('')
  const [draft, setDraft] = useState('')
  const [version, setVersion] = useState(0)
  const [snapshot, setSnapshot] = useState<AuditSnapshot | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => { setPage(1); setQuery(''); setDraft(''); setSnapshot(null); setError('') }, [motherId])
  useEffect(() => {
    if (motherId === null) return
    const controller = new AbortController()
    setLoading(true); setError(''); setSnapshot(null)
    const params = new URLSearchParams({ page: String(page), page_size: '10', q: query })
    apiFetch(`/nv-automation/mothers/${motherId}/audit?${params}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setSnapshot(readAudit(value, motherId, page)) })
      .catch(reason => { if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : '读取失败') })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [motherId, page, query, version])
  const data = snapshot?.mother.parent_account_id === motherId ? snapshot : null
  const finance = data?.finance
  const rotationRevenue = data?.rotation_revenue
  const money = (value: string | null | undefined, unknown = '未记录') => value == null ? unknown : `¥${value}`
  return <Drawer title="母号收益与子号记录" open={motherId !== null} onClose={onClose}
    width="min(1060px, 96vw)" rootClassName="business-mother-audit" destroyOnClose
    extra={<Button loading={loading} onClick={() => setVersion(value => value + 1)}>刷新记录</Button>}>
    {error && <Alert type="error" showIcon message="记录读取失败" description={error} />}
    <Space wrap><Text strong>{data?.mother.parent_email || `母号 #${motherId ?? ''}`}</Text>
      <BusinessDeadStamp dead={data?.mother.is_dead} detectedAt={data?.mother.dead_detected_at} />
      <Text type="secondary">{data?.mother.parent_note || ''}</Text>
    </Space>
    {data?.mother.is_dead && <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
      停用标记记录：{timeLabel(data.mother.dead_detected_at)} · 已停止自动处理，保留记录供排查
    </Text>}
    <div className="audit-metrics" style={{ '--audit-border': token.colorBorderSecondary } as React.CSSProperties}>
      {[
        ['累计实收', money(finance?.recorded_revenue_yuan)],
        ['累计成本', money(finance?.cost_yuan, '未录入')],
        ['净收益', money(finance?.profit_yuan, '待补全金额 / 成本')],
        ['已实收订单', finance ? `${finance.received_count} / ${finance.order_count} 笔` : '—'],
      ].map(([label, value]) => <div key={label} className="audit-metric"><Text type="secondary">{label}</Text><strong>{value}</strong></div>)}
    </div>
    {rotationRevenue && <Alert type={rotationRevenue.rotation_blocked ? 'warning' : 'info'} showIcon style={{ marginBottom: 12 }}
      message={rotationRevenue.rotation_blocked ? '该母号已达到营收轮转上限，已停止新增轮转任务' : '营收轮转上限'}
      description={<Space wrap>{(['default', 'prolite'] as const).map(key => {
        const item = rotationRevenue.tiers?.[key]
        if (!item) return null
        return <Tag key={key} color={item.exceeded ? 'red' : 'blue'}>{key === 'prolite' ? '5X' : '普通'}：¥{item.current_yuan || '0.00'} / {item.threshold_yuan ? `¥${item.threshold_yuan}` : '不限'}</Tag>
      })}</Space>} />}
    {!!finance?.unpriced_count && <Alert type="warning" showIcon message={`${finance.unpriced_count} 笔已实收订单金额未记录；当前金额仅为已知部分`} style={{ marginBottom: 12 }} />}
    <Space wrap style={{ marginBottom: 12 }}>
      <Text strong>子号提拉记录 {data ? `（${data.summary.membership_count} 次归属）` : ''}</Text>
      <Input.Search allowClear placeholder="搜索子号邮箱" value={draft} onChange={event => setDraft(event.target.value)}
        onSearch={value => { setPage(1); setQuery(value.trim()) }} style={{ width: 260 }} />
    </Space>
    <Table<AuditItem> size="small" rowKey="record_id" dataSource={data?.items || []} columns={columns}
      loading={loading} scroll={{ x: 850 }} pagination={{ current: page, pageSize: 10, total: data?.total || 0,
        showSizeChanger: false, onChange: setPage, showTotal: total => `共 ${total} 条` }}
      locale={{ emptyText: error ? '本次未取得记录' : '暂无匹配的子号记录' }} />
    <details style={{ marginTop: 14 }}><summary style={{ cursor: 'pointer', color: token.colorTextSecondary }}>时间与收益口径</summary>
      {data?.notes.map((note, index) => <Typography.Paragraph type="secondary" key={index} style={{ marginTop: 8 }}>{note}</Typography.Paragraph>)}
      <Text type="secondary">记录可用于对照操作顺序，不能单凭时间推断封控原因。净收益 = 实收 − 已录成本，未录成本不按零计算。</Text>
    </details>
  </Drawer>
}
