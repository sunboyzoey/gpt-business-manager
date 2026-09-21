import { Space, Tag, Typography } from 'antd'
import type { InviteQuotaView, InviteSeatType } from '@/lib/businessInviteQuota'

const timeLabel = (value: string) => {
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : '待服务端确认'
}

export default function BusinessInviteQuotaSummary({ quota, stale = false, seatType, seatTypes, labelPrefix = '' }: {
  quota: InviteQuotaView
  stale?: boolean
  seatType?: InviteSeatType
  seatTypes?: readonly InviteSeatType[]
  labelPrefix?: string
}) {
  if (!quota.limited && !seatType) {
    return <Tag data-business-invite-stats="true" style={{ margin: 0, whiteSpace: 'normal' }}
      color={stale ? 'default' : 'blue'}>
      {labelPrefix}邀请成功：今日 {quota.todaySuccessCount} · 累计 {quota.totalSuccessCount}
      {stale ? ' · 旧数据' : ''}
    </Tag>
  }
  const visibleTypes = seatType ? [seatType] : seatTypes ?? ['default', 'prolite'] as const
  if (visibleTypes.length === 0) return <Typography.Text type="secondary" data-business-invite-quota-unavailable="true">
    子号席位类型待确认，请刷新成员/席位
  </Typography.Text>
  const rows = quota.classified
    ? visibleTypes.map(type => ({ type, label: type === 'default' ? '普通' : '高级', quota: quota.byType[type] }))
    : [{ type: 'shared', label: '共享（旧数据）', quota }]
  return <Space direction="vertical" size={3} style={{ width: '100%' }}>
    {rows.map(({ type, label, quota: row }) => <div key={type} data-business-invite-seat-type={type}>
      {row && !row.limited ? <Tag data-business-invite-stats="true" style={{ margin: 0, whiteSpace: 'normal' }}
        color={stale ? 'default' : 'blue'}>
        {labelPrefix}{label}邀请：今日成功 {row.todaySuccessCount} · 累计成功 {row.totalSuccessCount}
        {stale ? ' · 旧数据' : ''}
      </Tag> : <>
      <Tag data-business-invite-quota="true" style={{ margin: 0, whiteSpace: 'normal' }}
        color={stale || !row?.known ? 'default' : Number(row.remaining || 0) <= 0 ? 'error' : 'success'}>
        {labelPrefix}{label}邀请额度：{row?.known ? `剩余 ${row.remaining}/${row.limit} · 已用 ${row.used ?? '—'} · 预留 ${row.reserved}` : '未知'}
        {stale ? ' · 旧数据' : ''}
      </Tag>
      <div><Typography.Text data-business-invite-quota-reset="true" type="secondary" style={{ fontSize: 11 }}>
        {row?.resetAt ? `重置：${timeLabel(row.resetAt)}` : `首个成功邀请后开始 ${row?.windowHours ?? 30} 小时窗口`}
      </Typography.Text></div>
      {row && (row.legacySharedUsed > 0 || row.legacySharedReserved > 0) && <div>
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          含历史共享已用 {row.legacySharedUsed} / 预留 {row.legacySharedReserved}
          {row.legacySharedResetAt ? `，${timeLabel(row.legacySharedResetAt)} 释放` : ''}
        </Typography.Text>
      </div>}
      </>}
    </div>)}
  </Space>
}
