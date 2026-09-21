import { useEffect, useRef, useState } from 'react'
import {
  App, Button, Card, DatePicker, Form, Input, InputNumber, Modal, Popconfirm,
  Segmented, Select, Space, Spin, Switch, Tag, Tooltip, Typography, Row, Col, theme,
} from 'antd'
import dayjs from 'dayjs'
import {
  CreditCardOutlined, DeleteOutlined, EditOutlined, ImportOutlined, MailOutlined,
  PlusOutlined, ReloadOutlined, ClockCircleOutlined, ChromeOutlined, SyncOutlined, DollarOutlined, RollbackOutlined,
} from '@ant-design/icons'
import { apiFetch } from '@/lib/utils'

const { Text } = Typography

interface CardRow {
  id: number
  payment_account_id: number
  opened_at?: string | null
  label: string
  number_masked: string
  number?: string
  exp_month: number
  exp_year: number
  cvc?: string
  holder_name: string
  status: string
  reserved_by_account_id: number
  last_error: string
  single_use: boolean
  enabled: boolean
  priority?: number
  use_count?: number
  paid_account_count?: number
  note: string
}

interface PaymentAccount {
  id: number
  name: string
  account_type: string   // "Y" | "E"
  enabled: boolean
  is_default: boolean
  note: string
  card_count: number
  max_cards: number | null   // null = 不限(默认账号)
  status_counts: Record<string, number>
  roxy_dir_id?: string
  last_card_opened_at?: string | null
  open_cooldown_seconds?: number   // E卡开卡冷却剩余秒(0=可开)
  balance_usd?: number
  balance_text?: string
  balance_updated_at?: string | null
  paid_count?: number
  refunded_count?: number
  pending_refund_count?: number
  card_open_count?: number
  unrefunded_count?: number          // 未发起退款 = 支付 − 已退 − 待退
  unrefunded_dates?: string[]        // 这些未退款支付的日期(最近 N 笔)
  pending_refund_updated_at?: string | null
}

const STATUS_COLOR: Record<string, string> = {
  unused: 'green', in_use: 'processing', used: 'default', failed: 'error', disabled: 'default',
}
const STATUS_LABEL: Record<string, string> = {
  unused: '未用', in_use: '占用中', used: '已用', failed: '失败', disabled: '停用',
}
const TYPE_LABEL: Record<string, string> = { Y: 'Y卡', E: 'E卡' }
const TYPE_COLOR: Record<string, string> = { Y: 'geekblue', E: 'purple' }

interface CardsPageProps {
  /** 空值=旧 GPT PRO 卡池；/gpt-plans=套餐管理专属卡池。 */
  apiPrefix?: '' | '/gpt-plans'
}

export default function CardsPage({ apiPrefix = '' }: CardsPageProps) {
  const { message } = App.useApp()
  const { token } = theme.useToken()
  const inventoryFetch = (
    path: string,
    options?: Parameters<typeof apiFetch>[1],
  ) => {
    // 这一个历史邮件回填地址也必须跟随当前账号目录，不能让旧 PRO 页面
    // 触发套餐账号回填，或让套餐页面回写旧 PRO 账号。
    const scopedPath = path.startsWith('/gpt-plans/')
      ? `${apiPrefix || '/gpt-pro'}${path.slice('/gpt-plans'.length)}`
      : `${apiPrefix}${path}`
    return apiFetch(scopedPath, options)
  }
  const [accounts, setAccounts] = useState<PaymentAccount[]>([])
  const [cardsByAcc, setCardsByAcc] = useState<Record<number, CardRow[]>>({})
  const [loading, setLoading] = useState(false)
  const [viewMode, setViewMode] = useState<'account' | 'card'>('card')
  const accountRefs = useRef<Record<number, HTMLDivElement | null>>({})
  // 「该卡支付了哪些账号」弹窗
  const [paidModal, setPaidModal] = useState<{ card: CardRow; loading: boolean; accounts: { id: number; email: string; is_pro: boolean; created_at?: string | null }[] } | null>(null)
  const openPaidAccounts = async (card: CardRow) => {
    setPaidModal({ card, loading: true, accounts: [] })
    try {
      const r = (await inventoryFetch(`/cards/${card.id}/paid-accounts`)) as {
        accounts: { id: number; email: string; is_pro: boolean; created_at?: string | null }[]
      }
      setPaidModal({ card, loading: false, accounts: r.accounts || [] })
    } catch (e: any) {
      message.error(e.message || '加载失败')
      setPaidModal(null)
    }
  }
  const [highlightPa, setHighlightPa] = useState<number | null>(null)
  // 从「按卡片」点账号 → 切到「按账号」并滚动定位 + 高亮
  const jumpToAccount = (paId: number) => {
    setViewMode('account')
    setHighlightPa(paId)
    setTimeout(() => {
      accountRefs.current[paId]?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }, 60)
    setTimeout(() => setHighlightPa((v) => (v === paId ? null : v)), 2200)
  }
  // 打开浏览器需要用户从候选里选 profile 时
  const [browserSelect, setBrowserSelect] = useState<{ pa: PaymentAccount; profiles: { dir_id: string; name: string }[] } | null>(null)
  const [selectedDirId, setSelectedDirId] = useState<string | undefined>(undefined)
  // 记开卡冷却"开始时的剩余秒"和拉取时刻,前端每秒本地递减做倒计时(不用一直打接口)
  const [cooldownAt, setCooldownAt] = useState<Record<number, { left: number; at: number }>>({})
  const [nowTick, setNowTick] = useState(Date.now())
  useEffect(() => {
    const t = setInterval(() => setNowTick(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  const cooldownLeft = (pa: PaymentAccount): number => {
    const rec = cooldownAt[pa.id]
    if (!rec) return pa.open_cooldown_seconds || 0
    return Math.max(0, Math.round(rec.left - (nowTick - rec.at) / 1000))
  }
  const fmtCd = (secs: number): string => {
    const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), s = secs % 60
    return h > 0 ? `${h}h${m}m` : (m > 0 ? `${m}m${s}s` : `${s}s`)
  }

  // 支付账号 新建/编辑
  const [paModalOpen, setPaModalOpen] = useState(false)
  const [editingPa, setEditingPa] = useState<PaymentAccount | null>(null)
  const [paForm] = Form.useForm()

  // U卡 新建/编辑
  const [cardModalOpen, setCardModalOpen] = useState(false)
  const [cardTargetAcc, setCardTargetAcc] = useState<PaymentAccount | null>(null)
  const [editingCard, setEditingCard] = useState<CardRow | null>(null)
  const [cardForm] = Form.useForm()

  // 导入
  const [importOpen, setImportOpen] = useState(false)
  const [importAcc, setImportAcc] = useState<PaymentAccount | null>(null)
  const [importText, setImportText] = useState('')

  const refresh = async () => {
    setLoading(true)
    try {
      const [pa, cards] = await Promise.all([
        inventoryFetch('/payment-accounts'),
        inventoryFetch('/cards'),
      ])
      const accs = (pa.items || []) as PaymentAccount[]
      setAccounts(accs)
      // 记录每个账号的开卡冷却基线(前端本地倒计时)
      const cd: Record<number, { left: number; at: number }> = {}
      for (const a of accs) cd[a.id] = { left: a.open_cooldown_seconds || 0, at: Date.now() }
      setCooldownAt(cd)
      const grouped: Record<number, CardRow[]> = {}
      for (const c of (cards.items || []) as CardRow[]) {
        (grouped[c.payment_account_id] ||= []).push(c)
      }
      setCardsByAcc(grouped)
    } catch (e: any) {
      message.error(`加载失败: ${e.message || e}`)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  // ── 支付账号 ──
  const openCreatePa = () => {
    setEditingPa(null)
    paForm.resetFields()
    paForm.setFieldsValue({ account_type: 'Y' })
    setPaModalOpen(true)
  }
  const openEditPa = (pa: PaymentAccount) => {
    setEditingPa(pa)
    paForm.setFieldsValue({ name: pa.name, account_type: pa.account_type, note: pa.note, roxy_dir_id: pa.roxy_dir_id || '' })
    setPaModalOpen(true)
  }
  const submitPa = async () => {
    try {
      const values = await paForm.validateFields()
      if (editingPa) {
        await inventoryFetch(`/payment-accounts/${editingPa.id}`, { method: 'PATCH', body: JSON.stringify(values) })
        message.success('支付账号已更新')
      } else {
        await inventoryFetch('/payment-accounts', { method: 'POST', body: JSON.stringify(values) })
        message.success('支付账号已创建')
      }
      setPaModalOpen(false)
      refresh()
    } catch (e: any) {
      if (e?.errorFields) return
      message.error(e.message || '保存失败')
    }
  }
  const togglePaEnabled = async (pa: PaymentAccount, enabled: boolean) => {
    setAccounts((prev) => prev.map((a) => (a.id === pa.id ? { ...a, enabled } : a)))
    try {
      await inventoryFetch(`/payment-accounts/${pa.id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) })
    } catch (e: any) {
      message.error(e.message || '切换失败')
      setAccounts((prev) => prev.map((a) => (a.id === pa.id ? { ...a, enabled: !enabled } : a)))
    }
  }
  const deletePa = async (pa: PaymentAccount) => {
    try {
      await inventoryFetch(`/payment-accounts/${pa.id}?force=true`, { method: 'DELETE' })
      message.success('支付账号已删除')
      refresh()
    } catch (e: any) {
      message.error(e.message || '删除失败')
    }
  }
  const [syncingCards, setSyncingCards] = useState<number | null>(null)
  const syncCardsFromBrowser = async (pa: PaymentAccount) => {
    setSyncingCards(pa.id)
    const hide = message.loading(`正在从「${pa.name}」的浏览器抓取 ether.fi 卡信息…(约 20-40s)`, 0)
    try {
      const r = (await inventoryFetch(`/payment-accounts/${pa.id}/sync-cards-from-browser`, { method: 'POST' })) as {
        found: number; synced: number; backfilled?: number; skipped: number; message?: string; logs?: string[]
      }
      hide()
      if (!r.found && !r.backfilled) {
        const detail = Array.isArray(r.logs) ? r.logs.filter(Boolean).slice(-4).join(' · ') : ''
        message.warning(`${r.message || '没抓到卡(先在浏览器里登录/过验证)'}${detail ? ` · ${detail}` : ''}`, 10)
      }
      else if (!r.found) message.success(`未抓到新卡,但已补开卡时间 ${r.backfilled} 张`, 6)
      else message.success(`抓到 ${r.found} 张:新增 ${r.synced},补开卡时间 ${r.backfilled || 0},忽略 ${r.skipped}`, 6)
      refresh()
    } catch (e: any) {
      hide()
      message.error(e.message || '同步失败')
    } finally {
      setSyncingCards(null)
    }
  }
  const [syncingBalance, setSyncingBalance] = useState<number | null>(null)
  const syncBalance = async (pa: PaymentAccount) => {
    setSyncingBalance(pa.id)
    const hide = message.loading(`正在读「${pa.name}」余额…`, 0)
    try {
      const r = (await inventoryFetch(`/payment-accounts/${pa.id}/sync-balance`, { method: 'POST' })) as {
        ok: boolean; balance_usd?: number; message?: string
      }
      hide()
      if (r.ok) message.success(`余额已刷新:$${(r.balance_usd ?? 0).toFixed(2)}`)
      else message.warning(r.message || '没读到余额')
      refresh()
    } catch (e: any) {
      hide()
      message.error(e.message || '刷余额失败')
    } finally {
      setSyncingBalance(null)
    }
  }
  const [openingUrl, setOpeningUrl] = useState<string | null>(null)  // `${pa.id}:${kind}`
  const openBrowserAt = async (pa: PaymentAccount, kind: 'recharge' | 'order-card', label: string) => {
    setOpeningUrl(`${pa.id}:${kind}`)
    const hide = message.loading(`正在为「${pa.name}」打开${label}页…`, 0)
    try {
      const r = (await inventoryFetch(`/payment-accounts/${pa.id}/open-${kind}`, { method: 'POST' })) as {
        ok: boolean; message?: string
      }
      hide()
      message.success(r.message || `已打开${label}页`)
    } catch (e: any) {
      hide()
      message.error(e.message || `打开${label}页失败`)
    } finally {
      setOpeningUrl(null)
    }
  }
  const [syncingRefunds, setSyncingRefunds] = useState<number | null>(null)
  const syncPendingRefunds = async (pa: PaymentAccount) => {
    setSyncingRefunds(pa.id)
    const hide = message.loading(`正在读「${pa.name}」交易记录统计…`, 0)
    try {
      const r = (await inventoryFetch(`/payment-accounts/${pa.id}/sync-pending-refunds`, { method: 'POST' })) as {
        ok: boolean; changed?: boolean; balance_refreshed?: boolean; balance_usd?: number
        paid_count?: number; refunded_count?: number; pending_refund_count?: number
      }
      hide()
      message.success(`支付 ${r.paid_count ?? 0} · 成功退款 ${r.refunded_count ?? 0} · 待退款 ${r.pending_refund_count ?? 0} 笔`, 5)
      if (r.changed && r.balance_refreshed) message.info(`交易有变更,余额已同步刷新:$${(r.balance_usd ?? 0).toFixed(2)}`, 5)
      else if (r.changed) message.warning('交易有变更,但余额刷新失败,请手动点「刷余额」')
      refresh()
    } catch (e: any) {
      hide()
      message.error(e.message || '统计交易失败')
    } finally {
      setSyncingRefunds(null)
    }
  }
  const [backfilling, setBackfilling] = useState(false)
  const backfillLast4FromMail = async () => {
    setBackfilling(true)
    const hide = message.loading('正在读邮件回填卡尾号…(账号较多时可能要 1-2 分钟)', 0)
    try {
      const r = (await inventoryFetch('/gpt-plans/accounts/backfill-card-last4-from-mail', { method: 'POST' })) as {
        scanned: number; filled: number; not_found: number; errors: number
      }
      hide()
      message.success(`扫描 ${r.scanned} 个:回填 ${r.filled},未找到 ${r.not_found},出错 ${r.errors}`, 6)
      refresh()
    } catch (e: any) {
      hide()
      message.error(e.message || '回填失败')
    } finally {
      setBackfilling(false)
    }
  }
  const openBrowser = async (pa: PaymentAccount, dirId?: string) => {
    const hide = message.loading(`正在打开「${pa.name}」的指纹浏览器…`, 0)
    try {
      const q = dirId ? `?dir_id=${encodeURIComponent(dirId)}` : ''
      const r = (await inventoryFetch(`/payment-accounts/${pa.id}/open-browser${q}`, { method: 'POST' })) as {
        ok: boolean; need_select?: boolean; profiles?: { dir_id: string; name: string }[]; message?: string
      }
      hide()
      if (r.ok) {
        message.success('已打开指纹浏览器窗口')
        setBrowserSelect(null)
        refresh()
      } else if (r.need_select) {
        // 未按 ID/邮箱名找到 → 让用户从候选里选一个
        setBrowserSelect({ pa, profiles: r.profiles || [] })
        setSelectedDirId(undefined)
        message.info(r.message || '请选择一个指纹浏览器')
      } else {
        message.error(r.message || '打开失败')
      }
    } catch (e: any) {
      hide()
      message.error(e.message || '打开失败')
    }
  }
  // ── U卡 ──
  const openAddCard = (pa: PaymentAccount) => {
    setCardTargetAcc(pa)
    setEditingCard(null)
    cardForm.resetFields()
    cardForm.setFieldsValue({ single_use: true, priority: 100 })
    setCardModalOpen(true)
  }
  const openEditCard = async (row: CardRow) => {
    try {
      const full = await inventoryFetch(`/cards/${row.id}?reveal=true`)
      setCardTargetAcc(accounts.find((a) => a.id === row.payment_account_id) || null)
      setEditingCard(row)
      cardForm.setFieldsValue({
        number: full.number, exp_month: full.exp_month, exp_year: full.exp_year, cvc: full.cvc,
        holder_name: full.holder_name, label: full.label, single_use: full.single_use,
        enabled: full.enabled, priority: full.priority ?? 100, note: full.note,
        opened_at: full.opened_at ? dayjs(full.opened_at) : null,
      })
      setCardModalOpen(true)
    } catch (e: any) {
      message.error(e.message || '加载失败')
    }
  }
  const submitCard = async () => {
    try {
      const values = await cardForm.validateFields()
      // opened_at (dayjs) → ISO 字符串(空=清除)
      if ('opened_at' in values) values.opened_at = values.opened_at ? values.opened_at.toISOString() : ''
      if (editingCard) {
        const patch: any = { ...values }
        if (!patch.number) delete patch.number
        if (!patch.cvc) delete patch.cvc
        await inventoryFetch(`/cards/${editingCard.id}`, { method: 'PATCH', body: JSON.stringify(patch) })
        message.success('U卡已更新')
      } else {
        await inventoryFetch('/cards', {
          method: 'POST',
          body: JSON.stringify({ ...values, payment_account_id: cardTargetAcc?.id }),
        })
        message.success('U卡已添加')
      }
      setCardModalOpen(false)
      refresh()
    } catch (e: any) {
      if (e?.errorFields) return
      message.error(e.message || '保存失败')
    }
  }
  const deleteCard = async (id: number) => {
    try {
      await inventoryFetch(`/cards/${id}`, { method: 'DELETE' })
      message.success('已删除')
      refresh()
    } catch (e: any) {
      message.error(e.message || '删除失败')
    }
  }
  const toggleCardEnabled = async (row: CardRow, enabled: boolean) => {
    try {
      await inventoryFetch(`/cards/${row.id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) })
      refresh()
    } catch (e: any) {
      message.error(e.message || '切换失败')
    }
  }
  const updateCardPriority = async (row: CardRow, priority: number) => {
    const p = Math.max(1, Math.min(9999, Number(priority) || 100))
    if (p === (row.priority ?? 100)) return
    // 乐观更新
    setCardsByAcc((prev) => {
      const list = (prev[row.payment_account_id] || []).map((c) => (c.id === row.id ? { ...c, priority: p } : c))
      return { ...prev, [row.payment_account_id]: list }
    })
    try {
      await inventoryFetch(`/cards/${row.id}`, { method: 'PATCH', body: JSON.stringify({ priority: p }) })
    } catch (e: any) {
      message.error(e.message || '优先级更新失败')
      refresh()
    }
  }

  // ── 导入 ──
  const openImport = (pa: PaymentAccount) => {
    setImportAcc(pa)
    setImportText('')
    setImportOpen(true)
  }
  const submitImport = async () => {
    if (!importText.trim()) { message.warning('请粘贴卡内容'); return }
    try {
      const r = await inventoryFetch('/cards/import', {
        method: 'POST',
        body: JSON.stringify({ csv_text: importText, payment_account_id: importAcc?.id }),
      })
      message.success(`导入完成:成功 ${r.ok},失败 ${r.fail}`)
      if (r.errors?.length) {
        Modal.warning({
          title: '部分未导入',
          content: <pre style={{ maxHeight: 400, overflow: 'auto', fontSize: 12 }}>{r.errors.join('\n')}</pre>,
          width: 700,
        })
      }
      setImportOpen(false)
      refresh()
    } catch (e: any) {
      message.error(e.message || '导入失败')
    }
  }

  // ── 父表(支付账号)──
  // 账号操作按钮(账号视图/卡片视图共用)
  const renderAccountActions = (pa: PaymentAccount) => {
    const full = !!pa.max_cards && pa.card_count >= pa.max_cards
    const cd = pa.account_type === 'E' ? cooldownLeft(pa) : 0
    return (
      <Space size={4} wrap>
        {pa.account_type === 'E' && (
          cd > 0 ? (
            <Tooltip title="距下次可开卡的倒计时(按最新一张卡的开卡时间 +24h 自动算)">
              <Tag color="orange" icon={<ClockCircleOutlined />} style={{ margin: 0 }}>还需 {fmtCd(cd)}</Tag>
            </Tooltip>
          ) : (
            <Tooltip title="已过 24 小时,可以开新卡了">
              <Tag color="success" icon={<ClockCircleOutlined />} style={{ margin: 0 }}>可开卡</Tag>
            </Tooltip>
          )
        )}
        <Tooltip title="打开该账号的指纹浏览器(优先用已存ID,否则按账号名查找,再没有让你选)">
          <Button size="small" icon={<ChromeOutlined />} onClick={() => openBrowser(pa)}>浏览器</Button>
        </Tooltip>
        {pa.account_type === 'E' && (
          <Tooltip title="在该账号指纹浏览器里打开 ether.fi 充值(接收地址)页">
            <Button size="small" icon={<DollarOutlined />} loading={openingUrl === `${pa.id}:recharge`}
              onClick={() => openBrowserAt(pa, 'recharge', '充值')}>充值</Button>
          </Tooltip>
        )}
        {pa.account_type === 'E' && cd <= 0 && (
          <Tooltip title="可开卡:在该账号指纹浏览器里打开 ether.fi 开卡页(order-card)">
            <Button size="small" type="primary" icon={<CreditCardOutlined />} loading={openingUrl === `${pa.id}:order-card`}
              onClick={() => openBrowserAt(pa, 'order-card', '开卡')}>开卡</Button>
          </Tooltip>
        )}
        {pa.account_type === 'E' && (
          <Tooltip title="打开浏览器自动抓 ether.fi 完整卡信息(点 Ver detalles),按卡号去重加到本账号(已存在忽略)">
            <Button size="small" icon={<SyncOutlined />} loading={syncingCards === pa.id} onClick={() => syncCardsFromBrowser(pa)}>同步卡</Button>
          </Tooltip>
        )}
        {pa.account_type === 'E' && (
          <Tooltip title="打开浏览器读 ether.fi 保险库总余额(Saldo total)">
            <Button size="small" icon={<DollarOutlined />} loading={syncingBalance === pa.id} onClick={() => syncBalance(pa)}>刷余额</Button>
          </Tooltip>
        )}
        {pa.account_type === 'E' && (
          <Tooltip title="读 ether.fi 交易记录,统计「+$200 且 pending」的待退款笔数">
            <Button size="small" icon={<RollbackOutlined />} loading={syncingRefunds === pa.id} onClick={() => syncPendingRefunds(pa)}>刷待退款</Button>
          </Tooltip>
        )}
        <Tooltip title={full ? `已满 ${pa.max_cards} 张` : ''}>
          <Button size="small" type="primary" ghost icon={<PlusOutlined />} disabled={full}
            onClick={() => openAddCard(pa)}>加U卡</Button>
        </Tooltip>
        <Button size="small" icon={<ImportOutlined />} onClick={() => openImport(pa)}>导入</Button>
        <Button size="small" icon={<EditOutlined />} onClick={() => openEditPa(pa)} />
        <Popconfirm
          title={`删除支付账号「${pa.name}」?`}
          description={pa.card_count ? `其下 ${pa.card_count} 张 U卡 会一并删除!` : undefined}
          okText="删除" okButtonProps={{ danger: true }}
          onConfirm={() => deletePa(pa)}
        >
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      </Space>
    )
  }

  const totalCards = accounts.reduce((s, a) => s + a.card_count, 0)

  // 「按卡片」视图的单张卡片小块
  const renderCardTile = (c: CardRow, paEnabled: boolean, account?: PaymentAccount) => (
    <div key={c.id} style={{
      width: 220,
      border: `1px solid ${token.colorBorderSecondary}`,
      borderRadius: 8,
      padding: '8px 10px',
      background: token.colorFillQuaternary,
      opacity: paEnabled ? 1 : 0.55,
    }}>
      {account && (
        <Tooltip title="点击跳到「按账号」并定位该账号">
          <div
            onClick={() => jumpToAccount(account.id)}
            style={{ fontSize: 11, marginBottom: 3, display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}
          >
            <Tag color={TYPE_COLOR[account.account_type] || 'default'} style={{ margin: 0, lineHeight: '14px', fontSize: 10, padding: '0 4px' }}>
              {TYPE_LABEL[account.account_type] || account.account_type}
            </Tag>
            <span style={{ color: token.colorLink, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{account.name}</span>
            {account.account_type === 'E' && (account.balance_updated_at || account.balance_usd) ? (
              <span style={{ color: token.colorSuccess, fontWeight: 600, whiteSpace: 'nowrap' }}>${(account.balance_usd ?? 0).toFixed(2)}</span>
            ) : null}
          </div>
        </Tooltip>
      )}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Tooltip title="点击编辑(卡号/有效期/开卡时间等)">
          <Text code style={{ fontSize: 13, cursor: 'pointer' }} onClick={() => openEditCard(c)}>{c.number_masked}</Text>
        </Tooltip>
        {c.label && <Tag style={{ margin: 0 }}>{c.label}</Tag>}
      </div>
      <div style={{ fontSize: 12, color: token.colorTextSecondary, marginTop: 2 }}>
        {String(c.exp_month).padStart(2, '0')}/{String(c.exp_year).slice(-2)} · {c.holder_name || '—'}
      </div>
      <div style={{ fontSize: 11, color: token.colorTextTertiary, marginTop: 2 }}>
        <ClockCircleOutlined /> 开卡: {c.opened_at ? new Date(c.opened_at).toLocaleString() : '—'}
      </div>
      <div style={{ fontSize: 11, marginTop: 2 }}>
        <Tooltip title="该卡支付成功的 PRO 账号数(按卡尾号匹配)。点击查看具体账号">
          <span onClick={() => c.paid_account_count ? openPaidAccounts(c) : undefined}
            style={{ color: c.paid_account_count ? token.colorLink : token.colorTextTertiary, cursor: c.paid_account_count ? 'pointer' : 'default' }}>
            <CreditCardOutlined /> 已支付 {c.paid_account_count ?? 0} 个账号
          </span>
        </Tooltip>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 }}>
        <Tooltip title="优先级,越小越先用,改完即存">
          <Space size={2}>
            <span style={{ fontSize: 11, color: token.colorTextTertiary }}>优</span>
            <InputNumber key={`p${c.id}-${c.priority}`} size="small" min={1} max={9999}
              defaultValue={c.priority ?? 100} style={{ width: 58 }} controls={false}
              onBlur={(e) => updateCardPriority(c, Number((e.target as HTMLInputElement).value))}
              onPressEnter={(e) => updateCardPriority(c, Number((e.target as HTMLInputElement).value))} />
          </Space>
        </Tooltip>
        {paEnabled
          ? <Tag color={STATUS_COLOR[c.status] || 'default'} style={{ margin: 0 }}>{STATUS_LABEL[c.status] || c.status}</Tag>
          : <Tag color="error" style={{ margin: 0 }}>失效</Tag>}
        <span style={{ marginLeft: 'auto' }} />
        <Tooltip title={c.enabled ? '已启用,点停用' : '已停用,点启用'}>
          <Switch size="small" checked={c.enabled} checkedChildren="启" unCheckedChildren="停"
            disabled={!paEnabled} onChange={(v) => toggleCardEnabled(c, v)} />
        </Tooltip>
        <Popconfirm title="删除该 U卡?" onConfirm={() => deleteCard(c.id)}>
          <Button size="small" type="text" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      </div>
    </div>
  )

  return (
    <div style={{ padding: 16 }}>
      <Card
        title={<Space><CreditCardOutlined />支付账号 / 卡池<Text type="secondary" style={{ fontSize: 12 }}>({accounts.length} 个支付账号 · {totalCards} 张 U卡)</Text></Space>}
        extra={
          <Space>
            <Segmented
              value={viewMode}
              onChange={(v) => setViewMode(v as 'account' | 'card')}
              options={[{ label: '按账号', value: 'account' }, { label: '按卡片', value: 'card' }]}
            />
            <Button icon={<ReloadOutlined />} onClick={refresh}>刷新</Button>
            <Tooltip title="对「已付费但缺卡尾号」的 PRO 账号,读收据邮件解析卡尾号并回填,补全每张卡的「已支付账号数」。会读多个邮箱,较慢">
              <Popconfirm title="从邮件回填卡尾号?" description="将读取缺尾号 PRO 账号的邮箱(较慢,约每账号数秒)" okText="开始" onConfirm={backfillLast4FromMail}>
                <Button icon={<MailOutlined />} loading={backfilling}>邮件补尾号</Button>
              </Popconfirm>
            </Tooltip>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreatePa}>新建支付账号</Button>
          </Space>
        }
      >
        <Spin spinning={loading}>
        {viewMode === 'card' ? (
          /* 按卡片:所有 U卡 全平铺, 按开卡时间倒序(新开的在最上), 每张显示所属账号 + 开关 + 优先级 */
          (() => {
            const accById: Record<number, PaymentAccount> = {}
            for (const a of accounts) accById[a.id] = a
            const all = accounts.flatMap((a) => (cardsByAcc[a.id] || []).map((c) => ({ c, a })))
            all.sort((x, y) => {
              const tx = x.c.opened_at ? new Date(x.c.opened_at).getTime() : 0
              const ty = y.c.opened_at ? new Date(y.c.opened_at).getTime() : 0
              return ty - tx   // 新开的(时间大)排前
            })
            if (!all.length) return <Text type="secondary">还没有 U卡</Text>
            return (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {all.map(({ c, a }) => renderCardTile(c, a.enabled, a))}
              </div>
            )
          })()
        ) : (
          /* 按账号:分组卡片(账号头带开关/倒计时/余额/操作, 下面平铺该账号的卡) */
          <div>
            {accounts.map((pa) => {
              const accent = pa.account_type === 'E' ? token.purple : token.geekblue
              const cards = cardsByAcc[pa.id] || []
              return (
                <div key={pa.id}
                  ref={(el) => { accountRefs.current[pa.id] = el }}
                  style={{
                  marginBottom: 12,
                  border: `1px solid ${highlightPa === pa.id ? token.colorPrimary : token.colorBorderSecondary}`,
                  borderLeft: `4px solid ${accent}`,
                  borderRadius: 8,
                  padding: 10,
                  background: pa.enabled ? undefined : 'rgba(255,77,79,0.05)',
                  boxShadow: highlightPa === pa.id ? `0 0 0 2px ${token.colorPrimaryBorder}` : undefined,
                  transition: 'box-shadow 0.3s, border-color 0.3s',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
                    <Tag color={TYPE_COLOR[pa.account_type] || 'default'} style={{ margin: 0 }}>{TYPE_LABEL[pa.account_type] || pa.account_type}</Tag>
                    <b style={{ fontSize: 14 }}>{pa.name}</b>
                    {pa.is_default && <Tag>默认</Tag>}
                    <Tooltip title="停用后该账号下所有 U卡 失效">
                      <Switch checked={pa.enabled} checkedChildren="启" unCheckedChildren="停" onChange={(c) => togglePaEnabled(pa, c)} />
                    </Tooltip>
                    <span style={{ color: token.colorTextTertiary, fontSize: 12 }}>U卡 {pa.card_count}{pa.max_cards ? `/${pa.max_cards}` : ''}</span>
                    {pa.account_type === 'E' && (pa.balance_updated_at || pa.balance_usd) ? (
                      <Tooltip title={`${pa.balance_text || ''}${pa.balance_updated_at ? ` · 刷新于 ${new Date(pa.balance_updated_at).toLocaleString()}` : ''}`}>
                        <Tag color="green" style={{ margin: 0 }}>余额 ${(pa.balance_usd ?? 0).toFixed(2)}</Tag>
                      </Tooltip>
                    ) : null}
                    {pa.account_type === 'E' && pa.pending_refund_updated_at ? (
                      <Space size={3}>
                        <Tooltip title={`交易统计(Pro 档订阅, $200 或 PHP 换算) · 刷新于 ${new Date(pa.pending_refund_updated_at).toLocaleString()}\n支付 × ${pa.paid_count ?? 0}\n成功退款 × ${pa.refunded_count ?? 0}\n待退款(pending) × ${pa.pending_refund_count ?? 0}`}>
                          <Space size={3}>
                            <Tag style={{ margin: 0 }}>开卡 {pa.card_open_count ?? 0}</Tag>
                            <Tag color="blue" style={{ margin: 0 }}>支付 {pa.paid_count ?? 0}</Tag>
                            <Tag color="green" style={{ margin: 0 }}>已退 {pa.refunded_count ?? 0}</Tag>
                            <Tag color={pa.pending_refund_count ? 'orange' : 'default'} style={{ margin: 0 }}>待退 {pa.pending_refund_count ?? 0}</Tag>
                          </Space>
                        </Tooltip>
                        {(pa.unrefunded_count ?? 0) > 0 && (
                          <Tooltip title={`未发起退款(付了但还没退款、也没挂待退)的支付时间:\n${(pa.unrefunded_dates && pa.unrefunded_dates.length ? pa.unrefunded_dates : ['(时间未知,点「一键更新支付账号」或「刷待退款」后显示)']).join('\n')}`}>
                            <Tag color="red" style={{ margin: 0 }}>未发起退款 {pa.unrefunded_count}</Tag>
                          </Tooltip>
                        )}
                      </Space>
                    ) : null}
                    <div style={{ marginLeft: 'auto' }}>{renderAccountActions(pa)}</div>
                  </div>
                  {pa.note && <div style={{ fontSize: 11, color: token.colorTextTertiary, marginBottom: 6 }}>备注: {pa.note}</div>}
                  {!pa.enabled && <div style={{ color: token.colorError, fontSize: 12, marginBottom: 6 }}>⚠ 账号已停用 → 下面所有 U卡 失效</div>}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {cards.length === 0
                      ? <Text type="secondary" style={{ fontSize: 12 }}>还没有 U卡,点「加U卡」或「导入」</Text>
                      : cards.map((c) => renderCardTile(c, pa.enabled))}
                  </div>
                </div>
              )
            })}
            {accounts.length === 0 && <Text type="secondary">还没有支付账号,点右上「新建支付账号」</Text>}
          </div>
        )}
        </Spin>
      </Card>

      {/* 支付账号 新建/编辑 */}
      <Modal
        title={editingPa ? `编辑支付账号 #${editingPa.id}` : '新建支付账号'}
        open={paModalOpen}
        onCancel={() => setPaModalOpen(false)}
        onOk={submitPa}
        width={480}
        destroyOnClose
      >
        <Form form={paForm} layout="vertical">
          <Form.Item label="账号名称" name="name" rules={[{ required: true, message: '请输入账号名称' }]}>
            <Input placeholder="例如:卡商甲 / 张三-E" />
          </Form.Item>
          <Form.Item label="类型" name="account_type" rules={[{ required: true }]}>
            <Segmented options={[{ label: 'Y卡', value: 'Y' }, { label: 'E卡', value: 'E' }]} />
          </Form.Item>
          <Form.Item label="指纹浏览器ID (RoxyBrowser dir_id)" name="roxy_dir_id"
            tooltip="账号保存在指纹浏览器里。填 profile 的 dir_id,列表里可一键打开该浏览器去开卡">
            <Input placeholder="留空则不支持一键打开浏览器" />
          </Form.Item>
          <Form.Item label="备注" name="note">
            <Input.TextArea rows={2} />
          </Form.Item>
          <Text type="secondary" style={{ fontSize: 12 }}>每个支付账号下最多 5 张 U卡(默认账号不限)。E卡 每 24h 只能开一张。</Text>
        </Form>
      </Modal>

      {/* U卡 新建/编辑 */}
      <Modal
        title={editingCard ? `编辑 U卡 #${editingCard.id}` : `给「${cardTargetAcc?.name || ''}」添加 U卡`}
        open={cardModalOpen}
        onCancel={() => setCardModalOpen(false)}
        onOk={submitCard}
        width={680}
        destroyOnClose
      >
        <Form form={cardForm} layout="vertical" initialValues={{ single_use: true, priority: 100 }}>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item label="卡号" name="number" rules={editingCard ? [] : [{ required: true }]}>
                <Input placeholder={editingCard ? '留空 = 不修改' : '4242424242424242'} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item label="月" name="exp_month" rules={[{ required: true }]}>
                <InputNumber min={1} max={12} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item label="年(4位)" name="exp_year" rules={[{ required: true }]}>
                <InputNumber min={2024} max={2099} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={8}>
              <Form.Item label="CVC" name="cvc" rules={editingCard ? [] : [{ required: true }]}>
                <Input placeholder={editingCard ? '留空 = 不修改' : '3-4 位'} />
              </Form.Item>
            </Col>
            <Col span={16}>
              <Form.Item label="持卡人" name="holder_name">
                <Input placeholder="留空自动随机" />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item label="备注标签" name="label"><Input placeholder="例如:7月" /></Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item label="一次性" name="single_use" valuePropName="checked"
                tooltip="支付成功就标 used 不再复用"><Switch /></Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item label="优先级" name="priority" tooltip="升级 PRO 自动选卡顺序,数字越小越先用">
                <InputNumber min={1} max={9999} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
          {editingCard && (
            <Row gutter={12}>
              <Col span={12}>
                <Form.Item label="启用" name="enabled" valuePropName="checked"><Switch /></Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item label="开卡时间(E卡 24h 冷却按最新一张算)" name="opened_at"
                  tooltip="严格 24 小时:该账号最新一张卡开卡后 24h 内不能再开">
                  <DatePicker showTime style={{ width: '100%' }} format="YYYY-MM-DD HH:mm"
                    presets={[{ label: '设为现在', value: dayjs() }]} />
                </Form.Item>
              </Col>
            </Row>
          )}
          <Form.Item label="备注" name="note"><Input.TextArea rows={2} /></Form.Item>
          <Text type="secondary" style={{ fontSize: 12 }}>账单地址已由后端固定为美国免税地址,无需填写。</Text>
        </Form>
      </Modal>

      {/* 导入 */}
      <Modal
        title={`给「${importAcc?.name || ''}」批量导入 U卡`}
        open={importOpen}
        onCancel={() => setImportOpen(false)}
        onOk={submitImport}
        width={780}
      >
        <Text type="secondary" style={{ fontSize: 12 }}>
          支持两种格式(自动识别):① 多行块 <Text code>Card Number / Valid Thru / CVV</Text>;
          ② CSV 表头含 <Text code>number,exp_month,exp_year,cvc</Text>。
          {importAcc && !importAcc.is_default && <>该账号最多 5 张,超出的会跳过。</>}
        </Text>
        <Input.TextArea
          rows={12}
          style={{ marginTop: 8, fontFamily: 'monospace', fontSize: 12 }}
          placeholder={`Card Number: 493724202571978212\nValid Thru: 06/29\nCVV: 390\n\n— 或 CSV —\nnumber,exp_month,exp_year,cvc,holder_name\n4242424242424242,12,2028,123,JOHN SMITH`}
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
        />
      </Modal>

      {/* 打开浏览器:未按 ID/账号名找到时,选一个 profile */}
      <Modal
        title={`选择「${browserSelect?.pa.name || ''}」的指纹浏览器`}
        open={!!browserSelect}
        onCancel={() => setBrowserSelect(null)}
        onOk={() => { if (browserSelect && selectedDirId) openBrowser(browserSelect.pa, selectedDirId) }}
        okText="打开并保存"
        okButtonProps={{ disabled: !selectedDirId }}
        width={520}
      >
        <Text type="secondary" style={{ fontSize: 12 }}>
          没按"已保存ID / 账号名(邮箱)"找到对应浏览器。选一个 RoxyBrowser 窗口打开——
          <b>选后会把它的 ID 保存到该账号,下次直接用</b>。
        </Text>
        <Select
          style={{ width: '100%', marginTop: 10 }}
          showSearch
          optionFilterProp="label"
          placeholder="选择一个指纹浏览器窗口"
          value={selectedDirId}
          onChange={setSelectedDirId}
          options={(browserSelect?.profiles || []).map((p) => ({
            value: p.dir_id, label: `${p.name || '(无名)'} · ${p.dir_id}`,
          }))}
          notFoundContent="RoxyBrowser 里没有窗口(或未配置 API)"
        />
      </Modal>

      {/* 该卡支付了哪些账号 */}
      <Modal
        title={paidModal ? `卡 ${paidModal.card.number_masked} 支付的账号(${paidModal.accounts.length})` : ''}
        open={!!paidModal}
        onCancel={() => setPaidModal(null)}
        footer={null}
        width={520}
      >
        <Spin spinning={!!paidModal?.loading}>
          {paidModal && paidModal.accounts.length === 0 && !paidModal.loading
            ? <Text type="secondary">没有匹配的账号</Text>
            : (
              <div style={{ maxHeight: 420, overflow: 'auto' }}>
                {(paidModal?.accounts || []).map((a) => (
                  <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: `1px solid ${token.colorBorderSecondary}` }}>
                    <Text copyable style={{ flex: 1 }}>{a.email}</Text>
                    <Tag color={a.is_pro ? 'green' : 'default'} style={{ margin: 0 }}>{a.is_pro ? 'PRO' : '非PRO'}</Tag>
                    <span style={{ fontSize: 11, color: token.colorTextTertiary }}>{a.created_at ? new Date(a.created_at).toLocaleDateString() : ''}</span>
                  </div>
                ))}
              </div>
            )}
        </Spin>
      </Modal>
    </div>
  )
}
