import { useCallback, useEffect, useRef, useState } from 'react'
import { Alert, App, Button, Card, Collapse, Descriptions, Drawer, Empty, Input, InputNumber, Popover, Select, Space, Spin, Steps, Switch, Table, Tabs, Tag, Tooltip, Typography } from 'antd'
import type { TableProps } from 'antd'
import { InboxOutlined, PlayCircleOutlined, ReloadOutlined, SaveOutlined } from '@ant-design/icons'
import { apiFetch } from '@/lib/utils'
import { readSecurityProgress, SECURITY_STAGES, securityStageLabel } from '@/components/ChatGptSecurityProgress'

type BrowserMode = 'headless' | 'headed'
type MailProvider = 'icloud' | 'outlook' | 'gmail' | 'auto'

export interface PreparationSettings {
  enabled: boolean
  interval_minutes: number
  batch_size: number
  target_ready: number
  mail_provider: MailProvider
  browser_mode: BrowserMode
  max_attempts: number
}

export interface PreparationAccount {
  account_id: number
  email: string
  mail_provider?: string
  note?: string
  state?: string
  stage?: string
  stage_label?: string
  error?: string
  ready_at?: string
  registered_at?: string
  cookie_saved?: boolean
  cookie_health?: string
  cookie_checked_at?: string
  cookie_expires_at?: string
  has_password?: boolean
  has_totp?: boolean
}

export interface PreparationJob {
  id: string
  kind?: 'prepare' | 'check_cookie'
  account_id?: number
  email?: string
  mail_provider?: string
  status: string
  stage?: string
  stage_label?: string
  error?: string
  attempts?: number
  max_attempts?: number
  next_retry_at?: string
  created_at?: string
  updated_at?: string
  finished_at?: string
  security_progress?: unknown
}

interface JobDetail extends PreparationJob {
  logs?: { at?: string; message: string }[]
}

interface PreparationStatus {
  settings: PreparationSettings
  counts: { ready: number; pending: number; running: number; retry: number; failed: number; review: number; today_ready: number; today_attempts?: number; retryable_prepare?: number }
  runtime: {
    running: boolean
    next_run_at?: string
    last_error?: string
    schedule_state?: 'waiting_queue' | 'waiting_interval' | 'disabled'
    queue_busy?: boolean
  }
}

interface Paged<T> { items: T[]; total: number }

interface PreparationBulkRetryResult {
  ok: true
  queued: number
  skipped: number
  remaining: number
  items: { id: string; email: string; status: 'queued' | 'skipped'; reason: string }[]
  message: string
}

const DEFAULT_PREPARATION_SETTINGS: PreparationSettings = {
  enabled: false, interval_minutes: 5, batch_size: 5, target_ready: 20,
  mail_provider: 'icloud', browser_mode: 'headless', max_attempts: 3,
}

const BASE = '/gpt-plans/preparation'
const STAGES = [
  { key: 'cookie_check', label: '检查 Cookie' },
  { key: 'login', label: '注册 / 登录与邮箱验证' },
  { key: 'security', label: '完成密码与 2FA' },
  { key: 'verify', label: '保存结果 / 会话检查' },
  { key: 'ready', label: '进入准备号池' },
] as const

const integer = (value: unknown, fallback: number, max: number) =>
  typeof value === 'number' && Number.isFinite(value) ? Math.min(max, Math.max(1, Math.floor(value))) : fallback

function preparationSettingsPayload(value: Partial<PreparationSettings>, browserMode?: BrowserMode): PreparationSettings {
  return {
    enabled: value.enabled === true,
    interval_minutes: integer(value.interval_minutes, 5, 1440),
    batch_size: integer(value.batch_size, 5, 100),
    target_ready: integer(value.target_ready, 20, 10000),
    mail_provider: ['icloud', 'outlook', 'gmail', 'auto'].includes(String(value.mail_provider)) ? value.mail_provider as MailProvider : 'icloud',
    browser_mode: browserMode || (value.browser_mode === 'headed' ? 'headed' : 'headless'),
    max_attempts: integer(value.max_attempts, 3, 5),
  }
}

const preparationApi = {
  status: () => apiFetch(`${BASE}/status`) as Promise<PreparationStatus>,
  accounts: (query: URLSearchParams) => apiFetch(`${BASE}/accounts?${query}`) as Promise<Paged<PreparationAccount>>,
  jobs: (query: URLSearchParams) => apiFetch(`${BASE}/jobs?${query}`) as Promise<Paged<PreparationJob>>,
  detail: (id: string) => apiFetch(`${BASE}/jobs/${encodeURIComponent(id)}`) as Promise<JobDetail>,
  save: (settings: PreparationSettings, browserMode: BrowserMode) => apiFetch(`${BASE}/settings`, {
    method: 'PUT', body: JSON.stringify(preparationSettingsPayload(settings, browserMode)),
  }) as Promise<PreparationSettings>,
  run: (count: number, browserMode: BrowserMode) => apiFetch(`${BASE}/run`, {
    method: 'POST', body: JSON.stringify({ count: integer(count, 5, 100), browser_mode: browserMode }),
  }),
  retry: (id: string) => apiFetch(`${BASE}/jobs/${encodeURIComponent(id)}/retry`, { method: 'POST' }),
  retryFailed: (browserMode: BrowserMode) => apiFetch(`${BASE}/jobs/retry-failed`, {
    method: 'POST', body: JSON.stringify({ browser_mode: browserMode }),
  }),
  checkCookie: (id: number) => apiFetch(`${BASE}/accounts/${id}/check-cookie`, { method: 'POST' }),
}

function preparationQueueCount(status: PreparationStatus | null): number | null {
  const counts = status?.counts
  if (!counts || ![counts.pending, counts.running, counts.retry].every(value => Number.isSafeInteger(value) && value >= 0)) return null
  const total = counts.pending + counts.running + counts.retry
  return Number.isSafeInteger(total) ? total : null
}

function preparationRetryableCount(status: PreparationStatus | null): number | null {
  const value = status?.counts?.retryable_prepare
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null
}

function preparationRunBlockReason(status: PreparationStatus | null, error: string, pending: boolean): string {
  if (pending) return '正在确认提交后的最新队列状态，请稍候；读取失败时可点击刷新'
  if (error) return '准备队列状态读取失败，请刷新后再操作'
  const count = preparationQueueCount(status)
  if (count === null) return '等待确认准备队列状态'
  return count > 0 ? '已有排队、执行中或等待重试的任务（含 Cookie 检查），全部结束后可立即准备' : ''
}

function readPreparationBulkRetryResult(value: unknown): PreparationBulkRetryResult {
  const row = value as Partial<PreparationBulkRetryResult> | null
  if (!row || row.ok !== true || ![row.queued, row.skipped, row.remaining].every(count =>
    typeof count === 'number' && Number.isSafeInteger(count) && count >= 0)
    || !Array.isArray(row.items) || row.items.length > 100 || row.items.length !== Number(row.queued) + Number(row.skipped)
    || typeof row.message !== 'string' || row.message.length > 1500) throw new Error('批量重试结果尚未确认，请刷新队列后核对，不要重复提交')
  const ids = new Set<string>()
  for (const item of row.items) {
    if (!item || typeof item.id !== 'string' || !item.id || item.id.length > 128 || ids.has(item.id)
      || typeof item.email !== 'string' || item.email.length > 320 || !['queued', 'skipped'].includes(item.status)
      || typeof item.reason !== 'string' || item.reason.length > 1500) throw new Error('批量重试明细尚未确认，请刷新后核对')
    ids.add(item.id)
  }
  if (row.items.filter(item => item.status === 'queued').length !== row.queued) throw new Error('批量重试数量尚未确认，请刷新后核对')
  return row as PreparationBulkRetryResult
}

function preparationCookieState(health?: string) {
  if (health === 'valid') return { label: '有效', color: 'success' }
  if (health === 'expired') return { label: '失效，需登录', color: 'warning' }
  if (health === 'dead') return { label: '明确停用', color: 'error' }
  if (health === 'missing') return { label: '缺少 Cookie', color: 'default' }
  if (health === 'blocked') return { label: '需人工验证', color: 'warning' }
  if (health === 'wrong_identity') return { label: '身份不一致', color: 'error' }
  if (health === 'network_error') return { label: '网络检查失败', color: 'warning' }
  return { label: '未知', color: 'default' }
}

function preparationStatus(status?: string) {
  const labels: Record<string, { label: string; color: string }> = {
    ready: { label: '已准备', color: 'success' }, completed: { label: '已完成', color: 'success' },
    pending: { label: '排队中', color: 'default' }, running: { label: '执行中', color: 'processing' },
    retry: { label: '等待重试', color: 'warning' }, review: { label: '待核对', color: 'warning' },
    failed: { label: '失败', color: 'error' }, dead: { label: '明确停用', color: 'error' },
    cancelled: { label: '已取消', color: 'default' },
  }
  return labels[String(status)] || { label: '状态未知', color: 'default' }
}

const preparationCanRetry = (job: PreparationJob) => ['retry', 'review', 'failed'].includes(job.status)

const stageLabel = (row: { stage?: string; stage_label?: string; kind?: string }) =>
  row.kind === 'check_cookie' ? '检查 Cookie' : row.stage_label || STAGES.find(item => item.key === row.stage)?.label || '等待阶段更新'

const timeLabel = (value?: string) => {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '时间未记录' : date.toLocaleString('zh-CN', { hour12: false })
}

function preparationScheduleLabel(status: PreparationStatus | null, error = ''): string {
  if (error) return '补货计划读取失败，请刷新后确认'
  if (!status) return '正在读取补货计划'
  if (!status.settings.enabled || status.runtime.schedule_state === 'disabled') return '未开启自动补货'
  const queued = preparationQueueCount(status)
  if (status.runtime.schedule_state === 'waiting_queue' || status.runtime.queue_busy === true || (queued !== null && queued > 0)) {
    return '当前队列完成后再开始计时'
  }
  const nextRun = status.runtime.next_run_at
  if (queued !== null && (!status.runtime.schedule_state || status.runtime.schedule_state === 'waiting_interval')
    && typeof nextRun === 'string' && nextRun && !Number.isNaN(new Date(nextRun).getTime())) {
    return `下次补货：${timeLabel(nextRun)}`
  }
  return '下次补货时间待确认'
}

const errorLabel = (error: unknown, fallback: string) => error instanceof Error ? error.message : fallback
const providerLabel = (value?: string) => value === 'icloud' ? 'iCloud' : value === 'outlook' ? 'Outlook' : value === 'gmail' ? 'Gmail' : value === 'auto' ? '全部邮箱类型' : '未记录'

function preparationHandling(job: PreparationJob): string {
  if (job.status === 'retry') return job.next_retry_at ? `下次自动重试：${timeLabel(job.next_retry_at)}` : '等待安排自动重试'
  if (job.status === 'review') return '等待核对，可手动重试继续核验'
  if (job.status === 'failed') return '本轮已停止，可手动重试'
  if (job.status === 'dead') return '账号已明确停用'
  if (job.status === 'cancelled') return '任务已取消'
  if (job.status === 'completed') return job.kind === 'check_cookie' ? 'Cookie 检查已完成' : '已完成准备'
  if (job.kind === 'check_cookie') return job.status === 'running' ? '正在只读检查 Cookie' : '等待 Cookie 检查'
  return job.status === 'running' ? '正在执行当前阶段' : '等待队列执行'
}

function preparationSecurityProgress(job: PreparationJob) {
  if (job.kind === 'check_cookie') return null
  const progress = readSecurityProgress(job.security_progress, job.status)
  // Waiting for an outer retry does not mean a browser is still acting.
  return progress && job.status !== 'running' && ['running', 'retrying'].includes(progress.status)
    ? { ...progress, status: 'review' as const } : progress
}

export function PreparationJobProgress({ job }: { job: PreparationJob }) {
  if (job.kind === 'check_cookie') return <Space direction="vertical" size={10} style={{ width: '100%' }}>
    <Steps size="small" current={0} items={[{ title: '只读检查 Cookie', description: preparationHandling(job),
      status: job.status === 'completed' ? 'finish' : ['failed', 'review', 'dead'].includes(job.status) ? 'error' : job.status === 'running' ? 'process' : 'wait' }]} />
    <Typography.Text type="secondary">仅检查现有登录会话；检查结果会更新 Cookie 状态。</Typography.Text>
  </Space>
  const progress = preparationSecurityProgress(job)
  const current = job.status === 'completed' ? STAGES.length - 1 : STAGES.findIndex(item => item.key === job.stage)
  const stopped = ['failed', 'review', 'dead'].includes(job.status)
  return <Space direction="vertical" size={14} style={{ width: '100%' }}>
    <Steps size="small" direction="vertical" current={current} items={STAGES.map((item, index) => ({
      title: item.label,
      status: job.status === 'completed' ? 'finish' : index < current ? 'finish' : index > current || current < 0 ? 'wait'
        : stopped ? 'error' : job.status === 'running' ? 'process' : 'wait',
      description: index === current ? preparationHandling(job) : undefined,
    }))} />
    <Typography.Text type="secondary">新账号按密码注册 → 邮箱验证 → 同会话启用 2FA 完成准备，随后保存结果并检查当前会话。结果确认阶段不追加独立登录；历史任务按原步骤记录展示。</Typography.Text>
    {progress && <Card size="small" title="密码与 2FA 子步骤">
      <Space direction="vertical" size={10} style={{ width: '100%' }}>
        <Typography.Text type="secondary">新注册账号在注册浏览器中继续设置 2FA；已有账号先检查会话和已保存的安全凭据。是否完成以本次记录的确认结果为准。</Typography.Text>
        <Typography.Text strong>{securityStageLabel(progress)}</Typography.Text>
        {progress.reason && <Typography.Text type={['failed', 'review'].includes(progress.status) ? 'warning' : 'secondary'}>{progress.reason}</Typography.Text>}
        <Steps size="small" direction="vertical" items={Object.entries(SECURITY_STAGES).map(([key, label]) => ({
          title: key === progress.stage ? securityStageLabel(progress) : label,
          status: progress.completed_stages.includes(key) || key === progress.stage && progress.status === 'completed' ? 'finish'
            : key === progress.stage && job.status === 'running' ? 'process'
              : key === progress.stage && ['failed', 'review'].includes(progress.status) ? 'error' : 'wait',
        }))} />
        <Typography.Text type="secondary">当前页面动作已尝试 {progress.retry_attempt}/{progress.retry_limit} 次；任务后续安排以准备任务状态为准。</Typography.Text>
      </Space>
    </Card>}
  </Space>
}

interface GptPlanPreparationPanelProps {
  browserMode: BrowserMode
  onFetchMail: (account: { account_id: number; email: string }) => void
  mailFetchingAccountId?: number | null
}

export default function GptPlanPreparationPanel({ browserMode, onFetchMail, mailFetchingAccountId = null }: GptPlanPreparationPanelProps) {
  const { message } = App.useApp()
  const [status, setStatus] = useState<PreparationStatus | null>(null)
  const [draft, setDraft] = useState<PreparationSettings>({ ...DEFAULT_PREPARATION_SETTINGS })
  const [dirty, setDirty] = useState(false)
  const dirtyRef = useRef(false)
  const loadedRef = useRef(false)
  const mountedRef = useRef(true)
  const [statusLoading, setStatusLoading] = useState(false)
  const [statusError, setStatusError] = useState('')
  const [view, setView] = useState<'accounts' | 'jobs'>('accounts')
  const [accounts, setAccounts] = useState<PreparationAccount[]>([])
  const [jobs, setJobs] = useState<PreparationJob[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [keyword, setKeyword] = useState('')
  const [searchDraft, setSearchDraft] = useState('')
  const [jobStatus, setJobStatus] = useState('')
  const [listLoading, setListLoading] = useState(false)
  const [listError, setListError] = useState('')
  const [runCount, setRunCount] = useState(5)
  const [mutation, setMutation] = useState('')
  const mutationLock = useRef(false)
  const mutationEpoch = useRef(0)
  const queueConfirmationRef = useRef(false)
  const queueRefreshReadyRef = useRef(false)
  const [queueConfirmationPending, setQueueConfirmationPending] = useState(false)
  const statusRef = useRef<PreparationStatus | null>(null)
  const statusErrorRef = useRef('')
  const [bulkRetryResult, setBulkRetryResult] = useState<PreparationBulkRetryResult | null>(null)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [detail, setDetail] = useState<JobDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')
  const statusSeq = useRef(0)
  const listSeq = useRef(0)
  const detailSeq = useRef(0)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false; statusSeq.current += 1; listSeq.current += 1; detailSeq.current += 1 }
  }, [])

  const loadStatus = useCallback(async (quiet = false) => {
    const seq = ++statusSeq.current
    const epoch = mutationEpoch.current
    // A read begun before the write settled is not proof of its queue result.
    const canConfirmQueue = queueRefreshReadyRef.current
    if (!quiet) setStatusLoading(true)
    try {
      const next = await preparationApi.status()
      if (!mountedRef.current || seq !== statusSeq.current) return
      if (!next?.settings || typeof next.runtime?.running !== 'boolean' || preparationQueueCount(next) === null
        || ![next.counts.ready, next.counts.failed, next.counts.review, next.counts.today_ready].every(value => Number.isSafeInteger(value) && value >= 0)
        || (next.counts.retryable_prepare !== undefined && preparationRetryableCount(next) === null)) {
        throw new Error('准备队列状态响应不完整，请重新读取')
      }
      const settings = preparationSettingsPayload(next.settings || {})
      statusRef.current = { ...next, settings }
      setStatus(statusRef.current)
      if (!dirtyRef.current) setDraft(settings)
      if (!loadedRef.current) setRunCount(settings.batch_size)
      loadedRef.current = true
      statusErrorRef.current = ''
      setStatusError('')
      if (canConfirmQueue && queueRefreshReadyRef.current && epoch === mutationEpoch.current) {
        queueConfirmationRef.current = false
        queueRefreshReadyRef.current = false
        setQueueConfirmationPending(false)
        // A newer canonical poll may finish before the original refresh.
        // Do not let that superseded request keep the confirmed UI locked.
        mutationLock.current = false
        setMutation('')
      }
    } catch (error) {
      if (mountedRef.current && seq === statusSeq.current) {
        statusErrorRef.current = errorLabel(error, '准备池状态读取失败')
        setStatusError(statusErrorRef.current)
      }
    } finally {
      if (mountedRef.current && seq === statusSeq.current) setStatusLoading(false)
    }
  }, [])

  const loadList = useCallback(async (quiet = false) => {
    const seq = ++listSeq.current
    if (!quiet) setListLoading(true)
    const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (keyword.trim()) query.set('keyword', keyword.trim())
    if (view === 'jobs' && jobStatus) query.set('status', jobStatus)
    try {
      const next = view === 'accounts' ? await preparationApi.accounts(query) : await preparationApi.jobs(query)
      if (!mountedRef.current || seq !== listSeq.current) return
      if (view === 'accounts') setAccounts(next.items as PreparationAccount[] || [])
      else setJobs(next.items as PreparationJob[] || [])
      setTotal(Number(next.total) || 0)
      setListError('')
    } catch (error) {
      if (mountedRef.current && seq === listSeq.current) setListError(errorLabel(error, '准备列表读取失败'))
    } finally {
      if (mountedRef.current && seq === listSeq.current) setListLoading(false)
    }
  }, [jobStatus, keyword, page, pageSize, view])

  const loadDetail = useCallback(async (id: string, quiet = false) => {
    const seq = ++detailSeq.current
    if (!quiet) setDetailLoading(true)
    try {
      const next = await preparationApi.detail(id)
      if (!mountedRef.current || seq !== detailSeq.current) return
      setDetail(next)
      setDetailError('')
    } catch (error) {
      if (mountedRef.current && seq === detailSeq.current) setDetailError(errorLabel(error, '任务详情读取失败'))
    } finally {
      if (mountedRef.current && seq === detailSeq.current) setDetailLoading(false)
    }
  }, [])

  useEffect(() => { void loadStatus(); const timer = window.setInterval(() => { void loadStatus(true) }, 5000); return () => window.clearInterval(timer) }, [loadStatus])
  useEffect(() => { void loadList(); const timer = window.setInterval(() => { void loadList(true) }, 5000); return () => { window.clearInterval(timer); listSeq.current += 1 } }, [loadList])
  useEffect(() => {
    if (detailId === null) return
    setDetail(null)
    setDetailError('')
    void loadDetail(detailId)
    const timer = window.setInterval(() => { void loadDetail(detailId, true) }, 5000)
    return () => { window.clearInterval(timer); detailSeq.current += 1 }
  }, [detailId, loadDetail])

  const refresh = () => { void loadStatus(); void loadList(); if (detailId !== null) void loadDetail(detailId) }
  const updateDraft = (change: Partial<PreparationSettings>) => {
    dirtyRef.current = true
    setDirty(true)
    setDraft(current => ({ ...current, ...change }))
  }
  const beginMutation = (kind: string): boolean => {
    if (mutationLock.current || queueConfirmationRef.current || statusErrorRef.current || preparationQueueCount(statusRef.current) === null) return false
    mutationLock.current = true
    mutationEpoch.current += 1
    statusSeq.current += 1
    queueConfirmationRef.current = true
    queueRefreshReadyRef.current = false
    setQueueConfirmationPending(true)
    setMutation(kind)
    return true
  }
  const finishMutation = async () => {
    const epoch = mutationEpoch.current
    if (mountedRef.current) {
      queueRefreshReadyRef.current = true
      // Only the canonical queue read releases the conservative enqueue guard.
      // List/log refreshes do not need to hold up an already verified queue.
      void loadList()
      if (detailId !== null) void loadDetail(detailId)
      await loadStatus()
    }
    // A later action may start after another canonical GET already confirmed
    // this one. Its lock must not be cleared by this old refresh returning late.
    if (epoch === mutationEpoch.current) {
      mutationLock.current = false
      if (mountedRef.current) setMutation('')
    }
  }
  const showAllJobs = () => {
    setView('jobs')
    setPage(1)
    setJobStatus('')
    setKeyword('')
    setSearchDraft('')
  }
  const saveSettings = async () => {
    if (!beginMutation('save')) return
    try {
      const saved = await preparationApi.save(draft, browserMode)
      if (!mountedRef.current) return
      dirtyRef.current = false
      setDirty(false)
      setDraft(preparationSettingsPayload(saved))
      message.success('定时配置已保存')
    } catch (error) { message.error(errorLabel(error, '保存失败')) }
    finally { await finishMutation() }
  }
  const runNow = async () => {
    if (preparationRunBlockReason(statusRef.current, statusErrorRef.current, queueConfirmationRef.current) || !beginMutation('run')) return
    try {
      const result = await preparationApi.run(runCount, browserMode)
      if (!mountedRef.current) return
      if (result?.queued === 0) message.info(result.message || '没有新增准备任务，请检查普通账号余量及准备上限')
      else message.success(typeof result?.queued === 'number' ? `已加入 ${result.queued} 个准备任务` : '准备请求已提交，请在准备任务中查看进度')
      showAllJobs()
    } catch (error) { message.error(errorLabel(error, '启动准备失败')) }
    finally { await finishMutation() }
  }
  const retryJob = async (job: PreparationJob) => {
    if (!preparationCanRetry(job) || !beginMutation(`retry-${job.id}`)) return
    try {
      await preparationApi.retry(job.id)
      if (!mountedRef.current) return
      message.success('已提交重试，请等待后台核验并继续')
    } catch (error) { message.error(errorLabel(error, '重试提交失败')) }
    finally { await finishMutation() }
  }
  const checkCookie = async (account: PreparationAccount) => {
    if (!account.cookie_saved || account.cookie_health === 'dead' || !beginMutation(`cookie-${account.account_id}`)) return
    try {
      await preparationApi.checkCookie(account.account_id)
      if (!mountedRef.current) return
      message.success('Cookie 检查已启动，结果更新后会显示在列表中')
    } catch (error) { message.error(errorLabel(error, 'Cookie 检查启动失败')) }
    finally { await finishMutation() }
  }
  const bulkRetryFailed = async () => {
    if ((preparationRetryableCount(statusRef.current) ?? 0) <= 0 || !beginMutation('bulk-retry')) return
    setBulkRetryResult(null)
    try {
      const result = readPreparationBulkRetryResult(await preparationApi.retryFailed(browserMode))
      if (!mountedRef.current) return
      setBulkRetryResult(result)
      showAllJobs()
      if (result.queued) message.success(`已将 ${result.queued} 个失败或待核对任务加入串行队列`)
      else message.info(result.message || '本次没有可安全加入队列的失败准备任务，请查看跳过原因')
    } catch (error) { message.error(errorLabel(error, '批量重试提交失败，请刷新队列核对')) }
    finally { await finishMutation() }
  }

  const mutationDisabled = !status || Boolean(statusError) || Boolean(mutation) || queueConfirmationPending
  const runBlockReason = preparationRunBlockReason(status, statusError, queueConfirmationPending)
  const retryablePrepareCount = preparationRetryableCount(status)
  const bulkRetryDisabled = mutationDisabled || retryablePrepareCount === null || retryablePrepareCount <= 0

  const renderMailButton = (row: { account_id?: number; email?: string }) => {
    const validId = typeof row.account_id === 'number' && Number.isSafeInteger(row.account_id) && row.account_id > 0
    const account = validId && typeof row.email === 'string' && row.email.trim()
      ? { account_id: row.account_id as number, email: row.email.trim() } : null
    const unavailableReason = !validId ? '账号尚未分配，暂时无法查看邮件' : '缺少邮箱地址，暂时无法查看邮件'
    return <Tooltip title={account ? '查看最近10封邮件' : unavailableReason}>
      <span onClick={event => event.stopPropagation()}><Button size="small" icon={<InboxOutlined />}
        aria-label={account ? `查看 ${account.email} 的最近10封邮件` : unavailableReason}
        disabled={!account} loading={Boolean(account && mailFetchingAccountId === account.account_id)}
        onClick={event => {
          event.stopPropagation()
          if (account && mailFetchingAccountId !== account.account_id) onFetchMail(account)
        }}>邮箱</Button></span>
    </Tooltip>
  }

  const accountColumns: TableProps<PreparationAccount>['columns'] = [
    { title: '账号', key: 'account', width: 260, render: (_, row) => <Space direction="vertical" size={0}>
      <Typography.Text copyable>{row.email}</Typography.Text>
      <Typography.Text type="secondary">#{row.account_id}{row.note ? ` · ${row.note}` : ''}</Typography.Text>
    </Space> },
    { title: '邮件', key: 'mail', width: 100, render: (_, row) => renderMailButton(row) },
    { title: '邮箱类型', key: 'provider', width: 105, render: (_, row) => providerLabel(row.mail_provider) },
    { title: '阶段 / 状态', key: 'stage', width: 220, render: (_, row) => <Space direction="vertical" size={3}>
      <Tag color={preparationStatus(row.state).color}>{preparationStatus(row.state).label}</Tag>
      <Typography.Text>{stageLabel(row)}</Typography.Text>
      {row.error && <Typography.Text type="danger" ellipsis={{ tooltip: row.error }} style={{ maxWidth: 200 }}>{row.error}</Typography.Text>}
    </Space> },
    { title: '密码 / 2FA', key: 'security', width: 170, render: (_, row) => <Space direction="vertical" size={3}>
      <Tag color={row.has_password ? 'success' : 'default'}>{row.has_password ? '密码已完成' : '密码未完成'}</Tag>
      <Tag color={row.has_totp ? 'success' : 'default'}>{row.has_totp ? '2FA 已完成' : '2FA 未完成'}</Tag>
    </Space> },
    { title: 'Cookie 最近检查', key: 'cookie', width: 220, render: (_, row) => <Space direction="vertical" size={2}>
      <Tag color={preparationCookieState(row.cookie_health).color}>{preparationCookieState(row.cookie_health).label}</Tag>
      <Typography.Text type="secondary">{row.cookie_saved ? '已保存 Cookie' : '未保存 Cookie'}{row.cookie_health === 'error' ? ' · 检查失败' : ''}</Typography.Text>
      {row.cookie_checked_at && <Typography.Text type="secondary" style={{ fontSize: 12 }}>检查：{timeLabel(row.cookie_checked_at)}</Typography.Text>}
      {row.cookie_expires_at && <Typography.Text type="secondary" style={{ fontSize: 12 }}>到期：{timeLabel(row.cookie_expires_at)}</Typography.Text>}
    </Space> },
    { title: '准备完成时间', key: 'ready_at', width: 190, render: (_, row) => <Space direction="vertical" size={0}>
      <Typography.Text>{timeLabel(row.ready_at)}</Typography.Text>
      {row.registered_at && <Typography.Text type="secondary" style={{ fontSize: 12 }}>注册确认：{timeLabel(row.registered_at)}</Typography.Text>}
    </Space> },
    { title: '操作', key: 'actions', width: 120, render: (_, row) => <Tooltip title="只检查会话有效性，不重新登录">
      <Button size="small" disabled={mutationDisabled || !row.cookie_saved || row.cookie_health === 'dead'} loading={mutation === `cookie-${row.account_id}`} onClick={() => { void checkCookie(row) }}>检查 Cookie</Button>
    </Tooltip> },
  ]
  const jobColumns: TableProps<PreparationJob>['columns'] = [
    { title: '账号 / 任务', key: 'account', width: 260, render: (_, row) => <Space direction="vertical" size={0}>
      <Typography.Text>{row.email || '等待分配账号'}</Typography.Text>
      <Typography.Text type="secondary">{row.kind === 'check_cookie' ? 'Cookie 检查' : '账号准备'} · #{row.id.slice(0, 8)}{row.account_id ? ` · 账号 #${row.account_id}` : ''}{row.mail_provider ? ` · ${providerLabel(row.mail_provider)}` : ''}</Typography.Text>
    </Space> },
    { title: '邮件', key: 'mail', width: 100, render: (_, row) => renderMailButton(row) },
    { title: '逐步进度', key: 'stage', width: 310, render: (_, row) => {
      const progress = preparationSecurityProgress(row)
      return <Space direction="vertical" size={3}>
        <Space wrap><Tag color={preparationStatus(row.status).color}>{preparationStatus(row.status).label}</Tag><Typography.Text>{stageLabel(row)}</Typography.Text></Space>
        {progress && <Typography.Text type="secondary">子步骤：{securityStageLabel(progress)}</Typography.Text>}
        {row.error && <Typography.Text type="danger" ellipsis={{ tooltip: row.error }} style={{ maxWidth: 290 }}>{row.error}</Typography.Text>}
      </Space>
    } },
    { title: '尝试 / 下次重试', key: 'retry', width: 240, render: (_, row) => <Space direction="vertical" size={2}>
      <Typography.Text>已尝试 {row.attempts || 0}/{row.max_attempts || 3} 次</Typography.Text>
      <Typography.Text type="secondary">{preparationHandling(row)}</Typography.Text>
    </Space> },
    { title: '最近更新', key: 'updated', width: 180, render: (_, row) => timeLabel(row.updated_at || row.created_at) },
    { title: '操作', key: 'actions', width: 190, render: (_, row) => <Space wrap>
      <Button size="small" onClick={() => setDetailId(row.id)}>进度与日志</Button>
      {preparationCanRetry(row) && <Button size="small" disabled={mutationDisabled || Boolean(listError)} loading={mutation === `retry-${row.id}`} onClick={() => { void retryJob(row) }}>手动重试</Button>}
    </Space> },
  ]
  const unsaved = dirty || Boolean(status && status.settings.browser_mode !== browserMode)
  const settingsLocked = mutationDisabled
  const pagination = { current: page, pageSize, total, showSizeChanger: true, pageSizeOptions: [10, 20, 50, 100],
    showTotal: (value: number) => `共 ${value} 条`, onChange: (nextPage: number, nextSize: number) => { setPage(nextPage); setPageSize(nextSize) } }

  return <Space direction="vertical" size={12} style={{ width: '100%' }} data-preparation-panel="true">
    <Card size="small" title="准备号池" extra={<Space size={4}>
      <Popover trigger="click" placement="bottomRight" title="准备规则" content={
        <Descriptions size="small" column={1} style={{ width: 330, maxWidth: 'calc(100vw - 64px)' }} items={[
          { key: 'source', label: '入池', children: '普通账号完成登录或注册、密码与 2FA 后入池。' },
          { key: 'manual', label: '立即准备', children: '使用已保存的邮箱与重试配置，以及顶部 2FA 浏览器模式。' },
          { key: 'retry', label: '批量重试', children: '仅重试失败、待核对的准备任务，每次最多 100 个，不含 Cookie 检查。加入现有串行队列前核验密码与 2FA，不重置单号尝试次数。' },
        ]} />
      }><Button type="text" size="small">使用说明</Button></Popover>
      <Button icon={<ReloadOutlined />} loading={statusLoading || listLoading} onClick={refresh}>刷新</Button>
    </Space>}>
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Space size={[10, 8]} wrap>
          <Tag color="success">已准备 {status?.counts?.ready ?? '—'}</Tag>
          <Tag>排队 {status?.counts?.pending ?? '—'}</Tag>
          <Tag color="processing">执行中 {status?.counts?.running ?? '—'}</Tag>
          <Tag color="warning">等待重试 {status?.counts?.retry ?? '—'}</Tag>
          <Tag color="warning">待核对 {status?.counts?.review ?? '—'}</Tag>
          <Tag color="error">失败 {status?.counts?.failed ?? '—'}</Tag>
          <Typography.Text type="secondary">今日完成 {status?.counts?.today_ready ?? '—'} 个</Typography.Text>
          {status?.counts?.today_attempts !== undefined && <Typography.Text type="secondary">今日已尝试 {status.counts.today_attempts} 次</Typography.Text>}
        </Space>
        <Space wrap size={[12, 8]}>
          <Typography.Text>准备数量</Typography.Text>
          <InputNumber aria-label="立即准备数量" min={1} max={100} value={runCount} onChange={value => setRunCount(value || 1)} style={{ width: 88 }} />
          <Tooltip title={runBlockReason}><span><Button type="primary" icon={<PlayCircleOutlined />} disabled={mutationDisabled || Boolean(runBlockReason)} loading={mutation === 'run'} onClick={() => { void runNow() }}>立即准备 {runCount} 个</Button></span></Tooltip>
          <Tooltip title={retryablePrepareCount === null ? '后台尚未提供可批量重试的准备任务数量，请刷新或更新后端' : '仅把失败、待核对的账号准备任务加入串行队列；不重试 Cookie 检查任务'}>
            <span><Button disabled={bulkRetryDisabled} loading={mutation === 'bulk-retry'} onClick={() => { void bulkRetryFailed() }}>一键重试失败任务</Button></span>
          </Tooltip>
          <Tooltip title="沿用顶部 2FA 浏览器模式"><Tag>浏览器 · {browserMode === 'headed' ? '有头' : '无头'}</Tag></Tooltip>
          {retryablePrepareCount !== null && retryablePrepareCount > 0 && <Tag color="warning">可重试 {retryablePrepareCount}</Tag>}
        </Space>
        {runBlockReason && <Typography.Text type="secondary">{runBlockReason}</Typography.Text>}
      </Space>
    </Card>
    {bulkRetryResult && <Card size="small" title="本次批量重试结果">
      <Alert type={bulkRetryResult.skipped ? 'warning' : 'info'} showIcon
        message={`已入队 ${bulkRetryResult.queued} 个 · 跳过 ${bulkRetryResult.skipped} 个 · 未纳入本次 ${bulkRetryResult.remaining} 个`}
        description={bulkRetryResult.message || '入队不代表已经开始执行；由后台按现有串行队列继续。'} />
      {bulkRetryResult.items.length > 0 && <Collapse size="small" style={{ marginTop: 10 }} items={[{ key: 'items', label: '查看逐项结果与跳过原因', children:
        <Table size="small" rowKey="id" dataSource={bulkRetryResult.items} pagination={{ pageSize: 10, showSizeChanger: false }} scroll={{ x: 650 }} columns={[
          { title: '账号', dataIndex: 'email', width: 240, render: (value: string, item: PreparationBulkRetryResult['items'][number]) => value || `任务 #${item.id.slice(0, 8)}` },
          { title: '结果', dataIndex: 'status', width: 100, render: (value: string) => <Tag color={value === 'queued' ? 'processing' : 'warning'}>{value === 'queued' ? '已排队' : '已跳过'}</Tag> },
          { title: '说明', dataIndex: 'reason', render: (value: string) => value || '等待后台执行并核验' },
        ]} /> }]} />}
    </Card>}
    {statusError && <Alert type="error" showIcon message="准备池状态读取失败" description={statusError} />}
    {status?.runtime?.last_error && <Alert type="warning" showIcon message="最近调度提示" description={status.runtime.last_error} />}
    <Card size="small" title={<Space wrap>定时准备{unsaved && <Tag color="warning">有未保存修改</Tag>}</Space>} extra={<Space size={4}>
      <Popover trigger="click" placement="bottomRight" title="调度规则" content={
        <Descriptions size="small" column={1} style={{ width: 360, maxWidth: 'calc(100vw - 64px)' }} items={[
          { key: 'save', label: '生效', children: '保存后生效，使用保存时的顶部 2FA 浏览器模式；每次执行一个账号。' },
          { key: 'interval', label: '补货', children: '队列清空后等待完整间隔，再按库存缺额补一批。含 Cookie 检查在内的排队、执行和重试任务都会延后计时；失败、待核对任务保留，不阻塞下一批。' },
          { key: 'inventory', label: '取号', children: '定时开关只控制自动补货；关闭后仍优先邀请已有准备号，准备号不足时使用普通号补充。' },
          { key: 'pause', label: '关闭', children: '已有排队任务不会取消；暂停尚未执行的自动任务，手动任务仍串行执行，已开始的任务不强行中断。' },
        ]} />
      }><Button type="text" size="small">调度规则</Button></Popover>
      <Button icon={<SaveOutlined />} loading={mutation === 'save'} disabled={mutationDisabled} onClick={() => { void saveSettings() }}>保存配置</Button>
    </Space>}>
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(136px, 1fr))', gap: 16 }}>
          <div><Typography.Text type="secondary">启用定时</Typography.Text><div style={{ height: 32, marginTop: 6, display: 'flex', alignItems: 'center' }}><Switch aria-label="启用定时准备" checked={draft.enabled} disabled={settingsLocked} onChange={enabled => updateDraft({ enabled })} /></div></div>
          <div><Typography.Text type="secondary">补货间隔（分钟）</Typography.Text><InputNumber aria-label="准备间隔分钟" disabled={settingsLocked} min={1} max={1440} value={draft.interval_minutes} onChange={value => updateDraft({ interval_minutes: value || 1 })} style={{ width: '100%', marginTop: 6 }} /></div>
          <div><Typography.Text type="secondary">每批数量</Typography.Text><InputNumber aria-label="每批准备数量" disabled={settingsLocked} min={1} max={100} value={draft.batch_size} onChange={value => updateDraft({ batch_size: value || 1 })} style={{ width: '100%', marginTop: 6 }} /></div>
          <div><Typography.Text type="secondary">目标准备数</Typography.Text><InputNumber aria-label="目标准备数" disabled={settingsLocked} min={1} max={10000} value={draft.target_ready} onChange={value => updateDraft({ target_ready: value || 1 })} style={{ width: '100%', marginTop: 6 }} /></div>
          <div><Typography.Text type="secondary">单号最多尝试</Typography.Text><InputNumber aria-label="单号最多尝试次数" disabled={settingsLocked} min={1} max={5} value={draft.max_attempts} onChange={value => updateDraft({ max_attempts: value || 1 })} style={{ width: '100%', marginTop: 6 }} /></div>
          <div><Typography.Text type="secondary">邮箱类型</Typography.Text><Select aria-label="准备邮箱类型" disabled={settingsLocked} value={draft.mail_provider} onChange={mail_provider => updateDraft({ mail_provider })} options={[{ value: 'icloud', label: 'iCloud' }, { value: 'outlook', label: 'Outlook' }, { value: 'gmail', label: 'Gmail' }, { value: 'auto', label: '全部邮箱类型' }]} style={{ width: '100%', marginTop: 6 }} /></div>
        </div>
        {status?.settings.enabled && !draft.enabled && <Typography.Text type="warning">保存后暂停待执行的定时任务，正在执行的任务继续。</Typography.Text>}
        <Space wrap>
          <Tag color={status?.settings.enabled ? 'processing' : 'default'}>{!status ? '定时状态待加载' : status.settings.enabled ? '定时已开启' : '定时关闭'}</Tag>
          <Typography.Text type="secondary">{!status ? '正在读取状态' : status.runtime?.running ? '调度服务运行中' : '调度服务未运行'}</Typography.Text>
          <Typography.Text type="secondary" aria-label="补货调度状态">{preparationScheduleLabel(status, statusError)}</Typography.Text>
        </Space>
      </Space>
    </Card>
    <Card size="small" styles={{ body: { padding: '0 12px 12px' } }}>
      <Tabs activeKey={view} onChange={key => { setView(key as 'accounts' | 'jobs'); setPage(1); setTotal(0) }} items={[{ key: 'accounts', label: '准备号列表' }, { key: 'jobs', label: '准备任务' }]} />
      <Space wrap style={{ marginBottom: 12 }}>
        <Input.Search aria-label="搜索准备账号或任务" placeholder="搜索邮箱" allowClear value={searchDraft} onChange={event => setSearchDraft(event.target.value)} onSearch={value => { setSearchDraft(value); setKeyword(value); setPage(1) }} style={{ width: 280, maxWidth: '100%' }} />
        {view === 'jobs' && <Select aria-label="准备任务状态" value={jobStatus} onChange={value => { setJobStatus(value); setPage(1) }} options={[{ value: '', label: '全部状态' }, ...['pending', 'running', 'retry', 'review', 'failed', 'completed', 'dead', 'cancelled'].map(value => ({ value, label: preparationStatus(value).label }))]} style={{ width: 140 }} />}
      </Space>
      {listError && <Alert type="warning" showIcon message="列表读取失败，当前显示上次结果" description={listError} style={{ marginBottom: 12 }} />}
      {view === 'accounts' ? <Table<PreparationAccount> data-preparation-accounts="true" size="small" rowKey="account_id" loading={listLoading} dataSource={accounts} columns={accountColumns} pagination={pagination} scroll={{ x: 1385 }} locale={{ emptyText: <Empty description="暂无准备好的账号" /> }} />
        : <Table<PreparationJob> data-preparation-jobs="true" size="small" rowKey="id" loading={listLoading} dataSource={jobs} columns={jobColumns} pagination={pagination} scroll={{ x: 1280 }} locale={{ emptyText: <Empty description="暂无准备任务" /> }} />}
    </Card>
    <Drawer title={`任务详情${detailId ? ` #${detailId.slice(0, 8)}` : ''}`} open={detailId !== null} width="min(760px, 100vw)" onClose={() => setDetailId(null)} extra={<Button icon={<ReloadOutlined />} loading={detailLoading} onClick={() => { if (detailId !== null) void loadDetail(detailId) }}>刷新</Button>}>
      {detailError && <Alert type="warning" showIcon message="任务详情读取失败，后台状态尚未确认" description={detailError} style={{ marginBottom: 12 }} />}
      {detailLoading && !detail ? <div style={{ padding: 32, textAlign: 'center' }}><Spin /></div> : detail && <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Descriptions size="small" column={1} items={[
          { key: 'kind', label: '任务类型', children: detail.kind === 'check_cookie' ? 'Cookie 只读检查' : '账号准备' },
          { key: 'id', label: '任务编号', children: <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>{detail.id}</Typography.Text> },
          { key: 'email', label: '账号', children: detail.email || '等待分配账号' },
          { key: 'status', label: '任务状态', children: <Tag color={preparationStatus(detail.status).color}>{preparationStatus(detail.status).label}</Tag> },
          { key: 'stage', label: '当前阶段', children: stageLabel(detail) },
          { key: 'retry', label: '任务尝试', children: `${detail.attempts || 0}/${detail.max_attempts || 3} 次 · ${preparationHandling(detail)}` },
          { key: 'created', label: '创建时间', children: timeLabel(detail.created_at) },
          { key: 'finished', label: '完成时间', children: timeLabel(detail.finished_at) },
        ]} />
        {detail.error && <Alert type="warning" showIcon message={detail.error} />}
        {preparationCanRetry(detail) && <Button disabled={mutationDisabled || Boolean(detailError)} loading={mutation === `retry-${detail.id}`} onClick={() => { void retryJob(detail) }}>手动重试</Button>}
        <PreparationJobProgress job={detail} />
        <Card size="small" title="执行日志">
          <div role="log" aria-live="polite" style={{ maxHeight: 360, overflowY: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontFamily: 'monospace', fontSize: 12 }}>
            {detail.logs?.length ? detail.logs.slice(-300).map((line, index) => <div key={`${line.at || ''}-${index}`} style={{ marginBottom: 6 }}><Typography.Text type="secondary">{timeLabel(line.at)} </Typography.Text>{line.message}</div>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无日志" />}
          </div>
        </Card>
      </Space>}
    </Drawer>
  </Space>
}
