import { useEffect, useRef, useState } from 'react'
import { Alert, App, Button, Checkbox, Input, Modal, Space, Tooltip, Typography } from 'antd'
import { apiFetch } from '@/lib/utils'

interface AppealAccount {
  id: number
  email: string
  appeal_url?: string | null
  appeal_done_at?: string | null
  appeal_link_lookup?: {
    status?: 'idle' | 'pending' | 'running' | 'not_found' | 'error' | 'ready'
    last_checked_at?: string | null
    next_retry_at?: string | null
    error?: string | null
  } | null
}

interface PreparedAppeal {
  accountId: number
  email: string
  url: string
  script: string
  copied: boolean
}

function safeAppealUrl(value: unknown): string {
  if (typeof value !== 'string' || Array.from(value).some(character =>
    character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127 || character === '\\')) return ''
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && url.hostname && !url.username && !url.password ? url.href : ''
  } catch {
    return ''
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : '请求失败，请重试'
}

function lookupTime(value?: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : ''
}

async function copyScript(script: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(script)
    return true
  } catch {
    return false
  }
}

export default function GptPlanAppealActions({ account, onChange }: {
  account: AppealAccount
  onChange?: () => void
}) {
  const { message } = App.useApp()
  const [savedLink, setSavedLink] = useState({
    accountId: account.id, email: account.email, url: safeAppealUrl(account.appeal_url),
  })
  const [doneAt, setDoneAt] = useState(account.appeal_done_at || '')
  const [pending, setPending] = useState<'script' | 'mark' | 'find' | null>(null)
  const [prepared, setPrepared] = useState<PreparedAppeal | null>(null)
  const generation = useRef(0)
  const locked = useRef(false)

  useEffect(() => {
    const incoming = safeAppealUrl(account.appeal_url)
    setSavedLink(previous => {
      if (previous.accountId === account.id && previous.email === account.email) {
        // A poll started before the successful lookup may still contain no URL.
        if (!incoming || incoming === previous.url) return previous
      }
      return { accountId: account.id, email: account.email, url: incoming }
    })
  }, [account.id, account.email, account.appeal_url])
  useEffect(() => { setDoneAt(account.appeal_done_at || '') }, [account.id, account.appeal_done_at])
  useEffect(() => {
    generation.current += 1
    locked.current = false
    setPending(null)
    setPrepared(null)
    return () => { generation.current += 1 }
  }, [account.id, account.email])

  const appealUrl = (savedLink.accountId === account.id && savedLink.email === account.email ? savedLink.url : '')
    || account.appeal_url || ''
  const url = safeAppealUrl(appealUrl)
  const lookup = account.appeal_link_lookup
  const lookupRunning = lookup?.status === 'running' || pending === 'find'
  const lookupWaiting = lookup?.status === 'not_found' || lookup?.status === 'error'
  const lookupLabel = lookupRunning ? '查找中' : lookupWaiting ? '等待重试' : '待查找'
  const lookupDetails = [
    lookupRunning ? '正在查找该账号的申诉链接' : lookupWaiting ? '后台会自动重试，无需重复点击' : '后台将自动查找并保存申诉链接',
    lookupTime(lookup?.last_checked_at) && `上次查找：${lookupTime(lookup?.last_checked_at)}`,
    lookupTime(lookup?.next_retry_at) && `下次重试：${lookupTime(lookup?.next_retry_at)}`,
    lookup?.error?.slice(0, 240),
  ].filter(Boolean).join('\n')
  const validId = Number.isSafeInteger(account.id) && account.id > 0
  const unavailable = !validId ? '账号记录无效，请刷新后重试'
    : !appealUrl ? '未提取到申诉链接，后台将自动查找'
      : !url ? '申诉链接不是安全的 HTTPS 地址，请重新检查邮件' : ''

  const openUrl = (target: string) => {
    const safe = safeAppealUrl(target)
    if (!safe) return
    try {
      window.open(safe, '_blank', 'noopener,noreferrer')
    } catch {
      message.error('申诉页未能打开，请允许新标签页后重试')
    }
  }

  const run = async (kind: 'script' | 'mark' | 'find', operation: (current: () => boolean) => Promise<void>) => {
    if (!validId || locked.current) return
    const version = generation.current
    const current = () => version === generation.current
    locked.current = true
    setPending(kind)
    try {
      await operation(current)
    } catch (error) {
      if (current()) message.error(errorText(error))
    } finally {
      if (current()) {
        locked.current = false
        setPending(null)
      }
    }
  }

  const prepareAppeal = () => {
    if (!url) return
    void run('script', async current => {
      const result = await apiFetch(`/gpt-plans/accounts/${account.id}/appeal-script`)
      if (!current()) return
      const responseUrl = safeAppealUrl(result?.appeal_url)
      if (result?.ok !== true || result.account_id !== account.id || result.account !== account.email
        || result.auto_submit !== false || typeof result.script !== 'string' || !result.script.trim() || !responseUrl) {
        throw new Error('申诉脚本归属或内容未确认，请重新读取')
      }
      const copied = await copyScript(result.script)
      if (!current()) return
      setPrepared({ accountId: account.id, email: account.email, url: responseUrl, script: result.script, copied })
      openUrl(responseUrl)
    })
  }

  const markAppealed = (done: boolean) => {
    void run('mark', async current => {
      const result = await apiFetch(`/gpt-plans/accounts/${account.id}/mark-appealed?done=${done}`, { method: 'POST' })
      if (!current()) return
      if (result?.ok !== true || result.account_id !== account.id || typeof result.appeal_done_at !== 'string'
        || (done ? !result.appeal_done_at || !Number.isFinite(Date.parse(result.appeal_done_at)) : result.appeal_done_at !== '')) {
        throw new Error('申诉标记结果未确认，请刷新后核对')
      }
      setDoneAt(result.appeal_done_at)
      message.success(done ? '已标记为已申诉' : '已取消申诉标记')
      onChange?.()
    })
  }

  const findAppealUrl = () => {
    if (lookupRunning) return
    void run('find', async current => {
      try {
        const result = await apiFetch(`/gpt-plans/accounts/${account.id}/refresh-appeal-link`, { method: 'POST' })
        if (!current()) return
        if (result?.ok !== true || result.account_id !== account.id || result.account !== account.email
          || typeof result.appeal_url !== 'string') {
          throw new Error('申诉链接归属未确认，请重新检查邮件')
        }
        if (!result.appeal_url) {
          message.info('暂未找到申诉链接，后台会继续重试')
          return
        }
        const found = safeAppealUrl(result.appeal_url)
        if (!found) throw new Error('申诉链接不是安全的 HTTPS 地址，请重新检查邮件')
        setSavedLink({ accountId: account.id, email: account.email, url: found })
        message.success('已提取申诉链接')
      } finally {
        // Not-found, mailbox errors and an existing lookup lease also persist
        // their next status, even when the endpoint returns a non-2xx response.
        if (current()) onChange?.()
      }
    })
  }

  const scriptForAccount = prepared?.accountId === account.id && prepared.email === account.email ? prepared : null
  return <>
    <Space size={4} wrap onClick={event => event.stopPropagation()} data-gpt-plan-appeal-account-id={account.id}>
      <Tooltip title={unavailable || '打开申诉页，核对内容后由你提交'}>
        <span><Button size="small" disabled={!!unavailable} onClick={() => openUrl(url)}>申诉</Button></span>
      </Tooltip>
      <Tooltip title={unavailable || '复制填写脚本并打开申诉页，提交前请人工核对'}>
        <span><Button size="small" disabled={!!unavailable || pending !== null} loading={pending === 'script'}
          onClick={prepareAppeal}>自动填写</Button></span>
      </Tooltip>
      {!url && <>
        <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{lookupDetails}</span>}>
          <Typography.Text type={lookupWaiting ? 'warning' : 'secondary'} style={{ fontSize: 12 }}
            data-appeal-link-lookup={lookup?.status || 'pending'}>{lookupLabel}</Typography.Text>
        </Tooltip>
        <Tooltip title={lookupRunning ? '后台正在查找，请稍后查看' : '立即重试查找；后台也会按计划自动重试'}>
          <span><Button type="link" size="small" style={{ paddingInline: 2 }} disabled={!validId || pending !== null || lookupRunning}
            loading={pending === 'find'} onClick={findAppealUrl}>重试查找</Button></span>
        </Tooltip>
      </>}
      <Tooltip title={doneAt ? `已申诉：${doneAt}；取消勾选可取消标记` : '实际提交申诉后勾选；打开页面或复制脚本不会标记'}>
        <Checkbox checked={!!doneAt} disabled={!validId || pending !== null}
          onChange={event => markAppealed(event.target.checked)} style={{ fontSize: 12 }}>已申诉</Checkbox>
      </Tooltip>
    </Space>
    <Modal title={`自动填写申诉 · ${scriptForAccount?.email || account.email}`} open={!!scriptForAccount}
      width={640} onCancel={() => setPrepared(null)} footer={<Button onClick={() => setPrepared(null)}>关闭</Button>}>
      {scriptForAccount && <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Alert type={scriptForAccount.copied ? 'info' : 'warning'} showIcon
          message={scriptForAccount.copied ? '脚本已复制，请到申诉页完成填写' : '自动复制失败，请复制下方脚本'} />
        <ol style={{ margin: 0, paddingLeft: 20 }}>
          <li>在申诉页打开开发者工具（F12）→ Console，粘贴脚本并运行。</li>
          <li>核对账号、日期、产品、原因及申诉内容后手动提交；脚本不会自动提交。</li>
          <li>实际提交后，勾选该账号的“已申诉”。</li>
        </ol>
        <Space>
          <Button size="small" onClick={() => openUrl(scriptForAccount.url)}>打开申诉页</Button>
          <Button size="small" onClick={async () => {
            const copied = await copyScript(scriptForAccount.script)
            if (copied) message.success('脚本已复制')
            else message.error('复制失败，请在下方全选并手动复制')
          }}>复制脚本</Button>
        </Space>
        <Input.TextArea value={scriptForAccount.script} readOnly autoSize={{ minRows: 3, maxRows: 7 }}
          aria-label="申诉填写脚本" style={{ fontFamily: 'monospace', fontSize: 12 }} />
        <Typography.Text type="secondary">若申诉页未打开，可点击“打开申诉页”重试。</Typography.Text>
      </Space>}
    </Modal>
  </>
}
