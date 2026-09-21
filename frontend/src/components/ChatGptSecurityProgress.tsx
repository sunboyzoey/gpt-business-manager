import { Alert, Space, Steps, Tag, Typography } from 'antd'
import { SyncOutlined } from '@ant-design/icons'

export const SECURITY_STAGES = {
  session_check: '检查登录会话',
  password_settings: '打开密码设置',
  password_email: '验证密码设置邮件',
  password_submit: '提交新密码',
  password_verify: '确认密码设置结果',
  totp_identity: '启用 2FA 前验证身份',
  totp_settings: '设置 Authenticator 2FA',
  totp_verify: '确认 2FA 启用结果',
  done: '安全设置完成',
} as const

const PASSWORD_VERIFY_STAGE_LABELS: Record<string, string> = {
  password_login_email_transition: '推进登录邮箱中转页',
  password_login_email_transition_failed: '登录邮箱未完成跳转',
  password_login_route_missing: '等待密码输入页',
  password_login_page_error: '检查登录页面异常',
}

export interface SecurityProgress {
  stage: keyof typeof SECURITY_STAGES
  status: 'running' | 'retrying' | 'completed' | 'failed' | 'review'
  code: string
  reason: string
  retry_mode: 'none' | 'auto_local' | 'manual' | 'verify_first'
  retry_attempt: number
  retry_limit: number
  completed_stages: string[]
}

export function readSecurityProgress(value: unknown, taskStatus?: string): SecurityProgress | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const row = value as Record<string, unknown>
  if (typeof row.stage !== 'string' || !Object.hasOwn(SECURITY_STAGES, row.stage)) return null
  const count = (value: unknown) => typeof value === 'number' && Number.isInteger(value) ? Math.min(2, Math.max(0, value)) : 0
  const progress: SecurityProgress = {
    stage: row.stage as SecurityProgress['stage'],
    status: ['running', 'retrying', 'completed', 'failed', 'review'].includes(String(row.status)) ? row.status as SecurityProgress['status'] : 'review',
    code: typeof row.code === 'string' ? row.code.slice(0, 64) : '',
    reason: typeof row.reason === 'string' ? row.reason.slice(0, 1000) : '',
    retry_mode: ['none', 'auto_local', 'manual', 'verify_first'].includes(String(row.retry_mode)) ? row.retry_mode as SecurityProgress['retry_mode'] : 'verify_first',
    retry_attempt: count(row.retry_attempt), retry_limit: count(row.retry_limit),
    completed_stages: Array.isArray(row.completed_stages) ? row.completed_stages.filter((item): item is string => typeof item === 'string' && Object.hasOwn(SECURITY_STAGES, item)) : [],
  }
  // A terminal task (including older aliases) cannot keep a page-action spinner.
  const parentStatus = String(taskStatus || '').trim().toLowerCase()
  if (['running', 'retrying'].includes(progress.status)) {
    if (['done', 'completed', 'complete', 'success', 'succeeded'].includes(parentStatus)) {
      progress.stage = 'done'
      progress.status = 'completed'
      progress.retry_mode = 'none'
      progress.reason = '后端已确认安全设置完成；未记录的中间步骤不推测成功。'
    } else if (['failed', 'failure', 'error', 'stopped', 'interrupted', 'review', 'cancelled', 'canceled'].includes(parentStatus)) {
      progress.status = ['failed', 'failure', 'error'].includes(parentStatus) ? 'failed' : 'review'
      progress.retry_mode = 'verify_first'
      progress.reason = '任务已停止，最后记录在此步骤；请先核验结果再继续。'
    } else if (parentStatus === 'status_unavailable') {
      progress.status = 'review'
      progress.retry_mode = 'verify_first'
      progress.reason = '任务状态读取失败，后台是否仍在运行尚未确认；请先核对，不要重复启动。'
    }
  }
  return progress
}

export function securityStageLabel(progress?: SecurityProgress | null): string {
  if (progress?.stage === 'password_verify' && Object.hasOwn(PASSWORD_VERIFY_STAGE_LABELS, progress.code)) {
    return PASSWORD_VERIFY_STAGE_LABELS[progress.code]
  }
  return progress ? SECURITY_STAGES[progress.stage] || '安全设置子步骤未记录' : '安全设置子步骤未记录'
}

export function securityHandling(progress: SecurityProgress): string {
  if (progress.status === 'retrying') return `正在自动重试 ${progress.retry_attempt}/${progress.retry_limit}（仅当前页面动作）`
  if (progress.status === 'completed') return '该子步骤已完成'
  if (progress.retry_mode === 'verify_first') return '需人工触发核验；不会直接重设密码或重绑 2FA'
  if (progress.retry_mode === 'manual') return '等待人工处理后重试当前步骤'
  if (progress.retry_mode === 'auto_local') return ['failed', 'review'].includes(progress.status)
    ? '本轮自动重试已结束，等待人工处理'
    : `临时页面异常最多自动重试 ${progress.retry_limit} 次`
  return ['failed', 'review'].includes(progress.status) ? '等待人工核对，不会自动重跑' : '正在执行'
}

interface ChatGptSecurityProgressProps {
  progress?: SecurityProgress | null
  compact?: boolean
  taskHandling?: string
}

export default function ChatGptSecurityProgress({ progress, compact = false, taskHandling }: ChatGptSecurityProgressProps) {
  if (!progress) return null
  const working = ['running', 'retrying'].includes(progress.status)
  const failed = ['failed', 'review'].includes(progress.status)
  const keys = Object.keys(SECURITY_STAGES) as SecurityProgress['stage'][]
  const current = keys.indexOf(progress.stage)
  const localHandling = taskHandling
    ? progress.retry_limit > 0
      ? `本轮页面动作已尝试 ${progress.retry_attempt}/${progress.retry_limit} 次；后续是否执行以任务级策略为准`
      : '本轮页面动作已结束；后续是否执行以任务级策略为准'
    : securityHandling(progress)
  return <Space direction="vertical" size={compact ? 2 : 10} style={{ width: '100%' }}>
    <Tag color={working ? 'processing' : failed ? 'warning' : 'success'} icon={working ? <SyncOutlined spin /> : undefined}>
      {failed ? '失败位置' : '当前子步骤'}：{securityStageLabel(progress)}
    </Tag>
    <Typography.Text type="secondary">{taskHandling ? '任务级处理' : '处理方式'}：{taskHandling || securityHandling(progress)}</Typography.Text>
    {!compact && <>
      {progress.reason && <Alert showIcon type={failed ? 'warning' : 'info'} message={progress.reason} />}
      <Typography.Text type="secondary">{taskHandling
        ? `子步骤处理：${localHandling}`
        : progress.retry_limit > 0
          ? `本子步骤已自动重试 ${progress.retry_attempt}/${progress.retry_limit} 次`
          : '该步骤不自动重跑'}；不会从邀请步骤重新开始。</Typography.Text>
      <Steps size="small" direction="vertical" current={current} items={keys.map((key, index) => ({
        title: key === progress.stage ? securityStageLabel(progress) : SECURITY_STAGES[key],
        status: key === progress.stage ? failed ? 'error' : progress.status === 'completed' ? 'finish' : 'process'
          : progress.completed_stages.includes(key) ? 'finish' : 'wait',
        description: key === progress.stage ? localHandling
          : progress.completed_stages.includes(key) ? '已确认完成'
            : index < current ? '未记录完成证据，不推测成功' : '尚未执行',
        icon: key === progress.stage && working ? <SyncOutlined spin /> : undefined,
      }))} />
      <Typography.Text type="secondary">“提交新密码”完成仅表示已提交，以后台确认的密码与 2FA 结果为准。新注册流程在当前会话启用 2FA 后保存结果；历史任务保留原步骤记录，未确认结果不视为成功。</Typography.Text>
    </>}
  </Space>
}
