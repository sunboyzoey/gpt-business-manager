export type GmailRegistrationStatus = 'unregistered' | 'reserved' | 'registering' | 'retry_pending' | 'paused' | 'registered' | 'sync_pending' | 'failed'

export interface GmailRegistrationSource {
  id: number
  email: string
  enabled: boolean
  usability_status?: string
  receive_ready?: boolean
  production_blocked?: boolean
  production_block_reason?: string
  alias_count: number
  registration_counts?: Partial<Record<GmailRegistrationStatus, number>>
  unregistered_count?: number
  registered_count?: number
  registration_pending_count?: number
}

export interface GmailRegistrationAlias {
  id: number
  source_id: number
  email: string
  registration_status?: GmailRegistrationStatus
  registration_stage?: string
  registration_task_id?: string
  production_job_id?: string
  registration_error?: string
  registration_retry_at?: string | null
  registration_attempts?: number
  registration_busy?: boolean
  registered_account_id?: number | null
  gpt_plan_account_id?: number | null
  gpt_plan_account_type?: string
  gpt_plan_member_plan?: string
  registered_at?: string | null
  can_register?: boolean
  registration_resume?: boolean
  alias_limit_exceeded?: boolean
  source_production_blocked?: boolean
  source_production_block_reason?: string
}

export function gmailRegistrationUnavailableReason(source: GmailRegistrationSource): string {
  if (!source.enabled) return '母号已停用'
  if (source.usability_status !== 'usable') return source.usability_status === 'unavailable' ? '母号验证未通过' : '母号尚未验证'
  if (source.receive_ready !== true) return '尚未通过自动收件授权验证'
  return ''
}

export function gmailRegistrationStatus(status?: string): { label: string; color: string } {
  const states: Record<string, { label: string; color: string }> = {
    unregistered: { label: '未注册 GPT', color: 'default' },
    reserved: { label: '已分配 · 等待注册', color: 'processing' },
    registering: { label: '正在注册 GPT', color: 'processing' },
    retry_pending: { label: '等待自动重试', color: 'warning' },
    paused: { label: '注册已暂停', color: 'warning' },
    failed: { label: '注册已停止', color: 'error' },
    registered: { label: '已注册 GPT', color: 'success' },
    sync_pending: { label: '已注册 · 等待同步套餐', color: 'warning' },
  }
  return states[status || 'unregistered'] || { label: '状态待确认', color: 'default' }
}

export function gmailAliasUnavailableReason(alias: GmailRegistrationAlias): string {
  if (alias.registration_stage === 'account_deactivated') return 'GPT 账号已停用，不再自动选择或注册'
  if (alias.registration_stage === 'source_exhausted') return '注册返回 user_already_exists，已停止使用此 Gmail 母号生产新号'
  if (alias.registration_stage === 'alias_limit_exceeded') return '超过每个 Gmail 母号最多 3 个子号的上限'
  // Existing registered identities may still finish security setup or be read.
  if (!alias.registered_at && alias.registration_status !== 'registered') {
    if (alias.source_production_blocked) return alias.source_production_block_reason || '母号已停止新号生产，请使用其他 Gmail 母号'
    if (alias.alias_limit_exceeded) return '此子号超过每个 Gmail 母号最多 3 个的上限，不再参与新号注册'
  }
  return ''
}

export function gmailAliasCanResume(alias: GmailRegistrationAlias): boolean {
  if (gmailAliasUnavailableReason(alias)) return false
  return alias.registration_resume === true || ['retry_pending', 'paused'].includes(alias.registration_status || '')
    || ['security_pending', 'security_paused'].includes(alias.registration_stage || '')
}

export function gmailAliasSelectable(alias: GmailRegistrationAlias): boolean {
  return !gmailAliasUnavailableReason(alias) && !alias.production_job_id && alias.registration_busy !== true && ((alias.registration_status || 'unregistered') === 'unregistered' || gmailAliasCanResume(alias))
}

export function gmailRegistrationStage(stage?: string): string {
  const labels: Record<string, string> = {
    selected: '等待开始', register: '创建 GPT 账号', registration: '创建 GPT 账号', registering: '创建 GPT 账号',
    verification: '等待 / 校验 GPT 邮件验证码', oauth: '获取 GPT 授权 / RT',
    resume_login: '登录并核对注册结果', security: '设置 GPT 密码 / 2FA',
    security_pending: '等待补做 GPT 密码 / 2FA', security_paused: 'GPT 密码 / 2FA 设置已暂停',
    sync: '同步普通号池', pool_sync: '同步普通号池', sync_pending: '等待同步普通号池',
    production_paused: '自动售号准备已暂停', account_deactivated: 'GPT 账号已停用',
    source_exhausted: '母号已停止新号生产', alias_limit_exceeded: '已超出子号上限',
    registered: '注册完成 · 已同步套餐管理', completed: '注册完成', complete: '注册完成',
  }
  return stage ? labels[stage] || '正在处理注册任务' : ''
}

export function gmailRegisterPath(sourceId?: number, aliases: number[] = []): string {
  const params = new URLSearchParams({ platform: 'chatgpt', mail_provider: 'gmail' })
  if (sourceId) params.set('gmail_source_id', String(sourceId))
  if (aliases.length) params.set('gmail_alias_ids', aliases.join(','))
  return `/register?${params}`
}

export function gmailPlanPath(alias: GmailRegistrationAlias): string | null {
  if (!alias.gpt_plan_account_id) return null
  const type = ['regular', 'member', 'refunded'].includes(alias.gpt_plan_account_type || '')
    ? alias.gpt_plan_account_type! : 'regular'
  const params = new URLSearchParams({ focus_account_id: String(alias.gpt_plan_account_id), account_type: type })
  if (type === 'member' && alias.gpt_plan_member_plan) params.set('member_plan', alias.gpt_plan_member_plan)
  return `/gpt-plans?${params}`
}

export function gmailRegistrationSelectionError(
  sourceId: number | undefined, aliasIds: number[], count: number,
  sources: GmailRegistrationSource[], aliases: GmailRegistrationAlias[],
): string {
  const source = sourceId ? sources.find(item => item.id === sourceId) : undefined
  if (sourceId && !source) return '所选 Gmail 母号已不存在，请刷新后重新选择'
  if (source) {
    const reason = gmailRegistrationUnavailableReason(source)
    if (reason) return reason
  }
  if (!Number.isInteger(count) || count < 1) return '请输入有效的注册数量'
  const available = aliases.filter(alias => alias.can_register === true
    && (!sourceId || alias.source_id === sourceId)
    && gmailAliasSelectable(alias)
    && sources.some(mother => mother.id === alias.source_id && !gmailRegistrationUnavailableReason(mother)))
  if (aliasIds.length) {
    if (new Set(aliasIds).size !== aliasIds.length) return '选择的子号不能重复'
    const unavailable = aliases.find(alias => aliasIds.includes(alias.id) && gmailAliasUnavailableReason(alias))
    if (unavailable) return gmailAliasUnavailableReason(unavailable)
    if (aliasIds.some(id => !available.some(alias => alias.id === id))) return '部分所选子号当前不可注册，请刷新后重新选择'
    if (count !== aliasIds.length) return '注册数量须与所选子号数量一致'
  } else if (count > available.filter(alias => !gmailAliasCanResume(alias)).length) {
    return `当前有 ${available.filter(alias => !gmailAliasCanResume(alias)).length} 个未注册可用子号，请减少数量或先生成子号并配置收件；恢复任务请明确选择子号`
  }
  return ''
}
