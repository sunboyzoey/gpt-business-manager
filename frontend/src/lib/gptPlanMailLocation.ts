interface GptPlanMailLocationTarget {
  target_kind?: string
  account_type?: string
  member_plan?: string
  parent_email?: string
}

const MEMBER_TAB_LABELS: Record<string, string> = {
  pro: 'PRO',
  team: 'BUSINESS',
  plus: 'PLUS',
  go: 'GO',
}

/** Use the summary's current catalog classification, never the visible page's TAB. */
export function gptPlanMailLocation(target: GptPlanMailLocationTarget): string {
  if (target.target_kind === 'business_child' || target.account_type === 'business_child') {
    return `BUSINESS 子号 · ${target.parent_email?.trim() || '所属母号'}`
  }
  // A refund moves an account out of its old plan TAB even if plan_type remains PRO.
  if (target.account_type === 'refunded') return '已退款'
  if (target.account_type === 'regular') return '普通账号'
  const plan = String(target.member_plan || '').trim().toLowerCase()
  const label = Object.prototype.hasOwnProperty.call(MEMBER_TAB_LABELS, plan)
    ? MEMBER_TAB_LABELS[plan] : ''
  return label ? `会员账号 · ${label}` : '会员账号'
}
