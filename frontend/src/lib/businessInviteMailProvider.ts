export type BusinessInviteMailProvider = 'auto' | 'outlook' | 'icloud' | 'gmail'

export const BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS = [
  { label: '按席位默认', value: 'auto' },
  { label: 'Outlook', value: 'outlook' },
  { label: 'iCloud', value: 'icloud' },
  { label: 'Gmail', value: 'gmail' },
] satisfies Array<{ label: string; value: BusinessInviteMailProvider }>

export type BusinessInviteSeatType = 'default' | 'prolite'
export type BusinessInviteMailProviderDefaults = Record<BusinessInviteSeatType, Exclude<BusinessInviteMailProvider, 'auto'>>

export function readBusinessInviteMailProviderDefaults(value: unknown): BusinessInviteMailProviderDefaults {
  const row = value as Partial<BusinessInviteMailProviderDefaults> | null
  const allowed = ['icloud', 'gmail', 'outlook']
  if (!row || typeof row !== 'object' || Array.isArray(row)
    || typeof row.default !== 'string' || typeof row.prolite !== 'string'
    || !allowed.includes(row.default) || !allowed.includes(row.prolite)) {
    throw new Error('席位默认邮箱配置不完整或无效，请重新读取')
  }
  return { default: row.default!, prolite: row.prolite! }
}

const providerLabel = (provider: BusinessInviteMailProvider) => BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS.find(option => option.value === provider)?.label || ''

export const effectiveBusinessInviteMailProvider = (
  provider: BusinessInviteMailProvider, seatType?: BusinessInviteSeatType, defaults?: BusinessInviteMailProviderDefaults | null,
): BusinessInviteMailProvider => provider !== 'auto' ? provider : seatType && defaults ? defaults[seatType] : 'auto'

export function businessInviteMailProviderHint(provider: BusinessInviteMailProvider, seatType?: BusinessInviteSeatType, defaults?: BusinessInviteMailProviderDefaults | null): string {
  const resolved = effectiveBusinessInviteMailProvider(provider, seatType, defaults)
  const label = providerLabel(resolved)
  if (provider !== 'auto') return `已手动指定 ${label}；不因席位变化而切换邮箱来源`
  if (!defaults) return '席位默认邮箱配置尚未读取成功，请打开“配置席位默认邮箱”重新读取'
  if (seatType) return `本次${seatType === 'prolite' ? '高级席位（5X）' : '普通席位'}默认使用 ${label}，该类型库存不足时等待补充`
  return `普通席位使用 ${providerLabel(defaults.default)}，高级席位（5X）使用 ${providerLabel(defaults.prolite)}；待后端确认本次席位，不跨邮箱类型补位`
}

// A mother owning an advanced seat does not prove its next child gets one.
export function businessInviteTargetSeat(summary: unknown): BusinessInviteSeatType | undefined {
  if (!summary || typeof summary !== 'object') return undefined
  const seat = summary as Record<string, unknown>
  const rows = (seat.by_type || seat.seat_types || seat.capacity_by_type || seat.seat_type_summary) as Record<string, Record<string, unknown>> | undefined
  if (rows) {
    const capacities = (['default', 'prolite'] as const).map(type => {
      const row = rows[type]
      const available = row?.available
      return { type, known: row?.known !== false && (row?.known === true || seat.seat_type_capacity_known === true) && available !== null && available !== undefined && Number.isFinite(Number(available)), available: Number(available) }
    })
    if (capacities.every(capacity => capacity.known)) {
      const available = capacities.filter(capacity => capacity.available > 0)
      return available.length === 1 ? available[0].type : undefined
    }
  }
  const declared = seat.invitable_seat_types || seat.requestable_seat_types
  if (Array.isArray(declared) && declared.length === 1 && ['default', 'prolite'].includes(String(declared[0]))) {
    return declared[0] as BusinessInviteSeatType
  }
  return undefined
}

const normalizeProviderName = (value: unknown) => String(value || '')
  .trim()
  .toLowerCase()
  .replace(/[\s_-]+/g, '')

export const normalizeBusinessInviteMailProvider = (
  value: unknown,
): BusinessInviteMailProvider => {
  const normalized = String(value || '').trim().toLowerCase()
  return normalized === 'outlook' || normalized === 'icloud' || normalized === 'gmail' ? normalized : 'auto'
}

export const businessInviteCandidateMailProvider = (
  candidate: { email?: unknown; mail_provider?: unknown },
): Exclude<BusinessInviteMailProvider, 'auto'> | 'other' => {
  const provider = normalizeProviderName(candidate.mail_provider)
  if (provider === 'outlook') return 'outlook'
  if (provider === 'icloud') return 'icloud'
  if (provider === 'gmail') return 'gmail'
  return 'other'
}

export const businessInviteCandidateMatchesProvider = (
  candidate: { email?: unknown; mail_provider?: unknown },
  provider: BusinessInviteMailProvider,
  seatType?: BusinessInviteSeatType,
  defaults?: BusinessInviteMailProviderDefaults | null,
) => {
  if (provider === 'auto' && !defaults) return false
  const effective = effectiveBusinessInviteMailProvider(provider, seatType, defaults)
  const actual = businessInviteCandidateMailProvider(candidate)
  return effective === 'auto' ? actual === defaults?.default || actual === defaults?.prolite : actual === effective
}
