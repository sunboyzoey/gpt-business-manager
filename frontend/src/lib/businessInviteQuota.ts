/** Prefer the newest server evidence; a late drawer response must not undo a saved policy. */
export function latestBusinessInviteQuota(values: unknown[]): Record<string, unknown> | undefined {
  const candidates = values.filter((value): value is Record<string, unknown> =>
    value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length > 0)
  const time = (value: Record<string, unknown>) => {
    const parsed = typeof value.snapshot_at === 'string' ? Date.parse(value.snapshot_at) : NaN
    return Number.isFinite(parsed) ? parsed : 0
  }
  // Stable sort retains the historical precedence for legacy undated data.
  return candidates.sort((left, right) => time(right) - time(left))[0]
}

export type InviteSeatType = 'default' | 'prolite'

export interface InviteQuotaView {
  known: boolean
  limited: boolean
  limit: number
  used: number | null
  reserved: number
  remaining: number | null
  windowHours: number
  cycleState: string
  startedAt: string
  resetAt: string
  active: boolean
  todaySuccessCount: number
  totalSuccessCount: number
  legacySharedUsed: number
  legacySharedReserved: number
  legacySharedResetAt: string
  classified: boolean
  byType: Partial<Record<InviteSeatType, InviteQuotaView>>
}

const object = (value: unknown): Record<string, unknown> => (
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
)
const count = (value: unknown): number | null => (
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null
)

/** Remaining is authoritative, including reservations and any legacy shared usage. */
export function readBusinessInviteQuota(value: unknown, fallbackLimit = 3, fallbackWindowHours = 30): InviteQuotaView {
  const quota = object(value)
  const limited = quota.limited !== false && quota.mode !== 'unlimited_audit'
  const limit = count(quota.limit) ?? fallbackLimit
  const reserved = count(quota.reserved) ?? 0
  const effectiveUsed = count(quota.used)
  const reportedRemaining = count(quota.remaining)
  const used = count(quota.consumed_used)
    ?? (effectiveUsed === null ? null : Math.max(0, effectiveUsed - reserved))
  const known = Object.keys(quota).length > 0 && (!limited || (limit > 0 && (reportedRemaining !== null || used !== null)))
  // A client clock reaching reset_at cannot confirm that server reservations expired.
  const remaining = known ? Math.max(0, Math.min(limit, reportedRemaining ?? (limit - Number(used || 0) - reserved))) : null
  const cycleState = String(quota.cycle_state || '')
  const resetAt = String(quota.reset_at || quota.window_ends_at || quota.next_available_at || quota.earliest_recovery_at || '')
  const rows = object(quota.by_type)
  const classified = quota.mode === 'by_seat_type' || Object.keys(rows).length > 0
  const byType: InviteQuotaView['byType'] = {}
  if (classified) {
    for (const seatType of ['default', 'prolite'] as const) {
      const row = object(rows[seatType])
      byType[seatType] = readBusinessInviteQuota(Object.keys(row).length ? {
        ...row, window_hours: row.window_hours ?? quota.window_hours,
      } : undefined, fallbackLimit, fallbackWindowHours)
    }
  }
  return {
    known, limited, limit, used, reserved,
    remaining: limited ? remaining : Number.MAX_SAFE_INTEGER,
    windowHours: (count(quota.window_hours) || fallbackWindowHours),
    cycleState, startedAt: String(quota.window_started_at || ''), resetAt,
    active: Boolean(limited && known && Number(used || 0) > 0 && cycleState !== 'inactive'),
    todaySuccessCount: count(quota.today_success_count) ?? 0,
    totalSuccessCount: count(quota.total_success_count) ?? count(quota.consumed_used) ?? 0,
    legacySharedUsed: count(quota.legacy_shared_used) ?? 0,
    legacySharedReserved: count(quota.legacy_shared_reserved) ?? 0,
    legacySharedResetAt: String(quota.legacy_shared_reset_at || ''),
    classified, byType,
  }
}

/** Match quota and vacancy on the same seat type; totals alone can give a false positive. */
export function hasBusinessInviteQuotaForVacancy(
  _quota: InviteQuotaView,
  available: Record<InviteSeatType, number | null>,
): boolean {
  return Object.values(available).some(value => Number(value || 0) > 0)
}

export function businessInviteVacancies(value: unknown): Record<InviteSeatType, number | null> {
  const seat = object(value)
  const result: Record<InviteSeatType, number | null> = { default: null, prolite: null }
  for (const type of ['default', 'prolite'] as const) {
    const row = object(object(seat.by_type)[type] ?? object(seat.seat_types)[type]
      ?? object(seat.capacity_by_type)[type] ?? object(seat.seat_type_summary)[type])
    const exact = row.availability_exact === true
      || (row.availability_exact === undefined && row.known === true)
    if (exact) result[type] = count(row.available ?? object(seat.available_by_type)[type])
  }
  return result
}

/** Invitation budgets apply to child slots; the owner's seat is not one. */
export function businessInviteQuotaSeatTypes(value: unknown): InviteSeatType[] {
  const seat = object(value)
  const ownerType = String(seat.owner_seat_type || '').trim().toLowerCase()
  const ownerKnown = ownerType === 'default' || ownerType === 'prolite'
  const ownerUsed = count(seat.owner_used) ?? 1
  const declared = Array.isArray(seat.invitable_seat_types) ? seat.invitable_seat_types : []
  return (['default', 'prolite'] as const).filter(type => {
    const row = object(object(seat.by_type)[type] ?? object(seat.seat_types)[type]
      ?? object(seat.capacity_by_type)[type] ?? object(seat.seat_type_summary)[type])
    const used = count(row.used ?? row.occupied ?? object(seat.used_by_type)[type] ?? seat[`${type}_used`])
    const total = count(row.total ?? row.capacity ?? object(seat.total_by_type)[type] ?? seat[`${type}_total`])
    const available = count(row.available ?? row.remaining ?? object(seat.available_by_type)[type])
    // When the owner's type is unknown, only counts beyond its possible seat
    // establish a child slot. Exact vacancies still provide independent proof.
    const ownerSeats = !ownerKnown || ownerType === type ? ownerUsed : 0
    const capacityKnown = row.capacity_known === true || row.known === true
      || row.availability_exact === true || seat.seat_type_capacity_known === true
    const exact = row.availability_exact === true
      || (row.availability_exact === undefined && row.known === true)
    // requestable_seat_types includes speculative types with unknown capacity.
    // Old snapshots can also declare can_invite with availability_exact=false.
    const confirmedInvitable = exact && (row.can_invite === true || declared.includes(type))
    return (used !== null && used > ownerSeats)
      || (capacityKnown && total !== null && total > ownerSeats)
      || (exact && available !== null && available > 0)
      || confirmedInvitable
  })
}
