import BusinessInviteMailProviderSettings from '@/components/BusinessInviteMailProviderSettings'
import { useBusinessInviteMailProviderSettings } from '@/hooks/useBusinessInviteMailProviderSettings'
import { useCallback, useEffect, useMemo, useRef, useState, type HTMLAttributes, type ReactNode } from 'react'
import {
  Alert,
  App,
  Badge,
  Button,
  Card,
  Collapse,
  Descriptions,
  Drawer,
  Dropdown,
  Empty,
  Grid,
  Input,
  InputNumber,
  Modal,
  Popover,
  Popconfirm,
  Progress,
  Segmented,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  theme,
} from 'antd'
import type { MenuProps, TableProps } from 'antd'
import ChatGptSecurityProgress, { readSecurityProgress, securityStageLabel, type SecurityProgress } from '@/components/ChatGptSecurityProgress'
import BusinessMotherAudit, { BusinessDeadStamp } from '@/components/BusinessMotherAudit'
import GptPlanAppealActions from '@/components/GptPlanAppealActions'
import { latestBusinessInviteQuota, readBusinessInviteQuota, hasBusinessInviteQuotaForVacancy, businessInviteVacancies, businessInviteQuotaSeatTypes, type InviteQuotaView } from '@/lib/businessInviteQuota'
import BusinessInviteQuotaSummary from '@/components/BusinessInviteQuotaSummary'
import {
  BellOutlined,
  CopyOutlined,
  CloudUploadOutlined,
  CrownOutlined,
  DeleteOutlined,
  DollarOutlined,
  DownloadOutlined,
  DownOutlined,
  EditOutlined,
  FireOutlined,
  InboxOutlined,
  LinkOutlined,
  LoginOutlined,
  MailOutlined,
  MoreOutlined,
  PlusOutlined,
  ReloadOutlined,
  RocketOutlined,
  RollbackOutlined,
  SafetyOutlined,
  SearchOutlined,
  SyncOutlined,
  TeamOutlined,
  ThunderboltOutlined,
  UsergroupAddOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { Link, useSearchParams } from 'react-router-dom'
import PageHeader from '@/components/PageHeader'
import CardsPage from '@/pages/CardsPage'
import CpaProxyPanel from '@/components/CpaProxyPanel'
import GptPlanPreparationPanel from '@/components/GptPlanPreparationPanel'
import UpgradeBrowserConfigControls from '@/components/UpgradeBrowserConfigControls'
import { ApiFetchError, apiFetch, getToken } from '@/lib/utils'
import { gptPlanMailLocation } from '@/lib/gptPlanMailLocation'
import { canLoginWithSavedPassword } from '@/lib/gmailWorkspaceAccountState'
import { useUpgradeBrowserConfig } from '@/hooks/useUpgradeBrowserConfig'
import {
  BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS,
  businessInviteCandidateMatchesProvider,
  businessInviteTargetSeat,
  businessInviteMailProviderHint,
  type BusinessInviteSeatType,
  normalizeBusinessInviteMailProvider,
  type BusinessInviteMailProvider,
} from '@/lib/businessInviteMailProvider'

type LoginStatus = 'logged_in' | 'not_logged_in' | 'failed' | 'unknown'
type AccountType = 'regular' | 'member' | 'refunded'
type MemberPlan = 'go' | 'plus' | 'pro' | 'team'
type RefundedMigrationTarget = 'pro' | 'business' | 'plus' | 'go'
type BusinessUsageType = 'sale' | 'self_use' | 'transit'
type BusinessUsageFilter = BusinessUsageType | 'unassigned'
type BusinessSeatFilter = 'available' | 'full' | 'unknown'
type BusinessCatalogView = 'mothers' | 'children'
type BusinessChildTwoFactorFilter = 'all' | 'enabled' | 'not_enabled' | 'needs_attention'
type BusinessChildRtFilter = 'all' | 'acquired' | 'missing'
type BusinessChildSaleStatus = 'unlisted' | 'listed' | 'sold' | 'refunded' | 'partial_refund'
type BusinessChildSaleFilter = 'all' | BusinessChildSaleStatus

interface GptPlanFocusTarget {
  planAccountId: number
  accountType: AccountType
  memberPlan?: MemberPlan
  childAccountId: number | null
  membershipId: number | null
}

interface GptPlanAccount {
  id: number
  email: string
  mail_provider?: string
  mail_access_type?: string
  mail_access_type_label?: string
  mail_access_type_color?: string
  has_mail_credentials?: boolean
  has_mail_oauth?: boolean
  has_oauth?: boolean
  has_password?: boolean
  has_cookie?: boolean
  cookie_valid?: boolean
  cookie_updated_at?: string
  cookie_expires_at?: string
  login_status?: string
  login_status_label?: string
  login_state?: string
  last_login_at?: string
  last_login_error?: string
  plan_type?: string
  plan?: string
  plan_name?: string
  plan_label?: string
  account_type?: AccountType
  catalog_category?: AccountType | string
  member_plan?: MemberPlan | ''
  plan_checked_at?: string
  plan_detected_at?: string
  subscribed_at?: string
  plan_upgraded_at?: string
  pro_upgraded_at?: string
  business_upgraded_at?: string
  upgraded_at?: string
  payment_card_last4?: string
  last_checkout_at?: string
  last_checkout_plan?: string
  last_checkout_status?: string
  last_checkout_country?: string
  last_checkout_currency?: string
  last_checkout_region?: string
  checkout_session_id?: string
  enabled?: boolean
  dangerous?: boolean
  dead?: boolean
  dangerous_detected_at?: string
  appeal_url?: string
  appeal_done_at?: string
  appeal_link_lookup?: {
    status: 'idle' | 'pending' | 'running' | 'not_found' | 'error' | 'ready'
    last_checked_at?: string
    next_retry_at?: string
    error?: string
  }
  policy_warning?: boolean
  policy_warning_detected_at?: string
  note?: string
  business_usage_type?: BusinessUsageType | null
  last_mail_fetch_at?: string
  last_mail_error?: string
  last_mail_check_at?: string
  last_mail_check_error?: string
  created_at?: string
  updated_at?: string
  last_used?: string
  source_pool?: string
  source_account_id?: number | null
  source_missing?: boolean
  source_error?: string
  has_codex_rt?: boolean
  codex_refresh_token_len?: number
  codex_rt_updated_at?: string
  codex_rt_acquired_at?: string
  refund_status?: string
  human_review_requested_at?: string
  invite_cooldown?: BusinessInviteCooldown | null
  invite_cooldown_active?: boolean
  invite_cooldown_started_at?: string
  invite_cooldown_until?: string
  invite_cooldown_reason?: string
  invite_quota?: BusinessInviteQuota | null
  replenishment?: AutoReplenishmentStatus | null
  member_source?: MemberSource | null
  member_capabilities?: MemberCapabilities | null
  capabilities?: MemberCapabilities | null
  chatgpt_security?: ChatGptSecurityState | null
}

interface ChatGptSecurityState {
  password_state?: string
  mfa_state?: string
  has_password?: boolean
  has_totp?: boolean
  credentials_readable?: boolean
  last_error?: string
  password_updated_at?: string
  mfa_updated_at?: string
  updated_at?: string
}

interface ChatGptSecuritySetupTask {
  accountId: number
  email: string
  browserMode: 'headless' | 'headed'
  taskId: string
  status: 'running' | 'done' | 'failed'
  stage: string
  logs: string[]
  error?: string
  securityProgress?: SecurityProgress | null
}

interface BusinessChildSecuritySetupTask {
  parentAccountId: number
  childId: number
  email: string
  browserMode: 'headless' | 'headed'
  taskId: string
  status: 'running' | 'done' | 'failed'
  stage: string
  logs: string[]
  error?: string
  securityProgress?: SecurityProgress | null
}

interface AutoReplenishmentStatus {
  demand_id: string
  state: string
  stage?: string
  effective_state?: string
  effective_stage?: string
  effective_error?: string
  provider?: string
  device_id?: number | null
  parent_id?: number | null
  seat_type?: string
  next_check_at?: string
  resume_at?: string
  last_checked_at?: string
  attempt_count?: number | null
  fill_job_id?: string
  fill_state?: string
  fill_stage?: string
  fill_email?: string
  candidate_email?: string
  invite_status?: string
  invite_confirmed?: boolean | null
  cooldown_reason?: string
  cooldown_active?: boolean
  cooldown_until?: string
  fill?: {
    email?: string
    candidate_email?: string
    invite_status?: string
    invite_confirmed?: boolean | null
    cooldown_reason?: string
    cooldown_active?: boolean
    cooldown_until?: string
    resume_at?: string
  } | null
  created_at?: string
  updated_at?: string
  completed_at?: string
  error?: string
}

type MemberCapabilityName = 'refund' | 'oauth' | 'oauth_file' | 'sync_device' | 'device_usage' | 'pro_refund_burn' | 'business_children'

interface MemberCapability {
  supported?: boolean
  reason?: string
  formats?: string[]
  providers?: string[]
  remaining?: number | null
  limit?: number | null
  [key: string]: unknown
}

type MemberCapabilities = Partial<Record<MemberCapabilityName, MemberCapability | boolean>> & Record<string, unknown>

interface MemberDeviceStatus {
  device_ref?: string
  target_id?: number
  device_id?: number
  id?: number | string
  name?: string
  [key: string]: unknown
}

interface BusinessMemberDeviceBinding {
  bound?: boolean
  persisted?: boolean
  device_ref?: string
  delivery_type?: string
  provider?: string
  delivery_target_id?: number | null
  target_id?: number | null
  device_id?: number | null
  cpa_target_id?: number | null
  sub2api_device_id?: number | null
  name?: string
  device_name?: string
  state?: string
  device_state?: string
  enabled?: boolean
  auto_rotation_enabled?: boolean
  policy_revision?: number
  can_bind?: boolean
  eligible_for_new_binding?: boolean
  binding_blockers?: unknown[]
  updated_at?: string
  delivery_target?: MemberDeviceStatus | null
  target?: MemberDeviceStatus | null
  [key: string]: unknown
}

interface MemberSource {
  source_pool?: string
  source_account_id?: number | null
  source_missing?: boolean
  source_error?: string
  has_codex_rt?: boolean
  codex_refresh_token_len?: number
  codex_rt_acquired_at?: string
  codex_rt_updated_at?: string
  refund_status?: string
  refund_detected_at?: string
  refund_credited_at?: string
  refund_manual_at?: string
  human_review_requested_at?: string
  policy_warning?: boolean
  policy_warning_detected_at?: string
  dangerous?: boolean
  dangerous_detected_at?: string
  cpa?: MemberDeviceStatus | null
  sub2api?: MemberDeviceStatus | null
  business_device_binding?: BusinessMemberDeviceBinding | null
  business_workspace?: BusinessWorkspaceCapability | null
  invite_cooldown?: BusinessInviteCooldown | null
  invite_cooldown_active?: boolean
  invite_cooldown_started_at?: string
  invite_cooldown_until?: string
  invite_cooldown_reason?: string
  seat_summary?: BusinessSeatSummary | null
  invite_quota?: BusinessInviteQuota | null
  rotation_quota?: BusinessRotationQuota | null
  workspace_checked_at?: string
  invite_candidate_count?: number | null
  replenishment?: AutoReplenishmentStatus | null
  capabilities?: MemberCapabilities | null
  [key: string]: unknown
}

type BusinessSeatType = 'default' | 'prolite'

interface BusinessSeatTypeCapacity {
  used: number | null
  total: number | null
  available: number | null
  known: boolean
  can_invite?: boolean
  capacity_known?: boolean
  availability_exact?: boolean | null
}

interface BusinessSeatSummary {
  total?: number | null
  used?: number | null
  available?: number | null
  full?: boolean
  known?: boolean
  owner_seat_type?: string | null
  invitable_seat_types?: string[] | null
  requestable_seat_types?: string[] | null
  seat_type_capacity_known?: boolean
  seat_type_occupancy_known?: boolean
  checked_at?: string
  by_type?: Record<string, Partial<BusinessSeatTypeCapacity> | null> | null
  seat_types?: Record<string, Partial<BusinessSeatTypeCapacity> | null> | null
  capacity_by_type?: Record<string, Partial<BusinessSeatTypeCapacity> | null> | null
  seat_type_summary?: Record<string, Partial<BusinessSeatTypeCapacity> | null> | null
  used_by_type?: Record<string, number | null> | null
  total_by_type?: Record<string, number | null> | null
  available_by_type?: Record<string, number | null> | null
  [key: string]: unknown
}

interface BusinessRotationQuota {
  limit?: number | null
  window_hours?: number | null
  used?: number | null
  remaining?: number | null
  next_available_at?: string
  earliest_recovery_at?: string
  reset_at?: string
  window_started_at?: string
  reserved?: number | null
  [key: string]: unknown
}

interface BusinessInviteQuota {
  mode?: string
  by_type?: Partial<Record<BusinessSeatType, BusinessInviteQuota>>
  snapshot_at?: string
  limit?: number | null
  used?: number | null
  consumed_used?: number | null
  remaining?: number | null
  window_hours?: number | null
  window_started_at?: string
  window_ends_at?: string
  reset_at?: string
  next_available_at?: string
  earliest_recovery_at?: string
  reserved?: number | null
  cycle_state?: string
  [key: string]: unknown
}

interface BusinessInviteCooldown {
  active?: boolean
  started_at?: string
  until?: string
  resume_at?: string
  reason?: string
  remaining_seconds?: number | null
  duration_seconds?: number | null
  snapshot_at?: string
  [key: string]: unknown
}

interface BusinessVacancyPolicy {
  policy_present?: boolean
  http_status?: number | null
  free_vacancy_threshold?: number | null
  vacancy_ordinal?: number | null
  billing_starts_at?: string | null
  expires_at?: string | null
  captured_at?: string | null
}

interface BusinessWorkspaceCapability {
  team_session_usable?: boolean
  team_session_reason?: string
  session_health?: BusinessSessionHealth | null
  team_id?: string
  team_plan?: string
  workspace_referrals_enabled?: boolean | null
  workspace_referrals_enabled_visible?: boolean | null
  workspace_referrals_enabled_checked_at?: string
  default_payment_method?: BusinessDefaultPaymentMethod | null
  seat_summary?: BusinessSeatSummary | null
  invite_quota?: BusinessInviteQuota | null
  rotation_quota?: BusinessRotationQuota | null
  rotation_revenue?: {
    rotation_blocked?: boolean
    blocked_tiers?: string[]
    tiers?: Record<string, { current_yuan?: string; threshold_yuan?: string | null; exceeded?: boolean }>
  } | null
  invite_cooldown?: BusinessInviteCooldown | null
  replaceable_count?: number | null
  invite_candidate_count?: number | null
  [key: string]: unknown
}

interface BusinessDefaultPaymentMethod {
  status: 'unknown' | 'ready' | 'none' | 'error'
  type: string
  brand: string
  last4: string
  checked_at: string
  error: string
}

interface BusinessSessionHealth {
  status: 'valid' | 'unchecked' | 'expired' | 'missing' | 'refreshing' | 'invalid' | 'unauthorized' | 'blocked' | 'error' | 'wrong_identity' | 'busy'
  message: string
  checked_at: string
  access_token_expires_at: string
  session_expires_at: string
  cookie_updated_at: string
  refreshed_at: string
  can_refresh: boolean
  http_status: number | null
}

interface BusinessSessionCheckResult {
  ok?: boolean
  session_health?: BusinessSessionHealth | null
  member_source?: MemberSource | null
  error?: string
}

interface BusinessManagedChild {
  membership_id?: number | null
  pro_account_id?: number | null
  email?: string
  source?: string
  candidate_source?: 'prepared' | 'regular'
  prepared?: boolean
  status?: 'candidate' | 'pending' | 'member' | 'local' | string
  role?: string
  user_id?: string
  invite_id?: string
  managed_pro_account_id?: number | null
  mail_provider?: string
  mail_access_type?: string
  has_password?: boolean
  has_mail_oauth?: boolean
  has_mail_credentials?: boolean
  has_cookie?: boolean
  has_saved_login?: boolean
  cookie_valid?: boolean | null
  cookie_updated_at?: string
  cookie_expires_at?: string
  login_status?: string
  can_chatgpt_login?: boolean
  chatgpt_login_disabled_reason?: string
  can_setup_chatgpt_security?: boolean
  chatgpt_security_setup_disabled_reason?: string
  chatgpt_security_setup_recovery_hint?: string
  can_review_chatgpt_login?: boolean
  chatgpt_login_review_disabled_reason?: string
  can_fetch_mail?: boolean
  fetch_mail_disabled_reason?: string
  chatgpt_oauth_credentials_ready?: boolean
  chatgpt_oauth_disabled_reason?: string
  has_codex_rt?: boolean
  rt_supported?: boolean
  can_get_rt?: boolean
  enabled?: boolean
  dangerous?: boolean
  dangerous_detected_at?: string
  policy_warning?: boolean
  policy_warning_detected_at?: string
  refund_status?: string
  monitor_enabled?: boolean
  last_mail_check_at?: string
  last_mail_check_error?: string
  pending_alerts_count?: number
  pending_inbox_count?: number
  codex_rt_acquired_at?: string
  business_invited_at?: string
  sale_status?: BusinessChildSaleStatus
  sold_at?: string | null
  warranty_hours?: number
  nv_team5x_warranty_until?: string
  deletion_ready?: boolean
  can_delete?: boolean
  nv_listed_at?: string
  nv_listing_confirmed_at?: string
  nv_last_synced_at?: string
  deactivated?: boolean
  seat_type?: string
  assigned_seat_type?: string
  workspace_seat_type?: string
  cpa_synced_to?: BusinessChildCpaDeviceLink | null
  sub2api_synced_to?: BusinessChildSub2ApiDeviceLink | null
  chatgpt_security?: ChatGptSecurityState | null
  [key: string]: unknown
}

interface BusinessChildCpaDeviceLink {
  target_id: number
  name: string
  synced_at: string
}

interface BusinessChildSub2ApiDeviceLink {
  device_id: number
  name: string
  synced_at: string
}

interface BusinessReplaceableChild {
  key?: string
  membership_id?: number | null
  kind?: 'member' | 'invite'
  old_kind?: 'member' | 'invite'
  email?: string
  user_id?: string
  invite_id?: string
  pro_account_id?: number | null
  managed_pro_account_id?: number | null
  seat_type?: string
  [key: string]: unknown
}

interface BusinessChildrenSnapshot {
  team_id?: string
  plan?: string
  members?: BusinessManagedChild[]
  invites?: BusinessManagedChild[]
  managed_children?: BusinessManagedChild[]
  replaceable_children?: BusinessReplaceableChild[]
  seat_summary?: BusinessSeatSummary | null
  invite_quota?: BusinessInviteQuota | null
  rotation_quota?: BusinessRotationQuota | null
  invite_cooldown?: BusinessInviteCooldown | null
  vacancy_policy?: BusinessVacancyPolicy | null
  invite_candidate_count?: number | null
  workspace_checked_at?: string
  checked_at?: string
  [key: string]: unknown
}

interface BusinessChildrenView {
  loading: boolean
  loaded: boolean
  error: string
  snapshot: BusinessChildrenSnapshot | null
}

interface BusinessChildDisplayRow extends BusinessManagedChild {
  _kind: 'member' | 'invite' | 'local'
  _managed: boolean
}

interface BusinessChildCatalogRow extends BusinessChildDisplayRow {
  child_id?: number | null
  child_name?: string
  child_email?: string
  parent_account_id: number
  parent_email: string
  parent_note?: string
  membership_status?: string
  invited_at?: string
  sale_status?: BusinessChildSaleStatus
  sold_at?: string | null
  warranty_hours?: number
  warranty_expires_at?: string | null
  warranty_status?: string
  actions?: Record<string, MemberCapability | boolean | undefined>
}

interface BusinessChildDeviceSyncTarget {
  account: GptPlanAccount
  child: BusinessChildDisplayRow
}

interface BusinessChildNvListingTarget {
  account: GptPlanAccount
  child: BusinessChildDisplayRow
}

interface BusinessChildNvBatchItem {
  membership_id: number
  email: string
  status: 'pending' | 'running' | 'success' | 'failed' | 'skipped'
  stage: string
  error: string
  logs: string[]
}

interface BusinessChildNvBatchTask {
  task_id: string
  status: 'running' | 'done' | 'failed'
  total: number
  completed: number
  succeeded: number
  failed: number
  skipped: number
  percent: number
  items: BusinessChildNvBatchItem[]
  logs: string[]
  error: string
}

type BusinessChildNvSalesStatus = 'sold' | 'refunded' | 'partial_refund' | 'pending_sale' | 'not_found' | 'needs_review' | 'invalid_local' | 'skipped_changed'

interface BusinessChildNvSalesDetail {
  membership_id: number
  email: string
  status: BusinessChildNvSalesStatus
  reason: string
}

interface BusinessChildNvLegacyDetail {
  email: string
  membership_ids: number[]
  record_count: number
  reason: string
}

interface BusinessChildNvSalesResult {
  updated_refunded: number
  updated_partial_refund: number
  listed_checked: number
  sold_found: number
  sold_updated: number
  deletion_ready: number
  pending_sale: number | null
  not_found: number | null
  needs_review: number | null
  invalid_local: number
  skipped_changed: number
  classified: boolean
  details: BusinessChildNvSalesDetail[]
  legacy_pending: number | null
  legacy_records: number | null
  legacy_classified: boolean
  legacy_details: BusinessChildNvLegacyDetail[]
}

interface NvTokensConfigState {
  base_url: string
  api_key_configured: boolean
  query_session_configured: boolean
}

interface BusinessBurnCandidate {
  id: number
  email: string
  subscribed_at?: string
}

interface BusinessBurnTask {
  taskId: string
  status: 'running' | 'done' | 'failed'
  logs: string[]
  progress?: { done: number; total: number; burned: number } | null
  error?: string
}

interface BusinessBatchInviteProgress {
  total_mothers: number
  completed_mothers: number
  total_invites: number
  completed_invites: number
  successful_invites: number
  failed_invites: number
  partial_invites: number
  skipped_invites: number
  percent: number
}

interface BusinessBatchInvitationProgress {
  index: number
  status: string
  status_label: string
  pro_account_id?: number | null
  email?: string
  error?: string
  started_at?: string
  finished_at?: string
  steps: Record<string, BusinessBatchActionStep>
}

interface BusinessBatchActionStep {
  status: string
  label: string
  error?: string
  taskId?: string
  startedAt?: string
  finishedAt?: string
}

interface BusinessBatchMotherProgress {
  account_id: number
  email: string
  status: string
  status_label: string
  planned_invites: number
  completed_invites: number
  successful_invites: number
  failed_invites: number
  partial_invites: number
  skipped_invites: number
  percent: number
  current_invite?: BusinessBatchInvitationProgress | null
  error?: string
  invitations: BusinessBatchInvitationProgress[]
}

interface BusinessBatchInviteTask {
  taskId: string
  status: string
  outcome?: string
  hasFailures: boolean
  candidateMailProvider: BusinessInviteMailProvider
  workflow: string
  phase?: string
  attempts?: number
  nextRetryAt?: string
  seatType?: BusinessSeatType
  postSetupSecurity: boolean
  postAcquireRt: boolean
  securityBrowserMode: 'headless' | 'headed'
  currentAccountId?: number | null
  currentAccountEmail?: string
  progress: BusinessBatchInviteProgress
  mothers: BusinessBatchMotherProgress[]
  logs: string[]
  since: number
  error?: string
  startedAt?: string
  finishedAt?: string
  pollingError?: string
}

type BusinessChildBatchAction = 'setup_security' | 'oauth' | 'leave_workspace'

interface BusinessChildBatchActionItem {
  membershipId: number
  parentAccountId: number
  childId?: number | null
  email: string
  status: string
  statusLabel: string
  steps: Record<string, BusinessBatchActionStep>
  logs: string[]
  error?: string
}

interface BusinessChildBatchActionTask {
  taskId: string
  action: BusinessChildBatchAction
  browserMode: 'headless' | 'headed'
  status: string
  outcome?: string
  attempts?: number
  nextRetryAt?: string
  progress: {
    total: number
    completed: number
    success: number
    failed: number
    skipped: number
    percent: number
  }
  items: BusinessChildBatchActionItem[]
  logs: string[]
  since: number
  error?: string
  pollingError?: string
}

interface BusinessChildRtTask {
  accountId: number
  parentEmail: string
  childId: number
  childEmail: string
  taskId: string
  reacquire: boolean
  status: 'running' | 'success' | 'failed'
  stage: string
  logs: string[]
  error?: string
}

type BusinessInviteStage = 'idle' | 'preflight' | 'inviting' | 'refreshing' | 'success' | 'failed'

interface BusinessInviteProgressState {
  stage: BusinessInviteStage
  detail?: string
}

interface DeliveryDeviceOption {
  deviceRef: string
  provider: 'cpa' | 'sub2api'
  name: string
  enabled: boolean
}

interface LinkedMemberDevice {
  deviceRef: string
  provider: 'cpa' | 'sub2api'
  name: string
}

interface MemberDeviceUsageView {
  accountId: number
  email: string
  deviceRef: string
  provider: 'cpa' | 'sub2api'
  usage: Record<string, unknown>
}

interface MemberSourceTask {
  accountId: number
  email: string
  action: 'oauth' | 'refund'
  taskId: string
  status: 'running' | 'done' | 'failed'
  stage: string
  logs: string[]
  error?: string
}

interface RoxyProxy {
  id: number
  host: string
  port: string
  protocol: string
  note?: string
  last_country?: string
  check_status?: number
  enabled?: boolean
}

interface UpgradeTask {
  accountId: number
  taskId: string
  stage: string
}

interface RefundedUpgradeReview {
  accountId: number
  taskId: string
  stage: string
}

type MailAccountTarget = Pick<GptPlanAccount, 'id' | 'email'> & Partial<Pick<GptPlanAccount, 'account_type'>>

interface MailMessage {
  id?: string
  from?: string
  subject?: string
  preview?: string
  body?: string
  is_html?: boolean
  time?: string
  folder?: string
}

interface MailAlert {
  id: string
  from?: string
  subject?: string
  preview?: string
  time?: string
  folder?: string
  is_html?: boolean
  detected_at?: string
}

interface MailAlertSummaryItem {
  id: number
  email: string
  unread_count: number
  inbox_unread_count: number
  latest_subject?: string
  latest_time?: string
  target_kind?: 'account' | 'business_child'
  account_type?: AccountType | 'business_child'
  plan_type?: string
  member_plan?: string
  parent_id?: number | null
  parent_email?: string
  child_id?: number | null
  membership_id?: number | null
}

type MailAlertTarget = GptPlanAccount | MailAlertSummaryItem

interface ImportTaskSnapshot {
  id: string
  status: 'pending' | 'running' | 'done' | 'failed'
  progress?: string
  total: number
  processed: number
  success: number
  failed: number
  errors?: string[]
  created_at?: number
  updated_at?: number
}

interface PlanStat {
  plan_type: string
  plan_label?: string
  count: number
}

interface GptPlanStats {
  total?: number
  enabled?: number
  disabled?: number
  logged_in?: number
  not_logged_in?: number
  dead?: number
  regular?: number
  member?: number
  refunded?: number
  member_plans?: Partial<Record<MemberPlan, number>>
  plans?: PlanStat[]
}

const API_ROOT = '/gpt-plans'
const BUSINESS_CHILD_RT_POLL_MAX_RETRIES = 3
const BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY = 'gmail-business:business-batch-invite-task-id'
const BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY = 'gmail-business:business-child-batch-action-task'
const BUSINESS_CHILD_NV_BATCH_TASK_STORAGE_KEY = 'gmail-business:business-child-nv-listing-task-id'
const SECURITY_BROWSER_MODE_STORAGE_KEY = 'gmail-business:security-browser-mode'
const MAIL_MONITOR_INTERVAL_MS = 5 * 60 * 1000
const BUSINESS_INVITE_SUCCESS_LIMIT = 3
const BUSINESS_INVITE_WINDOW_HOURS = 30

const CHECKOUT_REGION_PRESETS = [
  { label: '菲律宾 PH/PHP', country: 'PH', currency: 'PHP' },
  { label: '尼日利亚 NG/NGN', country: 'NG', currency: 'NGN' },
  { label: '印度 IN/INR', country: 'IN', currency: 'INR' },
  { label: '土耳其 TR/TRY', country: 'TR', currency: 'TRY' },
  { label: '巴西 BR/BRL', country: 'BR', currency: 'BRL' },
  { label: '阿根廷 AR/ARS', country: 'AR', currency: 'ARS' },
  { label: '埃及 EG/EGP', country: 'EG', currency: 'EGP' },
  { label: '日本 JP/JPY', country: 'JP', currency: 'JPY' },
  { label: '加拿大 CA/CAD', country: 'CA', currency: 'CAD' },
  { label: '巴基斯坦 PK/PKR', country: 'PK', currency: 'PKR' },
  { label: '美国 US/USD', country: 'US', currency: 'USD' },
] as const

const UPGRADE_STAGE_LABELS: Record<string, string> = {
  awaiting_card_pick: '等待在浏览器选择付款卡',
  filling_card: '正在填写付款卡',
  clicking_subscribe: '正在提交订阅',
  waiting_redirect: '正在等待订阅结果',
  go_subscribed_wait: 'GO 已订阅，等待套餐生效后继续升级 PRO',
  creating_pro_checkout: '正在创建 PRO 升级结账',
  clicking_subscribe_pro: '正在确认 PRO 订阅',
  waiting_pro_redirect: '正在等待 PRO 订阅结果',
  pro_failed: '等待人工确认升级结果',
  success: '升级 PRO 成功',
  failed: '升级失败',
  timeout: '等待付款超时',
  cancelled: '任务已取消',
  confirmation_pending: '付款已完成，等待重新登录复核 PRO 套餐',
}

const REFUNDED_UPGRADE_REVIEW_STATUSES = new Set([
  'manual_confirmation_pending',
  'confirmation_pending',
  // 历史版本曾把轮询超时或未复核到套餐当作升级失败。
  // 已退款账号不再沿用这个自动裁决，统一交给人工确认。
  'failed',
  'timeout',
  'pro_failed',
])

const refundedUpgradeNeedsManualReview = (status: unknown) => (
  REFUNDED_UPGRADE_REVIEW_STATUSES.has(String(status || '').trim().toLowerCase())
)

const CHECKOUT_STATUS_META: Record<string, { label: string; color: string }> = {
  created: { label: '已创建', color: 'blue' },
  submitted: { label: '已提交', color: 'processing' },
  confirmation_pending: { label: '待复核', color: 'warning' },
  manual_confirmation_pending: { label: '等待人工确认', color: 'warning' },
  manual_not_upgraded: { label: '人工确认未升级', color: 'default' },
  success: { label: '成功', color: 'success' },
  failed: { label: '失败', color: 'error' },
}

const PLAN_LABELS: Record<string, string> = {
  free: 'Free',
  chatgptfreeplan: 'Free',
  go: 'GO 套餐',
  chatgptgo: 'GO 套餐',
  chatgptgoplan: 'GO 套餐',
  plus: 'Plus',
  chatgptplusplan: 'Plus',
  pro: 'GPT PRO',
  chatgptproplan: 'GPT PRO',
  pro_20x: 'PRO 20X',
  pro_5x: 'PRO 5X',
  team: 'TEAM',
  chatgptteamplan: 'TEAM',
  enterprise: 'Enterprise',
  business: 'TEAM',
  chatgptbusinessplan: 'TEAM',
  self_serve_business: 'TEAM',
  self_serve_business_prolite: 'TEAM 5X 套餐',
  business_master: 'BUSINESS 母号',
}

const MEMBER_PLAN_META: Record<MemberPlan, { label: string; color: string }> = {
  go: { label: 'GO', color: 'cyan' },
  plus: { label: 'PLUS', color: 'green' },
  pro: { label: 'PRO', color: 'gold' },
  team: { label: 'BUSINESS', color: 'purple' },
}

const DEFAULT_MEMBER_PLAN: MemberPlan = 'pro'
const MEMBER_PLAN_TAB_ORDER: MemberPlan[] = ['pro', 'team', 'plus', 'go']
const REFUNDED_MIGRATION_META: Record<RefundedMigrationTarget, {
  label: string
  memberPlan: MemberPlan
}> = {
  pro: { label: 'PRO', memberPlan: 'pro' },
  business: { label: 'BUSINESS', memberPlan: 'team' },
  plus: { label: 'PLUS', memberPlan: 'plus' },
  go: { label: 'GO', memberPlan: 'go' },
}

function planTypeOf(account: GptPlanAccount): string {
  return String(account.plan_type || account.plan || account.plan_name || '').trim()
}

function planLabelOf(account: GptPlanAccount): string {
  const raw = planTypeOf(account)
  const normalized = raw.toLowerCase()
  if (normalized === 'pro_20x') return 'PRO 20X'
  if (normalized === 'pro_5x') return 'PRO 5X'
  if (normalized === 'business_master') return 'BUSINESS 母号'
  // BUSINESS 统一归入 TEAM 展示；prolite 保留可区分的 TEAM 5X 标签。
  if (normalized === 'self_serve_business_prolite') return 'TEAM 5X 套餐'
  if (['business', 'chatgptbusinessplan', 'self_serve_business', 'team', 'chatgptteamplan'].includes(normalized)) {
    return 'TEAM'
  }
  return String(account.plan_label || PLAN_LABELS[normalized] || raw || '未检测')
}

function memberPlanKey(value?: string | null): MemberPlan | undefined {
  const normalized = String(value || '').trim().toLowerCase()
  if (!normalized) return undefined
  if (
    normalized.includes('prolite')
    || normalized.includes('business')
    || normalized.includes('team')
  ) return 'team'
  if (normalized === 'go' || normalized.includes('goplan') || normalized.includes('chatgptgo')) return 'go'
  if (normalized === 'plus' || normalized.includes('plusplan')) return 'plus'
  if (normalized === 'pro' || normalized === 'pro_20x' || normalized === 'pro_5x' || normalized.includes('proplan')) return 'pro'
  return undefined
}

function loginStatusOf(account: GptPlanAccount): LoginStatus {
  const raw = String(account.login_status || account.login_state || '').trim().toLowerCase()
  if (['logged_in', 'login_success', 'success', 'ok'].includes(raw)) return 'logged_in'
  if (['not_logged_in', 'never', 'pending', ''].includes(raw)) {
    return account.has_cookie ? 'logged_in' : 'not_logged_in'
  }
  if (['failed', 'error', 'login_failed'].includes(raw)) return 'failed'
  return account.has_cookie ? 'logged_in' : 'unknown'
}

function hasMailCredentials(account: GptPlanAccount): boolean {
  if (typeof account.has_mail_credentials === 'boolean') return account.has_mail_credentials
  if (typeof account.has_mail_oauth === 'boolean') return account.has_mail_oauth
  if (typeof account.has_oauth === 'boolean') return account.has_oauth
  return account.mail_provider === 'icloud'
}

function formatTime(value?: string | number | null): string {
  if (!value) return '—'
  const date = typeof value === 'number'
    ? new Date(value < 10_000_000_000 ? value * 1000 : value)
    : new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}

function businessChildNvListingTime(child: BusinessManagedChild): string {
  const listedAt = String(child.nv_listed_at || '').trim()
  const confirmedAt = String(child.nv_listing_confirmed_at || '').trim()
  // Older manual sale labels also populated nv_listed_at, without NV proof.
  if (listedAt && confirmedAt
    && Number.isFinite(Date.parse(listedAt))
    && Number.isFinite(Date.parse(confirmedAt))) return formatTime(listedAt)
  return ['listed', 'sold', 'refunded', 'partial_refund'].includes(child.sale_status || '') ? '未记录' : '未上架'
}

function autoReplenishmentTime(value?: string): number {
  if (!value) return 0
  const timestamp = Date.parse(value)
  return Number.isFinite(timestamp) ? timestamp : 0
}

function businessInviteCooldownCountdown(value: string | undefined, now: number): string {
  const target = autoReplenishmentTime(value)
  if (!target || target <= now) return '即将恢复'
  let seconds = Math.max(0, Math.ceil((target - now) / 1000))
  const days = Math.floor(seconds / 86_400)
  seconds %= 86_400
  const hours = Math.floor(seconds / 3_600)
  seconds %= 3_600
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  const clock = [hours, minutes, rest].map((part) => String(part).padStart(2, '0')).join(':')
  return days > 0 ? `${days}天 ${clock} 后恢复` : `${clock} 后恢复`
}

function businessInviteCooldownReasonLabel(value: string | undefined): string {
  const key = String(value || '').trim().toLowerCase()
  if (key === 'explicit_rejection') return '邀请接口明确拒绝邀请'
  if (!key) return '邀请接口调用失败'
  if (key.includes('timeout')) return '邀请接口超时'
  if (key.includes('rate') || key.includes('429')) return '邀请请求频率受限'
  if (key.includes('seat')) return '邀请时席位校验失败'
  if (key.includes('session') || key.includes('auth') || key.includes('401')) return '母号会话无法完成邀请'
  return '邀请接口调用失败'
}

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) return error.message
  if (typeof error === 'string' && error.trim()) return error
  if (error && typeof error === 'object') {
    const value = error as { message?: unknown; detail?: unknown }
    if (typeof value.message === 'string' && value.message.trim()) return value.message
    if (typeof value.detail === 'string' && value.detail.trim()) return value.detail
  }
  return fallback
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function businessCheckoutCouponFromResponse(value: unknown): string {
  const result = asRecord(value)
  const coupon = typeof result.coupon === 'string' ? result.coupon.trim() : ''
  if (result.ok !== true || !coupon || coupon.length > 200) {
    throw new Error(String(result.detail || result.error || '后端未返回有效的 BUSINESS 默认优惠码'))
  }
  return coupon
}

function businessBatchCount(value: unknown): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? Math.max(0, Math.floor(parsed)) : 0
}

function businessBatchPercent(value: unknown): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? Math.max(0, Math.min(100, Math.round(parsed))) : 0
}

function sanitizeBusinessChildNvBatchTask(value: unknown, taskId = ''): BusinessChildNvBatchTask {
  const row = asRecord(value)
  const id = String(row.task_id || taskId).trim()
  if (!id || !['running', 'done', 'failed'].includes(String(row.status))) {
    throw new Error('批量 NV 任务响应不完整，请重试读取进度')
  }
  return {
    task_id: id,
    status: row.status as BusinessChildNvBatchTask['status'],
    total: businessBatchCount(row.total),
    completed: businessBatchCount(row.completed),
    succeeded: businessBatchCount(row.succeeded),
    failed: businessBatchCount(row.failed),
    skipped: businessBatchCount(row.skipped),
    percent: businessBatchPercent(row.percent),
    items: (Array.isArray(row.items) ? row.items : []).map((value) => {
      const item = asRecord(value)
      return {
        membership_id: businessBatchCount(item.membership_id),
        email: String(item.email || ''),
        status: (['pending', 'running', 'success', 'failed', 'skipped'].includes(String(item.status))
          ? item.status : 'pending') as BusinessChildNvBatchItem['status'],
        stage: String(item.stage || ''),
        error: String(item.error || ''),
        logs: Array.isArray(item.logs) ? item.logs.map(String) : [],
      }
    }),
    logs: Array.isArray(row.logs) ? row.logs.map(String) : [],
    error: String(row.error || ''),
  }
}

function businessChildNvBatchStatusLabel(status: BusinessChildNvBatchItem['status']): string {
  return { pending: '排队中', running: '上架中', success: '上架成功', failed: '上架失败', skipped: '已跳过' }[status]
}

const BUSINESS_CHILD_NV_SALES_STATUS_LABELS: Record<BusinessChildNvSalesStatus, string> = {
  refunded: 'NV 已退款',
  partial_refund: 'NV 部分退款',
  sold: '已出库',
  pending_sale: '待售',
  not_found: '远端未找到',
  needs_review: '需复核',
  invalid_local: '本地记录异常',
  skipped_changed: '状态已变化，已跳过',
}

function sanitizeBusinessChildNvSalesResult(value: unknown): BusinessChildNvSalesResult {
  const row = asRecord(value)
  const categoryCount = (value: unknown) => (
    typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null
  )
  const pendingSale = categoryCount(row.pending_sale)
  const notFound = categoryCount(row.not_found)
  const needsReview = categoryCount(row.needs_review)
  const legacyPending = categoryCount(row.legacy_pending)
  const legacyRecords = categoryCount(row.legacy_records)
  return {
    listed_checked: businessBatchCount(row.listed_checked),
    sold_found: businessBatchCount(row.sold_found),
    updated_refunded: businessBatchCount(row.updated_refunded),
    updated_partial_refund: businessBatchCount(row.updated_partial_refund),
    sold_updated: businessBatchCount(row.sold_updated ?? row.updated),
    deletion_ready: businessBatchCount(row.deletion_ready),
    pending_sale: pendingSale,
    not_found: notFound,
    needs_review: needsReview,
    invalid_local: businessBatchCount(row.invalid_local),
    skipped_changed: businessBatchCount(row.skipped_changed),
    classified: pendingSale !== null && notFound !== null && needsReview !== null && Array.isArray(row.details),
    legacy_pending: legacyPending,
    legacy_records: legacyRecords,
    legacy_classified: legacyPending !== null && legacyRecords !== null && Array.isArray(row.legacy_details),
    legacy_details: (Array.isArray(row.legacy_details) ? row.legacy_details : []).map((value) => {
      const item = asRecord(value)
      return {
        email: String(item.email || '').trim().toLowerCase(),
        membership_ids: (Array.isArray(item.membership_ids) ? item.membership_ids : [])
          .map(Number).filter((id) => Number.isInteger(id) && id > 0),
        record_count: businessBatchCount(item.record_count),
        reason: String(item.reason || ''),
      }
    }),
    details: (Array.isArray(row.details) ? row.details : []).map((value) => {
      const item = asRecord(value)
      const knownStatus = Object.prototype.hasOwnProperty.call(BUSINESS_CHILD_NV_SALES_STATUS_LABELS, String(item.status))
      return {
        membership_id: businessBatchCount(item.membership_id),
        email: String(item.email || ''),
        status: (knownStatus ? item.status : 'needs_review') as BusinessChildNvSalesStatus,
        reason: String(item.reason || (knownStatus ? '' : '返回了未知库存状态，请复核')),
      }
    }),
  }
}

function businessChildNvSalesSummary(result: BusinessChildNvSalesResult): string {
  const parts = [`检查 ${result.listed_checked} 条`, `已出库 ${result.sold_found} 条`]
  if (result.updated_refunded) parts.push(`NV 已退款 ${result.updated_refunded} 条`)
  if (result.updated_partial_refund) parts.push(`NV 部分退款 ${result.updated_partial_refund} 条`)
  if (result.classified) {
    parts.push(`待售 ${result.pending_sale} 条`, `远端未找到 ${result.not_found} 条`)
    if (result.needs_review) parts.push(`需复核 ${result.needs_review} 条`)
  } else {
    parts.push('库存分类未提供')
  }
  if (result.invalid_local) parts.push(`本地记录异常 ${result.invalid_local} 条`)
  if (result.skipped_changed) parts.push(`状态已变化，已跳过 ${result.skipped_changed} 条`)
  if (!result.legacy_classified) parts.push('NV 上架核验待升级')
  return parts.join(' · ')
}

function sanitizeBusinessBatchInvitation(value: unknown): BusinessBatchInvitationProgress {
  const row = asRecord(value)
  const status = String(row.status || 'pending').trim().toLowerCase()
  return {
    index: businessBatchCount(row.index),
    status,
    status_label: String(row.status_label || businessBatchStatusLabel(status)),
    pro_account_id: nonNegativeNumber(row.pro_account_id),
    email: String(row.email || ''),
    error: String(row.error || ''),
    started_at: String(row.started_at || ''),
    finished_at: String(row.finished_at || ''),
    steps: sanitizeBusinessBatchSteps(row.steps),
  }
}

function sanitizeBusinessBatchStep(value: unknown, fallbackLabel = ''): BusinessBatchActionStep {
  const row = asRecord(value)
  const status = String(row.status || 'pending').trim().toLowerCase()
  return {
    status,
    label: String(row.label || row.status_label || businessBatchStatusLabel(status) || fallbackLabel),
    error: String(row.error || ''),
    taskId: String(row.task_id || ''),
    startedAt: String(row.started_at || ''),
    finishedAt: String(row.finished_at || ''),
  }
}

function sanitizeBusinessBatchSteps(value: unknown): Record<string, BusinessBatchActionStep> {
  const row = asRecord(value)
  const labels: Record<string, string> = {
    prepare: '注册、密码与 2FA',
    invite: '邀请',
    security: '检查密码 / 2FA',
    setup_security: '设置密码与 2FA',
    rt: '获取 RT',
    oauth: '获取 RT',
    leave_workspace: '退出空间',
    remove: '退出空间',
  }
  return Object.fromEntries(Object.entries(row).map(([key, step]) => [
    key,
    sanitizeBusinessBatchStep(step, labels[key] || key),
  ]))
}

function sanitizeBusinessBatchMother(value: unknown): BusinessBatchMotherProgress {
  const row = asRecord(value)
  const status = String(row.status || 'pending').trim().toLowerCase()
  const invitations = Array.isArray(row.invitations)
    ? row.invitations.map(sanitizeBusinessBatchInvitation)
    : []
  const currentInviteRecord = asRecord(row.current_invite)
  const currentInviteNumber = Number(row.current_invite)
  const currentInvite = Object.keys(currentInviteRecord).length
    ? sanitizeBusinessBatchInvitation(currentInviteRecord)
    : Number.isInteger(currentInviteNumber) && currentInviteNumber > 0
      ? invitations.find((item) => item.index === currentInviteNumber)
        || invitations.find((item) => item.index === currentInviteNumber - 1)
        || null
      : invitations.find((item) => ['running', 'processing', 'inviting'].includes(item.status)) || null
  return {
    account_id: businessBatchCount(row.account_id),
    email: String(row.email || ''),
    status,
    status_label: String(row.status_label || businessBatchStatusLabel(status)),
    planned_invites: businessBatchCount(row.planned_invites),
    completed_invites: businessBatchCount(row.completed_invites),
    successful_invites: businessBatchCount(row.successful_invites),
    failed_invites: businessBatchCount(row.failed_invites),
    partial_invites: businessBatchCount(row.partial_invites),
    skipped_invites: businessBatchCount(row.skipped_invites),
    percent: businessBatchPercent(row.percent),
    current_invite: currentInvite,
    error: String(row.error || ''),
    invitations,
  }
}

function sanitizeBusinessBatchProgress(value: unknown): BusinessBatchInviteProgress {
  const row = asRecord(value)
  return {
    total_mothers: businessBatchCount(row.total_mothers),
    completed_mothers: businessBatchCount(row.completed_mothers),
    total_invites: businessBatchCount(row.total_invites),
    completed_invites: businessBatchCount(row.completed_invites),
    successful_invites: businessBatchCount(row.successful_invites),
    failed_invites: businessBatchCount(row.failed_invites),
    partial_invites: businessBatchCount(row.partial_invites),
    skipped_invites: businessBatchCount(row.skipped_invites),
    percent: businessBatchPercent(row.percent),
  }
}

function businessBatchStatusLabel(value: unknown): string {
  const status = String(value || '').trim().toLowerCase()
  return {
    pending: '等待处理',
    queued: '等待处理',
    running: '执行中',
    processing: '执行中',
    inviting: '正在邀请',
    done: '已完成',
    completed: '已完成',
    success: '邀请成功',
    succeeded: '邀请成功',
    partial: '部分完成',
    failed: '失败',
    error: '失败',
    skipped: '已跳过',
    not_requested: '未选择',
  }[status] || '等待处理'
}

function businessBatchStatusColor(value: unknown): string {
  const status = String(value || '').trim().toLowerCase()
  if (['done', 'completed', 'success', 'succeeded'].includes(status)) return 'success'
  if (['failed', 'error'].includes(status)) return 'error'
  if (status === 'partial') return 'warning'
  if (status === 'skipped') return 'default'
  if (['running', 'processing', 'inviting'].includes(status)) return 'processing'
  return 'default'
}

function businessBatchStepPresentation(key: string, step?: BusinessBatchActionStep): { label: string; color: string } {
  const status = step?.status || 'not_requested'
  // Only the server's successful credential check can report reusable security.
  // Other skipped steps (including a failed prerequisite) must stay neutral.
  const securityReady = key === 'security' && status === 'skipped' && !step?.error
    && ['已完成，跳过设置', '2FA 已完成'].includes(step?.label || '')
  return {
    label: status === 'not_requested' ? '未选择'
      : securityReady ? '已完成，跳过设置'
        : step?.label || businessBatchStatusLabel(status),
    color: securityReady ? 'success' : businessBatchStatusColor(status),
  }
}

function businessInviteMailProviderLabel(value: BusinessInviteMailProvider): string {
  return BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS.find((option) => option.value === value)?.label
    || BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS[0].label
}

function mergeBusinessBatchInviteTask(
  previous: BusinessBatchInviteTask | null,
  value: unknown,
  fallbackTaskId = '',
): BusinessBatchInviteTask {
  const row = asRecord(value)
  const taskId = String(row.task_id || previous?.taskId || fallbackTaskId).trim()
  const incomingLogs = Array.isArray(row.logs) ? row.logs.map((line) => String(line)) : []
  const hasProgress = Object.keys(asRecord(row.progress)).length > 0
  const incomingMothers = Array.isArray(row.mothers)
    ? row.mothers.map(sanitizeBusinessBatchMother)
    : null
  const hasCurrentAccountId = Object.prototype.hasOwnProperty.call(row, 'current_account_id')
  const hasCurrentAccountEmail = Object.prototype.hasOwnProperty.call(row, 'current_account_email')
  return {
    taskId,
    status: String(row.status || previous?.status || 'running').trim().toLowerCase(),
    outcome: String(row.outcome || previous?.outcome || ''),
    hasFailures: row.has_failures === true || Boolean(previous?.hasFailures),
    candidateMailProvider: normalizeBusinessInviteMailProvider(
      Object.prototype.hasOwnProperty.call(row, 'candidate_mail_provider')
        ? row.candidate_mail_provider
        : previous?.candidateMailProvider,
    ),
    workflow: String(row.workflow || previous?.workflow || 'sequential'),
    phase: String(row.phase || previous?.phase || ''),
    attempts: Number.isFinite(Number(row.attempts))
      ? Math.max(0, Number(row.attempts))
      : previous?.attempts || 0,
    nextRetryAt: String(row.next_retry_at || previous?.nextRetryAt || ''),
    seatType: normalizeBusinessSeatType(row.seat_type || previous?.seatType),
    postSetupSecurity: Object.prototype.hasOwnProperty.call(row, 'post_setup_security')
      ? row.post_setup_security === true
      : previous?.postSetupSecurity ?? false,
    postAcquireRt: Object.prototype.hasOwnProperty.call(row, 'post_acquire_rt')
      ? row.post_acquire_rt === true
      : previous?.postAcquireRt ?? false,
    securityBrowserMode: String(row.security_browser_mode || previous?.securityBrowserMode || 'headless') === 'headed'
      ? 'headed'
      : 'headless',
    currentAccountId: hasCurrentAccountId
      ? nonNegativeNumber(row.current_account_id)
      : previous?.currentAccountId ?? null,
    currentAccountEmail: hasCurrentAccountEmail
      ? String(row.current_account_email || '')
      : String(previous?.currentAccountEmail || ''),
    progress: hasProgress
      ? sanitizeBusinessBatchProgress(row.progress)
      : previous?.progress || sanitizeBusinessBatchProgress({}),
    mothers: incomingMothers ?? previous?.mothers ?? [],
    logs: [...(previous?.logs || []), ...incomingLogs],
    since: Number.isFinite(Number(row.since)) ? Math.max(0, Number(row.since)) : previous?.since || 0,
    error: String(row.error || previous?.error || ''),
    startedAt: String(row.started_at || previous?.startedAt || ''),
    finishedAt: String(row.finished_at || previous?.finishedAt || ''),
    pollingError: '',
  }
}

function sanitizeBusinessChildBatchItem(value: unknown): BusinessChildBatchActionItem {
  const row = asRecord(value)
  const status = String(row.status || 'pending').trim().toLowerCase()
  const steps = sanitizeBusinessBatchSteps(row.steps)
  const legacyStep = String(row.step || '').trim()
  if (!Object.keys(steps).length && legacyStep) {
    steps.current = {
      status,
      label: legacyStep,
      error: String(row.error || ''),
    }
  }
  return {
    membershipId: businessBatchCount(row.membership_id),
    parentAccountId: businessBatchCount(row.parent_account_id),
    childId: nonNegativeNumber(row.child_id),
    email: String(row.email || row.child_email || ''),
    status,
    statusLabel: String(row.status_label || (['success', 'succeeded'].includes(status)
      ? '处理成功'
      : businessBatchStatusLabel(status))),
    steps,
    logs: Array.isArray(row.logs) ? row.logs.map((line) => String(line)) : [],
    error: String(row.error || ''),
  }
}

function normalizeBusinessChildBatchAction(
  value: unknown,
  fallback: BusinessChildBatchAction = 'setup_security',
): BusinessChildBatchAction {
  const action = String(value || '').trim().toLowerCase()
  return ['setup_security', 'oauth', 'leave_workspace'].includes(action)
    ? action as BusinessChildBatchAction : fallback
}

function businessChildBatchActionLabel(action: BusinessChildBatchAction): string {
  return { setup_security: '设置密码与 2FA', oauth: '获取 RT', leave_workspace: '退出空间' }[action]
}

function mergeBusinessChildBatchActionTask(
  previous: BusinessChildBatchActionTask | null,
  value: unknown,
  fallbackTaskId = '',
  fallbackAction: BusinessChildBatchAction = 'setup_security',
): BusinessChildBatchActionTask {
  const row = asRecord(value)
  const progress = asRecord(row.progress)
  const incomingLogs = Array.isArray(row.logs) ? row.logs.map((line) => String(line)) : []
  return {
    taskId: String(row.task_id || previous?.taskId || fallbackTaskId).trim(),
    action: normalizeBusinessChildBatchAction(row.action, previous?.action || fallbackAction),
    browserMode: String(row.browser_mode || previous?.browserMode || 'headless').trim().toLowerCase() === 'headed'
      ? 'headed'
      : 'headless',
    status: String(row.status || previous?.status || 'running').trim().toLowerCase(),
    outcome: String(row.outcome || previous?.outcome || ''),
    attempts: Number.isFinite(Number(row.attempts))
      ? Math.max(0, Number(row.attempts))
      : previous?.attempts || 0,
    nextRetryAt: String(row.next_retry_at || previous?.nextRetryAt || ''),
    progress: Object.keys(progress).length ? {
      total: businessBatchCount(progress.total),
      completed: businessBatchCount(progress.completed),
      success: businessBatchCount(progress.success ?? progress.successful),
      failed: businessBatchCount(progress.failed),
      skipped: businessBatchCount(progress.skipped),
      percent: businessBatchPercent(progress.percent),
    } : previous?.progress || {
      total: 0,
      completed: 0,
      success: 0,
      failed: 0,
      skipped: 0,
      percent: 0,
    },
    items: Array.isArray(row.items)
      ? row.items.map(sanitizeBusinessChildBatchItem)
      : previous?.items || [],
    logs: [...(previous?.logs || []), ...incomingLogs],
    since: Number.isFinite(Number(row.since)) ? Math.max(0, Number(row.since)) : previous?.since || 0,
    error: String(row.error || previous?.error || ''),
    pollingError: '',
  }
}

function memberSourceOf(account: GptPlanAccount, override?: MemberSource | null): MemberSource | null {
  const sourcePool = String(account.source_pool || '').trim()
  const listed = account.member_source && typeof account.member_source === 'object'
    ? account.member_source
    : sourcePool
      ? {
          source_pool: sourcePool,
          source_account_id: account.source_account_id,
          source_missing: account.source_missing,
          source_error: account.source_error,
          has_codex_rt: account.has_codex_rt,
          codex_refresh_token_len: account.codex_refresh_token_len,
          codex_rt_acquired_at: account.codex_rt_acquired_at || account.codex_rt_updated_at,
          refund_status: account.refund_status,
          human_review_requested_at: account.human_review_requested_at,
          invite_cooldown: account.invite_cooldown,
          invite_cooldown_active: account.invite_cooldown_active,
          invite_cooldown_started_at: account.invite_cooldown_started_at,
          invite_cooldown_until: account.invite_cooldown_until,
          invite_cooldown_reason: account.invite_cooldown_reason,
          invite_quota: account.invite_quota,
          policy_warning: account.policy_warning,
          policy_warning_detected_at: account.policy_warning_detected_at,
          dangerous: account.dangerous || account.dead,
          dangerous_detected_at: account.dangerous_detected_at,
          replenishment: account.replenishment,
          capabilities: account.member_capabilities || account.capabilities || null,
        }
      : null
  if (!override || typeof override !== 'object') return listed
  if (!listed) return override

  const merged: MemberSource = { ...listed, ...override }
  // 设备绑定来自 GptBusinessAutomationPolicy，是跨页面共享的数据库事实。
  // 能力/席位弹窗留下的内存 override 不能遮住列表刚读取到的新绑定（包括 null）。
  if (Object.prototype.hasOwnProperty.call(listed, 'business_device_binding')) {
    merged.business_device_binding = listed.business_device_binding ?? null
  }
  for (const key of [
    'invite_cooldown',
    'invite_cooldown_active',
    'invite_cooldown_started_at',
    'invite_cooldown_until',
    'invite_cooldown_reason',
  ] as const) {
    if (Object.prototype.hasOwnProperty.call(listed, key)) {
      merged[key] = listed[key] as never
    }
  }
  return merged
}

function memberCapabilityOf(
  account: GptPlanAccount,
  source: MemberSource | null,
  name: MemberCapabilityName,
): MemberCapability {
  const businessMother = String(source?.source_pool || account.source_pool || '')
    .trim()
    .toLowerCase() === 'gpt_business'
  // 非 BUSINESS 会员只认套餐管理账号自身的能力快照。source 仅作为旧响应的
  // 套餐目录是账号能力的唯一来源，不依赖任何旧账号页面或旧账号表。
  const containers = businessMother
    ? [source?.capabilities, account.member_capabilities, account.capabilities]
    : [account.member_capabilities, account.capabilities, source?.capabilities]
  for (const container of containers) {
    const raw = container?.[name]
    if (typeof raw === 'boolean') return { supported: raw }
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw as MemberCapability
  }
  return { supported: false, reason: '账号能力尚未读取，请打开账号操作菜单后重试' }
}

function nonNegativeNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') return null
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null
}

function positiveInteger(value: unknown): number | null {
  const parsed = nonNegativeNumber(value)
  return parsed !== null && Number.isInteger(parsed) && parsed > 0 ? parsed : null
}

function planFocusTargetFromSearch(params: URLSearchParams): GptPlanFocusTarget | null {
  const planAccountId = positiveInteger(params.get('focus_account_id'))
  if (!planAccountId) return null
  const rawAccountType = String(params.get('account_type') || '').trim().toLowerCase()
  const accountType: AccountType = ['regular', 'member', 'refunded'].includes(rawAccountType)
    ? rawAccountType as AccountType
    : 'member'
  const requestedMemberPlan = String(params.get('member_plan') || '').trim().toLowerCase()
  const childAccountId = positiveInteger(params.get('focus_child_account_id'))
  const membershipId = positiveInteger(params.get('focus_membership_id'))
  const memberPlan = accountType === 'member'
    ? requestedMemberPlan === 'team' || childAccountId || membershipId
      ? 'team'
      : requestedMemberPlan === 'go' || requestedMemberPlan === 'plus'
        ? requestedMemberPlan
        : 'pro'
    : undefined
  return {
    planAccountId,
    accountType,
    memberPlan,
    childAccountId,
    membershipId,
  }
}

const PLAN_FOCUS_QUERY_KEYS = [
  'account_type',
  'member_plan',
  'focus_account_id',
  'focus_child_account_id',
  'focus_membership_id',
] as const

function normalizeBusinessSeatType(value: unknown): BusinessSeatType | undefined {
  const normalized = String(value || '').trim().toLowerCase().replace(/[_\s-]+/g, '')
  if (['default', 'standard', 'normal'].includes(normalized)) return 'default'
  if (['prolite', 'advanced'].includes(normalized)) return 'prolite'
  return undefined
}

function businessChildSeatType(value: BusinessManagedChild | BusinessReplaceableChild): BusinessSeatType | undefined {
  const row = value as Record<string, unknown>
  const membership = asRecord(row.membership)
  const invite = asRecord(row.invite)
  return normalizeBusinessSeatType(
    row.seat_type
    ?? row.seatType
    ?? row.assigned_seat_type
    ?? row.workspace_seat_type
    ?? membership.seat_type
    ?? invite.seat_type,
  )
}

function businessChildNvWarrantyUntil(value: string, now = Date.now()): string | null {
  // datetime-local is deliberately interpreted as Beijing time, independent of the browser's timezone.
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value)) return null
  const timestamp = Date.parse(`${value}+08:00`)
  if (!Number.isFinite(timestamp) || timestamp <= now) return null
  const roundTrip = new Date(timestamp + 8 * 3600000).toISOString().slice(0, value.length)
  return roundTrip === value ? new Date(timestamp).toISOString() : null
}

function BusinessChildNvWarrantyInput({ value, disabled, onChange }: {
  value: string; disabled: boolean; onChange: (value: string) => void
}) {
  return <div>
    <Typography.Text strong>5X 质保截止（北京时间）</Typography.Text>
    <Input type="datetime-local" step={1} aria-label="5X 质保截止（北京时间）" value={value} disabled={disabled}
      style={{ width: '100%', marginTop: 6 }} onChange={event => onChange(event.target.value)} />
    <Typography.Text type="secondary" style={{ display: 'block', marginTop: 6, fontSize: 12 }}>
      5X 请指定未来截止时间；普通 TEAM 仍为质保首登 1 小时。
    </Typography.Text>
  </div>
}

function businessSeatTypeLabel(value: unknown): string {
  const seatType = normalizeBusinessSeatType(value)
  if (seatType === 'prolite') return '高级席位'
  if (seatType === 'default') return '普通席位'
  return '席位类型未知'
}

function businessOperationId(): string {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID()
    }
  } catch {
    // Older embedded browsers do not expose crypto.randomUUID.
  }
  return `plans-business-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function sanitizeBusinessChildCpaDeviceLink(value: unknown): BusinessChildCpaDeviceLink | null {
  const row = asRecord(value)
  const targetId = positiveInteger(row.target_id)
  if (!targetId) return null
  return {
    target_id: targetId,
    name: String(row.name || '').slice(0, 160),
    synced_at: String(row.synced_at || ''),
  }
}

function sanitizeBusinessChildSub2ApiDeviceLink(value: unknown): BusinessChildSub2ApiDeviceLink | null {
  const row = asRecord(value)
  const deviceId = positiveInteger(row.device_id)
  if (!deviceId) return null
  return {
    device_id: deviceId,
    name: String(row.name || '').slice(0, 160),
    synced_at: String(row.synced_at || ''),
  }
}

function sanitizeChatGptSecurityState(value: unknown): ChatGptSecurityState | null {
  const row = asRecord(value)
  if (!Object.keys(row).length) return null
  return {
    password_state: String(row.password_state || ''),
    mfa_state: String(row.mfa_state || ''),
    has_password: row.has_password === true,
    has_totp: row.has_totp === true,
    credentials_readable: row.credentials_readable !== false,
    last_error: String(row.last_error || ''),
    password_updated_at: String(row.password_updated_at || ''),
    mfa_updated_at: String(row.mfa_updated_at || ''),
    updated_at: String(row.updated_at || ''),
  }
}

function sanitizeBusinessChild(value: unknown): BusinessManagedChild | null {
  const row = asRecord(value)
  if (!Object.keys(row).length) return null
  const monitor = asRecord(row.mail_monitor)
  const cpa = asRecord(row.cpa)
  const sub2api = asRecord(row.sub2api)
  const monitorEnabled = row.monitor_enabled ?? monitor.monitor_enabled ?? monitor.enabled
  return {
    membership_id: nonNegativeNumber(row.membership_id),
    pro_account_id: nonNegativeNumber(row.pro_account_id ?? row.managed_pro_account_id),
    managed_pro_account_id: nonNegativeNumber(row.managed_pro_account_id),
    email: String(row.email || ''),
    source: String(row.source || ''),
    candidate_source: row.candidate_source === 'prepared' || row.candidate_source === 'regular'
      ? row.candidate_source : undefined,
    prepared: typeof row.prepared === 'boolean' ? row.prepared : undefined,
    status: String(row.status || ''),
    role: String(row.role || ''),
    user_id: String(row.user_id || ''),
    invite_id: String(row.invite_id || ''),
    mail_provider: String(row.mail_provider || ''),
    mail_access_type: String(row.mail_access_type || ''),
    has_password: row.has_password === true,
    has_mail_oauth: row.has_mail_oauth === true,
    has_mail_credentials: row.has_mail_credentials === true,
    has_cookie: row.has_cookie === true,
    has_saved_login: row.has_saved_login === true,
    cookie_valid: row.cookie_valid === null
      ? null
      : row.cookie_valid === undefined ? undefined : row.cookie_valid === true,
    cookie_updated_at: String(row.cookie_updated_at || ''),
    cookie_expires_at: String(row.cookie_expires_at || ''),
    login_status: String(row.login_status || ''),
    can_chatgpt_login: row.can_chatgpt_login === true,
    chatgpt_login_disabled_reason: String(row.chatgpt_login_disabled_reason || ''),
    can_setup_chatgpt_security: row.can_setup_chatgpt_security === true,
    chatgpt_security_setup_disabled_reason: String(row.chatgpt_security_setup_disabled_reason || ''),
    chatgpt_security_setup_recovery_hint: String(row.chatgpt_security_setup_recovery_hint || ''),
    can_review_chatgpt_login: row.can_review_chatgpt_login === true,
    chatgpt_login_review_disabled_reason: String(row.chatgpt_login_review_disabled_reason || ''),
    can_fetch_mail: row.can_fetch_mail === true,
    fetch_mail_disabled_reason: String(row.fetch_mail_disabled_reason || ''),
    chatgpt_oauth_credentials_ready: row.chatgpt_oauth_credentials_ready === true,
    chatgpt_oauth_disabled_reason: String(row.chatgpt_oauth_disabled_reason || ''),
    has_codex_rt: row.has_codex_rt === true,
    rt_supported: row.rt_supported === true,
    can_get_rt: row.can_get_rt === true,
    enabled: row.enabled !== false,
    dangerous: row.dangerous === true,
    dangerous_detected_at: String(row.dangerous_detected_at || ''),
    policy_warning: row.policy_warning === true,
    policy_warning_detected_at: String(row.policy_warning_detected_at || ''),
    refund_status: String(row.refund_status || ''),
    monitor_enabled: monitorEnabled === undefined ? undefined : monitorEnabled === true,
    last_mail_check_at: String(
      row.last_mail_check_at || monitor.last_mail_check_at || monitor.last_check_at || '',
    ),
    last_mail_check_error: String(
      row.last_mail_check_error || monitor.last_mail_check_error || monitor.last_error || '',
    ),
    pending_alerts_count: nonNegativeNumber(
      row.pending_alerts_count ?? row.unread_count
      ?? monitor.pending_alerts_count ?? monitor.unread_count,
    ) ?? 0,
    pending_inbox_count: nonNegativeNumber(
      row.pending_inbox_count ?? row.inbox_unread_count
      ?? monitor.pending_inbox_count ?? monitor.inbox_unread_count,
    ) ?? 0,
    codex_rt_acquired_at: String(row.codex_rt_acquired_at || ''),
    sale_status: String(row.sale_status || '').trim().toLowerCase() === 'refunded' ? 'refunded'
      : String(row.sale_status || '').trim().toLowerCase() === 'partial_refund' ? 'partial_refund'
      : String(row.sale_status || '').trim().toLowerCase() === 'sold'
      || (!['unlisted', 'listed', 'sold'].includes(String(row.sale_status || '').trim().toLowerCase()) && Boolean(row.sold_at))
      ? 'sold'
      : String(row.sale_status || '').trim().toLowerCase() === 'listed' ? 'listed' : 'unlisted',
    sold_at: row.sold_at == null ? null : String(row.sold_at || ''),
    warranty_hours: nonNegativeNumber(row.warranty_hours) ?? 0,
    nv_team5x_warranty_until: String(row.nv_team5x_warranty_until || ''),
    deletion_ready: row.deletion_ready === true || row.can_delete === true,
    can_delete: row.can_delete === true || row.deletion_ready === true,
    nv_listed_at: String(row.nv_listed_at || ''),
    nv_listing_confirmed_at: String(row.nv_listing_confirmed_at || ''),
    nv_last_synced_at: String(row.nv_last_synced_at || ''),
    business_invited_at: String(row.business_invited_at || row.invited_at || ''),
    deactivated: row.deactivated === true || row.enabled === false || row.dangerous === true,
    cpa_synced_to: sanitizeBusinessChildCpaDeviceLink(
      row.cpa_synced_to ?? cpa.cpa_synced_to ?? cpa.synced_to,
    ),
    sub2api_synced_to: sanitizeBusinessChildSub2ApiDeviceLink(
      row.sub2api_synced_to ?? sub2api.sub2api_synced_to ?? sub2api.synced_to,
    ),
    chatgpt_security: sanitizeChatGptSecurityState(row.chatgpt_security),
    seat_type: String(
      row.seat_type || row.assigned_seat_type || row.workspace_seat_type || '',
    ),
  }
}

function businessInviteCandidateLabel(child: BusinessManagedChild): string {
  const source = child.candidate_source === 'prepared' && child.prepared === true ? '准备号'
    : child.candidate_source === 'regular' && child.prepared === false ? '普通号' : '来源待确认'
  return `${child.email} · ${source}${child.has_codex_rt ? ' · 已有 RT' : ''}`
}

function sanitizeBusinessChildCatalogRow(value: unknown): BusinessChildCatalogRow | null {
  const row = asRecord(value)
  if (!Object.keys(row).length) return null
  const capabilities = asRecord(row.account_capabilities)
  const child = sanitizeBusinessChild({
    ...capabilities,
    ...row,
    membership_id: row.membership_id,
    pro_account_id: row.pro_account_id ?? row.child_id,
    managed_pro_account_id: row.pro_account_id ?? row.child_id,
    email: row.child_email || row.email,
    status: row.membership_status || row.status,
    role: row.role || 'standard-user',
    business_invited_at: row.invited_at || row.business_invited_at,
  })
  const parentAccountId = positiveInteger(row.parent_account_id)
  const membershipId = positiveInteger(row.membership_id)
  if (!child || !parentAccountId || !membershipId) return null
  const status = String(row.membership_status || row.status || '').trim().toLowerCase()
  const kind: BusinessChildDisplayRow['_kind'] = status === 'pending' || status === 'invite'
    ? 'invite'
    : status === 'member' || status === 'active' ? 'member' : 'local'
  return {
    ...child,
    membership_id: membershipId,
    child_id: positiveInteger(row.child_id ?? row.pro_account_id),
    child_name: String(row.child_name || ''),
    child_email: String(row.child_email || row.email || ''),
    parent_account_id: parentAccountId,
    parent_email: String(row.parent_email || ''),
    parent_note: String(row.parent_note || ''),
    membership_status: status,
    invited_at: String(row.invited_at || ''),
    sale_status: String(row.sale_status || '').trim().toLowerCase() === 'refunded' ? 'refunded'
      : String(row.sale_status || '').trim().toLowerCase() === 'partial_refund' ? 'partial_refund'
      : String(row.sale_status || '').trim().toLowerCase() === 'sold'
      || (!['unlisted', 'listed', 'sold'].includes(String(row.sale_status || '').trim().toLowerCase()) && Boolean(row.sold_at))
      ? 'sold'
      : String(row.sale_status || '').trim().toLowerCase() === 'listed' ? 'listed' : 'unlisted',
    sold_at: row.sold_at == null ? null : String(row.sold_at || ''),
    warranty_hours: nonNegativeNumber(row.warranty_hours) ?? 0,
    warranty_expires_at: row.warranty_expires_at == null
      ? null
      : String(row.warranty_expires_at || ''),
    warranty_status: String(row.warranty_status || ''),
    deletion_ready: row.deletion_ready === true || row.can_delete === true,
    can_delete: row.can_delete === true || row.deletion_ready === true,
    nv_last_synced_at: String(row.nv_last_synced_at || ''),
    actions: asRecord(row.actions) as Record<string, MemberCapability | boolean | undefined>,
    _kind: kind,
    _managed: row.managed === true || Boolean(positiveInteger(row.child_id ?? row.pro_account_id)),
  }
}

function sanitizeBusinessReplaceableChild(value: unknown): BusinessReplaceableChild | null {
  const row = asRecord(value)
  if (!Object.keys(row).length) return null
  const kind = String(row.old_kind || row.kind || (row.user_id ? 'member' : 'invite'))
  return {
    key: String(row.key || ''),
    membership_id: nonNegativeNumber(row.membership_id),
    kind: kind === 'member' ? 'member' : 'invite',
    old_kind: kind === 'member' ? 'member' : 'invite',
    email: String(row.email || ''),
    user_id: String(row.user_id || ''),
    invite_id: String(row.invite_id || ''),
    pro_account_id: nonNegativeNumber(row.pro_account_id),
    managed_pro_account_id: nonNegativeNumber(row.managed_pro_account_id),
    seat_type: String(row.seat_type || ''),
  }
}

function sanitizeBusinessVacancyPolicy(value: unknown): BusinessVacancyPolicy | null {
  const row = asRecord(value)
  if (!Object.keys(row).length) return null
  const nullableCount = (key: string): number | null | undefined => {
    if (row[key] === null) return null
    return nonNegativeNumber(row[key]) ?? undefined
  }
  const nullableTime = (key: string): string | null | undefined => {
    if (row[key] === null) return null
    const text = String(row[key] || '').trim()
    return text || undefined
  }
  return {
    policy_present: row.policy_present === true,
    http_status: nullableCount('http_status'),
    free_vacancy_threshold: nullableCount('free_vacancy_threshold'),
    vacancy_ordinal: nullableCount('vacancy_ordinal'),
    billing_starts_at: nullableTime('billing_starts_at'),
    expires_at: nullableTime('expires_at'),
    captured_at: nullableTime('captured_at'),
  }
}

function sanitizeBusinessChildrenSnapshot(value: unknown): BusinessChildrenSnapshot {
  const root = asRecord(value)
  const nested = asRecord(
    root.business_children || root.workspace_snapshot || root.snapshot || root.data,
  )
  const source = Object.keys(nested).length ? nested : root
  const rows = (key: string) => Array.isArray(source[key]) ? source[key] as unknown[] : []
  const seat = asRecord(source.seat_summary)
  const quota = asRecord(source.invite_quota)
  const rotationQuota = asRecord(source.rotation_quota)
  const inviteCooldown = asRecord(source.invite_cooldown)
  return {
    team_id: String(source.team_id || ''),
    plan: String(source.plan || source.team_plan || ''),
    members: rows('members').map(sanitizeBusinessChild).filter((row): row is BusinessManagedChild => Boolean(row)),
    invites: rows('invites').map(sanitizeBusinessChild).filter((row): row is BusinessManagedChild => Boolean(row)),
    managed_children: rows('managed_children').map(sanitizeBusinessChild).filter((row): row is BusinessManagedChild => Boolean(row)),
    replaceable_children: rows('replaceable_children')
      .map(sanitizeBusinessReplaceableChild)
      .filter((row): row is BusinessReplaceableChild => Boolean(row)),
    seat_summary: Object.keys(seat).length ? seat as BusinessSeatSummary : null,
    invite_quota: Object.keys(quota).length ? quota as BusinessInviteQuota : null,
    rotation_quota: Object.keys(rotationQuota).length
      ? rotationQuota as BusinessRotationQuota
      : null,
    invite_cooldown: Object.keys(inviteCooldown).length
      ? inviteCooldown as BusinessInviteCooldown
      : null,
    vacancy_policy: sanitizeBusinessVacancyPolicy(source.vacancy_policy),
    invite_candidate_count: nonNegativeNumber(
      source.invite_candidate_count
      ?? source.candidate_count
      ?? root.invite_candidate_count
      ?? root.candidate_count,
    ),
    workspace_checked_at: String(source.workspace_checked_at || source.checked_at || ''),
    checked_at: String(source.checked_at || ''),
  }
}

function businessChildMatchesFocus(
  row: BusinessManagedChild | BusinessChildDisplayRow,
  target: GptPlanFocusTarget | null,
): boolean {
  if (!target || (!target.childAccountId && !target.membershipId)) return false
  const rowChildId = positiveInteger(row.pro_account_id ?? row.managed_pro_account_id)
  const rowMembershipId = positiveInteger(row.membership_id)
  return Boolean(
    (target.childAccountId && rowChildId === target.childAccountId)
    || (target.membershipId && rowMembershipId === target.membershipId),
  )
}

function businessSnapshotHasFocusedChild(
  snapshot: BusinessChildrenSnapshot,
  target: GptPlanFocusTarget,
): boolean {
  return [
    ...(snapshot.members || []),
    ...(snapshot.invites || []),
    ...(snapshot.managed_children || []),
  ].some((row) => businessChildMatchesFocus(row, target))
}

function businessSeatCapacity(
  seat: BusinessSeatSummary | null | undefined,
  seatType: BusinessSeatType,
): BusinessSeatTypeCapacity {
  if (!seat) return { used: null, total: null, available: null, known: false }
  const row = seat.by_type?.[seatType]
    ?? seat.seat_types?.[seatType]
    ?? seat.capacity_by_type?.[seatType]
    ?? seat.seat_type_summary?.[seatType]
    ?? {}
  const used = nonNegativeNumber(row?.used ?? seat.used_by_type?.[seatType])
  const total = nonNegativeNumber(row?.total ?? seat.total_by_type?.[seatType])
  const reportedAvailable = nonNegativeNumber(row?.available ?? seat.available_by_type?.[seatType])
  const available = reportedAvailable ?? (
    total !== null && used !== null ? Math.max(0, total - used) : null
  )
  const explicitKnown = row?.known ?? row?.availability_exact
  const known = total !== null && available !== null && (
    explicitKnown === true
    || (explicitKnown !== false && seat.seat_type_capacity_known === true)
  )
  return { used, total, available, known, can_invite: row?.can_invite === true }
}

function businessSeatAvailable(
  seat: BusinessSeatSummary | null | undefined,
  capacity: BusinessSeatTypeCapacity,
): number | null {
  if (capacity.known) return capacity.available
  if (seat?.known && nonNegativeNumber(seat.available) === 0) return 0
  return null
}

function hasBusinessAdvancedSeat(
  seat: BusinessSeatSummary | null | undefined,
  capacity = businessSeatCapacity(seat, 'prolite'),
): boolean {
  if (!seat) return false
  const declaredSeatTypes = [
    ...(Array.isArray(seat.invitable_seat_types) ? seat.invitable_seat_types : []),
    ...(Array.isArray(seat.requestable_seat_types) ? seat.requestable_seat_types : []),
  ]
  const explicitlyInvitable = declaredSeatTypes
    .some((value) => normalizeBusinessSeatType(value) === 'prolite')
  return Number(capacity.used || 0) > 0
    || normalizeBusinessSeatType(seat.owner_seat_type) === 'prolite'
    || (capacity.known && Number(capacity.total || 0) > 0)
    || explicitlyInvitable
}

function nestedMemberSourceRecord(source: MemberSource | null, key: string): Record<string, unknown> {
  if (!source) return {}
  const direct = asRecord(source[key])
  if (Object.keys(direct).length) return direct
  for (const containerKey of ['business_workspace', 'business', 'workspace_snapshot', 'allocation_capability']) {
    const container = asRecord(source[containerKey])
    const nested = asRecord(container[key])
    if (Object.keys(nested).length) return nested
  }
  return {}
}

function businessSeatSummaryOf(source: MemberSource | null): BusinessSeatSummary | null {
  if (!source) return null
  if (source.business_workspace?.seat_summary && typeof source.business_workspace.seat_summary === 'object') {
    return source.business_workspace.seat_summary
  }
  if (source.seat_summary && typeof source.seat_summary === 'object') return source.seat_summary
  const value = nestedMemberSourceRecord(source, 'seat_summary')
  return Object.keys(value).length ? value as BusinessSeatSummary : null
}

function businessWorkspaceOf(source: MemberSource | null): BusinessWorkspaceCapability | null {
  if (!source) return null
  if (source.business_workspace && typeof source.business_workspace === 'object') return source.business_workspace
  const legacy = asRecord(source.business)
  return Object.keys(legacy).length ? legacy as BusinessWorkspaceCapability : null
}

function safeBusinessPaymentError(value: unknown): string {
  // Never echo a provider response: even an error string can contain billing
  // details, credentials, or a URL with a client secret.
  if (typeof value !== 'string') return '暂时无法读取默认支付方式，请稍后重试'
  const safeReasons = new Set([
    '远端未返回明确的默认支付方式',
    '默认支付方式详情不完整，请稍后重试',
    '默认支付方式读取失败（HTTP 401），请检查会话或重新登录母号',
    '暂无权限读取默认支付方式（HTTP 403）',
    '默认支付方式读取超时，请稍后重试',
    '默认支付方式读取失败，请稍后重试',
    '读取超时，请稍后重试',
    '会话不可用，请重新登录后重试',
    '暂无权限读取默认支付方式',
    '暂时无法读取默认支付方式，请稍后重试',
  ])
  if (safeReasons.has(value)) return value
  const hint = value.slice(0, 240)
  if (/timeout|timed out|超时/i.test(hint)) return '读取超时，请稍后重试'
  if (/\b401\b|unauthorized|未认证|重新登录/i.test(hint)) return '会话不可用，请重新登录后重试'
  if (/\b403\b|forbidden|权限不足|暂无权限/i.test(hint)) return '暂无权限读取默认支付方式'
  return '暂时无法读取默认支付方式，请稍后重试'
}

function sanitizeBusinessDefaultPaymentMethod(value: unknown): BusinessDefaultPaymentMethod {
  const row = asRecord(value)
  const requestedStatus = row.status === 'ready' || row.status === 'none' || row.status === 'error'
    ? row.status : 'unknown'
  const paymentType = typeof row.type === 'string' && /^[a-z][a-z0-9_]{0,39}$/.test(row.type)
    ? row.type : ''
  const status = requestedStatus === 'ready' && !paymentType ? 'unknown' : requestedStatus
  const brand = typeof row.brand === 'string' && /^(visa|mastercard|amex|american_express|discover|diners|diners_club|jcb|unionpay|union_pay|cartes_bancaires|eftpos)$/.test(row.brand.toLowerCase())
    ? row.brand.toLowerCase() : ''
  const checkedAt = typeof row.checked_at === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$/.test(row.checked_at)
    && Number.isFinite(Date.parse(row.checked_at)) ? new Date(row.checked_at).toISOString() : ''
  return {
    status,
    type: status === 'ready' ? paymentType : '',
    brand: status === 'ready' && paymentType === 'card' ? brand : '',
    last4: status === 'ready' && typeof row.last4 === 'string' && /^\d{4}$/.test(row.last4) ? row.last4 : '',
    checked_at: checkedAt,
    error: status === 'error' || (status === 'unknown' && typeof row.error === 'string' && row.error.length > 0)
      ? safeBusinessPaymentError(row.error)
      : requestedStatus === 'ready' && !paymentType ? '默认支付方式详情不完整，请稍后重试' : '',
  }
}

function businessDefaultPaymentMethodLabel(method: BusinessDefaultPaymentMethod): string {
  if (method.status === 'unknown') return method.checked_at ? '未确认' : '未查询'
  if (method.status === 'none') return '未设置'
  if (method.status === 'error') return '读取失败'
  const brands: Record<string, string> = {
    visa: 'Visa', mastercard: 'Mastercard', amex: 'Amex', american_express: 'Amex',
    discover: 'Discover', diners: 'Diners Club', diners_club: 'Diners Club', jcb: 'JCB',
    unionpay: '银联', union_pay: '银联', cartes_bancaires: 'Cartes Bancaires', eftpos: 'Eftpos',
  }
  const types: Record<string, string> = {
    card: '银行卡', paypal: '贝宝', alipay: '支付宝', wechat_pay: '微信支付',
    us_bank_account: '美国银行账户', sepa_debit: 'SEPA 直接扣款',
    bacs_debit: '英国银行扣款', au_becs_debit: '澳洲银行扣款',
    link: 'Link 支付', cashapp: 'Cash App 支付', customer_balance: '客户余额',
  }
  const label = method.type === 'card' ? brands[method.brand] || '银行卡'
    : Object.prototype.hasOwnProperty.call(types, method.type) ? types[method.type] : ''
  if (!label) return '支付方式'
  return method.last4 ? `${label} · ****${method.last4}` : label
}

function businessDefaultPaymentMethodOf(account: GptPlanAccount, source: MemberSource | null): BusinessDefaultPaymentMethod {
  // Only the current default snapshot is authoritative. Checkout history and
  // other payment-method lists are not evidence of the current default.
  const listed = sanitizeBusinessDefaultPaymentMethod(account.member_source?.business_workspace?.default_payment_method)
  const merged = sanitizeBusinessDefaultPaymentMethod(source?.business_workspace?.default_payment_method)
  if (!sameBusinessPaymentContext(account.member_source || null, source)) return listed
  // A stale capability override must not cover a newer payment result.
  return (Date.parse(listed.checked_at) || 0) > (Date.parse(merged.checked_at) || 0) ? listed : merged
}

function sameBusinessPaymentContext(left: MemberSource | null, right: MemberSource | null): boolean {
  const team = (source: MemberSource | null) => {
    const value = source?.business_workspace?.team_id
    return typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(value) ? value : ''
  }
  const sourceId = (source: MemberSource | null) => Number.isSafeInteger(source?.source_account_id)
    && Number(source?.source_account_id) > 0
    ? source?.source_account_id : null
  return Boolean(team(left) && team(left) === team(right)
    && sourceId(left) !== null && sourceId(left) === sourceId(right))
}

function mergeBusinessPaymentSource(
  previous: MemberSource | null,
  method: BusinessDefaultPaymentMethod,
  freshSource: MemberSource | null = null,
): MemberSource {
  // A new workspace needs its own source snapshot. On the same workspace,
  // preserve the latest seats/permissions rather than replaying response data.
  const base = freshSource && !sameBusinessPaymentContext(previous, freshSource) ? freshSource : previous
  return {
    ...base,
    business_workspace: {
      ...base?.business_workspace,
      default_payment_method: method,
    },
  }
}

function newestBusinessSessionHealth(
  current: BusinessSessionHealth | null | undefined,
  incoming: BusinessSessionHealth | null | undefined,
): BusinessSessionHealth | null {
  if (!incoming) return current || null
  if (!current) return incoming
  // 新登录写入的 Cookie 优先；同一份 Cookie 则采用最近一次检查。
  // 防止检查完成前发出的列表轮询把结果回滚到旧状态。
  for (const key of ['cookie_updated_at', 'checked_at', 'refreshed_at'] as const) {
    const currentTime = Date.parse(current[key]) || 0
    const incomingTime = Date.parse(incoming[key]) || 0
    if (currentTime !== incomingTime) return incomingTime > currentTime ? incoming : current
  }
  return incoming
}

function mergeBusinessSessionSource(
  previous: MemberSource | null,
  result: BusinessSessionCheckResult,
): MemberSource {
  const incoming = result.member_source || {}
  const workspace = incoming.business_workspace || {}
  return {
    ...previous,
    ...incoming,
    business_workspace: {
      ...previous?.business_workspace,
      ...workspace,
      session_health: result.session_health || workspace.session_health || previous?.business_workspace?.session_health || null,
    },
  }
}

function mergeBusinessSessionSnapshot(previous: MemberSource, incoming: MemberSource): MemberSource {
  const incomingWorkspace = incoming.business_workspace
  const incomingHealth = incomingWorkspace?.session_health
  if (!incomingWorkspace || !incomingHealth || newestBusinessSessionHealth(
    previous.business_workspace?.session_health, incomingHealth,
  ) !== incomingHealth) return previous
  const workspace: BusinessWorkspaceCapability = {
    ...previous.business_workspace,
    session_health: incomingHealth,
  }
  for (const key of ['team_session_usable', 'team_session_reason', 'team_id', 'team_plan'] as const) {
    if (Object.prototype.hasOwnProperty.call(incomingWorkspace, key)) {
      workspace[key] = incomingWorkspace[key] as never
    }
  }
  return {
    ...previous,
    business_workspace: workspace,
    // 健康状态与会话 gate 必须来自同一版快照；旧列表不能禁用刚恢复的母号。
    capabilities: Object.prototype.hasOwnProperty.call(incoming, 'capabilities')
      ? incoming.capabilities : previous.capabilities,
  }
}

function BusinessSessionStatus({
  health,
  checking,
  disabled,
  onCheck,
  compact = false,
}: {
  health?: BusinessSessionHealth | null
  checking: boolean
  disabled: boolean
  onCheck: () => void
  compact?: boolean
}) {
  const states = {
    valid: { color: 'success', label: '访问正常' },
    unchecked: { color: 'default', label: '未检查' },
    expired: { color: 'warning', label: 'AT 待刷新' },
    missing: { color: 'default', label: '缺少会话' },
    refreshing: { color: 'processing', label: '刷新中' },
    invalid: { color: 'error', label: '会话失效' },
    unauthorized: { color: 'error', label: '凭证被拒绝' },
    blocked: { color: 'warning', label: '访问受限' },
    error: { color: 'warning', label: '检查失败' },
    wrong_identity: { color: 'error', label: '身份不符' },
    busy: { color: 'processing', label: '会话占用' },
  }
  const status = health?.status || 'unchecked'
  const meta = Object.prototype.hasOwnProperty.call(states, status) ? states[status] : states.unchecked
  const expiryLabel = (value?: string) => value && Number.isFinite(Date.parse(value)) ? formatTime(value) : '未取得'
  return (
    <Space direction="vertical" size={1} data-business-session-health="true">
      <Space size={4}>
      <Tooltip title={(
        <div>
          <div>{health?.message || '尚未检查母号会话'}</div>
          <div>最近检查：{formatTime(health?.checked_at)}</div>
          <div>Cookie 更新：{formatTime(health?.cookie_updated_at)}</div>
          <div>AT 刷新：{formatTime(health?.refreshed_at)}</div>
          {health?.http_status != null && <div>HTTP：{health.http_status}</div>}
          {health?.can_refresh && <div>检查时可尝试通过现有会话刷新 AT</div>}
        </div>
      )}>
        <Tag color={checking ? 'processing' : meta.color} style={{ margin: 0 }}>
          {checking ? '检查中' : meta.label}
        </Tag>
      </Tooltip>
      {compact && (
        <Tooltip title="检查会话">
          <span>
            <Button type="text" size="small" icon={<ReloadOutlined />}
              aria-label="检查会话" loading={checking} disabled={disabled}
              style={{ width: 24, height: 24, color: 'inherit' }}
              onClick={(event) => { event.stopPropagation(); onCheck() }} />
          </span>
        </Tooltip>
      )}
      </Space>
      <Typography.Text type="secondary" style={{ fontSize: 11 }}>
        AT 到期：{expiryLabel(health?.access_token_expires_at)}
      </Typography.Text>
      <Typography.Text type="secondary" style={{ fontSize: 11 }}>
        会话到期：{expiryLabel(health?.session_expires_at)}
      </Typography.Text>
      {!compact && <Button
        type="link"
        size="small"
        icon={<ReloadOutlined />}
        loading={checking}
        disabled={disabled}
        style={{ height: 20, padding: '0 2px', fontSize: 11 }}
        onClick={(event) => {
          event.stopPropagation()
          onCheck()
        }}
      >
        检查会话
      </Button>}
    </Space>
  )
}

interface BusinessInviteCooldownView {
  active: boolean
  startedAt: string
  until: string
  reason: string
}

type BusinessInviteQuotaView = InviteQuotaView

/**
 * Only confirmed remote invitation successes consume the visible quota.
 * A provisional reservation prevents duplicate work, but it must not start
 * the displayed invitation window before the first invitation succeeds.
 */
function businessInviteQuotaOf(
  account: GptPlanAccount,
  source: MemberSource | null,
  workspace: BusinessWorkspaceCapability | null,
  snapshot?: BusinessChildrenSnapshot | null,
  _now = Date.now(),
): BusinessInviteQuotaView {
  const candidates = [
    snapshot?.invite_quota,
    workspace?.invite_quota,
    source?.invite_quota,
    account.invite_quota,
    account.member_source?.business_workspace?.invite_quota,
    account.member_source?.invite_quota,
  ]
  return readBusinessInviteQuota(latestBusinessInviteQuota(candidates), BUSINESS_INVITE_SUCCESS_LIMIT, BUSINESS_INVITE_WINDOW_HOURS)
}

function businessInviteCooldownOf(
  account: GptPlanAccount,
  source: MemberSource | null,
  workspace: BusinessWorkspaceCapability | null,
  snapshot?: BusinessChildrenSnapshot | null,
  now = Date.now(),
): BusinessInviteCooldownView {
  const records = [
    asRecord(snapshot),
    asRecord(workspace),
    asRecord(source),
    asRecord(account),
  ]
  const candidates: Record<string, unknown>[] = []
  for (const record of records) {
    const candidate = asRecord(record.invite_cooldown)
    if (Object.keys(candidate).length) candidates.push(candidate)
    if (
      record.invite_cooldown_until
      || record.invite_cooldown_started_at
      || record.invite_cooldown_reason
      || record.invite_cooldown_active !== undefined
    ) {
      candidates.push({
        active: record.invite_cooldown_active,
        started_at: record.invite_cooldown_started_at,
        until: record.invite_cooldown_until,
        reason: record.invite_cooldown_reason,
      })
    }
  }
  const nested = candidates.sort((left, right) => (
    autoReplenishmentTime(String(right.until || right.resume_at || ''))
    - autoReplenishmentTime(String(left.until || left.resume_at || ''))
  ))[0] || {}
  const until = String(
    nested.until || nested.resume_at || '',
  ).trim()
  const untilTime = autoReplenishmentTime(until)
  return {
    active: untilTime ? untilTime > now : nested.active === true,
    startedAt: String(
      nested.started_at || '',
    ).trim(),
    until,
    reason: String(
      nested.reason || '',
    ).trim(),
  }
}

function businessInviteButtonState(
  account: GptPlanAccount,
  source: MemberSource | null,
  view?: BusinessChildrenView,
  now = Date.now(),
): { disabled: boolean; reason: string; full: boolean } {
  const sourcePool = String(source?.source_pool || account.source_pool || '').trim().toLowerCase()
  if (sourcePool !== 'gpt_business' || source?.source_missing) {
    return { disabled: true, reason: '该账号没有可用的 BUSINESS 工作区记录', full: false }
  }
  if (account.enabled === false || account.dead || account.dangerous) {
    return { disabled: true, reason: '该 BUSINESS 母号已停用或标记为 Dead', full: false }
  }
  const refundedDirectoryRow = [
    account.catalog_category,
    account.account_type,
  ].some((value) => String(value || '').trim().toLowerCase() === 'refunded')
  if (refundedDirectoryRow) {
    return { disabled: true, reason: '该 BUSINESS 母号已进入“已退款”列表', full: false }
  }
  const actionGate = memberCapabilityOf(account, source, 'business_children')
  if (actionGate.supported !== true) {
    return {
      disabled: true,
      reason: String(actionGate.reason || '该 BUSINESS 母号当前不允许远端操作'),
      full: false,
    }
  }
  const workspace = businessWorkspaceOf(source)
  const snapshot = view?.snapshot
  if (workspace?.team_session_usable !== true || !(workspace?.team_id || snapshot?.team_id)) {
    return { disabled: true, reason: '该母号没有可用的 BUSINESS 登录会话', full: false }
  }
  const inviteQuota = businessInviteQuotaOf(account, source, workspace, snapshot, now)

  const inviteCooldown = businessInviteCooldownOf(account, source, workspace, snapshot, now)
  if (inviteCooldown.active) {
    return {
      disabled: true,
      reason: `上次邀请失败，正在冷却${inviteCooldown.until
        ? `；预计 ${formatTime(inviteCooldown.until)} 恢复（${businessInviteCooldownCountdown(inviteCooldown.until, now)}）`
        : ''}`,
      full: false,
    }
  }
  const seat = snapshot?.seat_summary || businessSeatSummaryOf(source)
  const available = nonNegativeNumber(seat?.available)
  if (!seat?.known || available === null) {
    return { disabled: true, reason: '数据库席位快照未知，请先刷新 BUSINESS 席位', full: false }
  }
  if (available <= 0) {
    return { disabled: true, reason: '当前母号没有空闲席位', full: true }
  }
  const typedSeatFieldsPresent = seat.seat_type_capacity_known !== undefined
    || seat.seat_type_occupancy_known !== undefined
    || Boolean(seat.by_type || seat.seat_types || seat.capacity_by_type || seat.seat_type_summary)
  if (typedSeatFieldsPresent) {
    const exactTypedVacancy = (['default', 'prolite'] as BusinessSeatType[]).some((seatType) => {
      const row = seat.by_type?.[seatType]
        ?? seat.seat_types?.[seatType]
        ?? seat.capacity_by_type?.[seatType]
        ?? seat.seat_type_summary?.[seatType]
        ?? null
      const typedAvailable = nonNegativeNumber(row?.available ?? seat.available_by_type?.[seatType])
      return row?.availability_exact === true && typedAvailable !== null && typedAvailable > 0
    })
    if (
      seat.seat_type_capacity_known !== true
      || seat.seat_type_occupancy_known !== true
      || !exactTypedVacancy
    ) {
      return {
        disabled: true,
        reason: '数据库中的分类席位状态不完整，请先刷新 BUSINESS 席位',
        full: false,
      }
    }
  }
  if (!hasBusinessInviteQuotaForVacancy(inviteQuota, businessInviteVacancies(seat))) {
    return { disabled: true, reason: '当前没有可用于该席位类型的空位，请刷新成员与席位状态', full: false }
  }

  const rawCandidateCount = snapshot?.invite_candidate_count
    ?? workspace?.invite_candidate_count
    ?? source?.invite_candidate_count
  const candidateCount = nonNegativeNumber(rawCandidateCount)
  return {
    disabled: false,
    reason: candidateCount !== null && candidateCount > 0
      ? `可用账号候选 ${candidateCount} 个，可从 Gmail 普通账号中选择`
      : '可用账号候选为空，可手动输入邮箱邀请',
    full: false,
  }
}

function businessSessionReasonLabel(value: unknown): string {
  const key = String(value || '').trim()
  const labels: Record<string, string> = {
    never_logged: '从未登录',
    missing_access_token: '登录凭证缺失',
    invalid_access_token: '登录凭证损坏',
    expired_access_token: 'AT 已到期，请检查会话',
    remote_session_invalid: '凭证被远端拒绝，请检查会话或重新登录',
    missing_workspace: '未识别到 BUSINESS 工作区',
    invalid_team_plan: '当前会话不是 BUSINESS 工作区',
  }
  return labels[key] || 'BUSINESS 会话不可用'
}

function normalizeDeliveryDevices(value: unknown): DeliveryDeviceOption[] {
  const body = asRecord(value)
  const rows = Array.isArray(body.items)
    ? body.items
    : Array.isArray(body.devices)
      ? body.devices
      : Array.isArray(value) ? value : []
  return rows.flatMap((item) => {
    const row = asRecord(item)
    const rawProvider = String(row.provider ?? row.type ?? '').trim().toLowerCase()
    const provider = rawProvider === 'cpa'
      ? 'cpa'
      : ['sub2api', 'sub', 'sub-2-api'].includes(rawProvider) ? 'sub2api' : null
    if (!provider) return []
    const providerId = row.provider_id ?? row.source_id ?? row.id
    const explicitRef = String(row.device_ref ?? row.device_key ?? '').trim()
    const deviceRef = explicitRef.includes(':')
      ? explicitRef
      : providerId != null && String(providerId).includes(':')
        ? String(providerId)
        : providerId != null && String(providerId).trim() ? `${provider}:${String(providerId)}` : ''
    if (!deviceRef) return []
    return [{
      deviceRef,
      provider,
      name: String(row.name || `${provider === 'cpa' ? 'CPA' : 'SUB'} ${String(providerId || deviceRef)}`),
      enabled: row.enabled !== false,
    }]
  })
}

function normalizeBusinessMemberDeviceBinding(value: unknown): BusinessMemberDeviceBinding {
  const body = asRecord(value)
  const row = asRecord(
    body.binding
    ?? body.business_device_binding
    ?? body.current_binding
    ?? body.device_binding
    ?? value,
  )
  const target = asRecord(row.delivery_target ?? row.target)
  const rawProvider = String(
    row.provider ?? row.delivery_type ?? target.provider ?? '',
  ).trim().toLowerCase()
  const provider = rawProvider === 'cpa'
    ? 'cpa'
    : ['sub2api', 'sub', 'sub-2-api'].includes(rawProvider) ? 'sub2api' : ''
  const rawTargetId = row.delivery_target_id
    ?? row.target_id
    ?? row.device_id
    ?? row.cpa_target_id
    ?? row.sub2api_device_id
    ?? target.target_id
    ?? target.device_id
    ?? target.id
  const targetId = Number(rawTargetId)
  const explicitRef = String(row.device_ref ?? target.device_ref ?? '').trim()
  const deviceRef = explicitRef.includes(':')
    ? explicitRef
    : provider && Number.isInteger(targetId) && targetId > 0
      ? `${provider}:${targetId}`
      : ''
  const policyRevision = Math.max(0, Number(
    row.policy_revision ?? row.revision ?? body.expected_policy_revision ?? 0,
  ) || 0)
  return {
    ...row,
    bound: row.bound === true || Boolean(deviceRef),
    persisted: row.persisted === true || policyRevision > 0,
    device_ref: deviceRef || undefined,
    delivery_type: provider || undefined,
    provider: provider || undefined,
    delivery_target_id: Number.isInteger(targetId) && targetId > 0 ? targetId : null,
    name: String(row.name ?? row.device_name ?? target.name ?? ''),
    device_name: String(row.device_name ?? row.name ?? target.name ?? ''),
    policy_revision: policyRevision,
    can_bind: row.can_bind !== false && row.eligible_for_new_binding !== false,
    eligible_for_new_binding: row.eligible_for_new_binding !== false && row.can_bind !== false,
    binding_blockers: Array.isArray(row.binding_blockers)
      ? row.binding_blockers
      : Array.isArray(row.blockers) ? row.blockers : [],
    delivery_target: Object.keys(target).length ? target : null,
  }
}

function businessMemberBindingLabel(binding: BusinessMemberDeviceBinding | null | undefined): string {
  if (!binding?.bound || !binding.device_ref) return '未绑定设备'
  const provider = String(binding.provider || binding.delivery_type || binding.device_ref.split(':')[0]).toLowerCase()
  const providerLabel = provider === 'sub2api' ? 'SUB' : 'CPA'
  return `${providerLabel} · ${binding.device_name || binding.name || binding.device_ref}`
}

function linkedMemberDevices(source: MemberSource | null): LinkedMemberDevice[] {
  if (!source) return []
  const candidates: Array<{ provider: 'cpa' | 'sub2api'; raw: unknown }> = [
    { provider: 'cpa', raw: source.cpa },
    { provider: 'sub2api', raw: source.sub2api },
  ]
  return candidates.flatMap(({ provider, raw }) => {
    const status = asRecord(raw)
    const nested = asRecord(
      provider === 'cpa'
        ? status.cpa_synced_to ?? status.synced_to ?? status.link
        : status.sub2api_synced_to ?? status.synced_to ?? status.link,
    )
    const link = Object.keys(nested).length ? nested : status
    const rawId = provider === 'cpa'
      ? link.target_id ?? link.device_id ?? link.id
      : link.device_id ?? link.target_id ?? link.id
    const explicitRef = String(link.device_ref ?? status.device_ref ?? '').trim()
    const deviceRef = explicitRef.includes(':')
      ? explicitRef
      : rawId != null && String(rawId).trim() ? `${provider}:${String(rawId)}` : ''
    if (!deviceRef) return []
    return [{
      deviceRef,
      provider,
      name: String(link.name || status.name || `${provider === 'cpa' ? 'CPA' : 'SUB'} ${String(rawId)}`),
    }]
  })
}

function linkedBusinessChildDevices(child: BusinessManagedChild): LinkedMemberDevice[] {
  const linked: LinkedMemberDevice[] = []
  if (child.cpa_synced_to?.target_id) {
    linked.push({
      deviceRef: `cpa:${child.cpa_synced_to.target_id}`,
      provider: 'cpa',
      name: child.cpa_synced_to.name || `CPA ${child.cpa_synced_to.target_id}`,
    })
  }
  if (child.sub2api_synced_to?.device_id) {
    linked.push({
      deviceRef: `sub2api:${child.sub2api_synced_to.device_id}`,
      provider: 'sub2api',
      name: child.sub2api_synced_to.name || `SUB ${child.sub2api_synced_to.device_id}`,
    })
  }
  return linked
}

function isExhaustedProMember(account: GptPlanAccount, source: MemberSource | null): boolean {
  const localMemberPlan = account.member_plan || memberPlanKey(planTypeOf(account))
  if (localMemberPlan !== 'pro') return false
  const cpaUsage = asRecord(asRecord(source?.cpa).cpa_usage)
  const sub2apiUsage = asRecord(asRecord(source?.sub2api).sub2api_usage)
  // 只认后端持久化并经安全序列化后的 literal true；错误、缺字段或字符串
  // "true" 都不能把账号误标成额度耗尽。
  return cpaUsage.limit_reached === true || sub2apiUsage.limit_reached === true
}

function nestedFiniteNumber(value: unknown, keys: string[], depth = 0): number | null {
  if (depth > 10 || !value || typeof value !== 'object') return null
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = nestedFiniteNumber(item, keys, depth + 1)
      if (found != null) return found
    }
    return null
  }
  const record = value as Record<string, unknown>
  for (const key of keys) {
    const candidate = record[key]
    if (candidate != null && candidate !== '' && typeof candidate !== 'boolean') {
      const parsed = Number(candidate)
      if (Number.isFinite(parsed)) return parsed
    }
  }
  for (const candidate of Object.values(record)) {
    const found = nestedFiniteNumber(candidate, keys, depth + 1)
    if (found != null) return found
  }
  return null
}

function nestedBoolean(value: unknown, key: string, depth = 0): boolean | null {
  if (depth > 10 || !value || typeof value !== 'object') return null
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = nestedBoolean(item, key, depth + 1)
      if (found != null) return found
    }
    return null
  }
  const record = value as Record<string, unknown>
  if (typeof record[key] === 'boolean') return record[key]
  for (const candidate of Object.values(record)) {
    const found = nestedBoolean(candidate, key, depth + 1)
    if (found != null) return found
  }
  return null
}

function memberUsageRows(usage: Record<string, unknown>): Array<{ label: string; remaining: number }> {
  const remainingOf = (remainingKeys: string[], usedKeys: string[]) => {
    const remaining = nestedFiniteNumber(usage, remainingKeys)
    const used = nestedFiniteNumber(usage, usedKeys)
    const value = remaining != null ? remaining : used != null ? 100 - used : null
    return value == null ? null : Math.max(0, Math.min(100, Math.round(value * 10) / 10))
  }
  const primary = remainingOf(
    ['usage_5h_remaining_percent', 'primary_remaining_percent', 'five_hour_remaining_percent'],
    ['usage_5h_percent', 'primary_used_percent', 'five_hour_used_percent'],
  )
  const secondary = remainingOf(
    ['usage_week_remaining_percent', 'secondary_remaining_percent', 'weekly_remaining_percent'],
    ['usage_week_percent', 'secondary_used_percent', 'weekly_used_percent', 'seven_day_used_percent'],
  )
  const general = primary == null && secondary == null
    ? remainingOf(
        ['remaining_percent', 'remaining_percentage', 'percent_remaining', 'quota_remaining'],
        ['used_percent', 'usage_percent', 'percent_used', 'percentage'],
      )
    : null
  return [
    primary == null ? null : { label: '5h', remaining: primary },
    secondary == null ? null : { label: '周', remaining: secondary },
    general == null ? null : { label: '额度', remaining: general },
  ].filter((row): row is { label: string; remaining: number } => row != null)
}

function safeBusinessChildRtLog(value: unknown): string {
  return String(value ?? '')
    .slice(0, 1200)
    .replace(/\baccount_deactivated\b/gi, '账号已被停用')
    .replace(/\baccess_deactivated\b/gi, '访问权限已停用')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [已隐藏]')
    .replace(/\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b/g, '[JWT 已隐藏]')
    .replace(
      /(["']?\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|authorization|cookie|password|client[_-]?secret)\b["']?\s*[:=]\s*["']?)[^"'\s,;}]+/gi,
      '$1[已隐藏]',
    )
    .replace(/\b(otp|验证码|verification[_ -]?code)\b\s*[:=：]?\s*\d{4,8}\b/gi, '$1=[已隐藏]')
    .replace(/([?&](?:code|token|state)=)[^&\s]+/gi, '$1[已隐藏]')
}

function mergeBusinessChildRtLogs(current: string[], incoming: unknown): string[] {
  const next = Array.isArray(incoming)
    ? incoming.map(safeBusinessChildRtLog).filter(Boolean)
    : []
  return Array.from(new Set([...current, ...next])).slice(-200)
}

function safeMailHtml(raw: string): string {
  const doc = new DOMParser().parseFromString(raw || '', 'text/html')
  const unsafeVisualAttributes = new Set([
    'style',
    'srcdoc',
    'srcset',
    'poster',
    'background',
    // Legacy HTML email attributes can survive after inline CSS is removed.
    // Keeping bgcolor while removing a matching light text style produces the
    // unreadable black-on-black mail body seen in the plans mailbox modal.
    'bgcolor',
    'color',
    'text',
    'link',
    'alink',
    'vlink',
  ])

  // HTML email preheaders are deliberately hidden snippets used by inbox
  // clients.  Removing their inline style before removing the node itself can
  // make large runs of preview padding visible (Stripe's ``st-Preheader`` is a
  // concrete example) and push the real message below the iframe viewport.
  // Prune only explicitly-hidden nodes while their original attributes still
  // exist, then continue with the normal white-background sanitisation.
  doc.querySelectorAll('.st-Preheader, [hidden]').forEach((node) => node.remove())
  doc.querySelectorAll('[style], [aria-hidden]').forEach((node) => {
    const style = String(node.getAttribute('style') || '').toLowerCase()
    const property = (name: string): string => {
      const match = style.match(new RegExp(`(?:^|;)\\s*${name}\\s*:\\s*([^;]*)`, 'i'))
      return String(match?.[1] || '').replace(/\s*!important\s*$/i, '').trim()
    }
    const zeroCssValue = (value: string): boolean => (
      /^(?:0+(?:\.0+)?|\.0+)(?:[a-z]+|%)?$/i.test(value)
    )
    const display = property('display')
    const visibility = property('visibility')
    const opacity = property('opacity')
    const overflow = property('overflow')
    const overflowX = property('overflow-x')
    const overflowY = property('overflow-y')
    const boxOverflowHidden = [overflow, overflowX, overflowY]
      .some((value) => value === 'hidden' || value === 'clip')
    const collapsedBox = boxOverflowHidden && [
      property('width'),
      property('height'),
      property('max-width'),
      property('max-height'),
    ].some(zeroCssValue)
    const ariaHidden = String(node.getAttribute('aria-hidden') || '').trim().toLowerCase() === 'true'
    const explicitlyHidden = display === 'none'
      || visibility === 'hidden'
      || visibility === 'collapse'
      || zeroCssValue(opacity)
      || property('mso-hide') === 'all'
      || collapsedBox
      || ariaHidden
    if (explicitlyHidden) node.remove()
  })

  doc.querySelectorAll(
    'script,style,link,meta,base,iframe,object,embed,form,input,button,textarea,select,svg,math',
  ).forEach((node) => node.remove())

  // Do not turn on explicit tracking pixels merely to restore ordinary
  // remote mail artwork.  This check runs before inline styles are stripped.
  doc.querySelectorAll('img').forEach((image) => {
    const width = Number.parseFloat(String(image.getAttribute('width') || ''))
    const height = Number.parseFloat(String(image.getAttribute('height') || ''))
    const style = String(image.getAttribute('style') || '').toLowerCase()
    const explicitTrackingSize = Number.isFinite(width) && Number.isFinite(height)
      && width >= 0 && height >= 0 && width <= 1 && height <= 1
    const hiddenByStyle = /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$))/.test(style)
    const tinyByStyle = /width\s*:\s*(?:0|1)(?:px)?(?:\s*!important)?\s*;/.test(style)
      && /height\s*:\s*(?:0|1)(?:px)?(?:\s*!important)?\s*;/.test(style)
    if (explicitTrackingSize || hiddenByStyle || tinyByStyle) image.remove()
  })

  doc.querySelectorAll('*').forEach((node) => {
    Array.from(node.attributes).forEach((attribute) => {
      const name = attribute.name.toLowerCase()
      if (name.startsWith('on') || unsafeVisualAttributes.has(name)) {
        node.removeAttribute(attribute.name)
        return
      }
      if (name === 'src') {
        const value = attribute.value.trim()
        const normalized = value.toLowerCase()
        let safeImageSource = normalized.startsWith('data:image/')
        if (!safeImageSource && normalized.startsWith('https://')) {
          try {
            const url = new URL(value)
            safeImageSource = url.protocol === 'https:' && !url.username && !url.password
          } catch {
            safeImageSource = false
          }
        }
        if (!safeImageSource) node.removeAttribute(attribute.name)
        return
      }
      if (name === 'href') {
        try {
          const url = new URL(attribute.value, window.location.origin)
          if (!['http:', 'https:', 'mailto:'].includes(url.protocol)) node.removeAttribute(attribute.name)
        } catch {
          node.removeAttribute(attribute.name)
        }
      }
    })
  })

  doc.querySelectorAll('img[src]').forEach((image) => {
    image.setAttribute('loading', 'lazy')
    image.setAttribute('decoding', 'async')
    image.setAttribute('referrerpolicy', 'no-referrer')
  })

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="color-scheme" content="light only"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: https:; style-src 'unsafe-inline'"><style>:root{color-scheme:light}html,body{background:#fff!important;color:#222!important}body{margin:0;padding:12px;font:14px/1.6 system-ui,sans-serif;overflow-wrap:anywhere}a{color:#1677ff!important}img{max-width:100%;height:auto}</style></head><body>${doc.body.innerHTML}</body></html>`
}

interface GptPlansProps {
  businessOnly?: boolean
  standalone?: boolean
}

export default function GptPlans({ businessOnly = false, standalone = false }: GptPlansProps) {
  const { defaults: seatMailDefaults, revision: seatMailRevision } = useBusinessInviteMailProviderSettings()
  const { message, modal, notification } = App.useApp()
  const { token } = theme.useToken()
  const breakpointScreens = Grid.useBreakpoint()
  const compactBusinessLayout = breakpointScreens.md === false
  const compactBusinessTable = breakpointScreens.lg === false
  const [searchParams, setSearchParams] = useSearchParams()
  const initialFocusTargetRef = useRef<GptPlanFocusTarget | null>(
    planFocusTargetFromSearch(searchParams),
  )
  const [mainTab, setMainTab] = useState<'accounts' | 'preparation' | 'cards' | 'proxy'>('accounts')
  // 与 GPT PRO「一键更新支付账号」保持相同执行逻辑；这里只调用
  // GPT 套餐管理的独立支付账号路由，避免回写旧 GPT PRO 卡池。
  const [refreshingAllBalance, setRefreshingAllBalance] = useState(false)
  const refreshAllBalance = async () => {
    setRefreshingAllBalance(true)
    const hide = message.loading('正在更新所有支付账号(开卡/余额/支付/待退款)…(每账号一线程并发,较慢请稍候)', 0)
    try {
      const r = (await apiFetch('/gpt-plans/payment-accounts/sync-all', { method: 'POST' })) as {
        ok: boolean; updated?: number; failed?: number; skipped?: number; total?: number
      }
      hide()
      message.success(`支付账号已更新:成功 ${r.updated ?? 0} / 失败 ${r.failed ?? 0} / 跳过 ${r.skipped ?? 0} / 共 ${r.total ?? 0}`, 6)
    } catch (e: any) {
      hide()
      message.error(`更新支付账号失败: ${e?.message || e}`)
    } finally {
      setRefreshingAllBalance(false)
    }
  }
  const [accounts, setAccounts] = useState<GptPlanAccount[]>([])
  const [nvMotherRevenue, setNvMotherRevenue] = useState<Record<number, BusinessWorkspaceCapability['rotation_revenue']>>({})
  const [auditMotherId, setAuditMotherId] = useState<number | null>(null)
  const [replenishmentNow, setReplenishmentNow] = useState(() => Date.now())
  const [stats, setStats] = useState<GptPlanStats | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadedFocusSignature, setLoadedFocusSignature] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [total, setTotal] = useState(0)
  const [keywordInput, setKeywordInput] = useState('')
  const [keyword, setKeyword] = useState('')
  const [loginStatus, setLoginStatus] = useState<string | undefined>()
  const [businessSeatFilter, setBusinessSeatFilter] = useState<BusinessSeatFilter | undefined>()
  const [businessUsageFilter, setBusinessUsageFilter] = useState<BusinessUsageFilter | undefined>()
  // 子号目录默认只展示标记为“出售”的母号下的当前子号。该筛选与母号
  // 目录分开保存，避免用户在两个展示维度之间切换时互相改写筛选条件。
  const [businessChildParentUsageFilter, setBusinessChildParentUsageFilter]
    = useState<BusinessUsageFilter | undefined>(standalone ? undefined : 'sale')
  const [businessChildTwoFactorFilter, setBusinessChildTwoFactorFilter]
    = useState<BusinessChildTwoFactorFilter>('all')
  const [businessChildRtFilter, setBusinessChildRtFilter]
    = useState<BusinessChildRtFilter>('all')
  const [businessChildSaleFilter, setBusinessChildSaleFilter]
    = useState<BusinessChildSaleFilter>('all')
  const [businessCatalogView, setBusinessCatalogView] = useState<BusinessCatalogView>('mothers')
  const [businessChildCatalogRows, setBusinessChildCatalogRows] = useState<BusinessChildCatalogRow[]>([])
  const [businessChildCatalogLoading, setBusinessChildCatalogLoading] = useState(false)
  const [businessChildCatalogTotal, setBusinessChildCatalogTotal] = useState(0)
  const [businessChildSaleEditor, setBusinessChildSaleEditor] = useState<BusinessChildCatalogRow | null>(null)
  const [businessChildSaleStatusDraft, setBusinessChildSaleStatusDraft]
    = useState<BusinessChildSaleStatus>('unlisted')
  const [businessChildSoldAtDraft, setBusinessChildSoldAtDraft] = useState('')
  const [businessChildWarrantyDraft, setBusinessChildWarrantyDraft] = useState<number>(0)
  const [businessChildSaleSaving, setBusinessChildSaleSaving] = useState(false)
  const [businessChildNvListingTarget, setBusinessChildNvListingTarget]
    = useState<BusinessChildNvListingTarget | null>(null)
  const [businessChildNvPriceDraft, setBusinessChildNvPriceDraft] = useState<number | null>(null)
  const [businessChildNvWarrantyUntilDraft, setBusinessChildNvWarrantyUntilDraft] = useState('')
  const [businessChildNvListingSaving, setBusinessChildNvListingSaving] = useState(false)
  const [businessChildNvBatchTargets, setBusinessChildNvBatchTargets]
    = useState<Array<{ membership_id: number; email: string; seat_type?: BusinessSeatType }> | null>(null)
  const [businessChildNvBatchPriceDraft, setBusinessChildNvBatchPriceDraft] = useState<number | null>(null)
  const [businessChildNvBatchWarrantyUntilDraft, setBusinessChildNvBatchWarrantyUntilDraft] = useState('')
  const businessChildNvNeedsWarranty = Boolean(businessChildNvListingTarget
    && businessChildSeatType(businessChildNvListingTarget.child) === 'prolite')
  const businessChildNvBatchNeedsWarranty = businessChildNvBatchTargets?.some(item => item.seat_type === 'prolite') === true
  const [businessChildNvBatchStarting, setBusinessChildNvBatchStarting] = useState(false)
  const businessChildNvBatchStartingRef = useRef(false)
  const [businessChildNvBatchTask, setBusinessChildNvBatchTask] = useState<BusinessChildNvBatchTask | null>(null)
  const [businessChildNvBatchTaskOpen, setBusinessChildNvBatchTaskOpen] = useState(false)
  const [businessChildNvBatchPollingError, setBusinessChildNvBatchPollingError] = useState('')
  const [businessChildNvBatchPollingStopped, setBusinessChildNvBatchPollingStopped] = useState(false)
  const [businessChildNvBatchUnavailable, setBusinessChildNvBatchUnavailable] = useState(false)
  const [businessChildNvBatchPollEpoch, setBusinessChildNvBatchPollEpoch] = useState(0)
  const businessChildNvBatchConfirmedRef = useRef(new Set<number>())
  const [businessChildNvSalesRefreshing, setBusinessChildNvSalesRefreshing] = useState(false)
  const [businessChildNvSalesResult, setBusinessChildNvSalesResult] = useState<BusinessChildNvSalesResult | null>(null)
  const [businessChildNvSalesResultOpen, setBusinessChildNvSalesResultOpen] = useState(false)
  const businessChildNvSalesRefreshInFlightRef = useRef(false)
  const [nvTokensConfigOpen, setNvTokensConfigOpen] = useState(false)
  const [nvTokensConfigLoading, setNvTokensConfigLoading] = useState(false)
  const [nvTokensConfigSaving, setNvTokensConfigSaving] = useState(false)
  const [nvTokensConfig, setNvTokensConfig] = useState<NvTokensConfigState>({
    base_url: 'https://nvtokens.com',
    api_key_configured: false,
    query_session_configured: false,
  })
  const [nvTokensApiKeyDraft, setNvTokensApiKeyDraft] = useState('')
  const [nvTokensQueryCookieDraft, setNvTokensQueryCookieDraft] = useState('')
  const [selectedBusinessChildMembershipIds, setSelectedBusinessChildMembershipIds] = useState<number[]>([])
  const [businessChildBatchStarting, setBusinessChildBatchStarting] = useState(false)
  const [businessChildBatchTask, setBusinessChildBatchTask] = useState<BusinessChildBatchActionTask | null>(null)
  const [businessChildBatchTaskOpen, setBusinessChildBatchTaskOpen] = useState(false)
  // 套餐账号、BUSINESS 母号与子号共用一份列表级 2FA 浏览器配置。
  // 单号设置、子号批量设置，以及批量邀请后的自动设置均在启动时冻结该值。
  const [securityBrowserMode, setSecurityBrowserMode] = useState<'headless' | 'headed'>(() => {
    try {
      return localStorage.getItem(SECURITY_BROWSER_MODE_STORAGE_KEY) === 'headed'
        ? 'headed'
        : 'headless'
    } catch {
      return 'headless'
    }
  })
  const updateSecurityBrowserMode = (value: string | number) => {
    const mode = value === 'headed' ? 'headed' : 'headless'
    setSecurityBrowserMode(mode)
    try { localStorage.setItem(SECURITY_BROWSER_MODE_STORAGE_KEY, mode) } catch { /* ignore */ }
  }
  const businessChildBatchTimerRef = useRef<number | undefined>(undefined)
  const businessChildBatchGenerationRef = useRef(0)
  const businessChildBatchParentIdsRef = useRef(new Set<number>())
  const businessChildSelectionSignatureRef = useRef('')
  const [selectedBusinessAccountIds, setSelectedBusinessAccountIds] = useState<number[]>([])
  const [businessSelectAllMatching, setBusinessSelectAllMatching] = useState(false)
  const [accountType, setAccountType] = useState<AccountType>(
    businessOnly ? 'member' : initialFocusTargetRef.current?.accountType || (standalone ? 'regular' : 'member'),
  )
  const [refundedUpgradeTimeOrder, setRefundedUpgradeTimeOrder] = useState<'asc' | 'desc'>('desc')
  const [memberPlan, setMemberPlan] = useState<MemberPlan>(
    businessOnly ? 'team' : initialFocusTargetRef.current?.memberPlan || DEFAULT_MEMBER_PLAN,
  )
  const [focusTarget, setFocusTarget] = useState<GptPlanFocusTarget | null>(
    initialFocusTargetRef.current,
  )
  const handledFocusRouteRef = useRef('')
  const completedFocusRouteRef = useRef('')
  const loadAccountsGenerationRef = useRef(0)
  const loadAccountsQuerySignatureRef = useRef('')
  const loadBusinessChildCatalogGenerationRef = useRef(0)
  const [memberSourceOverrides, setMemberSourceOverrides] = useState<Record<number, MemberSource>>({})
  const [memberCapabilityLoadingId, setMemberCapabilityLoadingId] = useState<number | null>(null)
  const [businessWorkspaceRefreshingIds, setBusinessWorkspaceRefreshingIds] = useState<number[]>([])
  const [businessSessionCheckingIds, setBusinessSessionCheckingIds] = useState<number[]>([])
  const businessSessionCheckInFlightRef = useRef(new Set<number>())
  const [businessPaymentRefreshingIds, setBusinessPaymentRefreshingIds] = useState<number[]>([])
  const businessPaymentRefreshInFlightRef = useRef(new Set<number>())
  const businessPaymentAccountsRef = useRef(accounts)
  businessPaymentAccountsRef.current = accounts
  const [businessWorkspaceReferralsSavingIds, setBusinessWorkspaceReferralsSavingIds] = useState<number[]>([])
  const [businessWorkspacePageRefreshing, setBusinessWorkspacePageRefreshing] = useState(false)
  const businessWorkspaceRefreshInFlightRef = useRef(new Map<number, Promise<boolean>>())
  const [businessBatchInviteStarting, setBusinessBatchInviteStarting] = useState(false)
  const [businessBatchInviteTask, setBusinessBatchInviteTask] = useState<BusinessBatchInviteTask | null>(null)
  const [businessBatchInviteTaskOpen, setBusinessBatchInviteTaskOpen] = useState(false)
  const [businessBatchInviteMailProvider, setBusinessBatchInviteMailProvider] = useState<BusinessInviteMailProvider>(standalone ? 'gmail' : 'auto')
  const [businessBatchInvitePostSecurity, setBusinessBatchInvitePostSecurity] = useState(false)
  const [businessBatchInvitePostRt, setBusinessBatchInvitePostRt] = useState(false)
  const businessBatchInviteTimerRef = useRef<number | undefined>(undefined)
  const businessBatchInviteGenerationRef = useRef(0)
  const [businessMembersAccountId, setBusinessMembersAccountId] = useState<number | null>(null)
  const [businessChildrenByAccount, setBusinessChildrenByAccount] = useState<Record<number, BusinessChildrenView>>({})
  const [businessInviteAccount, setBusinessInviteAccount] = useState<GptPlanAccount | null>(null)
  const [businessInviteCandidates, setBusinessInviteCandidates] = useState<BusinessManagedChild[]>([])
  const [businessInviteCandidatesLoading, setBusinessInviteCandidatesLoading] = useState(false)
  const [businessInviteMode, setBusinessInviteMode] = useState<'pool' | 'manual'>('pool')
  const [businessInviteMailProvider, setBusinessInviteMailProvider] = useState<BusinessInviteMailProvider>(standalone ? 'gmail' : 'auto')
  const businessInviteCandidateGeneration = useRef(0)
  const [businessInviteSelectedChildId, setBusinessInviteSelectedChildId] = useState<number>()
  const [businessInviteManualEmail, setBusinessInviteManualEmail] = useState('')
  const [businessInviteSeatType, setBusinessInviteSeatType] = useState<BusinessSeatType>('default')
  const [businessInviteCount, setBusinessInviteCount] = useState(1)
  const [businessInviting, setBusinessInviting] = useState(false)
  const [businessInviteProgress, setBusinessInviteProgress] = useState<BusinessInviteProgressState>({ stage: 'idle' })
  const [businessChildRtTask, setBusinessChildRtTask] = useState<BusinessChildRtTask | null>(null)
  const [businessChildRtTaskOpen, setBusinessChildRtTaskOpen] = useState(false)
  const businessChildRtTimerRef = useRef<number | undefined>(undefined)
  const businessChildRtGenerationRef = useRef(0)
  const businessChildRtActiveKeyRef = useRef('')
  const [businessChildActionBusyKeys, setBusinessChildActionBusyKeys] = useState<string[]>([])
  const [memberActionBusyKey, setMemberActionBusyKey] = useState('')
  const [memberTask, setMemberTask] = useState<MemberSourceTask | null>(null)
  const memberTaskTimerRef = useRef<number | undefined>(undefined)
  const memberTaskGenerationRef = useRef(0)
  const [refundAccount, setRefundAccount] = useState<GptPlanAccount | null>(null)
  const [refundManual, setRefundManual] = useState(false)
  const [downloadBusyKey, setDownloadBusyKey] = useState('')
  const [mailCredentialExportingId, setMailCredentialExportingId] = useState<number | null>(null)
  const [deviceAccount, setDeviceAccount] = useState<GptPlanAccount | null>(null)
  const [businessChildDeviceTarget, setBusinessChildDeviceTarget] = useState<BusinessChildDeviceSyncTarget | null>(null)
  const [deliveryDevices, setDeliveryDevices] = useState<DeliveryDeviceOption[]>([])
  const [deliveryDevicesLoading, setDeliveryDevicesLoading] = useState(false)
  const [selectedDeviceRef, setSelectedDeviceRef] = useState<string>()
  const [deviceSyncing, setDeviceSyncing] = useState(false)
  const [deviceUsageBusyKey, setDeviceUsageBusyKey] = useState('')
  const [memberDeviceUsage, setMemberDeviceUsage] = useState<MemberDeviceUsageView | null>(null)
  const [businessBindingAccount, setBusinessBindingAccount] = useState<GptPlanAccount | null>(null)
  const [businessBinding, setBusinessBinding] = useState<BusinessMemberDeviceBinding | null>(null)
  const [businessBindingDevices, setBusinessBindingDevices] = useState<DeliveryDeviceOption[]>([])
  const [businessBindingSelectedRef, setBusinessBindingSelectedRef] = useState<string>()
  const [businessBindingLoading, setBusinessBindingLoading] = useState(false)
  const [businessBindingSaving, setBusinessBindingSaving] = useState(false)
  const [businessBurnAccount, setBusinessBurnAccount] = useState<GptPlanAccount | null>(null)
  const [businessBurnCandidates, setBusinessBurnCandidates] = useState<BusinessBurnCandidate[]>([])
  const [businessBurnCandidatesLoading, setBusinessBurnCandidatesLoading] = useState(false)
  const [businessBurnSelectedIds, setBusinessBurnSelectedIds] = useState<number[]>([])
  const [businessBurnKick, setBusinessBurnKick] = useState(true)
  const [businessBurnMaxSelect, setBusinessBurnMaxSelect] = useState(0)
  const [businessBurnStarting, setBusinessBurnStarting] = useState(false)
  const [businessBurnTask, setBusinessBurnTask] = useState<BusinessBurnTask | null>(null)
  const [businessBurnStartSummary, setBusinessBurnStartSummary] = useState<{
    requested: number
    targets: number
    remaining: number | null
  } | null>(null)
  const businessBurnTimerRef = useRef<number | undefined>(undefined)
  const businessBurnGenerationRef = useRef(0)
  const [loginId, setLoginId] = useState<number | null>(null)
  const [securitySetupBusyId, setSecuritySetupBusyId] = useState<number | null>(null)
  const [securityExportingId, setSecurityExportingId] = useState<number | null>(null)
  const [securitySetupTask, setSecuritySetupTask] = useState<ChatGptSecuritySetupTask | null>(null)
  const securitySetupTimerRef = useRef<number | undefined>(undefined)
  const securitySetupGenerationRef = useRef(0)
  const [businessChildSecuritySetupBusyKey, setBusinessChildSecuritySetupBusyKey] = useState('')
  const [businessChildSecurityExportingKey, setBusinessChildSecurityExportingKey] = useState('')
  const [businessChildSecuritySetupTask, setBusinessChildSecuritySetupTask] = useState<BusinessChildSecuritySetupTask | null>(null)
  const businessChildSecuritySetupTimerRef = useRef<number | undefined>(undefined)
  const businessChildSecuritySetupGenerationRef = useRef(0)
  const [msLoginingId, setMsLoginingId] = useState<number | null>(null)
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [editingNoteId, setEditingNoteId] = useState<number | null>(null)
  const [noteDraft, setNoteDraft] = useState('')
  const [noteSavingId, setNoteSavingId] = useState<number | null>(null)
  const [businessUsageSavingIds, setBusinessUsageSavingIds] = useState<number[]>([])
  const noteSaveInFlightRef = useRef(new Set<number>())
  const noteCancelRef = useRef(new Set<number>())

  const [checkoutRegion, setCheckoutRegion] = useState({ country: 'PH', currency: 'PHP' })
  const [checkoutRegionSaving, setCheckoutRegionSaving] = useState(false)

  const [upgradeAccount, setUpgradeAccount] = useState<GptPlanAccount | null>(null)
  const [upgradeStarting, setUpgradeStarting] = useState(false)
  const [upgradeTask, setUpgradeTask] = useState<UpgradeTask | null>(null)
  const [refundedUpgradeReview, setRefundedUpgradeReview] = useState<RefundedUpgradeReview | null>(null)
  const [refundedUpgradeConfirmBusyKey, setRefundedUpgradeConfirmBusyKey] = useState('')
  const [refundedMigrationBusyKey, setRefundedMigrationBusyKey] = useState('')
  const [roxyProxies, setRoxyProxies] = useState<RoxyProxy[]>([])
  const [roxyLoading, setRoxyLoading] = useState(false)
  const {
    config: upgradeBrowserConfig,
    loading: upgradeBrowserConfigLoading,
    saving: upgradeBrowserConfigSaving,
    save: saveUpgradeBrowserConfig,
  } = useUpgradeBrowserConfig()
  const upgradeTimerRef = useRef<number | undefined>(undefined)

  const [businessAccount, setBusinessAccount] = useState<GptPlanAccount | null>(null)
  const [businessWorkspace, setBusinessWorkspace] = useState('')
  const [businessCoupon, setBusinessCoupon] = useState('')
  const [businessCouponLoading, setBusinessCouponLoading] = useState(false)
  const [businessCouponLoadError, setBusinessCouponLoadError] = useState('')
  const businessCouponRequestGenerationRef = useRef(0)
  const businessCouponRequestRef = useRef<AbortController | null>(null)
  const [businessDefaultCouponOpen, setBusinessDefaultCouponOpen] = useState(false)
  const [businessDefaultCoupon, setBusinessDefaultCoupon] = useState<string | null>(null)
  const [businessDefaultCouponDraft, setBusinessDefaultCouponDraft] = useState('')
  const [businessDefaultCouponLoading, setBusinessDefaultCouponLoading] = useState(false)
  const [businessDefaultCouponSaving, setBusinessDefaultCouponSaving] = useState(false)
  const [businessDefaultCouponLoadError, setBusinessDefaultCouponLoadError] = useState('')
  const [businessDefaultCouponSaveError, setBusinessDefaultCouponSaveError] = useState('')
  const businessDefaultCouponRequestGenerationRef = useRef(0)
  const businessDefaultCouponRequestRef = useRef<AbortController | null>(null)
  const businessDefaultCouponSavingRef = useRef(false)
  const [businessSeatType, setBusinessSeatType] = useState<'default' | 'prolite'>('default')
  const [businessSeats, setBusinessSeats] = useState(2)
  const [businessCountry, setBusinessCountry] = useState('US')
  const [businessCurrency, setBusinessCurrency] = useState('USD')
  const [businessAutoFill, setBusinessAutoFill] = useState(true)
  const [businessAutoSubmit, setBusinessAutoSubmit] = useState(false)
  const [businessCardText, setBusinessCardText] = useState('')
  const [businessLoading, setBusinessLoading] = useState(false)
  const [businessUrl, setBusinessUrl] = useState('')
  const [businessResult, setBusinessResult] = useState<Record<string, unknown> | null>(null)

  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [motherImportMailProvider, setMotherImportMailProvider] = useState('outlook')
  const [importLoading, setImportLoading] = useState(false)
  const [importTaskId, setImportTaskId] = useState('')
  const [importTask, setImportTask] = useState<ImportTaskSnapshot | null>(null)
  const handledImportTaskRef = useRef('')

  const [mailOpen, setMailOpen] = useState(false)
  const [mailAccount, setMailAccount] = useState<MailAccountTarget | null>(null)
  const mailRequestRef = useRef(0)
  const [mailBusinessChildTarget, setMailBusinessChildTarget] = useState<{
    account: GptPlanAccount
    child: BusinessManagedChild
  } | null>(null)
  const [mailLoading, setMailLoading] = useState(false)
  const [mailMessages, setMailMessages] = useState<MailMessage[]>([])
  const [mailMethod, setMailMethod] = useState('')
  const [mailError, setMailError] = useState('')
  const [mailLimit, setMailLimit] = useState(10)
  const [mailMonitorNow, setMailMonitorNow] = useState(() => Date.now())
  const [alertSummary, setAlertSummary] = useState<Record<number, number>>({})
  const [inboxSummary, setInboxSummary] = useState<Record<number, number>>({})
  const [alertItems, setAlertItems] = useState<MailAlertSummaryItem[]>([])
  const [totalAlertUnread, setTotalAlertUnread] = useState(0)
  const [totalInboxUnread, setTotalInboxUnread] = useState(0)
  const [alertAccount, setAlertAccount] = useState<MailAlertTarget | null>(null)
  const [alertOpen, setAlertOpen] = useState(false)
  const [alertLoading, setAlertLoading] = useState(false)
  const [alertList, setAlertList] = useState<MailAlert[]>([])
  const [inboxAccount, setInboxAccount] = useState<MailAlertTarget | null>(null)
  const [inboxOpen, setInboxOpen] = useState(false)
  const [inboxLoading, setInboxLoading] = useState(false)
  const [inboxList, setInboxList] = useState<MailAlert[]>([])
  const [checkingMailAccountId, setCheckingMailAccountId] = useState<number | null>(null)
  // The first successful summary read is a silent baseline: opening the page
  // must not replay months of unread backlog as a new desktop-style notice.
  // Subsequent count increases are notified once and then become the next
  // baseline, including after the user clears a queue.
  const mailSummaryReadyRef = useRef(false)
  const mailSummaryCountsRef = useRef<Record<number, number>>({})

  const routeFocusSignature = PLAN_FOCUS_QUERY_KEYS
    .map((key) => `${key}=${searchParams.get(key) || ''}`)
    .join('&')

  const accountListQuerySignature = JSON.stringify([
    page,
    pageSize,
    keyword,
    loginStatus || '',
    accountType,
    memberPlan || '',
    accountType === 'member' && memberPlan === 'team' ? businessSeatFilter || '' : '',
    accountType === 'member' && memberPlan === 'team' ? businessUsageFilter || '' : '',
    accountType === 'refunded' ? refundedUpgradeTimeOrder : '',
    focusTarget?.planAccountId || 0,
  ])
  const businessSelectionQuerySignature = JSON.stringify([
    accountType,
    memberPlan,
    keyword,
    loginStatus || '',
    businessSeatFilter || '',
    businessUsageFilter || '',
    focusTarget?.planAccountId || 0,
  ])
  const businessSelectionQuerySignatureRef = useRef(businessSelectionQuerySignature)
  const businessChildSelectionQuerySignature = JSON.stringify([
    businessCatalogView,
    keyword,
    businessChildParentUsageFilter || '',
    businessChildTwoFactorFilter,
    businessChildRtFilter,
    businessChildSaleFilter,
    page,
    pageSize,
  ])
  // Updated during every render so a long-running action that captured an old
  // loadAccounts closure cannot later overwrite the user's new tab/filter.
  loadAccountsQuerySignatureRef.current = accountListQuerySignature

  const clearFocusRouteParams = useCallback(() => {
    const next = new URLSearchParams(searchParams)
    PLAN_FOCUS_QUERY_KEYS.forEach((key) => next.delete(key))
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams])

  const dismissFocusTarget = useCallback(() => {
    setFocusTarget(null)
    completedFocusRouteRef.current = ''
    setPage(1)
    clearFocusRouteParams()
  }, [clearFocusRouteParams])

  useEffect(() => {
    const incoming = planFocusTargetFromSearch(searchParams)
    if (!incoming) {
      handledFocusRouteRef.current = ''
      return
    }
    if (handledFocusRouteRef.current === routeFocusSignature) return
    handledFocusRouteRef.current = routeFocusSignature
    completedFocusRouteRef.current = ''
    setMainTab('accounts')
    setAccountType(businessOnly ? 'member' : incoming.accountType)
    setMemberPlan(businessOnly ? 'team' : incoming.memberPlan || DEFAULT_MEMBER_PLAN)
    setBusinessCatalogView('mothers')
    setLoginStatus(undefined)
    setBusinessSeatFilter(undefined)
    setBusinessUsageFilter(undefined)
    setKeywordInput('')
    setKeyword('')
    setPage(1)
    setFocusTarget(incoming)
  }, [routeFocusSignature, searchParams])

  const loadAccounts = useCallback(async (silent = false) => {
    const requestSignature = accountListQuerySignature
    if (requestSignature !== loadAccountsQuerySignatureRef.current) return
    const requestGeneration = ++loadAccountsGenerationRef.current
    if (!silent) setLoading(true)
    setLoadedFocusSignature('')
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
      })
      if (keyword) params.set('keyword', keyword)
      if (standalone && !businessOnly && accountType === 'regular') params.set('mail_provider', 'gmail')
      const supportsLoginStatus = accountType === 'regular'
        || (accountType === 'member' && memberPlan === 'team')
      if (supportsLoginStatus && loginStatus) params.set('login_status', loginStatus)
      params.set('account_type', accountType)
      if (accountType === 'member') params.set('member_plan', memberPlan)
      if (accountType === 'member' && memberPlan === 'team') {
        if (businessSeatFilter) params.set('business_seat_filter', businessSeatFilter)
        if (businessUsageFilter) params.set('business_usage_type', businessUsageFilter)
      }
      if (accountType === 'refunded') params.set('upgrade_time_order', refundedUpgradeTimeOrder)
      if (focusTarget?.planAccountId) params.set('account_id', String(focusTarget.planAccountId))
      const data = await apiFetch(`${API_ROOT}/accounts?${params.toString()}`) as {
        items?: GptPlanAccount[]
        total?: number
      }
      const rows = Array.isArray(data.items) ? data.items : []
      // 只允许最后发出的列表请求提交结果。后台轮询、筛选切换和操作后的
      // 主动刷新可能并发；迟到旧响应不能把刚保存的设备绑定回滚到旧展示。
      if (
        requestGeneration !== loadAccountsGenerationRef.current
        || requestSignature !== loadAccountsQuerySignatureRef.current
      ) return
      setAccounts(rows)
      setBusinessInviteAccount((current) => (
        current ? rows.find((row) => row.id === current.id) || current : null
      ))
      // 能力/workspace 弹窗可能在内存中保留一份 source override。
      // 列表轮询时用服务端最新的任务与设备绑定覆盖对应字段，避免旧
      // override 把已完成任务或已跨页面修改的 policy 永久遮住。
      setMemberSourceOverrides((current) => {
        let changed = false
        const next = { ...current }
        for (const row of rows) {
          const existing = current[row.id]
          const incoming = row.member_source
          if (!existing || !incoming || typeof incoming !== 'object') continue
          let merged = existing
          if (
            Object.prototype.hasOwnProperty.call(incoming, 'replenishment')
            && existing.replenishment !== incoming.replenishment
          ) {
            merged = { ...merged, replenishment: incoming.replenishment ?? null }
          }
          if (
            Object.prototype.hasOwnProperty.call(incoming, 'business_device_binding')
            && existing.business_device_binding !== incoming.business_device_binding
          ) {
            merged = {
              ...merged,
              business_device_binding: incoming.business_device_binding ?? null,
            }
          }
          merged = mergeBusinessSessionSnapshot(merged, incoming)
          if (merged === existing) continue
          next[row.id] = merged
          changed = true
        }
        return changed ? next : current
      })
      setTotal(Number(data.total || 0))
      setLoadedFocusSignature(focusTarget?.planAccountId
        ? `${focusTarget.planAccountId}:${accountType}:${memberPlan || ''}`
        : '')
    } catch (error: unknown) {
      if (
        requestGeneration === loadAccountsGenerationRef.current
        && requestSignature === loadAccountsQuerySignatureRef.current
        && !silent
      ) {
        message.error(`加载 GPT 套餐账号失败：${errorMessage(error, '未知错误')}`)
      }
    } finally {
      if (
        requestGeneration === loadAccountsGenerationRef.current
        && requestSignature === loadAccountsQuerySignatureRef.current
      ) setLoading(false)
    }
  }, [accountListQuerySignature, accountType, businessSeatFilter, businessUsageFilter, focusTarget?.planAccountId, keyword, loginStatus, memberPlan, message, page, pageSize, refundedUpgradeTimeOrder])

  const loadStats = useCallback(async () => {
    try {
      setStats(await apiFetch(`${API_ROOT}/stats`) as GptPlanStats)
    } catch {
      setStats(null)
    }
  }, [])

  const loadMailAlertSummary = useCallback(async () => {
    try {
      const data = await apiFetch(`${API_ROOT}/alerts/summary`) as {
        total_unread?: number
        total_inbox_unread?: number
        items?: Array<Partial<MailAlertSummaryItem> & {
          account_id?: number
          plan_account_id?: number
          target_kind?: string
          account_type?: string
          parent_id?: number | null
          parent_email?: string
          child_id?: number | null
          membership_id?: number | null
        }>
      }
      const bellMap: Record<number, number> = {}
      const inboxMap: Record<number, number> = {}
      const items = (Array.isArray(data.items) ? data.items : []).flatMap((item) => {
        const id = Number(item.id ?? item.plan_account_id ?? item.account_id)
        if (!Number.isInteger(id) || id <= 0) return []
        const normalized: MailAlertSummaryItem = {
          id,
          email: String(item.email || ''),
          unread_count: Math.max(0, Number(item.unread_count || 0)),
          inbox_unread_count: Math.max(0, Number(item.inbox_unread_count || 0)),
          latest_subject: String(item.latest_subject || ''),
          latest_time: String(item.latest_time || ''),
          target_kind: item.target_kind === 'business_child' ? 'business_child' : 'account',
          account_type: item.account_type === 'business_child'
            ? 'business_child'
            : item.account_type === 'refunded' ? 'refunded' : 'member',
          plan_type: String(item.plan_type || ''),
          member_plan: String(item.member_plan || ''),
          parent_id: nonNegativeNumber(item.parent_id) || null,
          parent_email: String(item.parent_email || ''),
          child_id: nonNegativeNumber(item.child_id) || null,
          membership_id: nonNegativeNumber(item.membership_id) || null,
        }
        if (normalized.unread_count > 0) bellMap[id] = normalized.unread_count
        if (normalized.inbox_unread_count > 0) inboxMap[id] = normalized.inbox_unread_count
        return [normalized]
      })
      const nextCounts: Record<number, number> = {}
      for (const item of items) {
        // A deactivation notice exists in both queues.  max() counts that one
        // physical message once while still detecting ordinary inbox mail.
        nextCounts[item.id] = Math.max(item.unread_count, item.inbox_unread_count)
      }
      if (mailSummaryReadyRef.current) {
        const changed = items.flatMap((item) => {
          const before = Math.max(0, Number(mailSummaryCountsRef.current[item.id] || 0))
          const delta = Math.max(0, nextCounts[item.id] - before)
          return delta > 0 ? [{ item, delta }] : []
        })
        const added = changed.reduce((sum, row) => sum + row.delta, 0)
        if (added > 0) {
          const first = changed[0]?.item
          const more = Math.max(0, changed.length - 1)
          notification.info({
            key: `gpt-plans-new-mail-${Date.now()}`,
            message: `新增 ${added} 封未读邮件`,
            description: first
              ? `${first.email}（${gptPlanMailLocation(first)}）${first.latest_subject ? `：${first.latest_subject}` : ''}${more ? `，另有 ${more} 个账号` : ''}`
              : 'GPT 套餐账号有新增未读邮件',
            placement: 'topRight',
            duration: 8,
          })
        }
      } else {
        mailSummaryReadyRef.current = true
      }
      mailSummaryCountsRef.current = nextCounts
      setAlertSummary(bellMap)
      setInboxSummary(inboxMap)
      setAlertItems(items)
      setTotalAlertUnread(Math.max(0, Number(data.total_unread ?? Object.values(bellMap).reduce((sum, count) => sum + count, 0))))
      setTotalInboxUnread(Math.max(0, Number(data.total_inbox_unread ?? Object.values(inboxMap).reduce((sum, count) => sum + count, 0))))
    } catch {
      // 邮件监控摘要不影响账号主列表；后端短暂不可用时保留已有提醒。
    }
  }, [notification])

  const reload = useCallback(() => {
    void loadAccounts()
    void loadStats()
  }, [loadAccounts, loadStats])

  const refreshMemberCapabilities = async (account: GptPlanAccount, quiet = false) => {
    if (memberCapabilityLoadingId === account.id) return memberSourceOf(account, memberSourceOverrides[account.id])
    setMemberCapabilityLoadingId(account.id)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/member-capabilities`) as {
        member_source?: MemberSource | null
        capabilities?: MemberCapabilities | null
      }
      const previous = memberSourceOf(account, memberSourceOverrides[account.id]) || {}
      const incoming = result?.member_source && typeof result.member_source === 'object'
        ? result.member_source
        : {}
      const next: MemberSource = {
        ...previous,
        ...incoming,
        capabilities: incoming.capabilities || result?.capabilities || previous.capabilities || null,
      }
      setMemberSourceOverrides((current) => ({ ...current, [account.id]: next }))
      return next
    } catch (error: unknown) {
      if (!quiet) message.error(`读取账号能力失败：${errorMessage(error, '未知错误')}`)
      return memberSourceOf(account, memberSourceOverrides[account.id])
    } finally {
      setMemberCapabilityLoadingId((current) => current === account.id ? null : current)
    }
  }

  const checkBusinessSession = async (account: GptPlanAccount, quiet = false): Promise<boolean> => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    if (String(source?.source_pool || account.source_pool || '').trim().toLowerCase() !== 'gpt_business') return false
    if (businessSessionCheckInFlightRef.current.has(account.id)) return false
    businessSessionCheckInFlightRef.current.add(account.id)
    setBusinessSessionCheckingIds((current) => [...current, account.id])
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 60_000)
    const applyResult = (result: BusinessSessionCheckResult) => {
      setMemberSourceOverrides((current) => ({
        ...current,
        [account.id]: mergeBusinessSessionSource(memberSourceOf(account, current[account.id]), result),
      }))
      setAccounts((current) => current.map((row) => row.id === account.id
        ? { ...row, member_source: mergeBusinessSessionSource(memberSourceOf(row), result) }
        : row))
    }
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/business-session/check`, {
        method: 'POST',
        signal: controller.signal,
      }) as BusinessSessionCheckResult
      applyResult(result)
      const healthy = result.ok === true && result.session_health?.status === 'valid'
      if (!quiet) {
        if (healthy) message.success(`${account.email} 访问正常`)
        else message.warning(result.session_health?.message || result.error || '会话检查未通过')
      }
      return healthy
    } catch (error: unknown) {
      const payload = error instanceof ApiFetchError ? asRecord(error.payload) : {}
      const detail = asRecord(payload.detail)
      const result = (payload.session_health || payload.member_source ? payload : detail) as BusinessSessionCheckResult
      if (result.session_health || result.member_source) applyResult(result)
      else await loadAccounts(true)
      if (!quiet) message.error(controller.signal.aborted
        ? '会话检查超时，请稍后重试'
        : `会话检查失败：${errorMessage(error, '未知错误')}`)
      return false
    } finally {
      window.clearTimeout(timeout)
      businessSessionCheckInFlightRef.current.delete(account.id)
      setBusinessSessionCheckingIds((current) => current.filter((id) => id !== account.id))
    }
  }

  const refreshBusinessDefaultPaymentMethod = async (account: GptPlanAccount): Promise<boolean> => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    const initialSource = memberSourceOf(account)
    if (String(source?.source_pool || account.source_pool || '').trim().toLowerCase() !== 'gpt_business') return false
    if (businessPaymentRefreshInFlightRef.current.has(account.id)) return false
    businessPaymentRefreshInFlightRef.current.add(account.id)
    setBusinessPaymentRefreshingIds((current) => [...current, account.id])
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 60_000)
    const applyMethod = (method: BusinessDefaultPaymentMethod, sourceValue?: unknown) => {
      const incoming = asRecord(sourceValue)
      const incomingTeam = asRecord(incoming.business_workspace).team_id
      const freshSource = typeof incomingTeam === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(incomingTeam)
        ? incoming as MemberSource : null
      const resultContext = freshSource || initialSource
      const latestRow = businessPaymentAccountsRef.current.find((row) => row.id === account.id)
      const latestSource = latestRow ? memberSourceOf(latestRow) : null
      if (!sameBusinessPaymentContext(latestSource, initialSource)
        && !sameBusinessPaymentContext(latestSource, resultContext)) return
      setMemberSourceOverrides((current) => {
        const previous = memberSourceOf(account, current[account.id])
        if (!sameBusinessPaymentContext(previous, resultContext)) {
          // Do not attach this payment snapshot to another workspace's seats
          // or permissions retained by an earlier capability dialog.
          const next = { ...current }
          delete next[account.id]
          return next
        }
        return { ...current, [account.id]: mergeBusinessPaymentSource(previous, method, freshSource) }
      })
      setAccounts((current) => current.map((row) => {
        if (row.id !== account.id) return row
        const previous = memberSourceOf(row)
        if (!sameBusinessPaymentContext(previous, initialSource)
          && !sameBusinessPaymentContext(previous, resultContext)) return row
        return { ...row, member_source: mergeBusinessPaymentSource(previous, method, freshSource) }
      }))
    }
    const failedMethod = (error: unknown) => sanitizeBusinessDefaultPaymentMethod({
      status: 'error', checked_at: new Date().toISOString(), error,
    })
    try {
      const result = asRecord(await apiFetch(`${API_ROOT}/accounts/${account.id}/business-payment-method/refresh`, {
        method: 'POST',
        signal: controller.signal,
      }))
      const method = Object.keys(asRecord(result.default_payment_method)).length
        ? sanitizeBusinessDefaultPaymentMethod(result.default_payment_method)
        : failedMethod(result.error)
      applyMethod(method, result.member_source)
      return result.ok === true && (method.status === 'ready' || method.status === 'none')
    } catch (error: unknown) {
      const payload = error instanceof ApiFetchError ? asRecord(error.payload) : {}
      const detail = asRecord(payload.detail)
      const result = payload.default_payment_method ? payload : detail
      const method = Object.keys(asRecord(result.default_payment_method)).length
        ? sanitizeBusinessDefaultPaymentMethod(result.default_payment_method)
        : failedMethod(controller.signal.aborted ? 'timeout' : errorMessage(error, ''))
      applyMethod(method, result.member_source)
      return false
    } finally {
      window.clearTimeout(timeout)
      businessPaymentRefreshInFlightRef.current.delete(account.id)
      setBusinessPaymentRefreshingIds((current) => current.filter((id) => id !== account.id))
    }
  }

  const refreshBusinessWorkspace = async (
    account: GptPlanAccount,
    options: { quiet?: boolean; reloadAfter?: boolean; notifyReferrals?: boolean } = {},
  ): Promise<boolean> => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    const sourcePool = String(source?.source_pool || account.source_pool || '').trim().toLowerCase()
    if (sourcePool !== 'gpt_business') {
      if (!options.quiet) message.warning('只有 BUSINESS 母号支持刷新席位')
      return false
    }
    const existingRefresh = businessWorkspaceRefreshInFlightRef.current.get(account.id)
    if (existingRefresh) return await existingRefresh

    let settleRefresh: (value: boolean) => void = () => undefined
    const sharedRefresh = new Promise<boolean>((resolve) => {
      settleRefresh = resolve
    })
    businessWorkspaceRefreshInFlightRef.current.set(account.id, sharedRefresh)
    let refreshSucceeded = false
    setBusinessWorkspaceRefreshingIds((current) => (
      current.includes(account.id) ? current : [...current, account.id]
    ))
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/business-workspace/refresh`,
        { method: 'POST' },
      ) as {
        ok?: boolean
        member_source?: MemberSource | null
        business_workspace?: BusinessWorkspaceCapability | null
        error?: string
      }
      if (result?.ok === false) throw new Error(result.error || '成员刷新失败')

      const previous = memberSourceOf(account, memberSourceOverrides[account.id]) || {}
      const incoming = result?.member_source && typeof result.member_source === 'object'
        ? result.member_source
        : {}
      const incomingWorkspace = incoming.business_workspace
        || (result?.business_workspace && typeof result.business_workspace === 'object'
          ? result.business_workspace
          : null)
      const next: MemberSource = {
        ...previous,
        ...incoming,
        business_workspace: incomingWorkspace
          ? { ...(previous.business_workspace || {}), ...incomingWorkspace }
          : previous.business_workspace || null,
        capabilities: incoming.capabilities || previous.capabilities || null,
      }
      setMemberSourceOverrides((current) => ({ ...current, [account.id]: next }))
      setAccounts((current) => current.map((row) => (
        row.id === account.id ? { ...row, member_source: next } : row
      )))
      if (businessChildrenByAccount[account.id]?.loaded) {
        // 远端刷新是用户明确触发的；成功落库后只再读取一次套餐 facade，
        // 让已经打开的成员详情立即显示同一份新数据库快照。
        try {
          const childrenResult = await apiFetch(`${API_ROOT}/accounts/${account.id}/business-children`)
          const snapshot = sanitizeBusinessChildrenSnapshot(childrenResult)
          setBusinessChildrenByAccount((current) => ({
            ...current,
            [account.id]: { loading: false, loaded: true, error: '', snapshot },
          }))
        } catch {
          // 成员远端刷新已经成功，附属详情区读取失败不能把主操作误报为失败。
        }
      }
      if (options.reloadAfter !== false) {
        await Promise.all([loadAccounts(), loadStats()])
      }
      if (!options.quiet) {
        if (!options.notifyReferrals) message.success(`${account.email} 成员与席位已刷新`)
        else if (next.business_workspace?.workspace_referrals_enabled_visible === false) {
          message.warning(`${account.email} 远端当前不支持设置子号邀请权限`)
        } else if (
          typeof next.business_workspace?.workspace_referrals_enabled !== 'boolean'
          || next.business_workspace?.workspace_referrals_enabled_visible !== true
        ) {
          message.warning('成员与席位已刷新，但未取得该母号的邀请权限，请稍后重试')
        } else message.success(`${account.email} 子号邀请权限已刷新`)
      }
      refreshSucceeded = true
      return true
    } catch (error: unknown) {
      if (!options.quiet) message.error(`刷新成员失败：${errorMessage(error, '未知错误')}`)
      return false
    } finally {
      // 远端 401/403 会更新本地会话诊断；失败后只读取数据库，不重试远端操作。
      if (!refreshSucceeded) await loadAccounts(true)
      if (businessWorkspaceRefreshInFlightRef.current.get(account.id) === sharedRefresh) {
        businessWorkspaceRefreshInFlightRef.current.delete(account.id)
      }
      settleRefresh(refreshSucceeded)
      setBusinessWorkspaceRefreshingIds((current) => current.filter((id) => id !== account.id))
    }
  }

  const saveBusinessWorkspaceReferralsEnabled = async (
    account: GptPlanAccount,
    enabled: boolean,
  ) => {
    if (businessWorkspaceReferralsSavingIds.includes(account.id)) return
    const previous = memberSourceOf(account, memberSourceOverrides[account.id]) || {}
    const previousWorkspace = businessWorkspaceOf(previous) || {}
    const sourcePool = String(previous.source_pool || account.source_pool || '').trim().toLowerCase()
    if (sourcePool !== 'gpt_business') {
      message.warning('只有 BUSINESS 母号支持设置子号邀请权限')
      return
    }
    if (
      typeof previousWorkspace.workspace_referrals_enabled !== 'boolean'
      || previousWorkspace.workspace_referrals_enabled_visible !== true
    ) {
      message.warning('子号邀请权限尚不可设置，请先刷新成员/席位')
      return
    }

    setBusinessWorkspaceReferralsSavingIds((current) => (
      current.includes(account.id) ? current : [...current, account.id]
    ))
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/business-workspace/referrals`,
        {
          method: 'POST',
          body: JSON.stringify({ enabled }),
        },
      ) as {
        ok?: boolean
        error?: string
        enabled?: boolean | null
        workspace_referrals_enabled?: boolean | null
        workspace_referrals_enabled_visible?: boolean | null
        member_source?: MemberSource | null
        business_workspace?: BusinessWorkspaceCapability | null
        account?: GptPlanAccount | null
      }
      if (result?.ok === false) throw new Error(result.error || '子号邀请权限保存失败')

      const incomingSource = result?.member_source
        || (result?.account?.member_source && typeof result.account.member_source === 'object'
          ? result.account.member_source
          : null)
      const incomingWorkspace = incomingSource?.business_workspace
        || (result?.business_workspace && typeof result.business_workspace === 'object'
          ? result.business_workspace
          : null)
      const authoritativeEnabled = typeof incomingWorkspace?.workspace_referrals_enabled === 'boolean'
        ? incomingWorkspace.workspace_referrals_enabled
        : typeof result?.workspace_referrals_enabled === 'boolean'
          ? result.workspace_referrals_enabled
          : typeof result?.enabled === 'boolean' ? result.enabled : null
      if (authoritativeEnabled === null) {
        throw new Error('服务端未返回已保存的远端子号邀请权限')
      }
      const authoritativeVisible = typeof incomingWorkspace?.workspace_referrals_enabled_visible === 'boolean'
        ? incomingWorkspace.workspace_referrals_enabled_visible
        : typeof result?.workspace_referrals_enabled_visible === 'boolean'
          ? result.workspace_referrals_enabled_visible
          : previousWorkspace.workspace_referrals_enabled_visible
      const nextWorkspace: BusinessWorkspaceCapability = {
        ...previousWorkspace,
        ...(incomingWorkspace || {}),
        workspace_referrals_enabled: authoritativeEnabled,
        workspace_referrals_enabled_visible: authoritativeVisible,
      }
      const nextSource: MemberSource = {
        ...previous,
        ...(incomingSource || {}),
        business_workspace: nextWorkspace,
      }
      setMemberSourceOverrides((current) => ({ ...current, [account.id]: nextSource }))
      setAccounts((current) => current.map((row) => (
        row.id === account.id ? { ...row, member_source: nextSource } : row
      )))
      await loadAccounts(true)
      message.success(`已${authoritativeEnabled ? '开启' : '关闭'} ${account.email} 的子号邀请权限`)
    } catch (error: unknown) {
      message.error(`子号邀请权限保存失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setBusinessWorkspaceReferralsSavingIds((current) => current.filter((id) => id !== account.id))
    }
  }

  const loadBusinessChildren = useCallback(async (
    account: GptPlanAccount,
    options: { quiet?: boolean } = {},
  ): Promise<BusinessChildrenSnapshot | null> => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    if (String(source?.source_pool || account.source_pool || '').trim().toLowerCase() !== 'gpt_business') {
      if (!options.quiet) message.warning('只有 BUSINESS 母号支持查看子号')
      return null
    }
    setBusinessChildrenByAccount((current) => ({
      ...current,
      [account.id]: {
        loading: true,
        loaded: current[account.id]?.loaded || false,
        error: '',
        snapshot: current[account.id]?.snapshot || null,
      },
    }))
    try {
      // 套餐 facade 只读取数据库中最后一次确认快照；详情抽屉绝不隐式请求
      // OpenAI，也不把 BUSINESS 母号 Cookie / AT 带进该页面。
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/business-children`)
      const snapshot = sanitizeBusinessChildrenSnapshot(result)
      setBusinessChildrenByAccount((current) => ({
        ...current,
        [account.id]: { loading: false, loaded: true, error: '', snapshot: {
          ...snapshot,
          invite_quota: latestBusinessInviteQuota([
            snapshot.invite_quota, current[account.id]?.snapshot?.invite_quota,
          ]) as BusinessInviteQuota | undefined,
        } },
      }))
      return snapshot
    } catch (error: unknown) {
      const detail = errorMessage(error, '读取子号失败')
      setBusinessChildrenByAccount((current) => ({
        ...current,
        [account.id]: {
          loading: false,
          loaded: true,
          error: detail,
          snapshot: current[account.id]?.snapshot || null,
        },
      }))
      if (!options.quiet) message.error(`读取子号失败：${detail}`)
      return null
    }
  }, [memberSourceOverrides, message])

  const loadBusinessChildCatalog = useCallback(async (silent = false) => {
    if (
      mainTab !== 'accounts'
      || accountType !== 'member'
      || memberPlan !== 'team'
      || businessCatalogView !== 'children'
    ) return
    const generation = ++loadBusinessChildCatalogGenerationRef.current
    if (!silent) setBusinessChildCatalogLoading(true)
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
      })
      if (keyword) params.set('keyword', keyword)
      // 子号接口自身也以“出售”为安全缺省；清空下拉时必须显式传 all，
      // 才能表达用户确实要查看所有用途，而不是再次落回接口缺省值。
      params.set('business_usage_type', standalone ? 'all' : businessChildParentUsageFilter || 'all')
      params.set('two_factor_status', businessChildTwoFactorFilter)
      params.set('rt_status', businessChildRtFilter)
      params.set('sale_status', businessChildSaleFilter)
      const result = await apiFetch(`${API_ROOT}/business-children?${params.toString()}`) as {
        items?: unknown[]
        total?: number
      }
      if (generation !== loadBusinessChildCatalogGenerationRef.current) return
      const rows = (Array.isArray(result.items) ? result.items : [])
        .map(sanitizeBusinessChildCatalogRow)
        .filter((row): row is BusinessChildCatalogRow => Boolean(row))
      setBusinessChildCatalogRows(rows)
      setBusinessChildCatalogTotal(Math.max(0, Number(result.total || 0)))
    } catch (error: unknown) {
      if (generation !== loadBusinessChildCatalogGenerationRef.current) return
      if (!silent) message.error(`加载 BUSINESS 子号失败：${errorMessage(error, '未知错误')}`)
    } finally {
      if (generation === loadBusinessChildCatalogGenerationRef.current) {
        setBusinessChildCatalogLoading(false)
      }
    }
  }, [
    accountType,
    businessCatalogView,
    businessChildParentUsageFilter,
    businessChildRtFilter,
    businessChildSaleFilter,
    businessChildTwoFactorFilter,
    keyword,
    mainTab,
    memberPlan,
    message,
    page,
    pageSize,
    standalone,
  ])

  const businessChildNvCatalogReloadRef = useRef(loadBusinessChildCatalog)
  useEffect(() => {
    businessChildNvCatalogReloadRef.current = loadBusinessChildCatalog
  }, [loadBusinessChildCatalog])

  const openBusinessMotherFromCatalog = (row: BusinessChildCatalogRow) => {
    setBusinessCatalogView('mothers')
    setBusinessMembersAccountId(null)
    setKeywordInput('')
    setKeyword('')
    setLoginStatus(undefined)
    setBusinessSeatFilter(undefined)
    setBusinessUsageFilter(undefined)
    setPage(1)
    setFocusTarget({
      planAccountId: row.parent_account_id,
      accountType: 'member',
      memberPlan: 'team',
      childAccountId: positiveInteger(row.child_id ?? row.pro_account_id) || null,
      membershipId: positiveInteger(row.membership_id) || null,
    })
  }

  const openBusinessChildSaleEditor = (row: BusinessChildCatalogRow) => {
    if (['refunded', 'partial_refund'].includes(row.sale_status || '')) { message.warning('NV 已确认退款，不可通过出售状态编辑覆盖'); return }
    const soldAt = String(row.sold_at || '').trim()
    const parsed = soldAt ? new Date(soldAt) : null
    const localValue = parsed && !Number.isNaN(parsed.getTime())
      ? new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60_000).toISOString().slice(0, 16)
      : ''
    setBusinessChildSaleStatusDraft(
      row.sale_status === 'sold' || soldAt
        ? 'sold'
        : row.sale_status === 'listed' ? 'listed' : 'unlisted',
    )
    setBusinessChildSoldAtDraft(localValue)
    setBusinessChildWarrantyDraft(Math.max(0, Math.floor(Number(row.warranty_hours || 0))))
    setBusinessChildSaleEditor(row)
  }

  const saveBusinessChildSale = async () => {
    const row = businessChildSaleEditor
    const membershipId = positiveInteger(row?.membership_id)
    if (!row || !membershipId || businessChildSaleSaving) return
    let soldAt: string | null = null
    if (businessChildSaleStatusDraft === 'sold' && businessChildSoldAtDraft) {
      const parsed = new Date(businessChildSoldAtDraft)
      if (Number.isNaN(parsed.getTime())) {
        message.warning('请输入有效的出售时间')
        return
      }
      soldAt = parsed.toISOString()
    } else if (businessChildSaleStatusDraft === 'sold') {
      soldAt = new Date().toISOString()
    }
    const warrantyHours = Math.max(0, Math.floor(Number(businessChildWarrantyDraft || 0)))
    setBusinessChildSaleSaving(true)
    try {
      const result = await apiFetch(`${API_ROOT}/business-children/${membershipId}/sale`, {
        method: 'PATCH',
        body: JSON.stringify({
          sale_status: businessChildSaleStatusDraft,
          sold_at: soldAt,
          warranty_hours: warrantyHours,
        }),
      }) as { item?: unknown }
      const updated = sanitizeBusinessChildCatalogRow(result.item)
      if (updated) {
        setBusinessChildCatalogRows((current) => current.map((item) => (
          item.membership_id === updated.membership_id ? updated : item
        )))
      } else {
        await loadBusinessChildCatalog(true)
      }
      setBusinessChildSaleEditor(null)
      message.success(businessChildSaleStatusDraft === 'sold'
        ? '子号已标记为已出售，出售时间与质保已更新'
        : businessChildSaleStatusDraft === 'listed'
          ? '子号已标记为已上架，出售时间已清除'
          : '子号已标记为未上架，出售时间已清除')
      if (businessChildSaleFilter !== 'all') await loadBusinessChildCatalog(true)
    } catch (error: unknown) {
      message.error(`保存出售与质保失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setBusinessChildSaleSaving(false)
    }
  }

  const loadNvTokensConfig = async () => {
    setNvTokensConfigLoading(true)
    try {
      const result = asRecord(await apiFetch(`${API_ROOT}/nvtokens-config`))
      if (result.ok !== true) {
        throw new Error(String(result.detail || result.error || 'NV 设置读取失败'))
      }
      setNvTokensConfig({
        base_url: String(result.base_url || 'https://nvtokens.com'),
        api_key_configured: result.api_key_configured === true,
        query_session_configured: result.query_session_configured === true,
      })
    } catch (error: unknown) {
      message.error(`读取 NV 设置失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setNvTokensConfigLoading(false)
    }
  }

  const openNvTokensConfig = () => {
    setNvTokensApiKeyDraft('')
    setNvTokensQueryCookieDraft('')
    setNvTokensConfigOpen(true)
    void loadNvTokensConfig()
  }

  const saveNvTokensConfig = async () => {
    if (nvTokensConfigSaving) return
    const apiKey = nvTokensApiKeyDraft.trim()
    const queryCookie = nvTokensQueryCookieDraft.trim()
    if (
      !apiKey
      && !nvTokensConfig.api_key_configured
      && !queryCookie
      && !nvTokensConfig.query_session_configured
    ) {
      message.warning('请至少配置 NV 库存 API Key 或查询 Cookie')
      return
    }
    setNvTokensConfigSaving(true)
    try {
      const result = asRecord(await apiFetch(`${API_ROOT}/nvtokens-config`, {
        method: 'PUT',
        body: JSON.stringify({
          api_key: apiKey,
          query_cookie: queryCookie,
        }),
      }))
      const apiKeyConfigured = result.api_key_configured === true
        || (!apiKey && nvTokensConfig.api_key_configured)
      const querySessionConfigured = result.query_session_configured === true
        || (!queryCookie && nvTokensConfig.query_session_configured)
      if (result.ok !== true || (!apiKeyConfigured && !querySessionConfigured)) {
        throw new Error(String(result.detail || result.error || 'NV 设置保存失败'))
      }
      setNvTokensConfig({
        base_url: String(result.base_url || nvTokensConfig.base_url || 'https://nvtokens.com'),
        api_key_configured: apiKeyConfigured,
        query_session_configured: querySessionConfigured,
      })
      setNvTokensApiKeyDraft('')
      setNvTokensQueryCookieDraft('')
      setNvTokensConfigOpen(false)
      message.success(apiKey || queryCookie ? 'NV 设置已安全保存' : 'NV 设置已保留')
    } catch (error: unknown) {
      message.error(`保存 NV 设置失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setNvTokensConfigSaving(false)
    }
  }

  const refreshBusinessChildNvSales = async () => {
    if (businessChildNvSalesRefreshInFlightRef.current) return
    businessChildNvSalesRefreshInFlightRef.current = true
    setBusinessChildNvSalesRefreshing(true)
    try {
      const result = asRecord(await apiFetch(
        `${API_ROOT}/business-children/nexusvault-sales-refresh`,
        { method: 'POST' },
      ))
      if (result.ok !== true) {
        throw new Error(String(result.detail || result.error || 'NV 出库状态刷新失败'))
      }
      const salesResult = sanitizeBusinessChildNvSalesResult(result)
      setBusinessChildNvSalesResult(salesResult)
      setBusinessChildNvSalesResultOpen(true)
      await loadBusinessChildCatalog(true)
      if (salesResult.classified && salesResult.legacy_classified) message.success('出库状态刷新完成，请查看核对结果')
      else message.warning('出库状态刷新完成，但当前后端分类尚未升级，请查看说明')
    } catch (error: unknown) {
      message.error(`刷新出库状态失败：${errorMessage(error, '未知错误')}`)
    } finally {
      businessChildNvSalesRefreshInFlightRef.current = false
      setBusinessChildNvSalesRefreshing(false)
    }
  }

  const openBusinessChildNvListing = (
    account: GptPlanAccount,
    child: BusinessChildDisplayRow,
  ) => {
    setBusinessChildNvPriceDraft(null)
    setBusinessChildNvWarrantyUntilDraft('')
    setBusinessChildNvListingTarget({ account, child })
  }

  const saveBusinessChildNvListing = async () => {
    const target = businessChildNvListingTarget
    const membershipId = positiveInteger(target?.child.membership_id)
    const rawPrice = Number(businessChildNvPriceDraft)
    if (!target || !membershipId || businessChildNvListingSaving) return
    if (!Number.isFinite(rawPrice) || rawPrice <= 0) {
      message.warning('请输入大于 0 的上架价格')
      return
    }
    const priceYuan = Number(rawPrice.toFixed(2))
    const warrantyHours = 1
    const team5xWarrantyUntil = businessChildNvNeedsWarranty ? businessChildNvWarrantyUntil(businessChildNvWarrantyUntilDraft) : null
    if (businessChildNvNeedsWarranty && !team5xWarrantyUntil) {
      message.warning('请输入未来的 5X 质保截止时间（北京时间）')
      return
    }
    setBusinessChildNvListingSaving(true)
    try {
      const rawResult = await apiFetch(
        `${API_ROOT}/business-children/${membershipId}/nvtokens-listing`,
        {
          method: 'POST',
          body: JSON.stringify({
            price_yuan: priceYuan,
            warranty_hours: warrantyHours,
            ...(team5xWarrantyUntil ? { team5x_warranty: { mode: 'until', until: team5xWarrantyUntil } } : {}),
          }),
        },
      )
      const result = asRecord(rawResult)
      const published = nonNegativeNumber(
        result.published ?? asRecord(result.summary).published,
      ) ?? 0
      if (result.ok !== true || published !== 1) {
        const detail = String(
          result.detail || result.error || result.message || 'NV 未确认凭证已经成功入池',
        )
        throw new Error(detail)
      }

      const returnedItem = asRecord(result.item)
      const listingPatch: Partial<BusinessManagedChild> = {
        ...returnedItem,
        sale_status: 'listed',
        sold_at: null,
        warranty_hours: Math.max(
          businessChildNvNeedsWarranty ? 0 : 1,
          Math.floor(Number(returnedItem.warranty_hours ?? (businessChildNvNeedsWarranty ? 0 : warrantyHours))),
        ),
      }
      const targetChildId = positiveInteger(
        target.child.pro_account_id ?? target.child.managed_pro_account_id,
      )
      const targetEmail = String(target.child.email || '').trim().toLowerCase()
      const matchesTarget = (row: BusinessManagedChild) => (
        positiveInteger(row.membership_id) === membershipId
        || Boolean(
          targetChildId
          && positiveInteger(row.pro_account_id ?? row.managed_pro_account_id) === targetChildId,
        )
        || Boolean(
          targetEmail
          && String(row.email || '').trim().toLowerCase() === targetEmail,
        )
      )
      const updateRows = (rows: BusinessManagedChild[] | undefined) => (
        rows?.map((row) => matchesTarget(row) ? { ...row, ...listingPatch } : row)
      )

      setBusinessChildCatalogRows((current) => current.map((row) => (
        positiveInteger(row.membership_id) === membershipId
          ? { ...row, ...listingPatch }
          : row
      )))
      setBusinessChildrenByAccount((current) => {
        const view = current[target.account.id]
        if (!view?.snapshot) return current
        return {
          ...current,
          [target.account.id]: {
            ...view,
            snapshot: {
              ...view.snapshot,
              members: updateRows(view.snapshot.members),
              invites: updateRows(view.snapshot.invites),
              managed_children: updateRows(view.snapshot.managed_children),
            },
          },
        }
      })
      setBusinessChildNvListingTarget(null)
      message.success(`NV 上架成功：¥${priceYuan.toFixed(2)} · ${team5xWarrantyUntil ? `5X 质保截止 ${businessChildNvWarrantyUntilDraft.replace('T', ' ')}（北京时间）` : `质保 ${warrantyHours} 小时`}`)
      if (businessChildSaleFilter !== 'all') void loadBusinessChildCatalog(true)
    } catch (error: unknown) {
      message.error(`NV 上架失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setBusinessChildNvListingSaving(false)
    }
  }

  const applyBusinessChildNvBatchSnapshot = (task: BusinessChildNvBatchTask) => {
    setBusinessChildNvBatchTask(task)
    setBusinessChildNvBatchPollingError('')
    setBusinessChildNvBatchPollingStopped(false)
    setBusinessChildNvBatchUnavailable(false)
    const newlyListedIds = new Set(task.items.filter((item) => (
      item.status === 'success' && !businessChildNvBatchConfirmedRef.current.has(item.membership_id)
    )).map((item) => item.membership_id))
    if (newlyListedIds.size) {
      newlyListedIds.forEach((id) => businessChildNvBatchConfirmedRef.current.add(id))
      const updateRow = <T extends BusinessManagedChild,>(row: T): T => (
        newlyListedIds.has(Number(row.membership_id))
          ? { ...row, sale_status: 'listed', sold_at: null, warranty_hours: businessChildSeatType(row) === 'prolite' ? 0 : 1 }
          : row
      )
      setBusinessChildCatalogRows((current) => current.map(updateRow))
      setBusinessChildrenByAccount((current) => Object.fromEntries(Object.entries(current).map(([id, view]) => [
        id,
        view.snapshot ? {
          ...view,
          snapshot: {
            ...view.snapshot,
            members: view.snapshot.members?.map(updateRow),
            invites: view.snapshot.invites?.map(updateRow),
            managed_children: view.snapshot.managed_children?.map(updateRow),
          },
        } : view,
      ])))
    }
    if (newlyListedIds.size || task.status !== 'running') {
      void businessChildNvCatalogReloadRef.current(true)
    }
    if (task.status !== 'running') {
      if (task.status === 'failed') message.error(`批量上架 NV 失败：${task.error || '请查看账号明细'}`)
      else if (task.failed) message.warning(`批量上架 NV 完成：成功 ${task.succeeded}，失败 ${task.failed}，跳过 ${task.skipped}`)
      else message.success(`批量上架 NV 完成：成功 ${task.succeeded}，跳过 ${task.skipped}`)
    }
  }

  const openBusinessChildNvBatchListing = () => {
    if (businessChildNvBatchStartingRef.current || businessChildNvBatchTask?.status === 'running') {
      setBusinessChildNvBatchTaskOpen(true)
      return
    }
    const targets = [...new Set(selectedBusinessChildMembershipIds)]
      .filter((id) => Number.isInteger(id) && id > 0)
      .map((id) => ({
        membership_id: id,
        email: businessChildCatalogRows.find((row) => Number(row.membership_id) === id)?.email || `子号 #${id}`,
        seat_type: businessChildSeatType(businessChildCatalogRows.find((row) => Number(row.membership_id) === id) || {}),
      }))
    if (!targets.length) return
    setBusinessChildNvBatchTargets(targets)
    setBusinessChildNvBatchPriceDraft(null)
    setBusinessChildNvBatchWarrantyUntilDraft('')
  }

  const startBusinessChildNvBatchListing = async () => {
    if (businessChildNvBatchStartingRef.current || businessChildNvBatchTask?.status === 'running') return
    const rawPrice = Number(businessChildNvBatchPriceDraft)
    if (!businessChildNvBatchTargets?.length) return
    if (!Number.isFinite(rawPrice) || rawPrice < 0.01 || rawPrice > 1_000_000) {
      message.warning('请输入 0.01 至 1,000,000 元之间的上架价格')
      return
    }
    const team5xWarrantyUntil = businessChildNvBatchNeedsWarranty ? businessChildNvWarrantyUntil(businessChildNvBatchWarrantyUntilDraft) : null
    if (businessChildNvBatchNeedsWarranty && !team5xWarrantyUntil) {
      message.warning('请输入未来的 5X 质保截止时间（北京时间）')
      return
    }
    businessChildNvBatchStartingRef.current = true
    setBusinessChildNvBatchStarting(true)
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 30_000)
    try {
      const result = await apiFetch(`${API_ROOT}/business-children/nvtokens-listing-tasks`, {
        method: 'POST',
        signal: controller.signal,
        body: JSON.stringify({
          membership_ids: businessChildNvBatchTargets.map((item) => item.membership_id),
          price_yuan: rawPrice.toFixed(2),
          warranty_hours: 1,
          ...(team5xWarrantyUntil ? { team5x_warranty: { mode: 'until', until: team5xWarrantyUntil } } : {}),
        }),
      })
      const task = sanitizeBusinessChildNvBatchTask(result)
      try { sessionStorage.setItem(BUSINESS_CHILD_NV_BATCH_TASK_STORAGE_KEY, task.task_id) } catch { /* ignore */ }
      businessChildNvBatchConfirmedRef.current.clear()
      applyBusinessChildNvBatchSnapshot(task)
      setBusinessChildNvBatchTargets(null)
      setBusinessChildNvBatchTaskOpen(true)
    } catch (error: unknown) {
      const payload = error instanceof ApiFetchError ? asRecord(error.payload) : {}
      const existingTaskId = String(asRecord(payload.detail).existing_task_id || payload.existing_task_id || '').trim()
      if (error instanceof ApiFetchError && error.status === 409 && existingTaskId) {
        try { sessionStorage.setItem(BUSINESS_CHILD_NV_BATCH_TASK_STORAGE_KEY, existingTaskId) } catch { /* ignore */ }
        businessChildNvBatchConfirmedRef.current.clear()
        setBusinessChildNvBatchTask(sanitizeBusinessChildNvBatchTask({ task_id: existingTaskId, status: 'running' }))
        setBusinessChildNvBatchPollingError('')
        setBusinessChildNvBatchPollingStopped(false)
        setBusinessChildNvBatchUnavailable(false)
        setBusinessChildNvBatchTargets(null)
        setBusinessChildNvBatchTaskOpen(true)
        message.info('已有批量上架 NV 任务，已恢复查看进度')
      } else {
        message.error(controller.signal.aborted
          ? '创建任务请求超时，尚未取得任务状态。请先核对上架状态后再重试。'
          : `启动批量上架 NV 失败：${errorMessage(error, '未知错误')}`)
      }
    } finally {
      window.clearTimeout(timeout)
      businessChildNvBatchStartingRef.current = false
      setBusinessChildNvBatchStarting(false)
    }
  }

  const openBusinessMembers = useCallback((account: GptPlanAccount) => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    if (String(source?.source_pool || account.source_pool || '').trim().toLowerCase() !== 'gpt_business') {
      message.warning('只有 BUSINESS 母号支持查看成员')
      return
    }
    setBusinessMembersAccountId(account.id)
    const childView = businessChildrenByAccount[account.id]
    if (!childView?.loaded && !childView?.loading) {
      void loadBusinessChildren(account)
    }
  }, [businessChildrenByAccount, loadBusinessChildren, memberSourceOverrides, message])

  useEffect(() => {
    if (!focusTarget || loading || accountType !== focusTarget.accountType) return
    const expectedLoadSignature = `${focusTarget.planAccountId}:${focusTarget.accountType}:${focusTarget.memberPlan || ''}`
    if (loadedFocusSignature !== expectedLoadSignature) return
    const signature = [
      focusTarget.planAccountId,
      focusTarget.accountType,
      focusTarget.memberPlan,
      focusTarget.childAccountId || 0,
      focusTarget.membershipId || 0,
    ].join(':')
    if (completedFocusRouteRef.current === signature) return

    const account = accounts.find((row) => row.id === focusTarget.planAccountId)
    if (!account) {
      if (total > 0) return
      completedFocusRouteRef.current = signature
      message.warning('设备账号对应的 GPT 套餐记录已不存在或已不在当前分类')
      setFocusTarget(null)
      clearFocusRouteParams()
      return
    }

    if (focusTarget.accountType === 'member' && focusTarget.memberPlan === 'team') {
      setBusinessMembersAccountId(account.id)
      const childView = businessChildrenByAccount[account.id]
      if (!childView?.loaded && !childView?.loading) {
        void loadBusinessChildren(account, { quiet: true })
      }
      if (focusTarget.childAccountId || focusTarget.membershipId) {
        if (!childView?.loaded) return
        if (!childView.snapshot) {
          message.warning('已定位 BUSINESS 母号，但暂时无法读取子号快照')
        } else if (!businessSnapshotHasFocusedChild(childView.snapshot, focusTarget)) {
          message.warning('已定位 BUSINESS 母号，但目标子号不在当前成员快照中')
        }
      }
    }

    completedFocusRouteRef.current = signature
    clearFocusRouteParams()
    window.setTimeout(() => {
      const childSelector = focusTarget.childAccountId
        ? `[data-business-child-account-id="${focusTarget.childAccountId}"]`
        : focusTarget.membershipId
          ? `[data-business-membership-id="${focusTarget.membershipId}"]`
          : ''
      const childRow = childSelector ? document.querySelector(childSelector) : null
      const accountRow = document.querySelector(`[data-row-key="${account.id}"]`)
      ;(childRow || accountRow)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }, 80)
  }, [
    accountType,
    accounts,
    businessChildrenByAccount,
    clearFocusRouteParams,
    focusTarget,
    loadBusinessChildren,
    loadedFocusSignature,
    loading,
    message,
    total,
  ])

  const loadBusinessChildCandidates = useCallback(async (accountId: number, provider: BusinessInviteMailProvider, seatType?: BusinessInviteSeatType) => {
    const generation = ++businessInviteCandidateGeneration.current
    setBusinessInviteCandidatesLoading(true)
    try {
      let currentPage = 1
      let total = 0
      const items: BusinessManagedChild[] = []
      do {
        const result = await apiFetch(
          `${API_ROOT}/accounts/${accountId}/business-child-candidates?page=${currentPage}&page_size=500&candidate_mail_provider=${provider}${seatType ? `&seat_type=${seatType}` : ''}`,
        ) as { items?: unknown[]; total?: number }
        if (generation !== businessInviteCandidateGeneration.current) return
        const rawItems = Array.isArray(result?.items) ? result.items : []
        items.push(...rawItems
          .map(sanitizeBusinessChild)
          .filter((row): row is BusinessManagedChild => Boolean(row?.pro_account_id && row.email)))
        total = Math.max(0, Number(result?.total || 0))
        currentPage += 1
        if (!rawItems.length) break
      } while (items.length < total)
      setBusinessInviteCandidates(items)
    } catch (error: unknown) {
      if (generation !== businessInviteCandidateGeneration.current) return
      setBusinessInviteCandidates([])
      message.error(`读取可邀请子号失败：${errorMessage(error, '未知错误')}`)
    } finally {
      if (generation === businessInviteCandidateGeneration.current) setBusinessInviteCandidatesLoading(false)
    }
  }, [message])

  const openBusinessInvite = (account: GptPlanAccount) => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    const availability = businessInviteButtonState(
      account,
      source,
      businessChildrenByAccount[account.id],
    )
    if (availability.disabled) {
      message.warning(availability.reason)
      return
    }
    setBusinessInviteAccount(account)
    setBusinessInviteMode('pool')
    setBusinessInviteMailProvider(standalone ? 'gmail' : 'auto')
    setBusinessInviteSelectedChildId(undefined)
    setBusinessInviteManualEmail('')
    const seat = businessChildrenByAccount[account.id]?.snapshot?.seat_summary
      || businessSeatSummaryOf(source)
    const ordinaryAvailable = businessSeatAvailable(seat, businessSeatCapacity(seat, 'default')) || 0
    const advancedAvailable = businessSeatAvailable(seat, businessSeatCapacity(seat, 'prolite')) || 0
    setBusinessInviteSeatType(ordinaryAvailable > 0 ? 'default' : advancedAvailable > 0 ? 'prolite' : 'default')
    setBusinessInviteCount(1)
    setBusinessInviteProgress({ stage: 'idle' })
    setBusinessInviteCandidates([])
    // 两个请求都只读本地数据库，候选按后端返回顺序保留准备号优先、普通号补充。
    void loadBusinessChildren(account, { quiet: true })
  }

  const setBusinessChildActionBusy = (key: string, busy: boolean) => {
    setBusinessChildActionBusyKeys((current) => {
      if (busy) return current.includes(key) ? current : [...current, key]
      return current.filter((item) => item !== key)
    })
  }

  const stopBusinessChildRtPoll = (accountId: number, childId: number) => {
    if (businessChildRtTimerRef.current !== undefined) {
      window.clearTimeout(businessChildRtTimerRef.current)
    }
    businessChildRtTimerRef.current = undefined
    businessChildRtActiveKeyRef.current = ''
    setBusinessChildActionBusy(`oauth:${accountId}:${childId}`, false)
  }

  const scheduleBusinessChildRtPoll = (
    account: GptPlanAccount,
    childId: number,
    taskId: string,
    generation: number,
    delay = 1200,
    transientFailureCount = 0,
  ) => {
    if (businessChildRtTimerRef.current !== undefined) {
      window.clearTimeout(businessChildRtTimerRef.current)
    }
    businessChildRtTimerRef.current = window.setTimeout(async () => {
      if (businessChildRtGenerationRef.current !== generation) return
      try {
        const snapshot = await apiFetch(
          `${API_ROOT}/accounts/${account.id}/business-child-oauth/${childId}/${encodeURIComponent(taskId)}`,
        ) as {
          status?: string
          rt_status?: string
          logs?: unknown[]
          result?: Record<string, unknown> | null
          error?: string
        }
        if (businessChildRtGenerationRef.current !== generation) return
        const result = asRecord(snapshot?.result)
        const status = String(snapshot?.status || snapshot?.rt_status || result.status || 'running')
          .trim().toLowerCase()
        const stage = safeBusinessChildRtLog(
          result.stage || result.rt_status || snapshot?.rt_status || status || 'running',
        )
        setBusinessChildRtTask((current) => current?.taskId === taskId ? {
          ...current,
          stage,
          logs: mergeBusinessChildRtLogs(current.logs, snapshot?.logs),
          error: undefined,
        } : current)
        if (['running', 'pending', 'queued', 'starting', 'processing'].includes(status)) {
          // A successful status read resets the transient network/server failure budget.
          scheduleBusinessChildRtPoll(account, childId, taskId, generation, 1600, 0)
          return
        }
        stopBusinessChildRtPoll(account.id, childId)
        if (['success', 'succeeded', 'done', 'completed', 'ready'].includes(status)) {
          setBusinessChildRtTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'success',
            stage,
          } : current)
          const completedEmail = String(result.email || '').trim()
          message.success(`${completedEmail ? `${completedEmail} ` : ''}子号 RT 获取成功`)
          // 后端只会在 RT 已提交数据库后把任务标为成功。先据此更新当前详情项，
          // 让 CPA / SUB 下载立即出现；不能把凭证可用性串行依赖到耗时的远端
          // BUSINESS 成员刷新上。
          const acquiredAt = String(result.acquired_at || new Date().toISOString()).trim()
          setBusinessChildrenByAccount((current) => {
            const view = current[account.id]
            if (!view?.snapshot) return current
            const markReady = (rows: BusinessManagedChild[] | undefined) => rows?.map((row) => (
              positiveInteger(row.pro_account_id ?? row.managed_pro_account_id) === childId
                ? { ...row, has_codex_rt: true, codex_rt_acquired_at: acquiredAt }
                : row
            ))
            return {
              ...current,
              [account.id]: {
                ...view,
                snapshot: {
                  ...view.snapshot,
                  members: markReady(view.snapshot.members),
                  invites: markReady(view.snapshot.invites),
                  managed_children: markReady(view.snapshot.managed_children),
                },
              },
            }
          })

          // 先从本地数据库重读一次权威子号记录。这个接口不访问 OpenAI，
          // 因而即使后续远端成员对账失败，下载按钮也不需要人工刷新页面。
          const localSnapshot = await loadBusinessChildren(account, { quiet: true })
          if (!localSnapshot) {
            message.warning('子号 RT 已保存；本地子号状态暂时读取失败，当前仍可直接下载凭证')
          }

          // 新后端在共用 OAuth 流程中完成成员对账；旧服务仍由前端补做刷新。
          if (typeof result.workspace_refreshed === 'boolean') {
            const warning = String(result.workspace_refresh_warning || '').trim()
            if (!result.workspace_refreshed || warning) {
              message.warning(warning || '子号 RT 已保存，但 BUSINESS 成员状态未同步，请稍后刷新母号成员')
            }
          } else {
            const workspaceRefreshed = await refreshBusinessWorkspace(account, {
              quiet: true,
              reloadAfter: false,
            }).catch(() => false)
            if (!workspaceRefreshed) {
              message.warning('子号 RT 已保存，但 BUSINESS 成员远端刷新失败；请稍后点击母号“刷新”，远端确认已加入后即可下载或同步')
            }
          }
        } else {
          const detail = safeBusinessChildRtLog(snapshot?.error || result.error || '子号 RT 获取失败')
          setBusinessChildRtTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'failed',
            stage,
            error: detail,
          } : current)
          message.error(`子号 RT 获取失败：${detail}`)
        }
        setMemberSourceOverrides({})
        // 终态后的列表刷新也不能反向改变已经判定的 RT 成败。
        await Promise.allSettled([
          loadBusinessChildren(account, { quiet: true }),
          loadAccounts(),
          loadStats(),
          loadBusinessChildCatalog(true),
        ])
      } catch (error: unknown) {
        if (businessChildRtGenerationRef.current !== generation) return
        const detail = safeBusinessChildRtLog(errorMessage(error, '状态读取暂时失败'))
        const apiStatus = error instanceof ApiFetchError ? error.status : 0
        const clientError = apiStatus >= 400 && apiStatus < 500
        const retryableError = !(error instanceof ApiFetchError) || apiStatus >= 500
        const nextFailureCount = transientFailureCount + 1

        if (
          clientError
          || !retryableError
          || nextFailureCount > BUSINESS_CHILD_RT_POLL_MAX_RETRIES
        ) {
          stopBusinessChildRtPoll(account.id, childId)
          const failure = clientError
            ? `状态读取被拒绝（HTTP ${apiStatus}）：${detail}`
            : `状态连续读取失败，已停止重试：${detail}`
          setBusinessChildRtTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'failed',
            stage: 'poll_failed',
            error: failure,
            logs: mergeBusinessChildRtLogs(current.logs, [failure]),
          } : current)
          message.error(`子号 RT 获取失败：${failure}`)
          // 状态接口可能因为账号刚被后端标记为 Dead 而返回 4xx；及时刷新
          // 子号能力，让“登录复核”等后续操作立即可用。
          void Promise.all([
            loadBusinessChildren(account, { quiet: true }),
            loadAccounts(),
            loadStats(),
            loadBusinessChildCatalog(true),
          ]).catch(() => undefined)
          return
        }

        const retryLog = `状态读取暂时失败，第 ${nextFailureCount}/${BUSINESS_CHILD_RT_POLL_MAX_RETRIES} 次重试：${detail}`
        setBusinessChildRtTask((current) => current?.taskId === taskId ? {
          ...current,
          stage: 'poll_retry',
          logs: mergeBusinessChildRtLogs(current.logs, [retryLog]),
        } : current)
        scheduleBusinessChildRtPoll(
          account,
          childId,
          taskId,
          generation,
          3500,
          nextFailureCount,
        )
      }
    }, delay)
  }

  const startBusinessChildRtPoll = (
    account: GptPlanAccount,
    result: Record<string, unknown>,
  ) => {
    const taskId = String(result.rt_task_id || '').trim()
    const childId = positiveInteger(result.rt_child_id)
    if (!taskId || !childId) return
    const activeKey = `${account.id}:${childId}:${taskId}`
    if (businessChildRtActiveKeyRef.current === activeKey) return
    if (businessChildRtTimerRef.current !== undefined) {
      window.clearTimeout(businessChildRtTimerRef.current)
    }
    const generation = businessChildRtGenerationRef.current + 1
    businessChildRtGenerationRef.current = generation
    businessChildRtActiveKeyRef.current = activeKey
    const task: BusinessChildRtTask = {
      accountId: account.id,
      parentEmail: account.email,
      childId,
      childEmail: String(result.child_email || result.email || ''),
      taskId,
      reacquire: result.rt_reacquire === true,
      status: 'running',
      stage: safeBusinessChildRtLog(result.rt_status || 'queued'),
      logs: [],
    }
    setBusinessChildRtTask(task)
    setBusinessChildRtTaskOpen(true)
    message.info(`正在为 ${task.childEmail || '该子号'} ${task.reacquire ? '重取' : '获取'} RT`)
    scheduleBusinessChildRtPoll(account, childId, taskId, generation, 300)
  }

  const startBusinessChildOAuth = async (
    account: GptPlanAccount,
    child: BusinessChildDisplayRow,
  ) => {
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号池 ID')
      return
    }
    if (
      businessChildRtTask?.status === 'running'
      || businessChildActionBusyKeys.some((key) => key.startsWith('oauth:'))
    ) {
      setBusinessChildRtTaskOpen(true)
      message.warning('已有子号 RT 任务正在运行，请等待完成后再操作')
      return
    }
    const busyKey = `oauth:${account.id}:${childId}`
    setBusinessChildActionBusy(busyKey, true)
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/business-child-oauth/${childId}`,
        { method: 'POST', body: JSON.stringify({}) },
      ) as Record<string, unknown>
      if (result?.ok === false) throw new Error(String(result.error || '任务启动失败'))
      const taskId = String(result.task_id || result.rt_task_id || '').trim()
      if (!taskId) throw new Error('后端未返回子号 RT 任务 ID')
      startBusinessChildRtPoll(account, {
        ...result,
        rt_task_id: taskId,
        rt_child_id: childId,
        child_email: child.email,
        rt_status: result.status || result.rt_status || 'running',
        rt_reacquire: child.has_codex_rt === true,
      })
    } catch (error: unknown) {
      setBusinessChildActionBusy(busyKey, false)
      message.error(`启动子号 RT 失败：${errorMessage(error, '未知错误')}`)
    }
  }

  const finishBusinessInvite = async (account: GptPlanAccount, result: Record<string, unknown>) => {
    const invited = Array.isArray(result.invited) ? result.invited.length : 0
    const errorItems = Array.isArray(result.errored)
      ? result.errored.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      : []
    const failed = Math.max(
      errorItems.length,
      result.action_required || result.partial ? 1 : 0,
    )
    if (failed > 0) {
      const warning = String(
        result.warning
        || result.message
        || '邀请失败，请检查账号、席位和冷却状态后重新发送',
      )
      const details = errorItems.map((item) => {
        const email = String(item.email || '').trim()
        const error = String(item.error || '远端拒绝邀请').trim()
        return `${email ? `${email}：` : ''}${error}`
      })
      modal.error({
        title: `邀请失败：成功 ${invited} · 失败 ${failed}`,
        width: 560,
        content: (
          <Space direction="vertical" size={8} style={{ width: '100%' }}>
            <Typography.Text>{warning}</Typography.Text>
            {details.map((detail) => (
              <Typography.Text key={detail} type="danger">{detail}</Typography.Text>
            ))}
          </Space>
        ),
      })
      setBusinessInviteProgress({
        stage: 'failed',
        detail: String(result.warning || result.message || '远端返回邀请失败，请查看失败明细'),
      })
    } else {
      message.success(`邀请成功${invited ? `：${invited} 个子号` : ''}`)
      setBusinessInviteProgress({ stage: 'refreshing', detail: '邀请已返回，正在刷新工作区成员与席位' })
      setBusinessInviteAccount(null)
    }
    // 新增/邀请操作结束后主动读取一次远端成员与席位并写回数据库；详情区随后
    // 只读取这份确认快照，不会把“刷新列表”误当作远端成员刷新。
    const workspaceRefreshed = await refreshBusinessWorkspace(account, {
      quiet: true,
      reloadAfter: false,
    })
    if (!workspaceRefreshed) {
      message.warning('邀请已结束，但工作区成员刷新失败；请在母号详情顶部点击“刷新成员/席位”重试')
    }
    await Promise.all([
      loadBusinessChildren(account, { quiet: true }),
      loadAccounts(),
      loadStats(),
    ])
  }

  const submitBusinessInvite = async () => {
    const account = businessInviteAccount
    if (!account || businessInviting) return
    const view = businessChildrenByAccount[account.id]
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    const availability = businessInviteButtonState(account, source, view)
    if (availability.disabled) {
      message.warning(availability.reason)
      return
    }
    if (standalone) {
      if (businessInviteCount < 1 || businessInviteCount > businessInviteSelectedTypeAvailable) {
        message.warning(`该席位类型当前最多可邀请 ${businessInviteSelectedTypeAvailable} 个子号`)
        return
      }
      if (businessBatchInviteTask && !['done', 'failed'].includes(businessBatchInviteTask.status)) {
        setBusinessBatchInviteTaskOpen(true)
        message.info('已有子号准备与批量邀请任务正在执行')
        return
      }
      setBusinessInviting(true)
      setBusinessInviteProgress({ stage: 'preflight', detail: '正在冻结席位、Gmail 子号和不同代理' })
      const generation = businessBatchInviteGenerationRef.current + 1
      businessBatchInviteGenerationRef.current = generation
      try {
        const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/prepared-batch-invite-tasks`, {
          method: 'POST',
          body: JSON.stringify({
            seat_type: businessInviteSeatType,
            count: businessInviteCount,
            post_acquire_rt: true,
          }),
        }) as Record<string, unknown>
        const taskId = String(result.task_id || '').trim()
        if (!taskId) throw new Error('后端未返回批量邀请任务 ID')
        try { localStorage.setItem(BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY, taskId) } catch { /* ignore */ }
        setBusinessBatchInviteTask(mergeBusinessBatchInviteTask(null, result, taskId))
        setBusinessBatchInviteTaskOpen(true)
        setBusinessInviteProgress({ stage: 'success', detail: '任务已启动：并发完成注册、密码和 2FA，一次性批量邀请后自动获取 RT' })
        setBusinessInviteAccount(null)
        message.info(`已启动 ${businessInviteCount} 个子号的并发准备、统一邀请与自动 RT`)
        scheduleBusinessBatchInvitePoll(taskId, generation, businessBatchCount(result.since), 500)
      } catch (error: unknown) {
        const payload = error instanceof ApiFetchError ? asRecord(error.payload) : {}
        const detailPayload = asRecord(payload.detail)
        const existingTaskId = String(detailPayload.existing_task_id || '').trim()
        if (error instanceof ApiFetchError && error.status === 409 && existingTaskId) {
          setBusinessBatchInviteTaskOpen(true)
          scheduleBusinessBatchInvitePoll(existingTaskId, generation, 0, 200)
          message.info('已有批量邀请任务，已继续读取其进度')
        } else {
          const detail = errorMessage(error, '未知错误')
          setBusinessInviteProgress({ stage: 'failed', detail })
          message.error(`启动子号准备失败：${detail}`)
        }
      } finally {
        setBusinessInviting(false)
      }
      return
    }
    const manualEmail = businessInviteManualEmail.trim().toLowerCase()
    if (businessInviteMode === 'manual' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(manualEmail)) {
      message.warning('请输入一个有效的子号邮箱')
      return
    }
    if (businessInviteMode === 'pool' && businessInviteSelectedChildId !== undefined && !selectedBusinessInviteCandidate) {
      setBusinessInviteProgress({ stage: 'failed', detail: '所选子号已不在当前候选范围，请重新选择，或清空选择以自动选号' })
      message.warning('所选子号已不可用，请重新选择或清空选择以自动选号')
      return
    }
    setBusinessInviting(true)
    setBusinessInviteProgress({ stage: 'preflight', detail: '正在复核母号会话、席位类型和邀请额度' })
    if (businessInviteMode === 'pool') {
      setBusinessInviteProgress({
        stage: 'preflight',
        detail: selectedBusinessInviteCandidate
          ? `正在核验所选子号 ${selectedBusinessInviteCandidate.email}、母号会话、席位类型和邀请额度`
          : standalone ? '正在复核邀请条件，将从 Gmail 普通账号中自动选择可用子号' : '正在复核邀请条件，将按当前邮箱类型自动选择可用子号，准备号优先、普通号补充',
      })
    }
    let inviteFailed = false
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 180_000)
    try {
      setBusinessInviteProgress({
        stage: 'inviting',
        detail: businessInviteMode === 'manual'
          ? '正在核验邀请条件并发送邀请；此阶段可能需要等待远端响应'
          : selectedBusinessInviteCandidate
            ? `正在核验所选子号 ${selectedBusinessInviteCandidate.email}，通过后发送邀请`
            : '正在自动选择并核验可用子号，通过后发送邀请；此阶段可能需要等待登录及远端响应',
      })
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/business-invite`, {
        method: 'POST',
        signal: controller.signal,
        body: JSON.stringify({
          ...(businessInviteMode === 'manual'
            ? { manual_email: manualEmail }
            : {
                ...(businessInviteSelectedChildId !== undefined
                  ? { pro_account_id: businessInviteSelectedChildId }
                  : {}),
                candidate_mail_provider: businessInviteMailProvider,
              }),
        }),
      }) as Record<string, unknown>
      // 母号邀请 API 返回即结束本次请求；接受邀请与 RT 属于子号独立能力。
      await finishBusinessInvite(account, result)
    } catch (error: unknown) {
      inviteFailed = true
      const timedOut = error instanceof DOMException && error.name === 'AbortError'
      const detail = timedOut
        ? '邀请请求超过 3 分钟未返回。服务端可能仍在处理，请先刷新工作区成员后再重试。'
        : errorMessage(error, '未知错误')
      setBusinessInviteProgress({ stage: 'failed', detail })
      message.error(`邀请子号失败：${detail}`)
      if (timedOut) {
        // The browser request can time out while the server is still finishing
        // the remote mutation. Reconcile once automatically before releasing
        // the busy state, so a successful remote invite is visible without a
        // second manual click (which could duplicate the invitation).
        setBusinessInviteProgress({ stage: 'refreshing', detail: '请求超时，正在自动核对远端成员与席位状态' })
        const reconciled = await refreshBusinessWorkspace(account, { quiet: true, reloadAfter: false })
        await loadBusinessChildren(account, { quiet: true })
        if (reconciled) {
          setBusinessInviteProgress({ stage: 'success', detail: '已完成自动核对，请查看工作区成员列表确认结果' })
          message.info('邀请请求超时，已自动核对工作区状态；请以成员列表为准')
        } else {
          setBusinessInviteProgress({ stage: 'failed', detail: '自动核对未完成，请刷新工作区成员与席位后再决定是否重试' })
          message.warning('邀请请求和自动核对均未完成，请先刷新成员与席位，避免重复邀请')
        }
      }
    } finally {
      window.clearTimeout(timeout)
      if (inviteFailed) await loadAccounts(true)
      setBusinessInviting(false)
    }
  }

  const removeBusinessChild = async (
    account: GptPlanAccount,
    child: BusinessChildDisplayRow,
  ) => {
    const membershipId = positiveInteger(child.membership_id)
    if (!membershipId) {
      message.warning('该子号缺少可确认的成员记录 ID，请先刷新 BUSINESS 席位')
      return
    }
    const busyKey = `remove:${account.id}:${membershipId}`
    if (businessChildActionBusyKeys.includes(busyKey)) return
    setBusinessChildActionBusy(busyKey, true)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/business-remove`, {
        method: 'POST',
        body: JSON.stringify({
          membership_id: membershipId,
          operation_id: businessOperationId(),
          confirm_remove: true,
        }),
      }) as Record<string, unknown>
      const needsReview = result.partial === true || result.action_required === true
      if (result?.ok === false && !needsReview) {
        throw new Error(String(result.error || '移除失败'))
      }

      const immediateChildren = asRecord(result.business_children)
      if (Object.keys(immediateChildren).length) {
        const snapshot = sanitizeBusinessChildrenSnapshot(immediateChildren)
        setBusinessChildrenByAccount((current) => ({
          ...current,
          [account.id]: { loading: false, loaded: true, error: '', snapshot },
        }))
      }
      if (needsReview) {
        message.warning(String(
          result.warning || result.error || '远端操作结果需要核对，已刷新数据库子号快照',
        ))
      } else {
        message.success(
          child._kind === 'invite'
            ? `已撤销对 ${child.email || '该子号'} 的邀请`
            : `${child.email || '该子号'} 已退出空间`,
        )
      }
      setMemberSourceOverrides({})
      await Promise.all([
        loadBusinessChildren(account, { quiet: true }),
        loadAccounts(),
        loadStats(),
        loadBusinessChildCatalog(true),
      ])
    } catch (error: unknown) {
      message.error(`${child._kind === 'invite' ? '撤销邀请' : '退出空间'}失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setBusinessChildActionBusy(busyKey, false)
    }
  }

  const refreshCurrentBusinessWorkspacePage = async () => {
    if (businessWorkspacePageRefreshing) return
    const targets = accounts.filter((account) => {
      const source = memberSourceOf(account, memberSourceOverrides[account.id])
      return String(source?.source_pool || account.source_pool || '').trim().toLowerCase() === 'gpt_business'
    })
    if (!targets.length) {
      message.warning('当前页没有可刷新的 BUSINESS 母号')
      return
    }
    setBusinessWorkspacePageRefreshing(true)
    let succeeded = 0
    let failed = 0
    try {
      // 明确由人工触发并顺序执行，避免同时向多个 BUSINESS 工作区发起远端请求。
      for (const account of targets) {
        const ok = await refreshBusinessWorkspace(account, { quiet: true, reloadAfter: false })
        if (ok) succeeded += 1
        else failed += 1
      }
      await Promise.all([loadAccounts(), loadStats()])
      setMemberSourceOverrides({})
      if (failed) message.warning(`成员刷新完成：成功 ${succeeded} · 失败 ${failed}`)
      else message.success(`当前页 ${succeeded} 个 BUSINESS 母号的工作区成员与席位已刷新`)
    } finally {
      setBusinessWorkspacePageRefreshing(false)
    }
  }

  const refreshAfterMemberAction = async () => {
    // 套餐管理接口会原子更新对应目录记录；这里只刷新当前视图。
    setMemberSourceOverrides({})
    await Promise.all([loadAccounts(), loadStats()])
  }

  const loadBusinessBurnCandidates = async (account: GptPlanAccount, generation: number) => {
    setBusinessBurnCandidatesLoading(true)
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/pro-refund-burn/candidates`,
      ) as {
        items?: BusinessBurnCandidate[]
        total?: number
        max_select?: number
      }
      if (businessBurnGenerationRef.current !== generation) return
      const items = Array.isArray(result?.items)
        ? result.items.filter((item) => Number.isFinite(Number(item?.id)) && Boolean(item?.email))
        : []
      setBusinessBurnCandidates(items)
      setBusinessBurnMaxSelect(Math.max(0, Number(result?.max_select || 0)))
      setBusinessBurnSelectedIds([])
    } catch (error: unknown) {
      if (businessBurnGenerationRef.current !== generation) return
      setBusinessBurnCandidates([])
      setBusinessBurnMaxSelect(0)
      message.error(`读取可焚决 PRO 账号失败：${errorMessage(error, '未知错误')}`)
    } finally {
      if (businessBurnGenerationRef.current === generation) setBusinessBurnCandidatesLoading(false)
    }
  }

  const openBusinessBurn = (account: GptPlanAccount) => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    const sourcePool = String(source?.source_pool || account.source_pool || '').trim().toLowerCase()
    const capability = memberCapabilityOf(account, source, 'pro_refund_burn')
    if (sourcePool !== 'gpt_business') {
      message.warning('只有 BUSINESS 母号可以发起 PRO 焚决')
      return
    }
    if (capability.supported !== true) {
      message.warning(String(capability.reason || '该 BUSINESS 母号当前不能发起 PRO 焚决'))
      return
    }
    if (businessBurnTimerRef.current !== undefined) window.clearTimeout(businessBurnTimerRef.current)
    const generation = businessBurnGenerationRef.current + 1
    businessBurnGenerationRef.current = generation
    setBusinessBurnAccount(account)
    setBusinessBurnCandidates([])
    setBusinessBurnSelectedIds([])
    setBusinessBurnKick(true)
    setBusinessBurnMaxSelect(Math.max(0, Number(capability.remaining || 0)))
    setBusinessBurnTask(null)
    setBusinessBurnStartSummary(null)
    void loadBusinessBurnCandidates(account, generation)
  }

  const scheduleBusinessBurnPoll = (
    account: GptPlanAccount,
    taskId: string,
    generation: number,
    since = 0,
    delay = 500,
  ) => {
    if (businessBurnTimerRef.current !== undefined) window.clearTimeout(businessBurnTimerRef.current)
    businessBurnTimerRef.current = window.setTimeout(async () => {
      if (businessBurnGenerationRef.current !== generation) return
      try {
        const snapshot = await apiFetch(
          `${API_ROOT}/accounts/${account.id}/pro-refund-burn/${encodeURIComponent(taskId)}?since=${since}`,
        ) as {
          status?: string
          logs?: unknown[]
          since?: number
          progress?: { done?: number; total?: number; burned?: number } | null
          result?: { total?: number; burned?: number } | null
          error?: string
        }
        if (businessBurnGenerationRef.current !== generation) return
        const status = String(snapshot?.status || 'running').trim().toLowerCase()
        const logs = Array.isArray(snapshot?.logs) ? snapshot.logs.map((line) => String(line)) : []
        const nextSince = Number.isFinite(Number(snapshot?.since)) ? Number(snapshot.since) : since
        const progress = snapshot?.progress && typeof snapshot.progress === 'object'
          ? {
              done: Math.max(0, Number(snapshot.progress.done || 0)),
              total: Math.max(0, Number(snapshot.progress.total || 0)),
              burned: Math.max(0, Number(snapshot.progress.burned || 0)),
            }
          : null
        setBusinessBurnTask((current) => current?.taskId === taskId ? {
          ...current,
          logs: [...current.logs, ...logs],
          progress,
        } : current)
        if (['running', 'pending', 'queued'].includes(status)) {
          scheduleBusinessBurnPoll(account, taskId, generation, nextSince, 1800)
          return
        }
        businessBurnTimerRef.current = undefined
        setBusinessBurnStarting(false)
        if (['done', 'completed', 'success', 'succeeded'].includes(status)) {
          const result = snapshot?.result || {}
          setBusinessBurnTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'done',
            progress: progress || {
              done: Number(result.total || 0),
              total: Number(result.total || 0),
              burned: Number(result.burned || 0),
            },
          } : current)
          message.success(`PRO 焚决完成：掉订阅成功 ${Number(result.burned || 0)}/${Number(result.total || 0)}`)
          setBusinessBurnSelectedIds([])
          await refreshAfterMemberAction()
          await loadBusinessBurnCandidates(account, generation)
          return
        }
        const detail = String(snapshot?.error || 'PRO 焚决任务执行失败')
        setBusinessBurnTask((current) => current?.taskId === taskId ? {
          ...current,
          status: 'failed',
          error: detail,
        } : current)
        message.error(`PRO 焚决失败：${detail}`)
        await refreshAfterMemberAction()
      } catch (error: unknown) {
        if (businessBurnGenerationRef.current !== generation) return
        businessBurnTimerRef.current = undefined
        setBusinessBurnStarting(false)
        const detail = errorMessage(error, '轮询失败')
        setBusinessBurnTask((current) => current?.taskId === taskId ? {
          ...current,
          status: 'failed',
          error: detail,
        } : current)
        message.error(`PRO 焚决状态读取失败：${detail}`)
      }
    }, delay)
  }

  const startBusinessBurn = async () => {
    const account = businessBurnAccount
    if (!account || businessBurnStarting || businessBurnTask?.status === 'running') return
    if (!businessBurnSelectedIds.length) {
      message.warning('请选择至少一个要处理的 PRO 账号')
      return
    }
    const selected = businessBurnMaxSelect > 0
      ? businessBurnSelectedIds.slice(0, businessBurnMaxSelect)
      : businessBurnSelectedIds
    const generation = businessBurnGenerationRef.current + 1
    businessBurnGenerationRef.current = generation
    setBusinessBurnStarting(true)
    setBusinessBurnTask({ taskId: '', status: 'running', logs: [] })
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/pro-refund-burn`, {
        method: 'POST',
        body: JSON.stringify({ account_ids: selected, concurrency: 1, kick: businessBurnKick }),
      }) as {
        ok?: boolean
        task_id?: string
        status?: string
        requested?: number
        targets?: number
        capped_to?: number
        remaining?: number
        error?: string
      }
      if (result?.ok === false) throw new Error(result.error || '任务启动失败')
      const taskId = String(result?.task_id || '')
      if (!taskId) throw new Error('后端未返回焚决任务 ID')
      setBusinessBurnTask({ taskId, status: 'running', logs: [] })
      const requested = Math.max(0, Number(result?.requested ?? selected.length))
      const targets = Math.max(0, Number(result?.targets ?? result?.capped_to ?? selected.length))
      setBusinessBurnStartSummary({
        requested,
        targets,
        remaining: nonNegativeNumber(result?.remaining),
      })
      message.info(`PRO 焚决已启动：提交 ${requested} 个 · 实际进入任务 ${targets} 个`)
      scheduleBusinessBurnPoll(account, taskId, generation)
    } catch (error: unknown) {
      setBusinessBurnStarting(false)
      const detail = errorMessage(error, '未知错误')
      setBusinessBurnTask({ taskId: '', status: 'failed', logs: [], error: detail })
      message.error(`启动 PRO 焚决失败：${detail}`)
    }
  }

  const scheduleBusinessBatchInvitePoll = (
    taskId: string,
    generation: number,
    since = 0,
    delay = 600,
  ) => {
    if (businessBatchInviteTimerRef.current !== undefined) {
      window.clearTimeout(businessBatchInviteTimerRef.current)
    }
    businessBatchInviteTimerRef.current = window.setTimeout(async () => {
      if (businessBatchInviteGenerationRef.current !== generation) return
      try {
        const snapshot = await apiFetch(
          `${API_ROOT}/business-batch-invite-tasks/${encodeURIComponent(taskId)}?since=${since}`,
        ) as Record<string, unknown>
        if (businessBatchInviteGenerationRef.current !== generation) return
        const status = String(snapshot.status || 'running').trim().toLowerCase()
        const nextSince = Number.isFinite(Number(snapshot.since)) ? Number(snapshot.since) : since
        setBusinessBatchInviteTask((current) => (
          current?.taskId === taskId
            ? mergeBusinessBatchInviteTask(current, snapshot, taskId)
            : current
        ))
        if (!['done', 'failed'].includes(status)) {
          scheduleBusinessBatchInvitePoll(taskId, generation, nextSince, 1400)
          return
        }

        businessBatchInviteTimerRef.current = undefined
        setBusinessBatchInviteStarting(false)
        setSelectedBusinessAccountIds([])
        setBusinessSelectAllMatching(false)
        const outcome = String(snapshot.outcome || '').trim().toLowerCase()
        if (status === 'failed' || outcome === 'failed') {
          message.error(`批量邀请任务失败：${String(snapshot.error || '请查看任务日志')}`)
        } else if (snapshot.has_failures === true || outcome === 'partial') {
          message.warning('批量邀请已完成，部分母号邀请失败或被跳过，请查看明细')
        } else {
          message.success('批量邀请子号已全部完成')
        }
        void Promise.all([loadAccounts(true), loadStats()])
      } catch (error: unknown) {
        if (businessBatchInviteGenerationRef.current !== generation) return
        const detail = errorMessage(error, '状态读取失败')
        if (error instanceof ApiFetchError && error.status === 404) {
          businessBatchInviteTimerRef.current = undefined
          try { localStorage.removeItem(BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY) } catch { /* ignore */ }
          setBusinessBatchInviteTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'failed',
            error: '批量邀请任务记录不存在或已过期',
            pollingError: detail,
          } : current)
          return
        }
        setBusinessBatchInviteTask((current) => current?.taskId === taskId ? {
          ...current,
          pollingError: detail,
        } : current)
        scheduleBusinessBatchInvitePoll(taskId, generation, since, 3000)
      }
    }, delay)
  }

  const startBusinessBatchInvite = async () => {
    if (businessBatchInviteStarting) return
    if (businessBatchInviteTask && !['done', 'failed'].includes(businessBatchInviteTask.status)) {
      setBusinessBatchInviteTaskOpen(true)
      message.info('已有批量邀请任务正在顺序执行')
      return
    }
    if (!businessSelectAllMatching && selectedBusinessAccountIds.length === 0) {
      message.warning('请先选择至少一个有空闲席位的 BUSINESS 母号')
      return
    }
    if (businessSelectAllMatching && businessSeatFilter !== 'available') {
      message.warning('全选筛选结果仅支持“有空闲席位”筛选')
      return
    }

    const estimatedTotal = businessSelectAllMatching ? total : selectedBusinessAccountIds.length
    const providerLabel = businessInviteMailProviderLabel(businessBatchInviteMailProvider)
    const generation = businessBatchInviteGenerationRef.current + 1
    businessBatchInviteGenerationRef.current = generation
    if (businessBatchInviteTimerRef.current !== undefined) {
      window.clearTimeout(businessBatchInviteTimerRef.current)
      businessBatchInviteTimerRef.current = undefined
    }
    try { localStorage.removeItem(BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY) } catch { /* ignore */ }
    const initialTask = mergeBusinessBatchInviteTask(null, {
      status: 'running',
      candidate_mail_provider: businessBatchInviteMailProvider,
      post_setup_security: businessBatchInvitePostSecurity,
      post_acquire_rt: businessBatchInvitePostRt,
      ...(businessBatchInvitePostSecurity ? { security_browser_mode: securityBrowserMode } : {}),
      progress: { total_mothers: estimatedTotal, percent: 0 },
      mothers: [],
      logs: [`正在创建批量邀请任务；子号邮箱类型：${providerLabel}；每个子号将顺序执行邀请${businessBatchInvitePostSecurity ? '、检查密码 / 2FA（已完成则跳过）' : ''}${businessBatchInvitePostRt ? '、获取 RT' : ''}。`],
    })
    setBusinessBatchInviteTask(initialTask)
    setBusinessBatchInviteTaskOpen(true)
    setBusinessBatchInviteStarting(true)
    try {
      const result = await apiFetch(`${API_ROOT}/business-batch-invite-tasks`, {
        method: 'POST',
        body: JSON.stringify({
          ...(businessSelectAllMatching
            ? {
                select_all_matching: true,
                keyword: keyword || null,
                login_status: loginStatus || null,
                business_usage_type: businessUsageFilter || null,
                account_id: focusTarget?.planAccountId || null,
              }
            : { account_ids: selectedBusinessAccountIds }),
          business_seat_filter: 'available',
          candidate_mail_provider: businessBatchInviteMailProvider,
          post_setup_security: businessBatchInvitePostSecurity,
          post_acquire_rt: businessBatchInvitePostRt,
          ...(businessBatchInvitePostSecurity ? { security_browser_mode: securityBrowserMode } : {}),
        }),
      }) as Record<string, unknown>
      if (result.ok === false) {
        const existingTaskId = String(result.existing_task_id || result.task_id || '').trim()
        if (existingTaskId) {
          try { localStorage.setItem(BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY, existingTaskId) } catch { /* ignore */ }
          setBusinessBatchInviteTask(mergeBusinessBatchInviteTask(initialTask, {
            task_id: existingTaskId,
            status: 'running',
            logs: ['检测到已有批量邀请任务，已接管并继续读取进度。'],
          }, existingTaskId))
          setBusinessBatchInviteStarting(false)
          scheduleBusinessBatchInvitePoll(existingTaskId, generation, 0, 200)
          message.info('已有批量邀请任务正在执行，已恢复查看现有任务')
          return
        }
        throw new Error(String(result.error || '任务启动失败'))
      }
      const taskId = String(result.task_id || '').trim()
      if (!taskId) throw new Error('后端未返回批量邀请任务 ID')
      try { localStorage.setItem(BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY, taskId) } catch { /* ignore */ }
      setBusinessBatchInviteTask((current) => mergeBusinessBatchInviteTask(current, result, taskId))
      setBusinessBatchInviteStarting(false)
      message.info(`批量邀请已启动：子号邮箱类型 ${providerLabel}，共 ${businessBatchCount(asRecord(result.progress).total_mothers) || estimatedTotal} 个母号；每个子号完成全部所选步骤后再处理下一个`)
      scheduleBusinessBatchInvitePoll(taskId, generation, businessBatchCount(result.since), 500)
    } catch (error: unknown) {
      const payload = error instanceof ApiFetchError ? asRecord(error.payload) : {}
      const detailPayload = asRecord(payload.detail)
      const existingTaskId = String(
        detailPayload.existing_task_id || payload.existing_task_id || '',
      ).trim()
      if (error instanceof ApiFetchError && error.status === 409 && existingTaskId) {
        try { localStorage.setItem(BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY, existingTaskId) } catch { /* ignore */ }
        setBusinessBatchInviteStarting(false)
        setBusinessBatchInviteTask(mergeBusinessBatchInviteTask(initialTask, {
          task_id: existingTaskId,
          status: 'running',
          logs: ['检测到已有批量邀请任务，已接管并继续读取进度。'],
        }, existingTaskId))
        scheduleBusinessBatchInvitePoll(existingTaskId, generation, 0, 200)
        message.info('已有批量邀请任务正在执行，已恢复查看现有任务')
        return
      }
      const detail = errorMessage(error, '未知错误')
      setBusinessBatchInviteStarting(false)
      setBusinessBatchInviteTask((current) => ({
        ...(current || initialTask),
        status: 'failed',
        error: detail,
      }))
      message.error(`启动批量邀请失败：${detail}`)
    }
  }

  const scheduleBusinessChildBatchPoll = (
    taskId: string,
    action: BusinessChildBatchAction,
    generation: number,
    since = 0,
    delay = 500,
  ) => {
    if (businessChildBatchTimerRef.current !== undefined) {
      window.clearTimeout(businessChildBatchTimerRef.current)
    }
    businessChildBatchTimerRef.current = window.setTimeout(async () => {
      if (businessChildBatchGenerationRef.current !== generation) return
      try {
        const snapshot = await apiFetch(
          `${API_ROOT}/business-child-batch-action-tasks/${encodeURIComponent(taskId)}?since=${since}`,
          { cache: 'no-store' },
        ) as Record<string, unknown>
        if (businessChildBatchGenerationRef.current !== generation) return
        const status = String(snapshot.status || 'running').trim().toLowerCase()
        const snapshotAction: BusinessChildBatchAction = normalizeBusinessChildBatchAction(snapshot.action, action)
        if (snapshotAction === 'leave_workspace' && Array.isArray(snapshot.items)) {
          snapshot.items.forEach((item) => {
            const parentId = positiveInteger(asRecord(item).parent_account_id)
            if (parentId) businessChildBatchParentIdsRef.current.add(parentId)
          })
        }
        const nextSince = Number.isFinite(Number(snapshot.since)) ? Number(snapshot.since) : since
        try {
          localStorage.setItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY, JSON.stringify({
            taskId,
            action: snapshotAction,
          }))
        } catch { /* ignore */ }
        setBusinessChildBatchTask((current) => current?.taskId === taskId
          ? mergeBusinessChildBatchActionTask(current, snapshot, taskId, snapshotAction)
          : current)
        if (!['done', 'failed', 'completed', 'success'].includes(status)) {
          scheduleBusinessChildBatchPoll(taskId, snapshotAction, generation, nextSince, 1200)
          return
        }
        businessChildBatchTimerRef.current = undefined
        setBusinessChildBatchStarting(false)
        setSelectedBusinessChildMembershipIds([])
        const progress = asRecord(snapshot.progress)
        const failed = businessBatchCount(progress.failed)
        const outcome = String(snapshot.outcome || '').trim().toLowerCase()
        const taskFailed = status === 'failed' || outcome === 'failed'
        if (taskFailed) {
          message.error(`批量${businessChildBatchActionLabel(snapshotAction)}失败：${String(snapshot.error || '请查看账号明细')}`)
        } else if (failed > 0 || outcome === 'partial') {
          message.warning(`批量${businessChildBatchActionLabel(snapshotAction)}完成，部分子号失败`)
        } else {
          message.success(`批量${businessChildBatchActionLabel(snapshotAction)}已完成`)
        }
        if (snapshotAction === 'leave_workspace') {
          setMemberSourceOverrides({})
          await Promise.allSettled([
            loadBusinessChildCatalog(true), loadAccounts(true), loadStats(),
            ...[...businessChildBatchParentIdsRef.current].map((id) => loadBusinessChildren(
              { id, source_pool: 'gpt_business' } as GptPlanAccount,
              { quiet: true },
            )),
          ])
        } else {
          await loadBusinessChildCatalog(true)
        }
      } catch (error: unknown) {
        if (businessChildBatchGenerationRef.current !== generation) return
        const detail = errorMessage(error, '状态读取失败')
        if (error instanceof ApiFetchError && error.status === 404) {
          businessChildBatchTimerRef.current = undefined
          setBusinessChildBatchStarting(false)
          try { localStorage.removeItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY) } catch { /* ignore */ }
          setBusinessChildBatchTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'failed',
            error: '批量子号任务记录不存在或已过期',
            pollingError: detail,
          } : current)
          return
        }
        setBusinessChildBatchTask((current) => current?.taskId === taskId ? {
          ...current,
          pollingError: detail,
        } : current)
        scheduleBusinessChildBatchPoll(taskId, action, generation, since, 3000)
      }
    }, delay)
  }

  const startBusinessChildBatchAction = async (
    action: BusinessChildBatchAction,
    force = false,
  ) => {
    if (businessChildBatchStarting) return
    if (businessChildBatchTask && !['done', 'failed', 'completed', 'success'].includes(businessChildBatchTask.status)) {
      setBusinessChildBatchTaskOpen(true)
      message.info('已有子号批量任务正在逐个执行')
      return
    }
    let membershipIds = selectedBusinessChildMembershipIds
      .map(Number)
      .filter((id) => Number.isInteger(id) && id > 0)
    if (!membershipIds.length) {
      message.warning('请先选择至少一个可操作的子号')
      return
    }
    const selectedRows = businessChildCatalogRows.filter((row) => (
      membershipIds.includes(Number(row.membership_id))
    ))
    let skippedSelectionCount = 0
    if (action === 'leave_workspace') {
      const rowsById = new Map(selectedRows.map((row) => [Number(row.membership_id), row]))
      const selectedCount = membershipIds.length
      membershipIds = membershipIds.filter((id) => {
        const row = rowsById.get(id)
        return Boolean(row && businessChildLeaveWorkspaceEligibility(row).allowed)
      })
      skippedSelectionCount = selectedCount - membershipIds.length
      if (!membershipIds.length) {
        message.warning('所选子号没有可退出的已加入成员；待邀请不会自动撤销')
        return
      }
      if (skippedSelectionCount) message.info(`已跳过 ${skippedSelectionCount} 个不可退出的子号，待邀请不会自动撤销`)
    }
    const ineligibleRows = selectedRows.filter((row) => (
      !businessChildBatchActionEligibility(row, action).allowed
    ))
    if (action !== 'leave_workspace' && ineligibleRows.length) {
      const first = businessChildBatchActionEligibility(ineligibleRows[0], action)
      message.warning(
        `选中的 ${ineligibleRows.length} 个子号当前不支持批量${businessChildBatchActionLabel(action)}：${first.reason}`,
      )
      return
    }
    const generation = businessChildBatchGenerationRef.current + 1
    businessChildBatchGenerationRef.current = generation
    businessChildBatchParentIdsRef.current = new Set(selectedRows
      .filter((row) => membershipIds.includes(Number(row.membership_id)))
      .map((row) => row.parent_account_id).filter((id) => Number.isInteger(id) && id > 0))
    if (businessChildBatchTimerRef.current !== undefined) {
      window.clearTimeout(businessChildBatchTimerRef.current)
      businessChildBatchTimerRef.current = undefined
    }
    try { localStorage.removeItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY) } catch { /* ignore */ }
    const initialTask = mergeBusinessChildBatchActionTask(null, {
      status: 'running',
      action,
      ...(action === 'setup_security' ? { browser_mode: securityBrowserMode } : {}),
      progress: { total: membershipIds.length, percent: 0 },
      logs: [
        `正在创建批量${businessChildBatchActionLabel(action)}任务；将严格一个子号一个子号处理。`,
        ...(skippedSelectionCount ? [`选中项中已跳过 ${skippedSelectionCount} 个不可退出子号；待邀请不会自动撤销。`] : []),
      ],
    }, '', action)
    setBusinessChildBatchTask(initialTask)
    setBusinessChildBatchTaskOpen(true)
    setBusinessChildBatchStarting(true)
    const actionOptions = action === 'leave_workspace'
      ? { confirm_remove: true }
      : {
        force,
        ...(action === 'setup_security' ? { browser_mode: securityBrowserMode } : {}),
      }
    try {
      const result = await apiFetch(`${API_ROOT}/business-child-batch-action-tasks`, {
        method: 'POST',
        body: JSON.stringify({
          action,
          membership_ids: membershipIds,
          ...actionOptions,
        }),
      }) as Record<string, unknown>
      if (result.ok === false) throw new Error(String(result.error || '任务启动失败'))
      const taskId = String(result.task_id || '').trim()
      if (!taskId) throw new Error('后端未返回批量子号任务 ID')
      try {
        localStorage.setItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY, JSON.stringify({ taskId, action }))
      } catch { /* ignore */ }
      setBusinessChildBatchTask((current) => mergeBusinessChildBatchActionTask(current, result, taskId, action))
      setBusinessChildBatchStarting(false)
      message.info(`批量${businessChildBatchActionLabel(action)}已启动，共 ${membershipIds.length} 个子号，严格串行处理`)
      scheduleBusinessChildBatchPoll(taskId, action, generation, businessBatchCount(result.since), 300)
    } catch (error: unknown) {
      const payload = error instanceof ApiFetchError ? asRecord(error.payload) : {}
      const detailPayload = asRecord(payload.detail)
      const existingTaskId = String(
        detailPayload.existing_task_id || payload.existing_task_id || '',
      ).trim()
      if (error instanceof ApiFetchError && error.status === 409 && existingTaskId) {
        const existingAction = normalizeBusinessChildBatchAction(
          detailPayload.existing_action || payload.existing_action, action,
        )
        businessChildBatchParentIdsRef.current.clear()
        try {
          localStorage.setItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY, JSON.stringify({
            taskId: existingTaskId,
            action: existingAction,
          }))
        } catch { /* ignore */ }
        setBusinessChildBatchStarting(false)
        setBusinessChildBatchTask(mergeBusinessChildBatchActionTask(initialTask, {
          task_id: existingTaskId,
          action: existingAction,
          status: 'running',
          logs: ['检测到已有子号批量任务，已接管并继续读取进度。'],
        }, existingTaskId, existingAction))
        scheduleBusinessChildBatchPoll(existingTaskId, existingAction, generation, 0, 200)
        message.info('已有子号批量任务正在执行，已恢复查看现有任务')
        return
      }
      const detail = errorMessage(error, '未知错误')
      setBusinessChildBatchStarting(false)
      setBusinessChildBatchTask((current) => ({
        ...(current || initialTask),
        status: 'failed',
        error: detail,
      }))
      message.error(`启动批量${businessChildBatchActionLabel(action)}失败：${detail}`)
    }
  }

  const startBusinessMotherBatchLeave = async (account: GptPlanAccount) => {
    const action: BusinessChildBatchAction = 'leave_workspace'
    if (businessChildBatchStarting) return
    if (businessChildBatchTask && !['done', 'failed', 'completed', 'success'].includes(businessChildBatchTask.status)) {
      setBusinessChildBatchTaskOpen(true)
      message.info('已有子号批量任务正在执行')
      return
    }
    const generation = businessChildBatchGenerationRef.current + 1
    businessChildBatchGenerationRef.current = generation
    businessChildBatchParentIdsRef.current = new Set([account.id])
    if (businessChildBatchTimerRef.current !== undefined) {
      window.clearTimeout(businessChildBatchTimerRef.current)
      businessChildBatchTimerRef.current = undefined
    }
    try { localStorage.removeItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY) } catch { /* ignore */ }
    const initialTask = mergeBusinessChildBatchActionTask(null, {
      status: 'running',
      action,
      logs: [`正在读取 ${account.email} 当前已加入空间的全部子号。`],
      progress: { total: 0, percent: 0 },
    }, '', action)
    setBusinessChildBatchTask(initialTask)
    setBusinessChildBatchTaskOpen(true)
    setBusinessChildBatchStarting(true)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/business-child-batch-leave-tasks`, {
        method: 'POST',
        body: JSON.stringify({ confirm_remove: true }),
      }) as Record<string, unknown>
      if (result.ok === false) throw new Error(String(result.error || '任务启动失败'))
      const taskId = String(result.task_id || '').trim()
      if (!taskId) throw new Error('后端未返回批量退出任务 ID')
      try {
        localStorage.setItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY, JSON.stringify({ taskId, action }))
      } catch { /* ignore */ }
      setBusinessChildBatchTask((current) => mergeBusinessChildBatchActionTask(current, result, taskId, action))
      setBusinessChildBatchStarting(false)
      const total = businessBatchCount(asRecord(result.progress).total)
      message.info(`已启动 ${account.email} 的批量退出任务，共 ${total} 个已加入子号`)
      scheduleBusinessChildBatchPoll(taskId, action, generation, businessBatchCount(result.since), 300)
    } catch (error: unknown) {
      const payload = error instanceof ApiFetchError ? asRecord(error.payload) : {}
      const detailPayload = asRecord(payload.detail)
      const existingTaskId = String(detailPayload.existing_task_id || payload.existing_task_id || '').trim()
      if (error instanceof ApiFetchError && error.status === 409 && existingTaskId) {
        const existingAction = normalizeBusinessChildBatchAction(
          detailPayload.existing_action || payload.existing_action,
          action,
        )
        try {
          localStorage.setItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY, JSON.stringify({
            taskId: existingTaskId,
            action: existingAction,
          }))
        } catch { /* ignore */ }
        setBusinessChildBatchStarting(false)
        setBusinessChildBatchTask(mergeBusinessChildBatchActionTask(initialTask, {
          task_id: existingTaskId,
          action: existingAction,
          status: 'running',
          logs: ['检测到已有子号批量任务，已接管并继续读取进度。'],
        }, existingTaskId, existingAction))
        scheduleBusinessChildBatchPoll(existingTaskId, existingAction, generation, 0, 200)
        message.info('已有子号批量任务正在执行，已恢复查看现有任务')
        return
      }
      const detail = errorMessage(error, '未知错误')
      setBusinessChildBatchStarting(false)
      setBusinessChildBatchTask((current) => ({
        ...(current || initialTask),
        status: 'failed',
        error: detail,
      }))
      message.error(`启动母号批量退出失败：${detail}`)
    }
  }

  const scheduleMemberTaskPoll = (
    account: GptPlanAccount,
    action: 'oauth' | 'refund',
    taskId: string,
    generation: number,
    since = 0,
    delay = 1200,
  ) => {
    if (memberTaskTimerRef.current !== undefined) window.clearTimeout(memberTaskTimerRef.current)
    memberTaskTimerRef.current = window.setTimeout(async () => {
      if (memberTaskGenerationRef.current !== generation) return
      try {
        const snapshot = await apiFetch(
          `${API_ROOT}/accounts/${account.id}/${action}/${encodeURIComponent(taskId)}?since=${since}`,
        ) as {
          status?: string
          logs?: unknown[]
          since?: number
          result?: Record<string, unknown> | null
          error?: string
          finished_at?: string
        }
        if (memberTaskGenerationRef.current !== generation) return
        const rawStatus = String(snapshot?.status || 'running').trim().toLowerCase()
        const logs = Array.isArray(snapshot?.logs) ? snapshot.logs.map((line) => String(line)) : []
        const result = asRecord(snapshot?.result)
        const finished = Boolean(String(snapshot?.finished_at || '').trim())
        const explicitSuccess = ['done', 'completed', 'complete', 'success', 'succeeded'].includes(rawStatus)
        const explicitFailure = ['failed', 'failure', 'error', 'cancelled', 'canceled'].includes(rawStatus)
        const terminalSuccess = explicitSuccess
          || (!explicitFailure && finished && !snapshot?.error && result.ok !== false)
        const terminalFailure = explicitFailure || (finished && !terminalSuccess)
        const status = terminalSuccess ? 'done' : terminalFailure ? 'failed' : 'running'
        const stage = String(result.stage || rawStatus || 'running')
        const nextSince = Number.isFinite(Number(snapshot?.since)) ? Number(snapshot.since) : since
        setMemberTask((current) => current && current.taskId === taskId ? {
          ...current,
          stage,
          logs: [...current.logs, ...logs],
        } : current)
        if (status === 'running') {
          scheduleMemberTaskPoll(account, action, taskId, generation, nextSince, 1500)
          return
        }
        memberTaskTimerRef.current = undefined
        setMemberActionBusyKey('')
        if (['done', 'completed', 'success', 'succeeded'].includes(status)) {
          setMemberTask((current) => current && current.taskId === taskId ? {
            ...current,
            status: 'done',
            stage,
          } : current)
          message.success(action === 'oauth'
            ? `${account.email} 获取 RT 成功`
            : `${account.email} 退款流程已完成`)
          await refreshAfterMemberAction()
          return
        }
        const detail = String(snapshot?.error || result.error || '账号任务执行失败')
        setMemberTask((current) => current && current.taskId === taskId ? {
          ...current,
          status: 'failed',
          stage,
          error: detail,
        } : current)
        message.error(`${action === 'oauth' ? '获取 RT' : '退款'}失败：${detail}`)
        await refreshAfterMemberAction()
      } catch (error: unknown) {
        if (memberTaskGenerationRef.current !== generation) return
        memberTaskTimerRef.current = undefined
        setMemberActionBusyKey('')
        const detail = errorMessage(error, '轮询失败')
        setMemberTask((current) => current && current.taskId === taskId ? {
          ...current,
          status: 'failed',
          stage: 'poll_error',
          error: detail,
        } : current)
        message.error(`账号任务状态读取失败：${detail}`)
      }
    }, delay)
  }

  const startMemberTask = async (
    account: GptPlanAccount,
    action: 'oauth' | 'refund',
    body: Record<string, unknown> = {},
  ) => {
    if (memberActionBusyKey) {
      message.warning('已有账号任务正在执行，请等待完成')
      return
    }
    const generation = memberTaskGenerationRef.current + 1
    memberTaskGenerationRef.current = generation
    setMemberActionBusyKey(`${account.id}-${action}`)
    setMemberTask({
      accountId: account.id,
      email: account.email,
      action,
      taskId: '',
      status: 'running',
      stage: 'starting',
      logs: [],
    })
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/${action}`, {
        method: 'POST',
        body: JSON.stringify(body),
      }) as { ok?: boolean; task_id?: string; status?: string; error?: string }
      if (result?.ok === false) throw new Error(result.error || '任务启动失败')
      const taskId = String(result?.task_id || '')
      if (!taskId) throw new Error('后端未返回账号任务 ID')
      setMemberTask((current) => current && current.accountId === account.id && current.action === action ? {
        ...current,
        taskId,
        stage: String(result.status || 'running'),
      } : current)
      message.info(action === 'oauth'
        ? `已启动 ${account.email} 的 RT 获取任务`
        : `已启动 ${account.email} 的${body.refund_manual ? '人工' : '自动'}退款流程`)
      scheduleMemberTaskPoll(account, action, taskId, generation, 0, 300)
    } catch (error: unknown) {
      setMemberActionBusyKey('')
      const detail = errorMessage(error, '未知错误')
      setMemberTask((current) => current && current.accountId === account.id ? {
        ...current,
        status: 'failed',
        stage: 'start_failed',
        error: detail,
      } : current)
      message.error(`${action === 'oauth' ? '获取 RT' : '退款'}启动失败：${detail}`)
    }
  }

  const downloadMemberOAuthFile = async (account: GptPlanAccount, format: 'cpa' | 'sub2api') => {
    const busyKey = `${account.id}-${format}`
    setDownloadBusyKey(busyKey)
    const label = format === 'cpa' ? 'CPA' : 'SUB'
    const toastKey = `gpt-plan-download-${busyKey}`
    message.loading({ content: `${label} 凭证生成中…`, key: toastKey, duration: 0 })
    try {
      const authToken = getToken()
      const response = await fetch(
        `/api${API_ROOT}/accounts/${account.id}/oauth-file?fmt=${encodeURIComponent(format)}&_t=${Date.now()}`,
        {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
        },
      )
      if (!response.ok) {
        let detail = `HTTP ${response.status}`
        try {
          const body = await response.json()
          const raw = body?.detail ?? body?.message ?? body?.error
          detail = typeof raw === 'string' ? raw : raw ? JSON.stringify(raw) : detail
        } catch { /* 保留 HTTP 状态 */ }
        throw new Error(detail)
      }
      const disposition = response.headers.get('Content-Disposition') || ''
      const match = /filename="?([^";]+)"?/i.exec(disposition)
      const filename = match?.[1] || `${format}_${account.email.replace(/[^a-zA-Z0-9._-]/g, '_')}.json`
      const objectUrl = URL.createObjectURL(await response.blob())
      const anchor = document.createElement('a')
      anchor.href = objectUrl
      anchor.download = filename
      document.body.appendChild(anchor)
      anchor.click()
      document.body.removeChild(anchor)
      URL.revokeObjectURL(objectUrl)
      message.success({ content: `${label} 凭证已下载：${filename}`, key: toastKey })
    } catch (error: unknown) {
      message.error({ content: `${label} 凭证下载失败：${errorMessage(error, '未知错误')}`, key: toastKey, duration: 6 })
    } finally {
      setDownloadBusyKey('')
    }
  }

  const copyMemberMailCredential = async (account: GptPlanAccount) => {
    setMailCredentialExportingId(account.id)
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/mail-credential-copy`,
        { method: 'GET', cache: 'no-store' },
      ) as { copy_text?: string }
      const copyText = String(result?.copy_text || '')
      if (!copyText) throw new Error('后端未返回可复制的邮箱密码')
      await navigator.clipboard.writeText(copyText)
      message.success('Outlook 邮箱密码已复制')
    } catch (error: unknown) {
      message.error(`导出邮箱密码失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setMailCredentialExportingId(null)
    }
  }

  const downloadBusinessChildOAuthFile = async (
    account: GptPlanAccount,
    child: BusinessChildDisplayRow,
    format: 'cpa' | 'sub2api',
  ) => {
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号池 ID，无法下载凭证')
      return
    }
    const busyKey = `business-child-${account.id}-${childId}-${format}`
    setDownloadBusyKey(busyKey)
    const label = format === 'cpa' ? 'CPA' : 'SUB'
    const toastKey = `gpt-plan-download-${busyKey}`
    message.loading({ content: `${label} 凭证生成中…`, key: toastKey, duration: 0 })
    try {
      const authToken = getToken()
      const response = await fetch(
        `/api${API_ROOT}/accounts/${account.id}/business-child-oauth-file/${childId}?fmt=${encodeURIComponent(format)}&_t=${Date.now()}`,
        {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
        },
      )
      if (!response.ok) {
        let detail = `HTTP ${response.status}`
        try {
          const body = await response.json()
          const raw = body?.detail ?? body?.message ?? body?.error
          detail = typeof raw === 'string' ? raw : raw ? JSON.stringify(raw) : detail
        } catch { /* 保留 HTTP 状态 */ }
        throw new Error(detail)
      }
      const disposition = response.headers.get('Content-Disposition') || ''
      const match = /filename="?([^";]+)"?/i.exec(disposition)
      const fallbackEmail = String(child.email || `child-${childId}`)
        .replace(/[^a-zA-Z0-9._-]/g, '_')
      const filename = match?.[1] || `${format}_${fallbackEmail}.json`
      const objectUrl = URL.createObjectURL(await response.blob())
      const anchor = document.createElement('a')
      anchor.href = objectUrl
      anchor.download = filename
      document.body.appendChild(anchor)
      anchor.click()
      document.body.removeChild(anchor)
      URL.revokeObjectURL(objectUrl)
      message.success({ content: `${label} 凭证已下载：${filename}`, key: toastKey })
      // 下载门面可能刚把本地仍为 invite 的远端正式成员完成权威对账；
      // 立即重读数据库快照，让工作区状态与后端保持一致。
      await loadBusinessChildren(account, { quiet: true })
    } catch (error: unknown) {
      message.error({
        content: `${label} 凭证下载失败：${errorMessage(error, '未知错误')}`,
        key: toastKey,
        duration: 6,
      })
    } finally {
      setDownloadBusyKey('')
    }
  }

  const openMemberDeviceSync = async (account: GptPlanAccount) => {
    setBusinessChildDeviceTarget(null)
    setDeviceAccount(account)
    setDeliveryDevices([])
    setSelectedDeviceRef(undefined)
    setDeliveryDevicesLoading(true)
    try {
      const source = memberSourceOf(account, memberSourceOverrides[account.id])
      const capability = memberCapabilityOf(account, source, 'sync_device')
      const allowedProviders = new Set(
        (Array.isArray(capability.providers) ? capability.providers : [])
          .map((provider) => String(provider).trim().toLowerCase()),
      )
      const response = await apiFetch('/delivery-devices?include_accounts=false')
      const devices = normalizeDeliveryDevices(response).filter((device) => (
        allowedProviders.size === 0 || allowedProviders.has(device.provider)
      ))
      setDeliveryDevices(devices)
      setSelectedDeviceRef(devices.find((device) => device.enabled)?.deviceRef)
      if (!devices.length) message.warning('没有符合该账号能力的 CPA / SUB 设备')
    } catch (error: unknown) {
      message.error(`读取设备失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setDeliveryDevicesLoading(false)
    }
  }

  const openBusinessChildDeviceSync = async (
    account: GptPlanAccount,
    child: BusinessChildDisplayRow,
  ) => {
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号池 ID，无法同步设备')
      return
    }
    setDeviceAccount(null)
    setBusinessChildDeviceTarget({ account, child })
    setDeliveryDevices([])
    setSelectedDeviceRef(undefined)
    setDeliveryDevicesLoading(true)
    try {
      const response = await apiFetch('/delivery-devices?include_accounts=false')
      const devices = normalizeDeliveryDevices(response)
      const source = memberSourceOf(account, memberSourceOverrides[account.id])
      const boundRef = normalizeBusinessMemberDeviceBinding(
        source?.business_device_binding || {},
      ).device_ref
      const linkedRefs = linkedBusinessChildDevices(child).map((device) => device.deviceRef)
      const preferredRef = [boundRef, ...linkedRefs].find((deviceRef) => (
        Boolean(deviceRef)
        && devices.some((device) => device.enabled && device.deviceRef === deviceRef)
      ))
      setDeliveryDevices(devices)
      setSelectedDeviceRef(
        preferredRef
        || devices.find((device) => device.enabled)?.deviceRef,
      )
      if (!devices.length) message.warning('暂无已配置的 CPA / SUB 设备')
    } catch (error: unknown) {
      message.error(`读取设备失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setDeliveryDevicesLoading(false)
    }
  }

  const updateBusinessBindingView = (
    account: GptPlanAccount,
    binding: BusinessMemberDeviceBinding,
  ) => {
    setBusinessBinding(binding)
    setBusinessBindingSelectedRef(binding.bound ? binding.device_ref : undefined)
    setMemberSourceOverrides((current) => {
      const source = memberSourceOf(account, current[account.id]) || {}
      return {
        ...current,
        [account.id]: {
          ...source,
          business_device_binding: binding,
        },
      }
    })
  }

  const readBusinessBindingEditor = async (
    account: GptPlanAccount,
    quiet = false,
  ): Promise<BusinessMemberDeviceBinding | null> => {
    if (!quiet) setBusinessBindingLoading(true)
    try {
      const response = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/business-device-binding`,
      )
      const root = asRecord(response)
      const rawBinding = Object.prototype.hasOwnProperty.call(root, 'binding')
        ? root.binding
        : root.business_device_binding ?? root.current_binding ?? root.device_binding ?? {}
      const binding = normalizeBusinessMemberDeviceBinding({
        ...asRecord(rawBinding),
        can_bind: root.can_bind ?? root.eligible_for_new_binding ?? asRecord(rawBinding).can_bind,
        eligible_for_new_binding: root.eligible_for_new_binding
          ?? root.can_bind
          ?? asRecord(rawBinding).eligible_for_new_binding,
        binding_blockers: root.binding_blockers ?? root.blockers ?? asRecord(rawBinding).binding_blockers,
      })
      const devices = normalizeDeliveryDevices(
        Array.isArray(root.devices) ? { items: root.devices } : response,
      )
      setBusinessBindingDevices(devices)
      updateBusinessBindingView(account, binding)
      return binding
    } catch (error: unknown) {
      if (!quiet) message.error(`读取母号设备绑定失败：${errorMessage(error, '未知错误')}`)
      return null
    } finally {
      if (!quiet) setBusinessBindingLoading(false)
    }
  }

  const openBusinessBindingEditor = (account: GptPlanAccount) => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    const initial = normalizeBusinessMemberDeviceBinding(source?.business_device_binding || {})
    setBusinessBindingAccount(account)
    setBusinessBinding(initial)
    setBusinessBindingSelectedRef(initial.bound ? initial.device_ref : undefined)
    setBusinessBindingDevices([])
    void readBusinessBindingEditor(account)
  }

  const closeBusinessBindingEditor = () => {
    if (businessBindingSaving) return
    setBusinessBindingAccount(null)
    setBusinessBinding(null)
    setBusinessBindingDevices([])
    setBusinessBindingSelectedRef(undefined)
  }

  const saveBusinessBindingEditor = async () => {
    if (!businessBindingAccount || !businessBindingSelectedRef || businessBindingSaving) return
    setBusinessBindingSaving(true)
    try {
      const response = await apiFetch(
        `${API_ROOT}/accounts/${businessBindingAccount.id}/business-device-binding`,
        {
          method: 'PUT',
          body: JSON.stringify({
            device_ref: businessBindingSelectedRef,
            expected_policy_revision: Number(businessBinding?.policy_revision || 0),
          }),
        },
      )
      const latest = normalizeBusinessMemberDeviceBinding(response)
      updateBusinessBindingView(businessBindingAccount, latest)
      message.success(`${businessBindingAccount.email} 已绑定到 ${businessMemberBindingLabel(latest)}`)
    } catch (error: unknown) {
      if (error instanceof ApiFetchError && error.status === 409) {
        message.warning('母号绑定已被其他操作修改，正在重新读取最新状态')
        await readBusinessBindingEditor(businessBindingAccount, true)
      } else {
        message.error(`保存母号设备绑定失败：${errorMessage(error, '未知错误')}`)
      }
    } finally {
      setBusinessBindingSaving(false)
    }
  }

  const removeBusinessBindingEditor = async () => {
    if (!businessBindingAccount || !businessBinding?.bound || businessBindingSaving) return
    setBusinessBindingSaving(true)
    try {
      const revision = Number(businessBinding.policy_revision || 0)
      const response = await apiFetch(
        `${API_ROOT}/accounts/${businessBindingAccount.id}/business-device-binding?expected_policy_revision=${revision}`,
        { method: 'DELETE' },
      )
      const latest = normalizeBusinessMemberDeviceBinding(response)
      updateBusinessBindingView(businessBindingAccount, latest)
      message.success(`${businessBindingAccount.email} 已解除设备绑定`)
    } catch (error: unknown) {
      if (error instanceof ApiFetchError && error.status === 409) {
        message.warning('母号绑定已被其他操作修改，正在重新读取最新状态')
        await readBusinessBindingEditor(businessBindingAccount, true)
      } else {
        message.error(`解除母号设备绑定失败：${errorMessage(error, '未知错误')}`)
      }
    } finally {
      setBusinessBindingSaving(false)
    }
  }

  const syncMemberDevice = async () => {
    if (!deviceAccount || !selectedDeviceRef) {
      message.warning('请选择设备')
      return
    }
    setDeviceSyncing(true)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${deviceAccount.id}/sync-device`, {
        method: 'POST',
        body: JSON.stringify({ device_ref: selectedDeviceRef }),
      }) as {
        provider?: string
        device_ref?: string
        sync?: { idempotent?: boolean; message?: string } | null
      }
      const provider = String(result?.provider || selectedDeviceRef.split(':')[0]).toLowerCase()
      const providerLabel = provider === 'sub2api' ? 'SUB' : 'CPA'
      const detail = String(result?.sync?.message || '').trim()
      message.success(
        detail
          ? `${providerLabel} 同步完成：${detail}`
          : `${deviceAccount.email} 已同步到 ${providerLabel} 设备${result?.sync?.idempotent ? '（已存在，无需重复创建）' : ''}`,
        6,
      )
      setDeviceAccount(null)
      setMemberSourceOverrides((current) => {
        const next = { ...current }
        delete next[deviceAccount.id]
        return next
      })
      await refreshAfterMemberAction()
    } catch (error: unknown) {
      message.error(`同步设备失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setDeviceSyncing(false)
    }
  }

  const syncBusinessChildDevice = async () => {
    if (!businessChildDeviceTarget || !selectedDeviceRef) {
      message.warning('请选择设备')
      return
    }
    const { account, child } = businessChildDeviceTarget
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号池 ID，无法同步设备')
      return
    }
    setDeviceSyncing(true)
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/business-child-sync-device/${childId}`,
        {
          method: 'POST',
          body: JSON.stringify({ device_ref: selectedDeviceRef }),
        },
      ) as {
        provider?: string
        device_ref?: string
        sync?: { idempotent?: boolean; message?: string } | null
      }
      const provider = String(result?.provider || selectedDeviceRef.split(':')[0]).toLowerCase()
      const providerLabel = provider === 'sub2api' ? 'SUB' : 'CPA'
      const detail = String(result?.sync?.message || '').trim()
      message.success(
        detail
          ? `${providerLabel} 同步完成：${detail}`
          : `${child.email || `子号 #${childId}`} 已同步到 ${providerLabel} 设备${result?.sync?.idempotent ? '（已存在，无需重复创建）' : ''}`,
        6,
      )
      setBusinessChildDeviceTarget(null)
      await Promise.all([
        loadBusinessChildren(account, { quiet: true }),
        loadBusinessChildCatalog(true),
      ])
    } catch (error: unknown) {
      message.error(`子号同步设备失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setDeviceSyncing(false)
    }
  }

  const fetchMemberDeviceUsage = async (account: GptPlanAccount, device: LinkedMemberDevice) => {
    const busyKey = `${account.id}-${device.deviceRef}`
    setDeviceUsageBusyKey(busyKey)
    try {
      const params = new URLSearchParams({
        device_ref: device.deviceRef,
        active: 'true',
      })
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/device-usage?${params.toString()}`,
      ) as {
        provider?: string
        device_ref?: string
        usage?: Record<string, unknown> | null
      }
      const provider = String(result?.provider || device.provider).toLowerCase() === 'sub2api'
        ? 'sub2api'
        : 'cpa'
      setMemberDeviceUsage({
        accountId: account.id,
        email: account.email,
        deviceRef: String(result?.device_ref || device.deviceRef),
        provider,
        usage: asRecord(result?.usage),
      })
      message.success(`${device.provider === 'cpa' ? 'CPA' : 'SUB'} 额度已刷新`)
      await Promise.all([loadAccounts(), loadStats()])
    } catch (error: unknown) {
      message.error(`查询设备额度失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setDeviceUsageBusyKey('')
    }
  }

  useEffect(() => {
    if (businessSelectionQuerySignatureRef.current === businessSelectionQuerySignature) return
    businessSelectionQuerySignatureRef.current = businessSelectionQuerySignature
    setSelectedBusinessAccountIds([])
    setBusinessSelectAllMatching(false)
  }, [businessSelectionQuerySignature])

  useEffect(() => {
    if (businessChildSelectionSignatureRef.current === businessChildSelectionQuerySignature) return
    businessChildSelectionSignatureRef.current = businessChildSelectionQuerySignature
    setSelectedBusinessChildMembershipIds([])
  }, [businessChildSelectionQuerySignature])

  useEffect(() => {
    const syncSecurityBrowserMode = (event: StorageEvent) => {
      if (event.key !== SECURITY_BROWSER_MODE_STORAGE_KEY) return
      setSecurityBrowserMode(event.newValue === 'headed' ? 'headed' : 'headless')
    }
    window.addEventListener('storage', syncSecurityBrowserMode)
    return () => window.removeEventListener('storage', syncSecurityBrowserMode)
  }, [])

  // 任务在当前服务进程中后台继续执行；浏览器只保存不敏感的 task_id
  // 作为恢复指针。关闭弹框不会中止任务，刷新页面后可在服务未重启时恢复查看。
  useEffect(() => {
    let taskId = ''
    try { taskId = String(localStorage.getItem(BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY) || '').trim() } catch { /* ignore */ }
    if (!taskId) return
    const generation = businessBatchInviteGenerationRef.current + 1
    businessBatchInviteGenerationRef.current = generation
    setBusinessBatchInviteTask(mergeBusinessBatchInviteTask(null, {
      task_id: taskId,
      status: 'running',
      logs: ['正在恢复上一次批量邀请任务状态…'],
    }, taskId))
    scheduleBusinessBatchInvitePoll(taskId, generation, 0, 100)
  // 仅在页面首次挂载时读取恢复指针；后续任务由 start 函数直接接管。
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    let stored = ''
    try { stored = String(localStorage.getItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY) || '').trim() } catch { /* ignore */ }
    if (!stored) return
    try {
      const parsed = JSON.parse(stored) as { taskId?: unknown; action?: unknown }
      const taskId = String(parsed.taskId || '').trim()
      const storedAction = String(parsed.action || '').trim().toLowerCase()
      if (!['oauth', 'setup_security', 'leave_workspace'].includes(storedAction)) {
        try { localStorage.removeItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY) } catch { /* ignore */ }
        return
      }
      const action = storedAction as BusinessChildBatchAction
      if (!taskId) return
      const generation = businessChildBatchGenerationRef.current + 1
      businessChildBatchGenerationRef.current = generation
      setBusinessChildBatchTask(mergeBusinessChildBatchActionTask(null, {
        task_id: taskId,
        action,
        status: 'running',
        logs: ['正在恢复上一次子号批量任务状态…'],
      }, taskId, action))
      scheduleBusinessChildBatchPoll(taskId, action, generation, 0, 100)
    } catch {
      try { localStorage.removeItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY) } catch { /* ignore */ }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    let taskId = ''
    try { taskId = String(sessionStorage.getItem(BUSINESS_CHILD_NV_BATCH_TASK_STORAGE_KEY) || '').trim() } catch { /* ignore */ }
    if (taskId) {
      setBusinessChildNvBatchTask(sanitizeBusinessChildNvBatchTask({ task_id: taskId, status: 'running' }))
    }
  }, [])

  useEffect(() => {
    const taskId = businessChildNvBatchTask?.task_id
    if (!taskId || businessChildNvBatchTask?.status !== 'running') return
    let cancelled = false
    let timer: number | undefined
    let requestTimeout: number | undefined
    let controller: AbortController | undefined
    let failures = 0
    const poll = async () => {
      controller = new AbortController()
      requestTimeout = window.setTimeout(() => controller?.abort(), 15_000)
      try {
        const result = await apiFetch(
          `${API_ROOT}/business-children/nvtokens-listing-tasks/${encodeURIComponent(taskId)}`,
          { cache: 'no-store', signal: controller.signal },
        )
        if (cancelled) return
        const task = sanitizeBusinessChildNvBatchTask(result, taskId)
        failures = 0
        applyBusinessChildNvBatchSnapshot(task)
        if (task.status === 'running') timer = window.setTimeout(() => { void poll() }, 1200)
      } catch (error: unknown) {
        if (cancelled) return
        failures += 1
        const terminalReadError = error instanceof ApiFetchError && [403, 404, 410].includes(error.status)
        const unavailable = error instanceof ApiFetchError && [404, 410].includes(error.status)
        const stopped = terminalReadError || failures > 3
        const detail = controller?.signal.aborted ? '读取任务进度超时' : errorMessage(error, '读取任务进度失败')
        setBusinessChildNvBatchPollingError(unavailable
          ? '任务记录不存在或已过期。请先核对 NV 实际上架状态，再清除本地任务记录重新选择；不会自动重复上架。'
          : stopped
          ? `${detail}。已暂停自动读取，任务实际状态以后台为准；可点击“重试读取进度”。`
          : `${detail}。正在自动重试（${failures}/3）。`)
        setBusinessChildNvBatchPollingStopped(stopped)
        setBusinessChildNvBatchUnavailable(unavailable)
        if (!stopped) timer = window.setTimeout(() => { void poll() }, 3000)
      } finally {
        if (requestTimeout !== undefined) window.clearTimeout(requestTimeout)
      }
    }
    void poll()
    return () => {
      cancelled = true
      if (timer !== undefined) window.clearTimeout(timer)
      if (requestTimeout !== undefined) window.clearTimeout(requestTimeout)
      controller?.abort()
    }
  // 任务 ID、结束状态或手动重试才重启轮询；关闭弹框不影响后台执行及状态读取。
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [businessChildNvBatchTask?.task_id, businessChildNvBatchTask?.status, businessChildNvBatchPollEpoch])

  useEffect(() => { void loadAccounts() }, [loadAccounts])
  useEffect(() => { void loadBusinessChildCatalog() }, [loadBusinessChildCatalog])
  // 进入页面立即读取套餐目录提醒摘要，之后每 30 秒刷新一次。
  // 真正的邮箱取件由后端调度器执行，前端轮询只读取已落库的未读状态。
  useEffect(() => {
    void loadMailAlertSummary()
    const timer = window.setInterval(() => { void loadMailAlertSummary() }, 30_000)
    return () => window.clearInterval(timer)
  }, [loadMailAlertSummary])

  // 会员账号列表每 60 秒静默读取一次，让最近检查时间与后台状态同步；
  // 不触发账号导入、远端 workspace 刷新或其他副作用。
  useEffect(() => {
    if (mainTab !== 'accounts' || accountType !== 'member') return undefined
    const timer = window.setInterval(() => { void loadAccounts(true) }, 60_000)
    return () => window.clearInterval(timer)
  }, [accountType, loadAccounts, mainTab])
  useEffect(() => {
    if (
      mainTab !== 'accounts'
      || accountType !== 'member'
      || memberPlan !== 'team'
      || businessCatalogView !== 'children'
    ) return undefined
    const timer = window.setInterval(() => { void loadBusinessChildCatalog(true) }, 60_000)
    return () => window.clearInterval(timer)
  }, [accountType, businessCatalogView, loadBusinessChildCatalog, mainTab, memberPlan])

  useEffect(() => {
    if (mainTab !== 'accounts' || accountType !== 'member') return undefined
    setMailMonitorNow(Date.now())
    const timer = window.setInterval(() => setMailMonitorNow(Date.now()), 1_000)
    return () => window.clearInterval(timer)
  }, [accountType, mainTab])

  // 一个页面级时钟用于刷新 BUSINESS 母号邀请失败冷却倒计时。
  useEffect(() => {
    if (mainTab !== 'accounts' || accountType !== 'member') return undefined
    setReplenishmentNow(Date.now())
    const timer = window.setInterval(() => setReplenishmentNow(Date.now()), 1_000)
    return () => window.clearInterval(timer)
  }, [accountType, mainTab])
  useEffect(() => { void loadStats() }, [loadStats])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const data = await apiFetch(`${API_ROOT}/import-tasks?limit=20`) as { items?: ImportTaskSnapshot[] }
        if (cancelled || importTaskId) return
        const active = (data.items || []).find((item) => item.status === 'pending' || item.status === 'running')
        if (active) {
          setImportTask(active)
          setImportTaskId(active.id)
        }
      } catch {
        // 页面主体不依赖任务历史；旧服务未提供任务列表时保持静默。
      }
    })()
    return () => { cancelled = true }
  }, [importTaskId])

  useEffect(() => {
    if (!importTaskId) return
    let cancelled = false
    let timer: number | undefined

    const poll = async () => {
      try {
        const task = await apiFetch(`${API_ROOT}/import-tasks/${importTaskId}`) as ImportTaskSnapshot
        if (cancelled) return
        setImportTask(task)
        if (task.status === 'done' || task.status === 'failed') {
          if (handledImportTaskRef.current !== task.id) {
            handledImportTaskRef.current = task.id
            if (task.status === 'done') {
              message.success(`导入完成：成功 ${task.success || 0}，失败 ${task.failed || 0}`)
            } else {
              message.error(task.errors?.[0] || '导入任务失败')
            }
            reload()
          }
          return
        }
        timer = window.setTimeout(poll, 2000)
      } catch (error: unknown) {
        if (!cancelled) {
          timer = window.setTimeout(poll, 3000)
          console.warn('[gpt-plans] import task poll failed', error)
        }
      }
    }

    void poll()
    return () => {
      cancelled = true
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [importTaskId, message, reload])

  useEffect(() => {
    void apiFetch(`${API_ROOT}/checkout-region`)
      .then((result: unknown) => {
        const value = result as { country?: string; currency?: string }
        if (value?.country && value?.currency) {
          setCheckoutRegion({
            country: String(value.country).toUpperCase(),
            currency: String(value.currency).toUpperCase(),
          })
        }
      })
      .catch(() => {
        // 升级弹框仍可使用默认 PH/PHP；保存时会显示真实接口错误。
      })
  }, [])

  useEffect(() => () => {
    businessCouponRequestGenerationRef.current += 1
    businessCouponRequestRef.current?.abort()
    businessDefaultCouponRequestGenerationRef.current += 1
    businessDefaultCouponRequestRef.current?.abort()
    if (upgradeTimerRef.current !== undefined) window.clearTimeout(upgradeTimerRef.current)
    if (memberTaskTimerRef.current !== undefined) window.clearTimeout(memberTaskTimerRef.current)
    if (businessBurnTimerRef.current !== undefined) window.clearTimeout(businessBurnTimerRef.current)
    if (businessBatchInviteTimerRef.current !== undefined) window.clearTimeout(businessBatchInviteTimerRef.current)
    if (businessChildBatchTimerRef.current !== undefined) window.clearTimeout(businessChildBatchTimerRef.current)
    if (businessChildRtTimerRef.current !== undefined) window.clearTimeout(businessChildRtTimerRef.current)
    if (securitySetupTimerRef.current !== undefined) window.clearTimeout(securitySetupTimerRef.current)
    if (businessChildSecuritySetupTimerRef.current !== undefined) {
      window.clearTimeout(businessChildSecuritySetupTimerRef.current)
    }
    memberTaskGenerationRef.current += 1
    businessBurnGenerationRef.current += 1
    businessBatchInviteGenerationRef.current += 1
    businessChildBatchGenerationRef.current += 1
    businessChildRtGenerationRef.current += 1
    securitySetupGenerationRef.current += 1
    businessChildSecuritySetupGenerationRef.current += 1
    businessChildRtActiveKeyRef.current = ''
  }, [])

  const saveCheckoutRegion = async (country: string, currency: string) => {
    const previous = checkoutRegion
    const next = { country: country.toUpperCase(), currency: currency.toUpperCase() }
    setCheckoutRegion(next)
    setCheckoutRegionSaving(true)
    try {
      await apiFetch(`${API_ROOT}/checkout-region`, {
        method: 'PUT',
        body: JSON.stringify(next),
      })
      message.success(`PRO 结账区已设为 ${next.country}/${next.currency}`)
    } catch (error: unknown) {
      setCheckoutRegion(previous)
      message.error(`保存结账区失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setCheckoutRegionSaving(false)
    }
  }

  const loadRoxyProxies = async () => {
    setRoxyLoading(true)
    try {
      const result = await apiFetch(`${API_ROOT}/roxy/proxies`) as { items?: RoxyProxy[] }
      setRoxyProxies(Array.isArray(result?.items) ? result.items : [])
    } catch (error: unknown) {
      setRoxyProxies([])
      message.warning(`读取 RoxyBrowser 代理失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setRoxyLoading(false)
    }
  }

  useEffect(() => {
    if (upgradeBrowserConfig.browserBackend === 'roxybrowser') void loadRoxyProxies()
    // 仅在统一配置切换为指纹模式时读取一次；手动刷新由顶部按钮触发。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [upgradeBrowserConfig.browserBackend])

  const updateUpgradeBrowserConfig = async (browserBackend: 'local' | 'roxybrowser', roxyProxyId?: number) => {
    try {
      await saveUpgradeBrowserConfig({ browserBackend, roxyProxyId })
      message.success(browserBackend === 'roxybrowser'
        ? `PRO 升级已统一使用 Roxy 指纹浏览器${roxyProxyId ? '及所选代理' : '（未指定代理）'}`
        : 'PRO 升级已统一使用本地浏览器')
    } catch (error: unknown) {
      message.error(`保存升级浏览器配置失败：${errorMessage(error, '未知错误')}`)
    }
  }

  const finishUpgradeSuccess = (account: GptPlanAccount) => {
    if (upgradeTimerRef.current !== undefined) window.clearTimeout(upgradeTimerRef.current)
    upgradeTimerRef.current = undefined
    setUpgradeTask(null)
    setUpgradeStarting(false)
    setUpgradeAccount(null)
    message.success(`升级 PRO 成功：${account.email}`)
    if (account.account_type === 'refunded') {
      setPage(1)
      void loadStats()
      reload()
      return
    }
    setAccountType('member')
    setMemberPlan('pro')
    setPage(1)
    void loadStats()
  }

  const waitForRefundedUpgradeReview = (
    account: GptPlanAccount,
    taskId: string,
    stage: string,
  ) => {
    if (upgradeTimerRef.current !== undefined) window.clearTimeout(upgradeTimerRef.current)
    upgradeTimerRef.current = undefined
    setUpgradeTask(null)
    setUpgradeStarting(false)
    setUpgradeAccount(null)
    setRefundedUpgradeReview({ accountId: account.id, taskId, stage })
    message.info(`升级流程已结束，请人工确认 ${account.email} 是否已升级为 PRO`, 8)
    reload()
  }

  const confirmRefundedUpgrade = async (account: GptPlanAccount, success: boolean) => {
    const busyKey = `${account.id}:${success ? 'success' : 'not-upgraded'}`
    const taskId = refundedUpgradeReview?.accountId === account.id
      ? refundedUpgradeReview.taskId
      : ''
    setRefundedUpgradeConfirmBusyKey(busyKey)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/upgrade-pro/manual-confirm`, {
        method: 'POST',
        body: JSON.stringify({
          success,
          ...(taskId ? { task_id: taskId } : {}),
        }),
      }) as { ok?: boolean; error?: string }
      if (result?.ok === false) throw new Error(result.error || '人工确认未生效')

      setRefundedUpgradeReview((current) => current?.accountId === account.id ? null : current)
      if (success) {
        message.success(`已人工确认升级 PRO：${account.email}`)
        setAccountType('member')
        setMemberPlan('pro')
        setLoginStatus(undefined)
        setPage(1)
      } else {
        message.info(`已人工确认未升级：${account.email}；未标记为 PRO 失败`)
        reload()
      }
      void loadStats()
    } catch (error: unknown) {
      message.error(`人工确认升级结果失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setRefundedUpgradeConfirmBusyKey('')
    }
  }

  const migrateRefundedAccount = async (
    account: GptPlanAccount,
    target: RefundedMigrationTarget,
  ) => {
    const meta = REFUNDED_MIGRATION_META[target]
    const busyKey = `${account.id}:${target}`
    setRefundedMigrationBusyKey(busyKey)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/migrate-refunded`, {
        method: 'POST',
        body: JSON.stringify({ target_plan: target }),
      }) as { ok?: boolean; migrated_at?: string }
      if (!result?.ok) throw new Error('后端未确认迁移成功')
      message.success(
        `已迁移至 ${meta.label}，升级时间：${formatTime(result.migrated_at)}`,
      )
      setAccountType('member')
      setMemberPlan(meta.memberPlan)
      setLoginStatus(undefined)
      setPage(1)
      void loadStats()
    } catch (error: unknown) {
      message.error(`迁移至 ${meta.label} 失败：${errorMessage(error, '未知错误')}`)
      throw error
    } finally {
      setRefundedMigrationBusyKey('')
    }
  }

  const confirmRefundedMigration = (
    account: GptPlanAccount,
    target: RefundedMigrationTarget,
  ) => {
    const meta = REFUNDED_MIGRATION_META[target]
    modal.confirm({
      title: `迁移至 ${meta.label}？`,
      content: `账号 ${account.email} 将离开“已退款”并进入会员账号 ${meta.label}；升级时间更新为服务器当前时间。迁移本身不会发起付款。`,
      okText: '确认迁移',
      cancelText: '取消',
      onOk: () => migrateRefundedAccount(account, target),
    })
  }

  const scheduleUpgradePoll = (account: GptPlanAccount, taskId: string, delay = 0) => {
    if (upgradeTimerRef.current !== undefined) window.clearTimeout(upgradeTimerRef.current)
    upgradeTimerRef.current = window.setTimeout(async () => {
      try {
        const result = await apiFetch(
          `${API_ROOT}/accounts/${account.id}/upgrade-pro/status/${encodeURIComponent(taskId)}`,
        ) as { stage?: string; error?: string }
        const stage = String(result?.stage || 'waiting_redirect')
        setUpgradeTask({ accountId: account.id, taskId, stage })
        if (account.account_type === 'refunded' && (
          stage === 'success'
          || refundedUpgradeNeedsManualReview(stage)
        )) {
          waitForRefundedUpgradeReview(account, taskId, stage)
          return
        }
        if (stage === 'success') {
          finishUpgradeSuccess(account)
          return
        }
        if (stage === 'confirmation_pending') {
          upgradeTimerRef.current = undefined
          setUpgradeTask(null)
          setUpgradeStarting(false)
          setUpgradeAccount(null)
          const detail = result?.error
            || '付款跳转已完成，但尚未复核到 PRO 套餐。账号仍保留在普通账号，请稍后点击“登录”重新检测。'
          message.warning(detail, 10)
          reload()
          return
        }
        if (['failed', 'timeout', 'cancelled'].includes(stage)) {
          upgradeTimerRef.current = undefined
          setUpgradeTask(null)
          setUpgradeStarting(false)
          setUpgradeAccount(null)
          const detail = result?.error || UPGRADE_STAGE_LABELS[stage] || stage
          if (stage === 'timeout') message.warning(detail)
          else if (stage !== 'cancelled') message.error(`升级 PRO 失败：${detail}`)
          return
        }
        scheduleUpgradePoll(account, taskId, 3000)
      } catch (error: unknown) {
        // 短暂网络错误不应终止正在付款的浏览器任务。
        console.warn('[gpt-plans] upgrade status poll failed', error)
        scheduleUpgradePoll(account, taskId, 4000)
      }
    }, delay)
  }

  const startUpgradePro = async (account: GptPlanAccount, targetPlan: 'pro_20x' | 'pro_5x' = 'pro_20x') => {
    if (upgradeBrowserConfigLoading) {
      message.warning('正在读取统一升级配置，请稍候')
      return
    }
    if (upgradeBrowserConfigSaving) {
      message.warning('正在保存统一升级配置，请稍候')
      return
    }
    if (upgradeStarting && !upgradeTask) {
      message.warning('正在启动 PRO 升级，请稍候')
      return
    }
    if (upgradeTask) {
      message.warning(upgradeTask.accountId === account.id
        ? '该账号的 PRO 升级任务正在执行，请等待其完成'
        : '已有一个 PRO 升级任务正在执行，请等待其完成')
      return
    }
    setUpgradeAccount(account)
    setUpgradeStarting(true)
    let result: {
      ok?: boolean
      task_id?: string
      stage?: string
      checkout_stage?: string
      error?: string
      browser_kept_open?: boolean
      http_status?: number
      already_pro?: boolean
      region?: string
    } | undefined
    try {
      result = await apiFetch(`${API_ROOT}/accounts/${account.id}/upgrade-pro`, {
        method: 'POST',
        body: JSON.stringify({
          target_plan: targetPlan,
          // 浏览器与代理由统一服务端配置决定；付款卡由共享卡池自动选择。
        }),
      })
      if (result?.ok === false) {
        throw new Error(result.error || '升级启动失败')
      }
      if (result?.region) message.info(`本次后端确认的结账区：${String(result.region)}`)
      if (result?.already_pro) {
        finishUpgradeSuccess(account)
        return
      }
      const taskId = String(result?.task_id || '')
      if (!taskId) throw new Error('后端未返回升级任务 ID')
      const stage = String(result?.stage || 'awaiting_card_pick')
      setUpgradeTask({ accountId: account.id, taskId, stage })
      message.success(`${targetPlan === 'pro_5x' ? 'PRO 5X' : 'PRO 20X'} 升级任务已启动（${upgradeBrowserConfig.browserBackend === 'roxybrowser' ? 'Roxy 指纹浏览器' : '本地浏览器'}），付款卡将从套餐管理卡池自动选择`)
      scheduleUpgradePoll(account, taskId)
    } catch (error: unknown) {
      const detail = errorMessage(error, '未知错误')
      const stage = result?.checkout_stage || result?.stage
      const stageLabels: Record<string, string> = {
        session: '读取登录会话',
        checkout: '创建结账链接',
        checkout_navigation: '打开付款页面',
        checkout_failed: '结账失败',
      }
      modal.error({
        title: `${targetPlan === 'pro_5x' ? 'PRO 5X' : 'PRO 20X'} 升级启动失败`,
        width: 600,
        okText: '关闭',
        closable: true,
        maskClosable: false,
        content: (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Typography.Text style={{ overflowWrap: 'anywhere' }}>账号：{account.email}</Typography.Text>
            {stage && <Typography.Text>阶段：{stageLabels[stage] ? `${stageLabels[stage]}（${stage}）` : stage}</Typography.Text>}
            {typeof result?.http_status === 'number' && <Typography.Text>HTTP 状态：{result.http_status}</Typography.Text>}
            <Typography.Paragraph type="danger" style={{ margin: 0, maxHeight: 240, overflowY: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
              {detail}
            </Typography.Paragraph>
            {result?.browser_kept_open === true && (
              <Alert type="info" showIcon message="浏览器已保留，可切换到浏览器查看当前页面。" />
            )}
          </Space>
        ),
      })
      setUpgradeStarting(false)
      setUpgradeAccount(null)
    }
  }

  const loadBusinessDefaultCoupon = async () => {
    if (businessDefaultCouponSavingRef.current) return
    const generation = ++businessDefaultCouponRequestGenerationRef.current
    businessDefaultCouponRequestRef.current?.abort()
    const controller = new AbortController()
    businessDefaultCouponRequestRef.current = controller
    const timeout = window.setTimeout(() => controller.abort(), 15_000)
    setBusinessDefaultCouponLoading(true)
    setBusinessDefaultCouponLoadError('')
    setBusinessDefaultCouponSaveError('')
    try {
      const result = await apiFetch(`${API_ROOT}/business-checkout-config`, {
        cache: 'no-store', signal: controller.signal,
      })
      if (generation !== businessDefaultCouponRequestGenerationRef.current) return
      const coupon = businessCheckoutCouponFromResponse(result)
      setBusinessDefaultCoupon(coupon)
      setBusinessDefaultCouponDraft(coupon)
    } catch (error: unknown) {
      if (generation !== businessDefaultCouponRequestGenerationRef.current) return
      setBusinessDefaultCouponLoadError(controller.signal.aborted
        ? '读取 BUSINESS 默认优惠码超时，请重试'
        : errorMessage(error, '读取 BUSINESS 默认优惠码失败'))
    } finally {
      window.clearTimeout(timeout)
      if (generation === businessDefaultCouponRequestGenerationRef.current) {
        setBusinessDefaultCouponLoading(false)
        businessDefaultCouponRequestRef.current = null
      }
    }
  }

  const openBusinessDefaultCouponSettings = () => {
    setBusinessDefaultCouponOpen(true)
    setBusinessDefaultCouponDraft(businessDefaultCoupon || '')
    void loadBusinessDefaultCoupon()
  }

  const closeBusinessDefaultCouponSettings = () => {
    if (businessDefaultCouponSavingRef.current) return
    businessDefaultCouponRequestGenerationRef.current += 1
    businessDefaultCouponRequestRef.current?.abort()
    businessDefaultCouponRequestRef.current = null
    setBusinessDefaultCouponLoading(false)
    setBusinessDefaultCouponOpen(false)
  }

  const saveBusinessDefaultCoupon = async () => {
    if (businessDefaultCouponSavingRef.current || businessDefaultCouponLoading || businessDefaultCouponLoadError) return
    const coupon = businessDefaultCouponDraft.trim()
    if (!coupon || coupon.length > 200) {
      setBusinessDefaultCouponSaveError('优惠码不能为空，且不能超过 200 个字符')
      return
    }
    businessDefaultCouponSavingRef.current = true
    const generation = ++businessDefaultCouponRequestGenerationRef.current
    businessDefaultCouponRequestRef.current?.abort()
    const controller = new AbortController()
    businessDefaultCouponRequestRef.current = controller
    const timeout = window.setTimeout(() => controller.abort(), 15_000)
    setBusinessDefaultCouponSaving(true)
    setBusinessDefaultCouponSaveError('')
    try {
      const result = await apiFetch(`${API_ROOT}/business-checkout-config`, {
        method: 'PUT',
        signal: controller.signal,
        body: JSON.stringify({ coupon }),
      })
      if (generation !== businessDefaultCouponRequestGenerationRef.current) return
      const savedCoupon = businessCheckoutCouponFromResponse(result)
      setBusinessDefaultCoupon(savedCoupon)
      setBusinessDefaultCouponDraft(savedCoupon)
      message.success('BUSINESS 默认优惠码已保存，下次打开支付链接弹框时自动使用')
    } catch (error: unknown) {
      if (generation !== businessDefaultCouponRequestGenerationRef.current) return
      setBusinessDefaultCouponSaveError(controller.signal.aborted
        ? '保存请求超时，尚未确认是否生效；已保留当前草稿，可重试保存'
        : `保存失败：${errorMessage(error, '未知错误')}；当前草稿已保留`)
    } finally {
      window.clearTimeout(timeout)
      businessDefaultCouponSavingRef.current = false
      if (generation === businessDefaultCouponRequestGenerationRef.current) {
        setBusinessDefaultCouponSaving(false)
        businessDefaultCouponRequestRef.current = null
      }
    }
  }

  const loadBusinessCheckoutCoupon = async () => {
    const generation = ++businessCouponRequestGenerationRef.current
    businessCouponRequestRef.current?.abort()
    const controller = new AbortController()
    businessCouponRequestRef.current = controller
    const timeout = window.setTimeout(() => controller.abort(), 15_000)
    setBusinessCoupon('')
    setBusinessCouponLoading(true)
    setBusinessCouponLoadError('')
    try {
      const result = await apiFetch(`${API_ROOT}/business-checkout-config`, {
        cache: 'no-store', signal: controller.signal,
      })
      if (generation !== businessCouponRequestGenerationRef.current) return
      setBusinessCoupon(businessCheckoutCouponFromResponse(result))
    } catch (error: unknown) {
      if (generation !== businessCouponRequestGenerationRef.current) return
      setBusinessCouponLoadError(controller.signal.aborted
        ? '读取默认优惠码超时，请重试后再生成支付链接'
        : `读取默认优惠码失败：${errorMessage(error, '未知错误')}；请重试后再生成支付链接`)
    } finally {
      window.clearTimeout(timeout)
      if (generation === businessCouponRequestGenerationRef.current) {
        setBusinessCouponLoading(false)
        businessCouponRequestRef.current = null
      }
    }
  }

  const closeBusinessCheckout = () => {
    businessCouponRequestGenerationRef.current += 1
    businessCouponRequestRef.current?.abort()
    businessCouponRequestRef.current = null
    setBusinessCouponLoading(false)
    setBusinessCouponLoadError('')
    setBusinessAccount(null)
  }

  const openBusinessCheckout = (account: GptPlanAccount) => {
    if (businessDefaultCouponLoading || businessDefaultCouponSavingRef.current) {
      message.info('默认优惠码正在读取或保存，请稍后打开支付链接')
      return
    }
    setBusinessAccount(account)
    setBusinessWorkspace('')
    void loadBusinessCheckoutCoupon()
    setBusinessSeatType('default')
    setBusinessSeats(2)
    setBusinessCountry('US')
    setBusinessCurrency('USD')
    setBusinessAutoFill(true)
    setBusinessAutoSubmit(false)
    setBusinessCardText('')
    setBusinessUrl('')
    setBusinessResult(null)
  }

  const generateBusinessCheckout = async () => {
    const account = businessAccount
    if (!account || businessLoading || businessCouponLoading || businessCouponLoadError || businessDefaultCouponSavingRef.current) return
    if (!businessWorkspace.trim()) {
      message.warning('请填写 BUSINESS 空间名称')
      return
    }
    if (!businessCoupon.trim()) {
      message.warning('请填写优惠码')
      return
    }
    if (businessCoupon.trim().length > 200) {
      message.warning('优惠码不能超过 200 个字符')
      return
    }
    if (businessSeatType === 'default' && businessSeats < 2) {
      message.warning('普通席位数量最少为 2')
      return
    }
    if (businessCountry.trim().length !== 2 || businessCurrency.trim().length !== 3) {
      message.warning('国家需为 2 位代码，货币需为 3 位代码')
      return
    }
    setBusinessLoading(true)
    setBusinessUrl('')
    setBusinessResult(null)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/business-checkout-link`, {
        method: 'POST',
        body: JSON.stringify({
          workspace_name: businessWorkspace.trim(),
          coupon: businessCoupon.trim(),
          seat_type: businessSeatType,
          seat_quantity: businessSeatType === 'prolite' ? 2 : businessSeats,
          country: businessCountry.trim().toUpperCase(),
          currency: businessCurrency.trim().toUpperCase(),
          auto_fill: businessAutoFill,
          auto_submit: businessAutoSubmit,
          checkout_card: businessCardText.trim() || undefined,
        }),
      }) as Record<string, unknown> & { ok?: boolean; url?: string; stage?: string; error?: string }
      if (result?.ok === false || !result?.url) {
        throw new Error(`${result?.stage ? `阶段 ${result.stage}：` : ''}${result?.error || '未返回支付链接'}`)
      }
      const parsed = new URL(String(result.url), window.location.origin)
      const allowedHosts = new Set(['chatgpt.com', 'pay.openai.com', 'checkout.stripe.com'])
      if (parsed.protocol !== 'https:' || !allowedHosts.has(parsed.hostname)) {
        throw new Error(`接口返回了非预期付款地址：${parsed.hostname}`)
      }
      setBusinessUrl(parsed.href)
      setBusinessResult(result)
      message.success('BUSINESS 支付链接已生成，请在付款页核对并完成订阅')
      reload()
    } catch (error: unknown) {
      message.error(`生成 BUSINESS 支付链接失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setBusinessLoading(false)
    }
  }

  const accountCounts = useMemo(() => {
    const memberPlans: Record<MemberPlan, number> = {
      go: Number(stats?.member_plans?.go || 0),
      plus: Number(stats?.member_plans?.plus || 0),
      pro: Number(stats?.member_plans?.pro || 0),
      team: Number(stats?.member_plans?.team || 0),
    }
    if (!stats?.member_plans) {
      for (const item of stats?.plans || []) {
        const key = memberPlanKey(item.plan_type)
        if (key) memberPlans[key] += Number(item.count || 0)
      }
    }
    const fallbackMember = Object.values(memberPlans).reduce((sum, value) => sum + value, 0)
    const member = Number(stats?.member ?? fallbackMember)
    const refunded = Number(stats?.refunded || 0)
    const regular = Number(stats?.regular ?? Math.max(0, Number(stats?.total || 0) - member - refunded))
    return { regular, member, refunded, memberPlans }
  }, [stats])

  const submitImport = async () => {
    const data = importText.trim()
    if (!data) {
      message.warning('请输入账号数据')
      return
    }
    setImportLoading(true)
    try {
      const result = await apiFetch(businessOnly ? '/workspace/business/import' : `${API_ROOT}/batch-import`, {
        method: 'POST',
        body: JSON.stringify({ data, enabled: true, ...(businessOnly ? { mail_provider: motherImportMailProvider } : {}) }),
      }) as { task_id?: string; total?: number; imported?: number; success?: number; failed?: number }
      if (result.task_id) {
        handledImportTaskRef.current = ''
        setImportTaskId(result.task_id)
        setImportTask({
          id: result.task_id,
          status: 'pending',
          total: Number(result.total || 0),
          processed: 0,
          success: 0,
          failed: 0,
          errors: [],
        })
        message.success(`导入任务已启动${result.total ? `，共 ${result.total} 行` : ''}`)
      } else {
        message.success(`导入完成：成功 ${result.imported ?? result.success ?? 0}，失败 ${result.failed || 0}`)
        reload()
      }
      setImportOpen(false)
      setImportText('')
    } catch (error: unknown) {
      message.error(`导入失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setImportLoading(false)
    }
  }

  const loadBusinessMotherBundle = async (file?: File) => {
    if (!file) return
    if (file.size > 1024 * 1024) {
      message.error('迁移包超过 1 MB，已拒绝读取')
      return
    }
    try {
      const text = await file.text()
      const payload = JSON.parse(text) as { schema?: string; account?: { mail_provider?: string } }
      if (payload.schema !== 'gmail-business-manager.business-mother.v1') {
        throw new Error('迁移包格式或版本不受支持')
      }
      const provider = String(payload.account?.mail_provider || '').toLowerCase()
      if (['outlook', 'gmail', 'icloud'].includes(provider)) setMotherImportMailProvider(provider)
      setImportText(text)
      message.success('迁移包已读取，导入时会自动使用包内邮箱类型')
    } catch (error: unknown) {
      message.error(`读取迁移包失败：${errorMessage(error, 'JSON 格式无效')}`)
    }
  }

  const loginAccount = async (account: GptPlanAccount) => {
    setLoginId(account.id)
    message.info(`正在登录 ${account.email}，浏览器流程可能需要 30–60 秒`)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/login`, {
        method: 'POST',
        body: JSON.stringify({}),
      }) as {
        ok?: boolean
        stage?: string
        error?: string
        plan_type?: string
        plan_label?: string
        account_type?: AccountType
        member_plan?: MemberPlan | ''
      }
      if (result?.ok === false) {
        throw new Error(`${result.stage ? `阶段 ${result.stage}：` : ''}${result.error || '登录失败'}`)
      }
      const plan = result.plan_label || result.plan_type
      message.success(`登录成功：${account.email}${plan ? ` · ${plan}` : ''}`)
      const detectedMemberPlan = result.member_plan || memberPlanKey(result.plan_type)
      const detectedAccountType: AccountType = businessOnly ? 'member' : result.account_type
        || (detectedMemberPlan ? 'member' : 'regular')
      const nextMemberPlan = businessOnly ? 'team' : detectedAccountType === 'member'
        ? (detectedMemberPlan || DEFAULT_MEMBER_PLAN)
        : memberPlan
      const viewWillChange = accountType !== detectedAccountType
        || (detectedAccountType === 'member' && memberPlan !== nextMemberPlan)
        || page !== 1
      setAccountType(detectedAccountType)
      if (detectedAccountType === 'member') setMemberPlan(nextMemberPlan)
      if (detectedAccountType !== 'regular' && nextMemberPlan !== 'team') setLoginStatus(undefined)
      setPage(1)
      void loadStats()
      // 分类 state 变化后由 loadAccounts effect 使用新参数请求，避免旧闭包请求覆盖新 TAB。
      if (!viewWillChange) void loadAccounts()
      const loginSource = memberSourceOf(account, memberSourceOverrides[account.id])
      if (String(loginSource?.source_pool || account.source_pool || '').trim().toLowerCase() === 'gpt_business') {
        if (businessOnly) {
          message.info('登录已确认，正在自动刷新工作区成员和席位…')
          await refreshBusinessWorkspace(account)
        } else {
          void checkBusinessSession(account, true)
        }
      }
    } catch (error: unknown) {
      message.error(`登录失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setLoginId(null)
    }
  }

  const scheduleSecuritySetupPoll = (
    account: GptPlanAccount,
    taskId: string,
    generation: number,
    since = 0,
    delay = 800,
  ): void => {
    if (securitySetupTimerRef.current !== undefined) {
      window.clearTimeout(securitySetupTimerRef.current)
    }
    securitySetupTimerRef.current = window.setTimeout(async () => {
      if (securitySetupGenerationRef.current !== generation) return
      try {
        const snapshot = await apiFetch(
          `${API_ROOT}/accounts/${account.id}/security/setup/task/${encodeURIComponent(taskId)}?since=${since}`,
          { cache: 'no-store' },
        ) as {
          status?: string
          stage?: string
          logs?: unknown[]
          since?: number
          logs_total?: number
          finished_at?: string
          result?: Record<string, unknown> | null
          error?: string
          meta?: { security_progress?: unknown }
        }
        if (securitySetupGenerationRef.current !== generation) return

        const rawStatus = String(snapshot.status || 'running').trim().toLowerCase()
        const result = asRecord(snapshot.result)
        const newLogs = Array.isArray(snapshot.logs)
          ? snapshot.logs.map((line) => String(line))
          : []
        const explicitSuccess = ['done', 'completed', 'complete', 'success', 'succeeded'].includes(rawStatus)
        const explicitFailure = ['failed', 'failure', 'error', 'stopped', 'cancelled', 'canceled'].includes(rawStatus)
        const finished = Boolean(String(snapshot.finished_at || '').trim())
        const succeeded = explicitSuccess
          || (!explicitFailure && finished && !snapshot.error && result.ok !== false)
        const failed = explicitFailure || (finished && !succeeded)
        const stage = String(snapshot.stage || result.stage || rawStatus || 'running')
        const nextSinceCandidate = snapshot.since ?? snapshot.logs_total
        const nextSince = Number.isFinite(Number(nextSinceCandidate))
          ? Number(nextSinceCandidate)
          : since + newLogs.length

        setSecuritySetupTask((current) => current?.taskId === taskId ? {
          ...current,
          stage,
          securityProgress: readSecurityProgress(snapshot.meta?.security_progress ?? current.securityProgress, succeeded ? 'done' : failed ? 'failed' : rawStatus),
          logs: [...current.logs, ...newLogs],
        } : current)

        if (!succeeded && !failed) {
          scheduleSecuritySetupPoll(account, taskId, generation, nextSince, 1200)
          return
        }

        securitySetupTimerRef.current = undefined
        setSecuritySetupBusyId(null)
        if (succeeded) {
          setSecuritySetupTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'done',
            stage,
          } : current)
          message.success(`${account.email} 的密码与 Authenticator 2FA 已设置`)
        } else {
          const detail = String(snapshot.error || result.error || '密码与 2FA 设置失败')
          setSecuritySetupTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'failed',
            stage,
            error: detail,
          } : current)
          message.error(`密码与 2FA 设置失败：${detail}`)
        }
        await loadAccounts(true)
      } catch (error: unknown) {
        if (securitySetupGenerationRef.current !== generation) return
        securitySetupTimerRef.current = undefined
        setSecuritySetupBusyId(null)
        const detail = errorMessage(error, '任务状态读取失败')
        setSecuritySetupTask((current) => current?.taskId === taskId ? {
          ...current,
          status: 'failed',
          stage: 'poll_error',
          securityProgress: readSecurityProgress(current.securityProgress, 'status_unavailable'),
          error: detail,
        } : current)
        message.error(`密码与 2FA 任务状态读取失败：${detail}`)
        await loadAccounts(true)
      }
    }, delay)
  }

  const setupAccountSecurity = async (
    account: GptPlanAccount,
    browserMode: 'headless' | 'headed',
  ) => {
    if (securitySetupBusyId !== null) {
      message.warning('已有密码与 2FA 设置任务正在执行，请等待完成')
      return
    }
    const generation = securitySetupGenerationRef.current + 1
    securitySetupGenerationRef.current = generation
    setSecuritySetupBusyId(account.id)
    setSecuritySetupTask({
      accountId: account.id,
      email: account.email,
      browserMode,
      taskId: '',
      status: 'running',
      stage: 'starting',
      logs: [],
    })
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/security/setup/task`,
        {
          method: 'POST',
          body: JSON.stringify({ browser_mode: browserMode }),
        },
      ) as { ok?: boolean; task_id?: string; status?: string; error?: string }
      if (result.ok === false) throw new Error(result.error || '任务启动失败')
      const taskId = String(result.task_id || '').trim()
      if (!taskId) throw new Error('后端未返回密码与 2FA 任务 ID')
      setSecuritySetupTask((current) => current?.accountId === account.id ? {
        ...current,
        taskId,
        stage: String(result.status || 'running'),
      } : current)
      message.info(
        `已启动 ${account.email} 的密码与 Authenticator 2FA 设置（${browserMode === 'headed' ? '有头浏览器' : '无头浏览器'}）`,
      )
      scheduleSecuritySetupPoll(account, taskId, generation, 0, 300)
    } catch (error: unknown) {
      setSecuritySetupBusyId(null)
      const detail = errorMessage(error, '未知错误')
      setSecuritySetupTask((current) => current?.accountId === account.id ? {
        ...current,
        status: 'failed',
        stage: 'start_failed',
        error: detail,
      } : current)
      message.error(`密码与 2FA 设置启动失败：${detail}`)
    }
  }

  const copyAccountSecurity = async (account: GptPlanAccount) => {
    if (securityExportingId !== null) return
    const toastKey = `gpt-plan-security-export-${account.id}`
    setSecurityExportingId(account.id)
    message.loading({
      content: '正在准备账号、密码与 2FA…',
      key: toastKey,
      duration: 0,
    })
    let copyText = ''
    try {
      const authToken = getToken()
      const response = await fetch(
        `/api${API_ROOT}/accounts/${account.id}/security/export`,
        {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
        },
      )
      if (!response.ok) {
        let detail = `HTTP ${response.status}`
        try {
          const body = await response.json()
          const raw = body?.detail ?? body?.message ?? body?.error
          detail = typeof raw === 'string' ? raw : raw ? JSON.stringify(raw) : detail
        } catch {
          // Keep the HTTP status when the response is not JSON.
        }
        if (response.status === 401) localStorage.removeItem('gmail_business_auth_token')
        throw new Error(detail)
      }
      copyText = (await response.text()).trim()
      if (!copyText) throw new Error('服务器未返回可复制的账号安全凭据')
      let copied = false
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(copyText)
          copied = true
        }
      } catch {
        // Async fetch may consume transient clipboard permission. Fall back to
        // a one-shot DOM copy and immediately wipe/remove the temporary node.
      }
      if (!copied) {
        const textarea = document.createElement('textarea')
        textarea.value = copyText
        textarea.readOnly = true
        textarea.setAttribute('aria-hidden', 'true')
        textarea.style.position = 'fixed'
        textarea.style.left = '-9999px'
        textarea.style.opacity = '0'
        document.body.appendChild(textarea)
        try {
          textarea.select()
          textarea.setSelectionRange(0, textarea.value.length)
          copied = document.execCommand('copy')
        } finally {
          textarea.value = ''
          textarea.remove()
        }
      }
      if (!copied) throw new Error('浏览器拒绝写入剪贴板')
      message.success({
        content: '账号--密码--2FA 已复制',
        key: toastKey,
      })
    } catch (error: unknown) {
      message.error({
        content: `复制账号--密码--2FA 失败：${errorMessage(error, '未知错误')}`,
        key: toastKey,
        duration: 6,
      })
    } finally {
      // Sensitive export text is intentionally never written to React state or logs.
      copyText = ''
      setSecurityExportingId(null)
    }
  }

  const scheduleBusinessChildSecuritySetupPoll = (
    parent: GptPlanAccount,
    childId: number,
    childEmail: string,
    taskId: string,
    generation: number,
    since = 0,
    delay = 800,
  ): void => {
    if (businessChildSecuritySetupTimerRef.current !== undefined) {
      window.clearTimeout(businessChildSecuritySetupTimerRef.current)
    }
    businessChildSecuritySetupTimerRef.current = window.setTimeout(async () => {
      if (businessChildSecuritySetupGenerationRef.current !== generation) return
      try {
        const snapshot = await apiFetch(
          `${API_ROOT}/accounts/${parent.id}/business-child-security/${childId}/setup/task/${encodeURIComponent(taskId)}?since=${since}`,
          { cache: 'no-store' },
        ) as {
          status?: string
          stage?: string
          logs?: unknown[]
          since?: number
          logs_total?: number
          finished_at?: string
          result?: Record<string, unknown> | null
          error?: string
          meta?: { security_progress?: unknown }
        }
        if (businessChildSecuritySetupGenerationRef.current !== generation) return

        const rawStatus = String(snapshot.status || 'running').trim().toLowerCase()
        const result = asRecord(snapshot.result)
        const newLogs = Array.isArray(snapshot.logs)
          ? snapshot.logs.map((line) => String(line))
          : []
        const explicitSuccess = ['done', 'completed', 'complete', 'success', 'succeeded'].includes(rawStatus)
        const explicitFailure = ['failed', 'failure', 'error', 'stopped', 'cancelled', 'canceled'].includes(rawStatus)
        const finished = Boolean(String(snapshot.finished_at || '').trim())
        const succeeded = explicitSuccess
          || (!explicitFailure && finished && !snapshot.error && result.ok !== false)
        const failed = explicitFailure || (finished && !succeeded)
        const stage = String(snapshot.stage || result.stage || rawStatus || 'running')
        const nextSinceCandidate = snapshot.since ?? snapshot.logs_total
        const nextSince = Number.isFinite(Number(nextSinceCandidate))
          ? Number(nextSinceCandidate)
          : since + newLogs.length

        setBusinessChildSecuritySetupTask((current) => current?.taskId === taskId ? {
          ...current,
          stage,
          securityProgress: readSecurityProgress(snapshot.meta?.security_progress ?? current.securityProgress, succeeded ? 'done' : failed ? 'failed' : rawStatus),
          logs: [...current.logs, ...newLogs],
        } : current)

        if (!succeeded && !failed) {
          scheduleBusinessChildSecuritySetupPoll(
            parent,
            childId,
            childEmail,
            taskId,
            generation,
            nextSince,
            1200,
          )
          return
        }

        businessChildSecuritySetupTimerRef.current = undefined
        setBusinessChildSecuritySetupBusyKey('')
        if (succeeded) {
          setBusinessChildSecuritySetupTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'done',
            stage,
          } : current)
          message.success(`${childEmail} 的密码与 Authenticator 2FA 已设置`)
        } else {
          const detail = String(snapshot.error || result.error || '子号密码与 2FA 设置失败')
          setBusinessChildSecuritySetupTask((current) => current?.taskId === taskId ? {
            ...current,
            status: 'failed',
            stage,
            error: detail,
          } : current)
          message.error(`子号密码与 2FA 设置失败：${detail}`)
        }
        await Promise.all([
          loadBusinessChildren(parent, { quiet: true }),
          loadBusinessChildCatalog(true),
        ])
      } catch (error: unknown) {
        if (businessChildSecuritySetupGenerationRef.current !== generation) return
        businessChildSecuritySetupTimerRef.current = undefined
        setBusinessChildSecuritySetupBusyKey('')
        const detail = errorMessage(error, '任务状态读取失败')
        setBusinessChildSecuritySetupTask((current) => current?.taskId === taskId ? {
          ...current,
          status: 'failed',
          stage: 'poll_error',
          securityProgress: readSecurityProgress(current.securityProgress, 'status_unavailable'),
          error: detail,
        } : current)
        message.error(`子号密码与 2FA 任务状态读取失败：${detail}`)
        await Promise.all([
          loadBusinessChildren(parent, { quiet: true }),
          loadBusinessChildCatalog(true),
        ])
      }
    }, delay)
  }

  const setupBusinessChildSecurity = async (
    parent: GptPlanAccount,
    child: BusinessChildDisplayRow,
    browserMode: 'headless' | 'headed',
  ) => {
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号 ID，请刷新成员列表')
      return
    }
    if (businessChildSecuritySetupBusyKey) {
      message.warning('已有子号密码与 2FA 设置任务正在执行，请等待完成')
      return
    }
    const key = `${parent.id}:${childId}`
    const childEmail = String(child.email || `子号 #${childId}`)
    const generation = businessChildSecuritySetupGenerationRef.current + 1
    businessChildSecuritySetupGenerationRef.current = generation
    setBusinessChildSecuritySetupBusyKey(key)
    setBusinessChildSecuritySetupTask({
      parentAccountId: parent.id,
      childId,
      email: childEmail,
      browserMode,
      taskId: '',
      status: 'running',
      stage: 'starting',
      logs: [],
    })
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${parent.id}/business-child-security/${childId}/setup/task`,
        {
          method: 'POST',
          body: JSON.stringify({ browser_mode: browserMode }),
        },
      ) as { ok?: boolean; task_id?: string; status?: string; error?: string }
      if (result.ok === false) throw new Error(result.error || '任务启动失败')
      const taskId = String(result.task_id || '').trim()
      if (!taskId) throw new Error('后端未返回子号密码与 2FA 任务 ID')
      setBusinessChildSecuritySetupTask((current) => current?.parentAccountId === parent.id
        && current.childId === childId ? {
          ...current,
          taskId,
          stage: String(result.status || 'running'),
        } : current)
      message.info(
        `已启动 ${childEmail} 的密码与 Authenticator 2FA 设置（${browserMode === 'headed' ? '有头浏览器' : '无头浏览器'}）`,
      )
      scheduleBusinessChildSecuritySetupPoll(
        parent,
        childId,
        childEmail,
        taskId,
        generation,
        0,
        300,
      )
    } catch (error: unknown) {
      setBusinessChildSecuritySetupBusyKey('')
      const detail = errorMessage(error, '未知错误')
      setBusinessChildSecuritySetupTask((current) => current?.parentAccountId === parent.id
        && current.childId === childId ? {
          ...current,
          status: 'failed',
          stage: 'start_failed',
          error: detail,
        } : current)
      message.error(`子号密码与 2FA 设置启动失败：${detail}`)
    }
  }

  const copyBusinessChildSecurity = async (
    parent: GptPlanAccount,
    child: BusinessChildDisplayRow,
  ) => {
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号 ID，请刷新成员列表')
      return
    }
    if (businessChildSecurityExportingKey) return
    const key = `${parent.id}:${childId}`
    const toastKey = `gpt-plan-business-child-security-export-${key}`
    setBusinessChildSecurityExportingKey(key)
    message.loading({ content: '正在准备子号账号、密码与 2FA…', key: toastKey, duration: 0 })
    let copyText = ''
    try {
      const authToken = getToken()
      const response = await fetch(
        `/api${API_ROOT}/accounts/${parent.id}/business-child-security/${childId}/export`,
        {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
        },
      )
      if (!response.ok) {
        let detail = `HTTP ${response.status}`
        try {
          const body = await response.json()
          const raw = body?.detail ?? body?.message ?? body?.error
          detail = typeof raw === 'string' ? raw : raw ? JSON.stringify(raw) : detail
        } catch {
          // Keep the HTTP status when the response is not JSON.
        }
        if (response.status === 401) localStorage.removeItem('gmail_business_auth_token')
        throw new Error(detail)
      }
      copyText = (await response.text()).trim()
      if (!copyText) throw new Error('服务器未返回可复制的子号安全凭据')
      let copied = false
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(copyText)
          copied = true
        }
      } catch {
        // Fall back to a one-shot DOM copy below.
      }
      if (!copied) {
        const textarea = document.createElement('textarea')
        textarea.value = copyText
        textarea.readOnly = true
        textarea.setAttribute('aria-hidden', 'true')
        textarea.style.position = 'fixed'
        textarea.style.left = '-9999px'
        textarea.style.opacity = '0'
        document.body.appendChild(textarea)
        try {
          textarea.select()
          textarea.setSelectionRange(0, textarea.value.length)
          copied = document.execCommand('copy')
        } finally {
          textarea.value = ''
          textarea.remove()
        }
      }
      if (!copied) throw new Error('浏览器拒绝写入剪贴板')
      message.success({ content: '子号账号--密码--2FA 已复制', key: toastKey })
    } catch (error: unknown) {
      message.error({
        content: `复制子号账号--密码--2FA 失败：${errorMessage(error, '未知错误')}`,
        key: toastKey,
        duration: 6,
      })
    } finally {
      // Sensitive export text is intentionally never written to React state or logs.
      copyText = ''
      setBusinessChildSecurityExportingKey('')
    }
  }

  const loginMicrosoftMailbox = async (account: GptPlanAccount) => {
    setMsLoginingId(account.id)
    try {
      await apiFetch(`${API_ROOT}/accounts/${account.id}/ms-web-login`, {
        method: 'POST',
        body: JSON.stringify({}),
      })
      message.success(`已打开浏览器登录 ${account.email}，请在弹出的窗口里使用或完成验证`)
    } catch (error: unknown) {
      message.error(`邮箱登录失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setMsLoginingId(null)
    }
  }

  const closeMail = () => {
    mailRequestRef.current += 1
    setMailOpen(false)
    setMailLoading(false)
    setMailMessages([])
    setMailError('')
  }

  const fetchMail = async (account: MailAccountTarget, limit = 10) => {
    const requestId = ++mailRequestRef.current
    setMailBusinessChildTarget(null)
    setMailAccount(account)
    setMailLimit(limit)
    setMailOpen(true)
    setMailLoading(true)
    setMailMessages([])
    setMailMethod('')
    setMailError('')
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/fetch-mail`, {
        method: 'POST',
        body: JSON.stringify({ limit }),
      }) as {
        messages?: MailMessage[]
        method?: string
        mail_access_type?: string
        refund_transition?: boolean
        refund_status?: string
        account_type?: AccountType
      }
      if (mailRequestRef.current !== requestId) return
      setMailMessages(Array.isArray(result.messages) ? result.messages.slice(0, limit) : [])
      setMailMethod(String(result.method || result.mail_access_type || ''))
      const lifecycleMovedToRefunded = result.refund_transition === true
        || (account.account_type !== 'refunded' && result.account_type === 'refunded')
      if (lifecycleMovedToRefunded) {
        message.success(`${account.email} 已识别到退款邮件，并移入已退款列表`)
        await Promise.all([loadStats(), loadAccounts(true), loadMailAlertSummary()])
      }
    } catch (error: unknown) {
      if (mailRequestRef.current === requestId) setMailError(errorMessage(error, '获取邮件失败'))
    } finally {
      if (mailRequestRef.current === requestId) setMailLoading(false)
    }
  }

  const loginBusinessChild = async (
    account: GptPlanAccount,
    child: BusinessManagedChild,
  ) => {
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号 ID，请刷新成员列表')
      return
    }
    const busyKey = `login:${account.id}:${childId}`
    if (businessChildActionBusyKeys.includes(busyKey)) return
    setBusinessChildActionBusy(busyKey, true)
    message.info(`正在登录子号 ${child.email || childId}，浏览器流程可能需要 30–60 秒`)
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/business-child-login/${childId}`,
        {
          method: 'POST',
          body: JSON.stringify({}),
        },
      ) as { ok?: boolean; stage?: string; error?: string; plan_label?: string; plan_type?: string }
      if (result?.ok === false) {
        throw new Error(`${result.stage ? `阶段 ${result.stage}：` : ''}${result.error || '登录失败'}`)
      }
      const plan = result.plan_label || result.plan_type
      message.success(`子号登录成功：${child.email || childId}${plan ? ` · ${plan}` : ''}`)
    } catch (error: unknown) {
      message.error(`子号登录失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setBusinessChildActionBusy(busyKey, false)
      void Promise.all([
        loadBusinessChildren(account, { quiet: true }),
        loadBusinessChildCatalog(true),
      ])
    }
  }

  const reviewBusinessChildLogin = async (
    account: GptPlanAccount,
    child: BusinessManagedChild,
  ) => {
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号 ID，请刷新成员列表')
      return
    }
    const busyKey = `login-review:${account.id}:${childId}`
    if (businessChildActionBusyKeys.includes(busyKey)) return
    setBusinessChildActionBusy(busyKey, true)
    message.info(`正在复核 Dead 子号 ${child.email || childId}，浏览器流程可能需要 30–60 秒`)
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/business-child-login-review/${childId}`,
        {
          method: 'POST',
          body: JSON.stringify({}),
        },
      ) as {
        ok?: boolean
        stage?: string
        error?: string
        dead_cleared?: boolean
        plan_label?: string
        plan_type?: string
      }
      if (result?.ok === false) {
        const stage = safeBusinessChildRtLog(result.stage || '')
        const detail = safeBusinessChildRtLog(result.error || '登录复核失败')
        throw new Error(`${stage ? `阶段 ${stage}：` : ''}${detail}`)
      }
      const plan = result.plan_label || result.plan_type
      if (result.dead_cleared === true) {
        message.success(`登录复核通过，已解除 Dead 标记：${child.email || childId}${plan ? ` · ${plan}` : ''}`)
      } else {
        message.warning(`登录复核已完成，但账号仍保留 Dead 标记：${child.email || childId}`)
      }
    } catch (error: unknown) {
      message.error(`子号登录复核失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setBusinessChildActionBusy(busyKey, false)
      void Promise.all([
        loadBusinessChildren(account, { quiet: true }),
        loadBusinessChildCatalog(true),
      ])
    }
  }

  const fetchBusinessChildMail = async (
    account: GptPlanAccount,
    child: BusinessManagedChild,
    limit = 10,
  ) => {
    const childId = positiveInteger(child.pro_account_id ?? child.managed_pro_account_id)
    if (!childId) {
      message.warning('该子号缺少可确认的账号 ID，请刷新成员列表')
      return
    }
    const busyKey = `mail:${account.id}:${childId}`
    if (businessChildActionBusyKeys.includes(busyKey)) return
    const requestId = ++mailRequestRef.current
    setBusinessChildActionBusy(busyKey, true)
    setMailBusinessChildTarget({ account, child })
    setMailAccount({ ...account, email: String(child.email || account.email) })
    setMailLimit(limit)
    setMailOpen(true)
    setMailLoading(true)
    setMailMessages([])
    setMailMethod('')
    setMailError('')
    try {
      const result = await apiFetch(
        `${API_ROOT}/accounts/${account.id}/business-child-fetch-mail/${childId}`,
        {
          method: 'POST',
          body: JSON.stringify({ limit }),
        },
      ) as { messages?: MailMessage[]; method?: string; mail_access_type?: string }
      if (mailRequestRef.current !== requestId) return
      setMailMessages(Array.isArray(result.messages) ? result.messages.slice(0, limit) : [])
      setMailMethod(String(result.method || result.mail_access_type || ''))
    } catch (error: unknown) {
      if (mailRequestRef.current === requestId) setMailError(errorMessage(error, '获取子号邮件失败'))
    } finally {
      if (mailRequestRef.current === requestId) setMailLoading(false)
      setBusinessChildActionBusy(busyKey, false)
    }
  }

  const businessChildAlertTarget = (target: MailAlertTarget) => {
    if (!('target_kind' in target) || target.target_kind !== 'business_child') return null
    const parentId = positiveInteger(target.parent_id)
    const childId = positiveInteger(target.child_id ?? target.id)
    return parentId && childId ? { parentId, childId } : null
  }

  const mailQueuePath = (
    account: MailAlertTarget,
    queue: 'alerts' | 'inbox',
    dismiss = false,
  ) => {
    const child = businessChildAlertTarget(account)
    if (child) {
      const base = `${API_ROOT}/accounts/${child.parentId}/business-children/${child.childId}/${queue}`
      return dismiss ? `${base}/dismiss` : base
    }
    if (queue === 'alerts') {
      return dismiss
        ? `${API_ROOT}/accounts/${account.id}/alerts/dismiss`
        : `${API_ROOT}/accounts/${account.id}/alerts`
    }
    return dismiss
      ? `${API_ROOT}/accounts/${account.id}/inbox/dismiss`
      : `${API_ROOT}/accounts/${account.id}/inbox`
  }

  const openMailAlerts = async (account: MailAlertTarget) => {
    setAlertAccount(account)
    setAlertOpen(true)
    setAlertLoading(true)
    setAlertList([])
    try {
      const result = await apiFetch(mailQueuePath(account, 'alerts')) as {
        alerts?: MailAlert[]
        items?: MailAlert[]
      }
      const alerts = Array.isArray(result.alerts)
        ? result.alerts
        : Array.isArray(result.items) ? result.items : []
      setAlertList(alerts)
      const alertIds = alerts.map((item) => item.id).filter(Boolean)
      if (alertIds.length > 0) {
        await apiFetch(mailQueuePath(account, 'alerts', true), {
          method: 'POST',
          body: JSON.stringify({ alert_ids: alertIds }),
        })
        const cleared = alertSummary[account.id] || alertIds.length
        setAlertSummary((current) => {
          const next = { ...current }
          delete next[account.id]
          return next
        })
        setTotalAlertUnread((current) => Math.max(0, current - cleared))
        void loadMailAlertSummary()
      }
    } catch (error: unknown) {
      message.error(`读取封禁报警失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setAlertLoading(false)
    }
  }

  const openMailInbox = async (account: MailAlertTarget) => {
    setInboxAccount(account)
    setInboxOpen(true)
    setInboxLoading(true)
    setInboxList([])
    try {
      const result = await apiFetch(mailQueuePath(account, 'inbox')) as {
        items?: MailAlert[]
        inbox?: MailAlert[]
      }
      const items = Array.isArray(result.items)
        ? result.items
        : Array.isArray(result.inbox) ? result.inbox : []
      setInboxList(items)
      const inboxIds = items.map((item) => item.id).filter(Boolean)
      if (inboxIds.length > 0) {
        await apiFetch(mailQueuePath(account, 'inbox', true), {
          method: 'POST',
          body: JSON.stringify({ inbox_ids: inboxIds }),
        })
        const cleared = inboxSummary[account.id] || inboxIds.length
        setInboxSummary((current) => {
          const next = { ...current }
          delete next[account.id]
          return next
        })
        setTotalInboxUnread((current) => Math.max(0, current - cleared))
        void loadMailAlertSummary()
      }
    } catch (error: unknown) {
      message.error(`读取未读邮件失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setInboxLoading(false)
    }
  }

  const openFullInboxForAlertTarget = (target: MailAlertTarget) => {
    const child = businessChildAlertTarget(target)
    if (!child) {
      void fetchMail(target as GptPlanAccount)
      return
    }
    void fetchBusinessChildMail(
      {
        id: child.parentId,
        email: ('parent_email' in target && target.parent_email)
          ? target.parent_email
          : 'BUSINESS 母号',
      } as GptPlanAccount,
      {
        pro_account_id: child.childId,
        managed_pro_account_id: child.childId,
        email: target.email,
      } as BusinessManagedChild,
    )
  }

  const checkMailNow = async (account: GptPlanAccount) => {
    if (checkingMailAccountId !== null) return
    setCheckingMailAccountId(account.id)
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/check-mail-now`, {
        method: 'POST',
      }) as {
        skipped?: boolean
        reason?: string
        success?: number
        failed?: number
        total_new_alerts?: number
        total_new_mail?: number
        total_new_messages?: number
        refund_transition?: boolean
        errors?: Array<{ error?: string }>
      }
      if (result.skipped === true) {
        message.warning(result.reason || '该账号的邮件检查正在执行，请稍后重试')
        return
      }
      if (Number(result.failed || 0) > 0) {
        throw new Error(result.errors?.[0]?.error || '邮件检查失败')
      }
      const newCount = Math.max(0, Number(
        result.total_new_messages
        ?? result.total_new_mail
        ?? result.total_new_alerts
        ?? 0,
      ))
      if (result.refund_transition === true) {
        message.success(`${account.email} 已识别到退款邮件，并移入已退款列表`)
      } else if (newCount > 0) message.success(`本次新增 ${newCount} 封邮件`)
      else message.info('本次未新增邮件')
      await Promise.all([loadMailAlertSummary(), loadAccounts(true), loadStats()])
    } catch (error: unknown) {
      message.error(`检查邮件失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setCheckingMailAccountId(null)
    }
  }

  const deleteAccount = async (account: GptPlanAccount) => {
    setDeletingId(account.id)
    try {
      await apiFetch(`${API_ROOT}/accounts/${account.id}`, { method: 'DELETE' })
      message.success(`已删除 ${account.email}`)
      if (accounts.length === 1 && page > 1) setPage((value) => value - 1)
      else reload()
    } catch (error: unknown) {
      message.error(`删除失败：${errorMessage(error, '未知错误')}`)
    } finally {
      setDeletingId(null)
    }
  }

  const startNoteEdit = (account: GptPlanAccount) => {
    if (noteSavingId === account.id) return
    noteCancelRef.current.delete(account.id)
    setEditingNoteId(account.id)
    setNoteDraft(String(account.note || ''))
  }

  const cancelNoteEdit = (account: GptPlanAccount) => {
    if (noteSaveInFlightRef.current.has(account.id)) return
    noteCancelRef.current.add(account.id)
    setNoteDraft(String(account.note || ''))
    setEditingNoteId((current) => current === account.id ? null : current)
  }

  const saveAccountNote = async (account: GptPlanAccount, value: string) => {
    const accountId = account.id
    if (noteCancelRef.current.has(accountId)) {
      noteCancelRef.current.delete(accountId)
      return
    }
    if (noteSaveInFlightRef.current.has(accountId)) return
    const original = String(account.note || '')
    const nextNote = String(value)
    if (nextNote === original) {
      setEditingNoteId((current) => current === accountId ? null : current)
      return
    }
    noteSaveInFlightRef.current.add(accountId)
    setNoteSavingId(accountId)
    // 乐观更新让失焦后内容立即稳定；失败时下面恢复到 original。
    setAccounts((current) => current.map((row) => (
      row.id === accountId ? { ...row, note: nextNote } : row
    )))
    try {
      const updated = await apiFetch(`${API_ROOT}/accounts/${accountId}`, {
        method: 'PUT',
        // 安全更新：仅发送 note，不回传或覆盖来源凭证、Cookie 与套餐字段。
        body: JSON.stringify({ note: nextNote }),
      }) as GptPlanAccount
      const authoritativeNote = String(updated?.note ?? nextNote)
      setAccounts((current) => current.map((row) => (
        row.id === accountId ? { ...row, note: authoritativeNote } : row
      )))
      setEditingNoteId((current) => current === accountId ? null : current)
      setNoteDraft(authoritativeNote)
      message.success(authoritativeNote ? '备注已更新' : '备注已清空')
    } catch (error: unknown) {
      setAccounts((current) => current.map((row) => (
        row.id === accountId ? { ...row, note: original } : row
      )))
      setEditingNoteId((current) => current === accountId ? null : current)
      setNoteDraft(original)
      message.error(`备注保存失败，已恢复原内容：${errorMessage(error, '未知错误')}`)
    } finally {
      noteSaveInFlightRef.current.delete(accountId)
      noteCancelRef.current.delete(accountId)
      setNoteSavingId((current) => current === accountId ? null : current)
    }
  }

  const saveBusinessUsage = async (
    account: GptPlanAccount,
    nextUsage: BusinessUsageType | null,
  ) => {
    if (businessUsageSavingIds.includes(account.id)) return
    const originalUsage = account.business_usage_type || null
    if (originalUsage === nextUsage) return

    setBusinessUsageSavingIds((current) => [...current, account.id])
    // 用途是套餐管理自己的运营标签，先乐观更新当前行；服务端失败时恢复。
    setAccounts((current) => current.map((row) => (
      row.id === account.id ? { ...row, business_usage_type: nextUsage } : row
    )))
    try {
      const result = await apiFetch(`${API_ROOT}/accounts/${account.id}/business-usage`, {
        method: 'PUT',
        body: JSON.stringify({ business_usage_type: nextUsage }),
      }) as GptPlanAccount | { account?: GptPlanAccount; business_usage_type?: BusinessUsageType | null }
      const resultAccount = 'account' in result ? result.account : result
      const returnedUsage = resultAccount?.business_usage_type
        ?? ('business_usage_type' in result ? result.business_usage_type : undefined)
      const authoritativeUsage = returnedUsage === 'sale' || returnedUsage === 'self_use' || returnedUsage === 'transit'
        ? returnedUsage
        : returnedUsage === null ? null : nextUsage
      setAccounts((current) => current.map((row) => (
        row.id === account.id ? { ...row, business_usage_type: authoritativeUsage } : row
      )))
      message.success(authoritativeUsage === 'sale'
        ? '已标记为出售'
        : authoritativeUsage === 'self_use' ? '已标记为自用'
          : authoritativeUsage === 'transit' ? '已标记为中转' : '已清除用途标记')
      // 当前用途筛选下，改标后的账号可能不再属于本页；重新读取权威分页。
      if (businessUsageFilter) {
        setSelectedBusinessAccountIds((current) => current.filter((id) => id !== account.id))
      }
      if (businessUsageFilter) await loadAccounts(true)
    } catch (error: unknown) {
      setAccounts((current) => current.map((row) => (
        row.id === account.id ? { ...row, business_usage_type: originalUsage } : row
      )))
      message.error(`用途保存失败，已恢复原标记：${errorMessage(error, '未知错误')}`)
    } finally {
      setBusinessUsageSavingIds((current) => current.filter((id) => id !== account.id))
    }
  }

  const renderBusinessChildNvListingButton = (
    account: GptPlanAccount,
    row: BusinessChildDisplayRow,
  ): ReactNode => {
    if (standalone || row.role === 'account-owner' || !row._managed) return null
    const membershipId = positiveInteger(row.membership_id)
    const childId = positiveInteger(row.pro_account_id ?? row.managed_pro_account_id)
    const security = row.chatgpt_security || {}
    const passwordReady = String(security.password_state || '').trim().toLowerCase() === 'configured'
      && security.has_password !== false
    const totpReady = String(security.mfa_state || '').trim().toLowerCase() === 'enabled'
      && security.has_totp !== false
    const listingThisChild = Boolean(
      businessChildNvListingSaving
      && membershipId
      && positiveInteger(businessChildNvListingTarget?.child.membership_id) === membershipId,
    )
    const disabledReason = !membershipId
      ? '缺少子号成员记录 ID，请先刷新 BUSINESS 成员'
      : !childId
        ? '只有账号池中的可管理子号支持上架 NV'
        : row.enabled === false || row.deactivated || row.dangerous
          ? '子号已停用或标记为 Dead，不能上架 NV'
          : row.policy_warning
            ? '子号存在政策告警，不能上架 NV'
            : String(row.refund_status || '').trim()
              ? '子号已进入退款流程，不能上架 NV'
              : ['refunded', 'partial_refund'].includes(row.sale_status || '')
                ? '该 NV 订单已退款，不能重复上架'
              : row.sale_status === 'sold'
                ? '子号已出售，不能重复上架 NV'
                : row.sale_status === 'listed'
                  ? '子号已经上架'
                  : !row.has_codex_rt
                    ? '请先获取子号 RT'
                    : !passwordReady
                      ? '请先设置并确认 ChatGPT 登录密码'
                      : !totpReady
                        ? '请先设置并确认 Authenticator 2FA'
                        : security.credentials_readable === false
                          ? '本地加密的密码或 2FA 密钥当前不可读取'
                          : businessChildNvListingSaving && !listingThisChild
                            ? '另一个子号正在上架 NV'
                            : ''
    return (
      <Tooltip title={disabledReason || '上传 SUB 凭证与安全凭据、设置价格并入池；NV 密钥仅由后端使用'}>
        <span>
          <Button
            data-business-child-nv-listing="true"
            size="small"
            type="primary"
            ghost
            icon={<DollarOutlined />}
            loading={listingThisChild}
            disabled={Boolean(disabledReason) || listingThisChild}
            onClick={() => openBusinessChildNvListing(account, row)}
          >
            {row.sale_status === 'listed' ? '已上架 NV' : '上架 NV'}
          </Button>
        </span>
      </Tooltip>
    )
  }

  // 母号详情与“子号视图”共用同一套能力判断和操作入口。子号视图仅改变
  // 数据排列方式，不创建第二套登录、RT、邮件、安全设置或移除业务逻辑。
  const renderBusinessChildActions = (
    account: GptPlanAccount,
    row: BusinessChildDisplayRow,
    preferRelease = false,
  ): ReactNode => {
    const childBatchActionBlocked = businessChildBatchTaskRunning
    const childBatchActionBlockedReason = '子号批量任务正在运行，完成后才能执行单号操作'
    const listedActions = asRecord(row.actions)
    const listedActionSupported = (name: string, fallback: boolean): boolean => {
      if (!Object.prototype.hasOwnProperty.call(listedActions, name)) return fallback
      const value = listedActions[name]
      if (typeof value === 'boolean') return value
      const capability = asRecord(value)
      return capability.supported === true
    }
    const listedActionReason = (name: string, fallback: string): string => {
      const value = asRecord(listedActions[name])
      return String(value.reason || fallback)
    }
    const childId = positiveInteger(row.pro_account_id ?? row.managed_pro_account_id)
    const membershipId = positiveInteger(row.membership_id)
    const isOwner = row.role === 'account-owner'
    const managedSourceChild = Boolean(
      !isOwner
      && row._managed
      && childId
      && String(row.source || '').trim().toLowerCase() !== 'manual',
    )
    const managedPoolChild = managedSourceChild && row.rt_supported !== false
    const loginBusyKey = childId ? `login:${account.id}:${childId}` : ''
    const loginBusy = Boolean(
      loginBusyKey && businessChildActionBusyKeys.includes(loginBusyKey),
    )
    const canLoginChild = listedActionSupported('login', Boolean(
      managedSourceChild
      && row.dangerous !== true
      && row.can_chatgpt_login === true,
    ))
    const loginHint = canLoginChild
      ? '登录该子号并更新本地会话'
      : listedActionReason(
        'login',
        String(row.chatgpt_login_disabled_reason || '该子号当前不能登录'),
      )
    const childSecurity = row.chatgpt_security || {}
    const childSecurityKey = childId ? `${account.id}:${childId}` : ''
    const childSecurityHealthy = Boolean(
      managedSourceChild
      && row.enabled !== false
      && !row.deactivated
      && !row.dangerous
      && !row.policy_warning
      && !String(row.refund_status || '').trim(),
    )
    const canSetupChildSecurity = listedActionSupported('security', Boolean(
      childSecurityHealthy
      && row.can_setup_chatgpt_security === true,
    )) && childSecurityHealthy && row.can_setup_chatgpt_security === true
    const childSecuritySetupDisabledReason = !managedSourceChild
      ? '只有账号池中的可管理子号支持设置密码与 2FA'
      : row.enabled === false || row.deactivated || row.dangerous
        ? '子号已停用或标记为 Dead，不能设置密码与 2FA'
        : row.policy_warning
          ? '子号存在政策告警，不能设置密码与 2FA'
          : String(row.refund_status || '').trim()
            ? '子号已进入退款流程，不能设置密码与 2FA'
            : row.can_setup_chatgpt_security !== true
              ? String(row.chatgpt_security_setup_disabled_reason || '该子号当前不能设置密码与 2FA')
              : businessChildSecuritySetupBusyKey
                && businessChildSecuritySetupBusyKey !== childSecurityKey
                ? '已有其他子号密码与 2FA 设置任务正在执行'
                : ''
    const canCopyChildSecurity = Boolean(
      childSecurityHealthy
      && String(childSecurity.password_state || '').trim().toLowerCase() === 'configured'
      && String(childSecurity.mfa_state || '').trim().toLowerCase() === 'enabled'
      && childSecurity.has_password === true
      && childSecurity.has_totp === true
      && childSecurity.credentials_readable !== false,
    )
    const childSecurityCopyDisabledReason = !childSecurityHealthy
      ? '该子号当前不能导出安全凭据'
      : childSecurity.credentials_readable === false
        ? '本地加密安全凭据当前不可读取'
        : !canCopyChildSecurity
          ? '密码与 2FA 均设置并远端确认后才可复制'
          : ''
    const loginReviewBusyKey = childId
      ? `login-review:${account.id}:${childId}`
      : ''
    const loginReviewBusy = Boolean(
      loginReviewBusyKey
      && businessChildActionBusyKeys.includes(loginReviewBusyKey),
    )
    const canReviewChildLogin = listedActionSupported('login_review', Boolean(
      managedSourceChild
      && row.dangerous === true
      && row.can_review_chatgpt_login === true,
    ))
    const loginReviewHint = canReviewChildLogin
      ? '重新登录复核账号；通过后自动解除 Dead 标记'
      : listedActionReason('login_review', String(
          row.chatgpt_login_review_disabled_reason
          || '该 Dead 子号当前不具备登录复核条件',
        ))
    const mailBusyKey = childId ? `mail:${account.id}:${childId}` : ''
    const mailBusy = Boolean(
      mailBusyKey && businessChildActionBusyKeys.includes(mailBusyKey),
    )
    const anotherChildMailRunning = businessChildActionBusyKeys.some(
      (key) => key.startsWith('mail:') && key !== mailBusyKey,
    )
    const canFetchChildMail = listedActionSupported('fetch_mail', Boolean(
      managedSourceChild && row.can_fetch_mail === true,
    ))
    const mailHint = canFetchChildMail
      ? '取件（最近 10 封）'
      : listedActionReason(
        'fetch_mail',
        String(row.fetch_mail_disabled_reason || '该子号缺少可用邮件凭证'),
      )
    const healthReason = row.enabled === false || row.deactivated || row.dangerous
      ? '子号已停用或标记为 Dead，不能获取 RT'
      : row.policy_warning
        ? '子号存在政策告警，不能获取 RT'
        : String(row.refund_status || '').trim()
          ? '子号已进入退款流程，不能获取 RT'
          : row._kind === 'local'
            ? '远端成员或邀请状态确认后才可获取 RT'
            : row.can_get_rt !== true
              ? String(
                row.chatgpt_oauth_disabled_reason
                || '当前数据库快照不允许该子号获取 RT',
              )
              : ''
    const canAcquireRt = listedActionSupported('oauth', Boolean(
      managedPoolChild
      && (row._kind === 'member' || row._kind === 'invite')
      && row.can_get_rt === true
      && !healthReason,
    )) && managedPoolChild && !healthReason
    const oauthBusyKey = childId ? `oauth:${account.id}:${childId}` : ''
    const oauthStarting = Boolean(
      oauthBusyKey && businessChildActionBusyKeys.includes(oauthBusyKey),
    )
    const oauthTaskMatches = Boolean(
      childId
      && businessChildRtTask?.status === 'running'
      && businessChildRtTask.accountId === account.id
      && businessChildRtTask.childId === childId,
    )
    const anotherOauthRunning = Boolean(
      businessChildRtTask?.status === 'running'
      || businessChildActionBusyKeys.some((key) => key.startsWith('oauth:')),
    ) && !oauthStarting && !oauthTaskMatches
    const oauthHint = canAcquireRt
      ? anotherOauthRunning
        ? '已有其他子号 RT 任务正在运行'
        : row._kind === 'invite'
          ? '邀请前账号检查已完成；获取 RT 将直接执行 Codex OAuth'
          : ''
      : healthReason || listedActionReason('oauth', '该行不支持获取 RT')

    const releaseKind = !isOwner && (row._kind === 'member' || row._kind === 'invite')
      ? row._kind
      : null
    const releaseBusyKey = membershipId
      ? `remove:${account.id}:${membershipId}`
      : ''
    const releaseBusy = Boolean(
      releaseBusyKey && businessChildActionBusyKeys.includes(releaseBusyKey),
    )
    const canRelease = listedActionSupported('remove', Boolean(membershipId))
    const releaseDisabled = Boolean(
      childBatchActionBlocked || !membershipId || !canRelease || releaseBusy || oauthStarting || oauthTaskMatches,
    )
    const releaseHint = childBatchActionBlocked
      ? childBatchActionBlockedReason
      : !membershipId
      ? '缺少可确认的成员记录 ID，请先刷新 BUSINESS 席位'
      : !canRelease
        ? listedActionReason('remove', '该子号当前不能移除')
        : oauthStarting || oauthTaskMatches
        ? '该子号正在获取 RT，暂不能移除'
        : ''
    const releaseLabel = releaseKind === 'invite' ? '撤销邀请' : '退出空间'
    const releaseButton = releaseKind ? (
      releaseDisabled ? (
        <Tooltip title={releaseHint}>
          <span>
            <Button
              data-business-child-release-action={releaseKind}
              size="small"
              danger={releaseKind === 'member'}
              loading={releaseBusy}
              disabled
            >
              {releaseLabel}
            </Button>
          </span>
        </Tooltip>
      ) : (
        <Popconfirm
          title={releaseKind === 'invite'
            ? `撤销对 ${row.email || '该子号'} 的邀请？`
            : `让子号 ${row.email || '该子号'} 退出 BUSINESS 空间？`}
          description="成功后将更新数据库成员与席位快照。"
          okText={releaseLabel}
          cancelText="取消"
          okButtonProps={{ danger: releaseKind === 'member' }}
          onConfirm={() => { void removeBusinessChild(account, row) }}
        >
          <Button
            data-business-child-release-action={releaseKind}
            size="small"
            danger={releaseKind === 'member'}
            loading={releaseBusy}
          >
            {releaseLabel}
          </Button>
        </Popconfirm>
      )
    ) : null

    const loginAction = managedSourceChild && row.dangerous !== true ? (
      <Tooltip title={childBatchActionBlocked ? childBatchActionBlockedReason : loginHint}>
        <span>
          <Button
            size="small"
            icon={<LoginOutlined />}
            loading={loginBusy}
            disabled={childBatchActionBlocked || !canLoginChild || oauthStarting || oauthTaskMatches}
            onClick={() => { void loginBusinessChild(account, row) }}
          >
            登录
          </Button>
        </span>
      </Tooltip>
    ) : null
    const securitySetupAction = childSecurityHealthy ? (
      <Tooltip title={childBatchActionBlocked
        ? childBatchActionBlockedReason
        : childSecuritySetupDisabledReason
          || row.chatgpt_security_setup_recovery_hint
          || `设置子号 ChatGPT 密码与 Authenticator 2FA（使用页面顶部统一配置的${securityBrowserMode === 'headed' ? '有头' : '无头'}模式）`}>
        <span>
          <Button
            size="small"
            icon={<SafetyOutlined />}
            loading={businessChildSecuritySetupBusyKey === childSecurityKey}
            disabled={childBatchActionBlocked || !canSetupChildSecurity || Boolean(childSecuritySetupDisabledReason)}
            onClick={() => { void setupBusinessChildSecurity(account, row, securityBrowserMode) }}
          >
            设置密码与 2FA
          </Button>
        </span>
      </Tooltip>
    ) : null
    const securityCopyAction = childSecurityHealthy ? (
      <Tooltip title={childSecurityCopyDisabledReason || '复制格式：账号--密码--2FA'}>
        <span>
          <Button
            size="small"
            icon={<CopyOutlined />}
            loading={businessChildSecurityExportingKey === childSecurityKey}
            disabled={!canCopyChildSecurity
              || Boolean(businessChildSecurityExportingKey
                && businessChildSecurityExportingKey !== childSecurityKey)}
            onClick={() => { void copyBusinessChildSecurity(account, row) }}
          >
            复制账号--密码--2FA
          </Button>
        </span>
      </Tooltip>
    ) : null
    const loginReviewAction = managedSourceChild && row.dangerous === true ? (
      <Tooltip title={childBatchActionBlocked ? childBatchActionBlockedReason : loginReviewHint}>
        <span>
          <Button
            size="small"
            icon={<SafetyOutlined />}
            loading={loginReviewBusy}
            disabled={childBatchActionBlocked || !canReviewChildLogin || oauthStarting || oauthTaskMatches}
            onClick={() => { void reviewBusinessChildLogin(account, row) }}
          >
            登录复核
          </Button>
        </span>
      </Tooltip>
    ) : null
    const mailboxAction = managedSourceChild ? (
      <Tooltip title={anotherChildMailRunning ? '正在获取另一个子号的邮件' : mailHint}>
        <span>
          <Button
            size="small"
            icon={<InboxOutlined />}
            loading={mailBusy}
            disabled={!canFetchChildMail || anotherChildMailRunning}
            onClick={(event) => { event.stopPropagation(); void fetchBusinessChildMail(account, row, 10) }}
          >
            邮箱
          </Button>
        </span>
      </Tooltip>
    ) : null
    const oauthAction = managedPoolChild ? (
      <Tooltip title={childBatchActionBlocked ? childBatchActionBlockedReason : oauthHint}>
        <span>
          <Button
            size="small"
            icon={<SafetyOutlined />}
            loading={oauthStarting || oauthTaskMatches}
            disabled={childBatchActionBlocked || !canAcquireRt || anotherOauthRunning}
            onClick={() => { void startBusinessChildOAuth(account, row) }}
          >
            {row.has_codex_rt ? '重新获取 RT' : '获取 RT'}
          </Button>
        </span>
      </Tooltip>
    ) : null
    const availableActions: Array<{ key: string; node: ReactNode }> = [
      { key: 'login', node: loginAction },
      { key: 'security-setup', node: securitySetupAction },
      { key: 'security-copy', node: securityCopyAction },
      { key: 'login-review', node: loginReviewAction },
      { key: 'mailbox', node: mailboxAction },
      { key: 'oauth', node: oauthAction },
      { key: 'release', node: releaseButton },
    ].filter((action) => action.node !== null)

    if (availableActions.length === 0) {
      return <Typography.Text type="secondary">—</Typography.Text>
    }
    // 子号目录需要把“退出空间 / 撤销邀请”直接展示为主按钮；母号详情仍
    // 保持原有的登录/RT 优先级。两处最终仍调用相同的 remove 能力。
    const preferredPrimaryKey = preferRelease && releaseKind
      ? 'release'
      : row.dangerous === true
        ? 'login-review'
        : managedPoolChild && !row.has_codex_rt
          ? 'oauth'
          : managedSourceChild
            ? 'login'
            : 'release'
    const primaryAction = availableActions.find((action) => action.key === preferredPrimaryKey)
      || availableActions[0]
    const secondaryActions = availableActions.filter((action) => action.key !== primaryAction.key && action.key !== 'mailbox')
    const secondaryActionsContent = (
      <Space direction="vertical" size={6} style={{ maxWidth: 340 }}>
        {secondaryActions.map((action) => (
          <div key={action.key}>{action.node}</div>
        ))}
      </Space>
    )
    if (compactBusinessLayout) {
      return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', flexWrap: 'wrap' }}>
          <div style={{ minWidth: 0 }}>{primaryAction.node}</div>
          {primaryAction.key !== 'mailbox' && mailboxAction}
          <Popover trigger="click" placement="bottomRight" content={secondaryActionsContent}>
            <Button
              data-business-child-actions-trigger="true"
              size="small"
              icon={<MoreOutlined />}
              disabled={secondaryActions.length === 0}
            >
              更多
            </Button>
          </Popover>
        </div>
      )
    }
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, width: '100%' }}>
        <div style={{ minWidth: 0, flex: 1 }}>{primaryAction.node}</div>
        {primaryAction.key !== 'mailbox' && mailboxAction}
        <Popover
          trigger="click"
          placement="bottomRight"
          content={secondaryActionsContent}
        >
          <Button
            data-business-child-actions-trigger="true"
            aria-label="更多子号操作"
            title="更多操作"
            size="small"
            icon={<MoreOutlined />}
            disabled={secondaryActions.length === 0}
          />
        </Popover>
      </div>
    )
  }

  const renderBusinessDrawerOverview = (account: GptPlanAccount) => {
    const source = memberSourceOf(account, memberSourceOverrides[account.id])
    const workspace = businessWorkspaceOf(source)
    const seat = businessSeatSummaryOf(source)
    const normal = businessSeatCapacity(seat, 'default')
    const advanced = businessSeatCapacity(seat, 'prolite')
    const snapshot = businessChildrenByAccount[account.id]?.snapshot
    const memberCount = snapshot
      ? (snapshot.members || []).filter((row) => row.role !== 'account-owner').length
      : null
    const inviteCount = snapshot ? (snapshot.invites || []).length : null
    const checkedAt = snapshot?.workspace_checked_at
      || snapshot?.checked_at
      || seat?.checked_at
      || source?.workspace_checked_at
    const security = account.chatgpt_security || {}
    const passwordReady = String(security.password_state || '').trim().toLowerCase() === 'configured'
    const mfaReady = String(security.mfa_state || '').trim().toLowerCase() === 'enabled'
    const passwordPresent = security.has_password === true
    const mfaPresent = security.has_totp === true
    const countLabel = (value: number | null | undefined) => (
      value === null || value === undefined ? '未知' : String(value)
    )
    const capacityLabel = (capacity: BusinessSeatTypeCapacity) => (
      `已用 ${countLabel(capacity.used)} · 可用 ${countLabel(businessSeatAvailable(seat, capacity))}`
    )

    return (
      <Card size="small" title="母号概览" style={{ marginBottom: 12 }}>
        <Descriptions
          size="small"
          column={{ xs: 1, sm: 2, md: 3 }}
          items={[
            {
              key: 'workspace-session',
              label: '工作区会话',
              children: workspace?.team_session_usable === false
                ? <Tooltip title={businessSessionReasonLabel(workspace.team_session_reason)}><Tag color="warning">不可用</Tag></Tooltip>
                : <Tag color="success">可用</Tag>,
            },
            ...(!standalone ? [{
              key: 'business-usage',
              label: '用途',
              children: account.business_usage_type === 'sale'
                ? <Tag color="gold">出售</Tag>
                : account.business_usage_type === 'self_use'
                  ? <Tag color="blue">自用</Tag>
                  : account.business_usage_type === 'transit'
                    ? <Tag color="purple">中转</Tag>
                    : <Tag>未标注</Tag>,
            }] : []),
            {
              key: 'login',
              label: 'ChatGPT 登录',
              children: <Tag color={loginStatusOf(account) === 'logged_in' ? 'success' : 'default'}>{account.login_status_label || (loginStatusOf(account) === 'logged_in' ? '已登录' : '未登录')}</Tag>,
            },
            {
              key: 'security',
              label: '密码 / 2FA',
              children: (
                <Space size={4} wrap>
                  <Tag color={passwordReady ? 'success' : passwordPresent ? 'processing' : 'default'}>
                    {passwordReady ? '密码已确认' : passwordPresent ? '密码已导入' : '密码未设置'}
                  </Tag>
                  <Tag color={mfaReady ? 'success' : mfaPresent ? 'processing' : 'default'}>
                    {mfaReady ? '2FA 已确认' : mfaPresent ? '2FA 已导入' : '2FA 未开启'}
                  </Tag>
                </Space>
              ),
            },
            {
              key: 'total-seats',
              label: '总席位',
              children: seat?.known
                ? `已用 ${countLabel(nonNegativeNumber(seat.used))}/${countLabel(nonNegativeNumber(seat.total))} · 可用 ${countLabel(nonNegativeNumber(seat.available))}`
                : '未知',
            },
            {
              key: 'normal-seats',
              label: '普通席位',
              children: seat ? capacityLabel(normal) : '未知',
            },
            {
              key: 'advanced-seats',
              label: '高级席位',
              children: seat && hasBusinessAdvancedSeat(seat, advanced) ? capacityLabel(advanced) : '未启用',
            },
            {
              key: 'children',
              label: '成员快照',
              children: memberCount === null || inviteCount === null
                ? '尚未读取'
                : `已加入 ${memberCount} · 待接受 ${inviteCount}`,
            },
            {
              key: 'updated',
              label: '数据时间',
              span: 2,
              children: formatTime(checkedAt),
            },
          ]}
        />
        {account.note && (
          <Typography.Paragraph type="secondary" style={{ margin: '10px 0 0' }} ellipsis={{ rows: 2, expandable: true }}>
            备注：{account.note}
          </Typography.Paragraph>
        )}
      </Card>
    )
  }

  const renderBusinessChildren = (account: GptPlanAccount) => {
    const view = businessChildrenByAccount[account.id]
    const snapshot = view?.snapshot
    if (view?.loading && !snapshot) {
      return <div style={{ padding: 24, textAlign: 'center' }}><Spin tip="正在读取数据库子号快照" /></div>
    }
    if (!snapshot) {
      return (
        <div style={{ padding: 12 }}>
          <Alert
            type={view?.error ? 'error' : 'info'}
            showIcon
            message={view?.error || '暂无子号快照'}
            description="请在母号列表或详情顶部点击“刷新成员/席位”，更新后再查看数据库记录。"
            action={(
              <Button size="small" loading={view?.loading} onClick={() => { void loadBusinessChildren(account) }}>
                重新读取
              </Button>
            )}
          />
        </div>
      )
    }

    const managedChildren = snapshot.managed_children || []
    const managedById = new Map(
      managedChildren
        .filter((row) => row.pro_account_id)
        .map((row) => [Number(row.pro_account_id), row]),
    )
    const managedByEmail = new Map(
      managedChildren
        .filter((row) => row.email)
        .map((row) => [String(row.email).trim().toLowerCase(), row]),
    )
    const representedManagedIds = new Set<number>()
    const currentRows: BusinessChildDisplayRow[] = []
    const mergeRow = (row: BusinessManagedChild, kind: 'member' | 'invite') => {
      const managedId = Number(row.managed_pro_account_id || row.pro_account_id || 0)
      const managed = managedById.get(managedId)
        || managedByEmail.get(String(row.email || '').trim().toLowerCase())
      if (managed?.pro_account_id) representedManagedIds.add(Number(managed.pro_account_id))
      // members / invites 只描述远端身份，不包含 RT 与本地健康能力。
      // sanitizeBusinessChild 会把这些缺失布尔值规范化为 false，因此必须在
      // 合并后重新以 managed_children 的本地账号状态为准；远端 user_id、
      // invite_id、role 和席位等身份字段仍由 row 覆盖。
      const managedCapabilities = managed ? {
        has_codex_rt: managed.has_codex_rt,
        rt_supported: managed.rt_supported,
        can_get_rt: managed.can_get_rt,
        enabled: managed.enabled,
        dangerous: managed.dangerous,
        dangerous_detected_at: managed.dangerous_detected_at,
        policy_warning: managed.policy_warning,
        policy_warning_detected_at: managed.policy_warning_detected_at,
        refund_status: managed.refund_status,
        deactivated: managed.deactivated,
        monitor_enabled: managed.monitor_enabled,
        last_mail_check_at: managed.last_mail_check_at,
        last_mail_check_error: managed.last_mail_check_error,
        pending_alerts_count: managed.pending_alerts_count,
        pending_inbox_count: managed.pending_inbox_count,
        cpa_synced_to: managed.cpa_synced_to,
        sub2api_synced_to: managed.sub2api_synced_to,
        mail_provider: managed.mail_provider,
        mail_access_type: managed.mail_access_type,
        has_password: managed.has_password,
        has_mail_oauth: managed.has_mail_oauth,
        has_mail_credentials: managed.has_mail_credentials,
        has_cookie: managed.has_cookie,
        has_saved_login: managed.has_saved_login,
        cookie_valid: managed.cookie_valid,
        cookie_updated_at: managed.cookie_updated_at,
        cookie_expires_at: managed.cookie_expires_at,
        login_status: managed.login_status,
        can_chatgpt_login: managed.can_chatgpt_login,
        chatgpt_login_disabled_reason: managed.chatgpt_login_disabled_reason,
        can_setup_chatgpt_security: managed.can_setup_chatgpt_security,
        chatgpt_security_setup_disabled_reason: managed.chatgpt_security_setup_disabled_reason,
        chatgpt_security_setup_recovery_hint: managed.chatgpt_security_setup_recovery_hint,
        can_review_chatgpt_login: managed.can_review_chatgpt_login,
        chatgpt_login_review_disabled_reason: managed.chatgpt_login_review_disabled_reason,
        can_fetch_mail: managed.can_fetch_mail,
        fetch_mail_disabled_reason: managed.fetch_mail_disabled_reason,
        codex_rt_acquired_at: managed.codex_rt_acquired_at,
        chatgpt_security: managed.chatgpt_security,
      } : {}
      currentRows.push({
        ...(managed || {}),
        ...row,
        ...managedCapabilities,
        pro_account_id: managed?.pro_account_id || row.pro_account_id || row.managed_pro_account_id,
        _kind: kind,
        _managed: Boolean(managed || managedId),
      })
    }
    ;(snapshot.members || []).forEach((row) => mergeRow(row, 'member'))
    ;(snapshot.invites || []).forEach((row) => mergeRow(row, 'invite'))
    managedChildren.forEach((row) => {
      if (row.pro_account_id && representedManagedIds.has(Number(row.pro_account_id))) return
      currentRows.push({
        ...row,
        _kind: row.status === 'pending' ? 'invite' : row.status === 'member' ? 'member' : 'local',
        _managed: true,
      })
    })
    const vacancyPolicy = snapshot.vacancy_policy
    const vacancyValue = (value: number | null | undefined) => (
      value === null ? 'null' : value === undefined ? '—' : String(value)
    )
    const freeThreshold = vacancyPolicy?.free_vacancy_threshold
    const vacancyOrdinal = vacancyPolicy?.vacancy_ordinal
    const vacancyBillable = typeof freeThreshold === 'number' && typeof vacancyOrdinal === 'number'
      ? vacancyOrdinal > freeThreshold
      : null
    return (
      <div style={{ padding: 10 }}>
        <Space wrap style={{ marginBottom: 8 }}>
          <Typography.Text strong>工作区成员</Typography.Text>
          <Tag color="cyan">当前 {currentRows.filter((row) => row.role !== 'account-owner').length}</Tag>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            数据：{formatTime(snapshot.workspace_checked_at || snapshot.checked_at)}
          </Typography.Text>
        </Space>
        {view.error && <Alert type="warning" showIcon message={view.error} style={{ marginBottom: 8 }} />}
        <Collapse
          size="small"
          style={{ marginBottom: 8, background: token.colorFillAlter }}
          items={[{
            key: 'vacancy-policy',
            label: (
              <Space wrap size={6}>
                <Typography.Text strong>技术详情 · 席位阈值(fr / va)</Typography.Text>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  仅在移除成员时由 OpenAI 返回并写入数据库
                </Typography.Text>
              </Space>
            ),
            children: !vacancyPolicy ? (
              <div style={{ color: token.colorTextTertiary, fontSize: 12 }}>
                暂无数据 —— 移除任意一个成员后会自动记录 fr/va(OpenAI 仅在删成员时返回该数据)
              </div>
            ) : vacancyPolicy.policy_present !== true ? (
              <div style={{ color: token.colorWarning, fontSize: 12 }}>
                已捕获移除结果，但 OpenAI 返回 policy_notice = null
                {vacancyPolicy.http_status ? `（HTTP ${vacancyPolicy.http_status}）` : ''}，当前无计费空缺，fr/va 不适用。
                {' '}采集时间：{formatTime(vacancyPolicy.captured_at)}
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(190px,1fr))', gap: '7px 16px', fontSize: 12 }}>
                <div>
                  <b>free_vacancy_threshold</b><br />
                  <Typography.Text style={{ color: token.colorSuccessText, fontSize: 15, fontWeight: 700 }}>
                    {vacancyValue(freeThreshold)}
                  </Typography.Text>
                </div>
                <div>
                  <b>vacancy_ordinal</b><br />
                  <Typography.Text style={{ color: token.colorSuccessText, fontSize: 15, fontWeight: 700 }}>
                    {vacancyValue(vacancyOrdinal)}
                  </Typography.Text>
                  {vacancyBillable !== null && (
                    <Tag color={vacancyBillable ? 'red' : 'green'} style={{ marginLeft: 6 }}>
                      {vacancyBillable ? 'va > fr：计费' : 'va ≤ fr：仍免费'}
                    </Tag>
                  )}
                </div>
                <div><b>billing_starts_at</b><br />{formatTime(vacancyPolicy.billing_starts_at)}</div>
                <div><b>expires_at</b><br />{formatTime(vacancyPolicy.expires_at)}</div>
                <div style={{ gridColumn: '1 / -1', color: token.colorTextTertiary }}>
                  captured_at：{formatTime(vacancyPolicy.captured_at)}
                </div>
              </div>
            ),
          }]}
        />
        {(() => {
          const childColumns: NonNullable<TableProps<BusinessChildDisplayRow>['columns']> = [
            {
              title: '成员邮箱',
              dataIndex: 'email',
              width: 280,
              render: (email: string, row: BusinessChildDisplayRow) => (
                <Space size={4} wrap>
                  <span>{email || '(无邮箱)'}</span>
                  {String(row.mail_provider || '').toLowerCase() === 'icloud' && <Tag color="cyan">iCloud</Tag>}
                  {String(row.mail_provider || '').toLowerCase() === 'gmail' && <Tag color="red">Gmail</Tag>}
                  <Tag color={businessChildSeatType(row) === 'prolite' ? 'magenta' : businessChildSeatType(row) === 'default' ? 'blue' : 'default'}>
                    {businessSeatTypeLabel(businessChildSeatType(row))}
                  </Tag>
                  {!standalone && row.role !== 'account-owner' && (
                    <Tag color={['refunded', 'partial_refund'].includes(row.sale_status || '') ? 'warning' : row.sale_status === 'sold' ? 'success' : row.sale_status === 'listed' ? 'processing' : 'default'}>
                      {row.sale_status === 'refunded' ? 'NV 已退款' : row.sale_status === 'partial_refund' ? 'NV 部分退款，待处理' : row.sale_status === 'sold' ? '已出售' : row.sale_status === 'listed' ? '已上架' : '未上架'}
                    </Tag>
                  )}
                  <BusinessDeadStamp dead={row.dangerous} detectedAt={row.dangerous_detected_at} />
                  {row.policy_warning && (
                    <Tooltip title={row.policy_warning_detected_at
                      ? `检测于 ${formatTime(row.policy_warning_detected_at)}`
                      : '邮箱监控检测到用量政策告警'}>
                      <Tag color="warning" icon={<WarningOutlined />}>政策告警</Tag>
                    </Tooltip>
                  )}
                  {row.deactivated && !row.dangerous && <Tag>已停用</Tag>}
                </Space>
              ),
            },
            {
              title: '密码 / 2FA',
              key: 'child_chatgpt_security',
              width: 210,
              render: (_: unknown, row: BusinessChildDisplayRow) => {
                if (row.role === 'account-owner') {
                  return <Typography.Text type="secondary">—</Typography.Text>
                }
                if (!row._managed || !positiveInteger(row.pro_account_id ?? row.managed_pro_account_id)) {
                  return <Tag>非账号池子号</Tag>
                }
                const securityStateAvailable = row.chatgpt_security != null
                const security = row.chatgpt_security || {}
                const passwordState = String(
                  securityStateAvailable ? security.password_state || 'not_configured' : 'unknown',
                ).trim().toLowerCase()
                const mfaState = String(
                  securityStateAvailable ? security.mfa_state || 'not_configured' : 'unknown',
                ).trim().toLowerCase()
                const passwordMeta = passwordState === 'configured'
                  ? { label: '密码已设置', color: 'success' }
                  : passwordState === 'pending'
                    ? { label: '密码确认中', color: 'processing' }
                    : passwordState === 'failed'
                      ? { label: '密码设置失败', color: 'error' }
                      : passwordState === 'unknown'
                        ? { label: '密码状态未知', color: 'warning' }
                        : { label: '密码未设置', color: 'default' }
                const mfaMeta = mfaState === 'enabled'
                  ? { label: '2FA 已开启', color: 'success' }
                  : mfaState === 'pending'
                    ? { label: '2FA 确认中', color: 'processing' }
                    : mfaState === 'unmanaged'
                      ? { label: '2FA 已开启 · 需修复', color: 'warning' }
                      : mfaState === 'failed'
                        ? { label: '密码与 2FA 设置失败', color: 'error' }
                        : mfaState === 'unknown'
                          ? { label: '2FA 状态未知', color: 'warning' }
                          : { label: '2FA 未开启', color: 'default' }
                return (
                  <Space direction="vertical" size={2} data-business-child-security-status="true">
                    <Space size={4} wrap>
                      <Tag color={passwordMeta.color} style={{ margin: 0 }}>{passwordMeta.label}</Tag>
                      <Tag color={mfaMeta.color} style={{ margin: 0 }}>{mfaMeta.label}</Tag>
                    </Space>
                    {security.credentials_readable === false && (
                      <Tag color="error" style={{ margin: 0 }}>本地安全凭据不可读取</Tag>
                    )}
                    {security.last_error && (
                      <Tooltip title={security.last_error}>
                        <Typography.Text type="danger" style={{ maxWidth: 195, fontSize: 11 }} ellipsis>
                          上次安全设置失败
                        </Typography.Text>
                      </Tooltip>
                    )}
                  </Space>
                )
              },
            },
            {
              title: '来源 / RT',
              width: 330,
              render: (_: unknown, row: BusinessChildDisplayRow) => {
                if (row.role === 'account-owner') return <Tag color="gold">母号</Tag>
                if (!row._managed || !row.pro_account_id) {
                  return <Space size={4}><Tag>手动邮箱</Tag><Tag>不支持 RT</Tag></Space>
                }
                const hasRemoteIdentity = row._kind === 'member' || row._kind === 'invite'
                const credentialHealthReason = row.enabled === false || row.deactivated || row.dangerous
                  ? '子号已停用或标记为 Dead，不能导出或同步凭证'
                  : row.policy_warning
                    ? '子号存在政策告警，不能导出或同步凭证'
                    : String(row.refund_status || '').trim()
                      ? '子号已进入退款流程，不能导出或同步凭证'
                      : !hasRemoteIdentity
                        ? '子号尚无可确认的 BUSINESS 成员或邀请身份'
                        : ''
                const canDownloadCredential = Boolean(
                  row.has_codex_rt && row.pro_account_id && !credentialHealthReason,
                )
                const canSyncCredential = canDownloadCredential
                const linkedDevices = linkedBusinessChildDevices(row)
                return (
                  <Space
                    size={4}
                    wrap
                    style={{ display: 'flex', width: '100%', minWidth: 0, maxWidth: '100%', overflowWrap: 'anywhere' }}
                  >
                    <Tag color="purple">账号池</Tag>
                    <Tag color="blue">支持 RT</Tag>
                    <Tag color={row.has_codex_rt ? 'green' : row._kind === 'member' ? 'orange' : 'default'}>
                      {row.has_codex_rt
                        ? 'RT 已获取'
                        : row._kind === 'invite'
                          ? '待接受 · 可直接获取 RT'
                        : row._kind === 'local' ? '远端确认后可获取' : 'RT 未获取'}
                    </Tag>
                    {row.has_codex_rt && (
                      <Tooltip title={canDownloadCredential
                        ? '下载该子号的 OAuth 凭证'
                        : credentialHealthReason || '该子号当前不能下载凭证'}>
                        <Space.Compact size="small">
                          <Button
                            size="small"
                            icon={<DownloadOutlined />}
                            loading={downloadBusyKey === `business-child-${account.id}-${row.pro_account_id}-cpa`}
                            disabled={!canDownloadCredential}
                            onClick={() => { void downloadBusinessChildOAuthFile(account, row, 'cpa') }}
                          >
                            {standalone ? 'OAuth' : 'CPA'}
                          </Button>
                          <Button
                            size="small"
                            icon={<DownloadOutlined />}
                            loading={downloadBusyKey === `business-child-${account.id}-${row.pro_account_id}-sub2api`}
                            disabled={!canDownloadCredential}
                            onClick={() => { void downloadBusinessChildOAuthFile(account, row, 'sub2api') }}
                          >
                            SUB
                          </Button>
                        </Space.Compact>
                      </Tooltip>
                    )}
                    {!standalone && row.has_codex_rt && (
                      <Tooltip title={canSyncCredential
                        ? '选择 CPA / SUB 设备并同步；后端会实时核验子号已正式加入工作区'
                        : credentialHealthReason || '该子号当前不能同步设备'}>
                        <span>
                          <Button
                            size="small"
                            icon={<CloudUploadOutlined />}
                            disabled={!canSyncCredential || deviceSyncing}
                            onClick={() => { void openBusinessChildDeviceSync(account, row) }}
                          >
                            同步
                          </Button>
                        </span>
                      </Tooltip>
                    )}
                    {!standalone && linkedDevices.map((device) => (
                      <Tag
                        key={device.deviceRef}
                        color={device.provider === 'cpa' ? 'blue' : 'purple'}
                        style={{ margin: 0 }}
                      >
                        {device.provider === 'cpa' ? 'CPA' : 'SUB'} · {device.name}
                      </Tag>
                    ))}
                  </Space>
                )
              },
            },
            {
              title: '工作区状态',
              width: 190,
              render: (_: unknown, row: BusinessChildDisplayRow) => (
                <Space size={4} wrap>
                  <Tag color={row._kind === 'invite' ? 'orange' : row._kind === 'local' || row.deactivated ? 'default' : 'green'}>
                    {row._kind === 'invite'
                      ? '待接受'
                      : row._kind === 'local' ? '远端未确认 / 待同步' : row.deactivated ? '已停用' : '已加入'}
                  </Tag>
                  {row.role && (
                    <Tag color={row.role === 'account-owner' ? 'gold' : 'blue'}>
                      {row.role === 'account-owner' ? '所有者' : row.role === 'standard-user' ? '子号' : row.role}
                    </Tag>
                  )}
                </Space>
              ),
            },
            {
              title: '邮件健康',
              width: 250,
              render: (_: unknown, row: BusinessChildDisplayRow) => {
                if (row.role === 'account-owner') return <Typography.Text type="secondary">—</Typography.Text>
                if (!row._managed || !row.pro_account_id) return <Tag>手动邮箱 · 不监控</Tag>
                const alertCount = nonNegativeNumber(row.pending_alerts_count) ?? 0
                const inboxCount = nonNegativeNumber(row.pending_inbox_count) ?? 0
                return (
                  <Space direction="vertical" size={2}>
                    <Space size={4} wrap>
                      <Tag color={row.monitor_enabled === true ? 'success' : row.monitor_enabled === false ? 'default' : 'processing'}>
                        {row.monitor_enabled === true ? '监控开启' : row.monitor_enabled === false ? '监控暂停' : '监控待同步'}
                      </Tag>
                      {alertCount > 0 && <Tag color="error" icon={<BellOutlined />}>告警 {alertCount}</Tag>}
                      {inboxCount > 0 && <Tag color="blue" icon={<InboxOutlined />}>未读邮件 {inboxCount}</Tag>}
                      {row.last_mail_check_error && (
                        <Tooltip title={row.last_mail_check_error}>
                          <Tag color="error">检查异常</Tag>
                        </Tooltip>
                      )}
                    </Space>
                    <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                      {row.last_mail_check_at
                        ? `最近检查 ${formatTime(row.last_mail_check_at)}`
                        : '尚未执行邮件检查'}
                    </Typography.Text>
                  </Space>
                )
              },
            },
            {
              title: '操作',
              key: 'business_child_actions',
              width: 132,
              fixed: 'right',
              onHeaderCell: () => ({ style: { background: token.colorBgContainer } }),
              onCell: (row: BusinessChildDisplayRow) => ({
                style: {
                  background: businessChildMatchesFocus(row, focusTarget)
                    ? token.colorPrimaryBg
                    : token.colorBgContainer,
                },
              }),
              render: (_: unknown, row: BusinessChildDisplayRow) => (
                <Space size={6} wrap>
                  {renderBusinessChildNvListingButton(account, row)}
                  {renderBusinessChildActions(account, row)}
                </Space>
              ),
            },
          ]
          const childRowKey = (row: BusinessChildDisplayRow) => (
            `${row._kind}:${row.membership_id || row.user_id || row.invite_id || row.pro_account_id || row.email}`
          )
          const childDataAttributes = (row: BusinessChildDisplayRow) => ({
            'data-business-child-account-id': positiveInteger(row.pro_account_id ?? row.managed_pro_account_id) || undefined,
            'data-business-membership-id': positiveInteger(row.membership_id) || undefined,
          })
          const childFocusStyle = (row: BusinessChildDisplayRow) => (
            businessChildMatchesFocus(row, focusTarget)
              ? {
                  background: token.colorPrimaryBg,
                  boxShadow: `inset 3px 0 ${token.colorPrimary}`,
                  transition: 'background 0.3s ease-in-out',
                }
              : { transition: 'background 0.3s ease-in-out' }
          )
          const renderChildCell = (
            columnIndex: number,
            row: BusinessChildDisplayRow,
            rowIndex: number,
          ): ReactNode => {
            const column = childColumns[columnIndex]
            if (!column || !('render' in column) || typeof column.render !== 'function') return null
            const dataIndex = 'dataIndex' in column ? column.dataIndex : undefined
            const value = typeof dataIndex === 'string'
              ? row[dataIndex as keyof BusinessChildDisplayRow]
              : undefined
            return column.render(value, row, rowIndex) as ReactNode
          }

          if (compactBusinessLayout) {
            if (currentRows.length === 0) {
              return <Empty description="当前母号暂无成员或待接受邀请" />
            }
            const mobileFields = [
              { label: '密码 / 2FA', columnIndex: 1 },
              { label: '来源 / RT', columnIndex: 2 },
              { label: '工作区状态', columnIndex: 3 },
              { label: '邮件健康', columnIndex: 4 },
            ]
            return (
              <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 10, minWidth: 0 }}>
                {currentRows.map((row, rowIndex) => {
                  const focused = businessChildMatchesFocus(row, focusTarget)
                  return (
                    <div
                      key={childRowKey(row)}
                      data-business-child-mobile-card="true"
                      {...childDataAttributes(row)}
                      style={{ ...childFocusStyle(row), width: '100%', minWidth: 0, maxWidth: '100%' }}
                    >
                      <Card
                        size="small"
                        styles={{ body: { padding: 12, minWidth: 0, overflow: 'hidden' } }}
                        style={{ width: '100%', minWidth: 0, background: focused ? token.colorPrimaryBg : token.colorBgContainer }}
                      >
                        <div style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
                          {renderChildCell(0, row, rowIndex)}
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 10, minWidth: 0, marginTop: 12 }}>
                          {mobileFields.map((field) => (
                            <div
                              key={field.label}
                              style={{ minWidth: 0, maxWidth: '100%', borderTop: `1px solid ${token.colorBorderSecondary}`, paddingTop: 8 }}
                            >
                              <Typography.Text type="secondary" style={{ display: 'block', fontSize: 11, marginBottom: 4 }}>
                                {field.label}
                              </Typography.Text>
                              {renderChildCell(field.columnIndex, row, rowIndex)}
                            </div>
                          ))}
                          <div style={{ minWidth: 0, borderTop: `1px solid ${token.colorBorderSecondary}`, paddingTop: 8 }}>
                            <Typography.Text strong style={{ display: 'block', fontSize: 12, marginBottom: 6 }}>
                              操作
                            </Typography.Text>
                            {renderChildCell(5, row, rowIndex)}
                          </div>
                        </div>
                      </Card>
                    </div>
                  )
                })}
              </div>
            )
          }

          return (
            <Table<BusinessChildDisplayRow>
              data-business-child-desktop-table="true"
              rowKey={childRowKey}
              size="small"
              pagination={false}
              scroll={{ x: 1420 }}
              dataSource={currentRows}
              onRow={(row) => ({
                ...childDataAttributes(row),
                style: childFocusStyle(row),
              })}
              locale={{ emptyText: '当前母号暂无成员或待接受邀请' }}
              columns={childColumns}
            />
          )
        })()}
      </div>
    )
  }

  const handleAccountTableChange: NonNullable<TableProps<GptPlanAccount>['onChange']> = (
    _pagination,
    _filters,
    sorter,
    extra,
  ) => {
    if (accountType !== 'refunded' || extra.action !== 'sort') return
    const activeSorter = Array.isArray(sorter) ? sorter[0] : sorter
    if (String(activeSorter?.columnKey || '') !== 'checkout' || !activeSorter?.order) return
    const nextOrder = activeSorter.order === 'ascend' ? 'asc' : 'desc'
    if (nextOrder === refundedUpgradeTimeOrder) return
    setRefundedUpgradeTimeOrder(nextOrder)
    setPage(1)
  }

  const businessMemberTab = accountType === 'member' && memberPlan === 'team'
  const businessMotherView = businessMemberTab && businessCatalogView === 'mothers'
  const businessChildView = businessMemberTab && businessCatalogView === 'children'
  useEffect(() => {
    if (standalone || !businessMotherView) return undefined
    const controller = new AbortController()
    apiFetch('/nv-automation/mothers', { signal: controller.signal }).then(value => {
      const rows = Array.isArray((value as { items?: unknown[] })?.items) ? (value as { items: unknown[] }).items : []
      const next: Record<number, BusinessWorkspaceCapability['rotation_revenue']> = {}
      rows.forEach(item => {
        if (!item || typeof item !== 'object') return
        const row = item as { id?: unknown; revenue_cap?: BusinessWorkspaceCapability['rotation_revenue'] }
        const id = Number(row.id)
        if (Number.isSafeInteger(id) && id > 0) next[id] = row.revenue_cap || null
      })
      if (!controller.signal.aborted) setNvMotherRevenue(next)
    }).catch(() => { /* GPT 套餐列表继续使用本地母号数据；记录抽屉可单独重试 */ })
    return () => controller.abort()
  }, [businessMotherView, standalone])
  const businessAccountHasAvailableSeat = (account: GptPlanAccount) => {
    // 勾选边界必须与列表 API 同一份数据库快照一致，不能被旧弹框留下的
    // 内存 override 改写；真正启动时服务端仍会再次复核。
    const source = memberSourceOf(account)
    if (String(source?.source_pool || account.source_pool || '').trim().toLowerCase() !== 'gpt_business') {
      return false
    }
    if (businessInviteButtonState(account, source, undefined, replenishmentNow).disabled) {
      return false
    }
    const seat = businessSeatSummaryOf(source)
    const aggregateAvailable = seat?.available
    if (
      seat?.known !== true
      || seat.seat_type_capacity_known !== true
      || seat.seat_type_occupancy_known !== true
      || typeof aggregateAvailable !== 'number'
      || !Number.isInteger(aggregateAvailable)
      || aggregateAvailable <= 0
    ) return false
    const typedAvailable = (['default', 'prolite'] as const).map((seatType) => {
      const typed = seat.by_type?.[seatType]
      const available = typed?.available
      if (
        typed?.availability_exact !== true
        || typeof available !== 'number'
        || !Number.isInteger(available)
        || available < 0
      ) return null
      return available
    })
    return typedAvailable.every((value) => value !== null)
      && typedAvailable.reduce<number>((sum, value) => sum + Number(value || 0), 0) > 0
  }
  const businessBatchTaskRunning = Boolean(
    businessBatchInviteStarting
    || (businessBatchInviteTask && !['done', 'failed'].includes(businessBatchInviteTask.status)),
  )
  const businessChildBatchTaskRunning = Boolean(
    businessChildBatchStarting
    || (businessChildBatchTask
      && !['done', 'failed', 'completed', 'success'].includes(businessChildBatchTask.status)),
  )
  const businessChildLeaveWorkspaceEligibility = (row: BusinessChildCatalogRow) => {
    const membershipId = positiveInteger(row.membership_id)
    const parentId = positiveInteger(row.parent_account_id)
    if (!membershipId || !parentId) return { allowed: false, reason: '缺少可确认的成员或母号记录' }
    if (row.role === 'account-owner') return { allowed: false, reason: '不能移除空间所有者' }
    if (row._kind !== 'member') return { allowed: false, reason: row._kind === 'invite' ? '待接受邀请不会自动撤销' : '尚未确认已加入空间' }
    const actions = asRecord(row.actions)
    const remove = actions.remove
    const canRemove = !Object.prototype.hasOwnProperty.call(actions, 'remove')
      || (typeof remove === 'boolean' ? remove : asRecord(remove).supported === true)
    if (!canRemove) return { allowed: false, reason: String(asRecord(remove).reason || '该成员当前不能退出空间') }
    const childId = positiveInteger(row.pro_account_id ?? row.child_id)
    if (businessChildActionBusyKeys.includes(`remove:${parentId}:${membershipId}`)
      || (childId && businessChildActionBusyKeys.includes(`oauth:${parentId}:${childId}`))
      || (childId && businessChildRtTask?.status === 'running'
        && businessChildRtTask.accountId === parentId && businessChildRtTask.childId === childId)) {
      return { allowed: false, reason: '该子号正在执行其他操作，请稍后退出' }
    }
    return { allowed: true, reason: '' }
  }
  const businessChildBatchLeaveIds = selectedBusinessChildMembershipIds.filter((id) => {
    const row = businessChildCatalogRows.find((item) => Number(item.membership_id) === id)
    return Boolean(row && businessChildLeaveWorkspaceEligibility(row).allowed)
  })
  const businessChildBatchLeaveSkipped = selectedBusinessChildMembershipIds.length - businessChildBatchLeaveIds.length
  const businessChildBatchEligibility = (row: BusinessChildCatalogRow) => {
    const membershipId = positiveInteger(row.membership_id)
    const childId = positiveInteger(row.pro_account_id ?? row.child_id)
    if (!membershipId || !childId || !row._managed) return { allowed: false, reason: '该成员未关联账号池子号' }
    if (row._kind === 'local') return { allowed: false, reason: '远端成员或邀请状态尚未确认' }
    if (row.enabled === false || row.deactivated || row.dangerous) return { allowed: false, reason: '子号已停用或标记为 Dead' }
    if (row.policy_warning) return { allowed: false, reason: '子号存在政策告警' }
    if (String(row.refund_status || '').trim()) return { allowed: false, reason: '子号处于退款流程' }
    const actions = asRecord(row.actions)
    const supported = (name: string, fallback: boolean) => {
      if (!Object.prototype.hasOwnProperty.call(actions, name)) return fallback
      const value = actions[name]
      return typeof value === 'boolean' ? value : asRecord(value).supported === true
    }
    const canSetupSecurity = supported('security', row.can_setup_chatgpt_security === true)
      && row.can_setup_chatgpt_security === true
    const canAcquireRt = supported('oauth', row.can_get_rt === true)
      && row.can_get_rt === true
    if (!canSetupSecurity && !canAcquireRt) {
      return { allowed: false, reason: '该子号当前不支持 2FA 或 RT 操作' }
    }
    return { allowed: true, reason: '' }
  }
  const businessChildBatchActionEligibility = (
    row: BusinessChildCatalogRow,
    action: BusinessChildBatchAction,
  ) => {
    if (action === 'leave_workspace') return businessChildLeaveWorkspaceEligibility(row)
    const base = businessChildBatchEligibility(row)
    if (!base.allowed) return base
    const actions = asRecord(row.actions)
    const value = actions[action === 'oauth' ? 'oauth' : 'security']
    const capabilitySupported = typeof value === 'boolean'
      ? value
      : Object.keys(asRecord(value)).length
        ? asRecord(value).supported === true
        : action === 'oauth' ? row.can_get_rt === true : row.can_setup_chatgpt_security === true
    const rowAllowsAction = action === 'oauth'
      ? row.can_get_rt === true
      : row.can_setup_chatgpt_security === true
    if (capabilitySupported && rowAllowsAction) return base
    const reason = String(asRecord(value).reason || (
      action === 'oauth'
        ? row.chatgpt_oauth_disabled_reason || '该子号当前不能获取 RT'
        : row.chatgpt_security_setup_disabled_reason || '该子号当前不能设置密码与 2FA'
    ))
    return { allowed: false, reason }
  }
  const businessBatchSelectionCount = businessSelectAllMatching
    ? total
    : selectedBusinessAccountIds.length
  const noteColumn = {
    title: '备注',
    dataIndex: 'note',
    key: 'note',
    width: 180,
    render: (value: string | undefined, account: GptPlanAccount) => {
      const original = String(value || '')
      const saving = noteSavingId === account.id
      if (editingNoteId === account.id) {
        return (
          <Input
            autoFocus
            size="small"
            maxLength={500}
            value={noteDraft}
            disabled={saving}
            suffix={saving ? <Spin size="small" /> : null}
            onClick={(event) => event.stopPropagation()}
            onChange={(event) => setNoteDraft(event.target.value)}
            onBlur={() => { void saveAccountNote(account, noteDraft) }}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault()
                void saveAccountNote(account, noteDraft)
                event.currentTarget.blur()
              } else if (event.key === 'Escape') {
                event.preventDefault()
                cancelNoteEdit(account)
                event.currentTarget.blur()
              }
            }}
          />
        )
      }
      return (
        <Tooltip title={original ? `${original}（双击编辑）` : '双击添加备注'}>
          <div
            onDoubleClick={(event) => {
              event.stopPropagation()
              startNoteEdit(account)
            }}
            style={{
              minHeight: 22,
              cursor: 'text',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              color: original ? undefined : token.colorTextTertiary,
            }}
          >
            {saving && <Spin size="small" style={{ marginRight: 6 }} />}
            {original || '双击添加备注'}
          </div>
        </Tooltip>
      )
    },
  }

  const columns = [
    {
      title: '账号',
      dataIndex: 'email',
      key: 'email',
      width: businessMotherView && compactBusinessLayout ? 220 : 270,
      fixed: accountType === 'member' ? 'left' as const : undefined,
      onHeaderCell: businessMotherView ? () => ({ style: { background: token.colorBgContainer } }) : undefined,
      onCell: businessMotherView ? (account: GptPlanAccount) => ({ style: {
        background: focusTarget?.planAccountId === account.id ? token.colorPrimaryBg : token.colorBgContainer,
      } }) : undefined,
      render: (email: string, account: GptPlanAccount) => {
        const source = memberSourceOf(account, memberSourceOverrides[account.id])
        const businessMother = String(source?.source_pool || account.source_pool || '')
          .trim()
          .toLowerCase() === 'gpt_business'
        const motherBinding = normalizeBusinessMemberDeviceBinding(source?.business_device_binding || {})
        const refundStatus = String(
          businessMother
            ? source?.refund_status || account.refund_status || ''
            : account.refund_status || source?.refund_status || '',
        ).trim()
        const humanReviewAt = String(
          businessMother
            ? source?.human_review_requested_at || account.human_review_requested_at || ''
            : account.human_review_requested_at || source?.human_review_requested_at || '',
        ).trim()
        return (
          <Space direction="vertical" size={1}>
            <Space size={5}>
              <Typography.Text
                style={{ fontFamily: 'monospace', maxWidth: businessMotherView ? (compactBusinessLayout ? 168 : 218) : undefined }}
                ellipsis={businessMotherView ? { tooltip: email } : false}
              >{email}</Typography.Text>
              <Tooltip title="复制邮箱">
                <CopyOutlined
                  style={{ cursor: 'pointer', color: token.colorTextTertiary }}
                  onClick={() => { void navigator.clipboard.writeText(email); message.success('邮箱已复制') }}
                />
              </Tooltip>
            </Space>
            <Space size={4} wrap>
              {account.mail_provider && <Tag style={{ margin: 0 }}>{account.mail_provider}</Tag>}
              <BusinessDeadStamp
                dead={account.dead === true || account.dangerous === true || (businessMother && source?.dangerous === true)}
                detectedAt={account.dangerous_detected_at || (businessMother ? source?.dangerous_detected_at : undefined)}
              />
              {account.policy_warning && (
                <Tooltip title={account.policy_warning_detected_at
                  ? `收到用量政策违规/停用警告邮件：${formatTime(account.policy_warning_detected_at)}`
                  : '收到用量政策违规/停用警告邮件'}>
                  <Tag color="warning" icon={<WarningOutlined />} style={{ margin: 0 }}>用量警告</Tag>
                </Tooltip>
              )}
              {refundStatus === 'refund_escalated' && (
                <Tooltip title={humanReviewAt
                  ? `已升级人工客服，等待退款到账。升级于 ${formatTime(humanReviewAt)}`
                  : '已升级人工客服，等待退款到账；退款邮件到达后会进入“已退款”'}>
                  <Tag color="cyan" style={{ margin: 0 }}>已升级人工·等待退款</Tag>
                </Tooltip>
              )}
              {humanReviewAt && (
                <Tooltip title={`人工复核时间：${formatTime(humanReviewAt)}`}>
                  <Tag color="purple" style={{ margin: 0 }}>人工复核</Tag>
                </Tooltip>
              )}
            </Space>
            {(businessMother || (accountType === 'member' && ['pro', 'plus', 'go'].includes(memberPlan))) && (
              <Space size={12} wrap style={{ marginTop: 3 }}>
              {businessMother && <>
              <Button
                type="link"
                size="small"
                icon={<TeamOutlined />}
                data-business-members-trigger="true"
                style={{ alignSelf: 'flex-start', height: 24, padding: 0 }}
                onClick={(event) => {
                  event.stopPropagation()
                  openBusinessMembers(account)
                }}
              >
                查看成员
              </Button>
              {!standalone && !(account.dead || account.dangerous) && (
                <Button type="link" size="small" style={{ height: 24, padding: 0 }}
                  onClick={event => { event.stopPropagation(); setAuditMotherId(account.id) }}>母号记录</Button>
              )}
              </>}
              {(businessMotherView || (accountType === 'member' && ['pro', 'plus', 'go'].includes(memberPlan))) && (
                <Space size={8} data-business-mother-mail={businessMotherView ? 'true' : undefined}
                  data-plan-member-mail={!businessMotherView ? 'true' : undefined}>
                  {(alertSummary[account.id] || 0) > 0 && (
                    <Tooltip title={`查看 ${alertSummary[account.id]} 封封禁报警邮件`}>
                      <Badge count={alertSummary[account.id]} size="small" offset={[-2, 1]}>
                        <Button type="text" danger size="small" icon={<BellOutlined />}
                          aria-label={`查看 ${account.email} 的封禁报警`}
                          onClick={() => { void openMailAlerts(account) }} />
                      </Badge>
                    </Tooltip>
                  )}
                  {(inboxSummary[account.id] || 0) > 0 && (
                    <Tooltip title={`查看 ${inboxSummary[account.id]} 封未读邮件`}>
                      <Badge count={inboxSummary[account.id]} size="small" offset={[-2, 1]}>
                        <Button type="text" size="small" icon={<MailOutlined />}
                          style={{ color: token.colorPrimary }}
                          aria-label={`查看 ${account.email} 的未读邮件`}
                          onClick={() => { void openMailInbox(account) }} />
                      </Badge>
                    </Tooltip>
                  )}
                </Space>
              )}
              </Space>
            )}
            {!standalone && businessMotherView && businessMother && motherBinding.bound && (
              <Tooltip title={`${businessMemberBindingLabel(motherBinding)} · 点击修改绑定`}>
                <Button type="text" size="small" icon={<LinkOutlined />}
                  data-business-mother-binding="true"
                  aria-label={`修改 ${account.email} 的设备绑定`}
                  style={{ padding: '0 4px', height: 24, maxWidth: '100%', color: token.colorTextSecondary }}
                  onClick={() => openBusinessBindingEditor(account)}>
                  <span style={{ maxWidth: compactBusinessLayout ? 140 : 190, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {businessMemberBindingLabel(motherBinding)}
                  </span>
                </Button>
              </Tooltip>
            )}
          </Space>
        )
      },
    },
    ...(businessMemberTab ? [noteColumn] : []),
    {
      title: '邮件',
      key: 'fetch_mail',
      width: 90,
      align: 'center' as const,
      render: (_: unknown, account: GptPlanAccount) => (
        <Tooltip title={hasMailCredentials(account) ? '取件（最近 10 封）' : '该账号缺少可用邮件凭证'}>
          <span>
            <Button size="small" icon={<InboxOutlined />}
              aria-label={`获取 ${account.email} 的最新 10 封邮件`}
              loading={mailLoading && !mailBusinessChildTarget && mailAccount?.id === account.id}
              disabled={!hasMailCredentials(account)}
              onClick={(event) => { event.stopPropagation(); void fetchMail(account, 10) }}>
              邮箱
            </Button>
          </span>
        </Tooltip>
      ),
    },
    ...(!businessMotherView ? [{
      title: '密码 / 2FA',
      key: 'chatgpt_security',
      width: 210,
      render: (_: unknown, account: GptPlanAccount) => {
        const securityStateAvailable = account.chatgpt_security != null
        const security = account.chatgpt_security || {}
        const passwordState = String(
          securityStateAvailable ? security.password_state || 'not_configured' : 'unknown',
        ).trim().toLowerCase()
        const mfaState = String(
          securityStateAvailable ? security.mfa_state || 'not_configured' : 'unknown',
        ).trim().toLowerCase()
        const passwordMeta = passwordState === 'configured'
          ? { label: '密码已设置', color: 'success' }
          : passwordState === 'pending'
            ? { label: '密码确认中', color: 'processing' }
            : passwordState === 'failed'
              ? { label: '密码设置失败', color: 'error' }
              : passwordState === 'unknown'
                ? { label: '密码状态未知', color: 'warning' }
              : { label: '密码未设置', color: 'default' }
        const mfaMeta = mfaState === 'enabled'
          ? { label: '2FA 已开启', color: 'success' }
          : mfaState === 'pending'
            ? { label: '2FA 确认中', color: 'processing' }
            : mfaState === 'unmanaged'
              ? { label: '2FA 已开启 · 需修复', color: 'warning' }
              : mfaState === 'failed'
                ? { label: '密码与 2FA 设置失败', color: 'error' }
                : mfaState === 'unknown'
                  ? { label: '2FA 状态未知', color: 'warning' }
                : { label: '2FA 未开启', color: 'default' }
        return (
          <Space direction="vertical" size={2}>
            <Space size={4} wrap>
              <Tag color={passwordMeta.color} style={{ margin: 0 }}>{passwordMeta.label}</Tag>
              <Tag color={mfaMeta.color} style={{ margin: 0 }}>{mfaMeta.label}</Tag>
            </Space>
            {security.credentials_readable === false && (
              <Tag color="error" style={{ margin: 0 }}>本地安全凭据不可读取</Tag>
            )}
            {security.last_error && (
              <Tooltip title={security.last_error}>
                <Typography.Text type="danger" style={{ maxWidth: 195, fontSize: 11 }} ellipsis>
                  上次安全设置失败
                </Typography.Text>
              </Tooltip>
            )}
          </Space>
        )
      },
    }] : []),
    ...(businessMotherView ? [{
      title: '轮转营收',
      key: 'rotation_revenue',
      width: 190,
      render: (_: unknown, account: GptPlanAccount) => {
        const revenue = nvMotherRevenue[account.id]
        const tiers = revenue?.tiers || {}
        const line = (key: string, label: string) => {
          const item = tiers[key]
          if (!item) return null
          return <Typography.Text type={item.exceeded ? 'danger' : 'secondary'} style={{ fontSize: 12 }}>
            {label} ¥{item.current_yuan || '0.00'} / {item.threshold_yuan ? `¥${item.threshold_yuan}` : '不限'}
          </Typography.Text>
        }
        return <Space direction="vertical" size={1}>
          {line('default', '普通')}{line('prolite', '5X')}
          {revenue?.rotation_blocked ? <Tag color="red" style={{ margin: 0 }}>已停止新增轮转</Tag> : !revenue ? <Typography.Text type="secondary">读取中</Typography.Text> : null}
        </Space>
      },
    }] : []),
    ...(businessMotherView ? [{
      title: '默认支付方式',
      key: 'default_payment_method',
      width: 150,
      render: (_: unknown, account: GptPlanAccount) => {
        const source = memberSourceOf(account, memberSourceOverrides[account.id])
        const method = businessDefaultPaymentMethodOf(account, source)
        const refreshing = businessPaymentRefreshingIds.includes(account.id)
        return (
          <Space direction="vertical" size={2}>
            <Tooltip title={(
              <div>
                <div>{method.error || (method.status === 'unknown' && method.checked_at
                  ? '已查询，远端尚未提供可确认的默认支付方式。'
                  : '手动查询此母号当前的默认支付方式，仅显示脱敏信息。')}</div>
                {method.checked_at && <div>查询时间：{formatTime(method.checked_at)}</div>}
              </div>
            )}>
              <Typography.Text
                type={method.status === 'error' ? 'danger' : method.status === 'unknown' ? 'secondary' : undefined}
                style={{ maxWidth: 130, fontSize: 12 }}
                ellipsis
                data-business-default-payment-status={method.status}
              >
                {businessDefaultPaymentMethodLabel(method)}
              </Typography.Text>
            </Tooltip>
            <Button
              type="link"
              size="small"
              icon={<ReloadOutlined />}
              loading={refreshing}
              disabled={refreshing}
              aria-label={`刷新 ${account.email} 的默认支付方式`}
              data-business-default-payment-refresh="true"
              style={{ height: 20, padding: '0 2px', fontSize: 11 }}
              onClick={(event) => {
                event.stopPropagation()
                void refreshBusinessDefaultPaymentMethod(account)
              }}
            >
              刷新
            </Button>
          </Space>
        )
      },
    }] : []),
    ...(businessMemberTab && !standalone ? [{
        title: '用途',
        key: 'business_usage_type',
        width: 125,
        render: (_: unknown, account: GptPlanAccount) => {
          const saving = businessUsageSavingIds.includes(account.id)
          const value: BusinessUsageFilter = account.business_usage_type === 'sale'
            ? 'sale'
            : account.business_usage_type === 'self_use' ? 'self_use'
              : account.business_usage_type === 'transit' ? 'transit' : 'unassigned'
          return (
            <Select
              size="small"
              value={value}
              loading={saving}
              disabled={saving}
              aria-label={`设置 ${account.email} 的用途`}
              data-business-usage-select="true"
              style={{ width: 100 }}
              options={[
                { value: 'unassigned', label: '未标注' },
                { value: 'sale', label: '出售' },
                { value: 'self_use', label: '自用' },
                { value: 'transit', label: '中转' },
              ]}
              onClick={(event) => event.stopPropagation()}
              onChange={(next: BusinessUsageFilter) => {
                void saveBusinessUsage(account, next === 'unassigned' ? null : next)
              }}
            />
          )
        },
      }] : []),
    ...(businessMotherView ? [{
      title: '子号邀请权限',
      key: 'workspace_referrals_enabled',
      width: 155,
      render: (_: unknown, account: GptPlanAccount) => {
        const source = memberSourceOf(account, memberSourceOverrides[account.id])
        const workspace = businessWorkspaceOf(source)
        const enabled = typeof workspace?.workspace_referrals_enabled === 'boolean'
          ? workspace.workspace_referrals_enabled
          : null
        const visible = typeof workspace?.workspace_referrals_enabled_visible === 'boolean'
          ? workspace.workspace_referrals_enabled_visible
          : null
        const saving = businessWorkspaceReferralsSavingIds.includes(account.id)
        const refreshing = businessWorkspaceRefreshingIds.includes(account.id)
          || businessWorkspacePageRefreshing
        const sourceUnavailable = Boolean(source?.source_missing)
        const disabled = saving || refreshing || sourceUnavailable || enabled === null || visible !== true
        const statusUnknown = visible !== false && (enabled === null || visible === null)
        const stateLabel = visible === false
          ? '远端不可用'
          : enabled === null || visible === null ? '状态未知' : enabled ? '允许邀请' : '禁止邀请'
        const stateReason = sourceUnavailable
          ? String(source?.source_error || 'BUSINESS 母号工作区记录不可用')
          : visible === false
            ? '远端返回 workspace_referrals_enabled_visible=false，此工作区不可操作该设置'
            : enabled === null || visible === null
              ? '状态未知，请点击本列“刷新”读取此母号的远端 Workspace 设置，无需全局刷新'
              : enabled
                ? '远端 Workspace 当前允许推荐/邀请子号'
                : '远端 Workspace 当前禁止推荐/邀请子号'
        return (
          <Tooltip title={(
            <div>
              <div>{stateReason}</div>
              <div>读取远端 workspace_referrals_enabled，仅代表 Workspace 推荐/子号邀请设置。</div>
              <div>不代表剩余席位、邀请额度或邀请冷却。</div>
              {workspace?.workspace_referrals_enabled_checked_at && (
                <div>权限数据：{formatTime(workspace.workspace_referrals_enabled_checked_at)}</div>
              )}
            </div>
          )}>
            <Space direction="vertical" size={2} align="center">
              <span onClick={(event) => event.stopPropagation()}>
                <Switch
                  checked={enabled === true}
                  loading={saving}
                  disabled={disabled}
                  checkedChildren="允许"
                  unCheckedChildren="禁止"
                  aria-label={`设置 ${account.email} 的子号邀请权限`}
                  data-business-workspace-referrals-switch="true"
                  onChange={(nextEnabled) => {
                    void saveBusinessWorkspaceReferralsEnabled(account, nextEnabled)
                  }}
                />
              </span>
              <Typography.Text
                type={enabled === null || visible !== true ? 'secondary' : undefined}
                style={{ fontSize: 11 }}
              >
                {stateLabel}
              </Typography.Text>
              {statusUnknown && (
                <Button
                  type="link"
                  size="small"
                  icon={<ReloadOutlined />}
                  loading={refreshing}
                  disabled={saving || refreshing || sourceUnavailable}
                  aria-label={`刷新 ${account.email} 的子号邀请权限`}
                  data-business-workspace-referrals-refresh="true"
                  style={{ height: 20, padding: '0 2px', fontSize: 11 }}
                  onClick={(event) => {
                    event.stopPropagation()
                    void refreshBusinessWorkspace(account, { reloadAfter: false, notifyReferrals: true })
                  }}
                >
                  刷新
                </Button>
              )}
            </Space>
          </Tooltip>
        )
      },
    }] : []),
    ...(!businessMemberTab ? [{
      title: '套餐',
      key: 'plan',
      width: 160,
      render: (_: unknown, account: GptPlanAccount) => {
        const raw = planTypeOf(account)
        const label = planLabelOf(account)
        return (
          <Space direction="vertical" size={1}>
            <Tooltip title={raw && raw !== label ? raw : undefined}>
              <Tag color={raw ? 'gold' : 'default'}>{label}</Tag>
            </Tooltip>
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              {formatTime(account.plan_checked_at || account.plan_detected_at)}
            </Typography.Text>
          </Space>
        )
      },
    }] : []),
    ...(businessMemberTab ? [{
      title: 'BUSINESS 席位 / 可用能力',
      key: 'business_capability',
      width: 330,
      render: (_: unknown, account: GptPlanAccount) => {
        const source = memberSourceOf(account, memberSourceOverrides[account.id])
        const sourcePool = String(source?.source_pool || account.source_pool || '').trim().toLowerCase()
        if (sourcePool !== 'gpt_business') return <Typography.Text type="secondary">—</Typography.Text>

        const workspace = businessWorkspaceOf(source)
        const seat = businessSeatSummaryOf(source)
        const inviteCooldown = businessInviteCooldownOf(
          account,
          source,
          workspace,
          businessChildrenByAccount[account.id]?.snapshot,
          replenishmentNow,
        )
        const inviteQuota = businessInviteQuotaOf(
          account,
          source,
          workspace,
          businessChildrenByAccount[account.id]?.snapshot,
          replenishmentNow,
        )
        const normal = businessSeatCapacity(seat, 'default')
        const advanced = businessSeatCapacity(seat, 'prolite')
        const showAdvanced = hasBusinessAdvancedSeat(seat, advanced)
        const ownerSeatType = normalizeBusinessSeatType(seat?.owner_seat_type)
        const aggregateAvailable = nonNegativeNumber(seat?.available)
        const checkedAt = seat?.checked_at || source?.workspace_checked_at
        const countLabel = (value: number | null) => value === null ? '未知' : String(value)
        const seatTag = (
          seatType: BusinessSeatType,
          capacity: BusinessSeatTypeCapacity,
        ) => (
          <Tag
            key={seatType}
            color={seatType === 'prolite' ? 'magenta' : 'blue'}
            style={{ margin: 0, whiteSpace: 'nowrap' }}
          >
            {seatType === 'prolite' ? '高级' : '普通'}：已用 {countLabel(capacity.used)}
            {' · '}可用 {countLabel(businessSeatAvailable(seat, capacity))}
          </Tag>
        )
        const sessionReady = workspace?.team_session_usable !== false
        const typedAvailability = ([
          { seatType: 'default' as const, capacity: normal, visible: true },
          { seatType: 'prolite' as const, capacity: advanced, visible: showAdvanced },
        ]).filter(({ capacity, visible }) => (
          visible && Number(businessSeatAvailable(seat, capacity) || 0) > 0
        )).map(({ seatType, capacity }) => (
          `${seatType === 'prolite' ? '高级' : '普通'} ${businessSeatAvailable(seat, capacity)}`
        ))
        const declaredInvitableTypes = Array.from(new Set(
          (seat?.invitable_seat_types || seat?.requestable_seat_types || [])
            .map(normalizeBusinessSeatType)
            .filter((value): value is BusinessSeatType => Boolean(value)),
        )).map((seatType) => seatType === 'prolite' ? '高级' : '普通')
        let seatStatus: { label: string; color: string; reason?: string }
        if (!sessionReady) {
          seatStatus = {
            label: '席位状态：会话不可用',
            color: 'warning',
            reason: businessSessionReasonLabel(workspace?.team_session_reason),
          }
        } else if (!seat?.known || aggregateAvailable === null) {
          seatStatus = { label: '席位状态：未知', color: 'default', reason: '请在母号列表或详情顶部点击“刷新成员/席位”获取席位快照' }
        } else if (aggregateAvailable > 0) {
          const availableTypes = typedAvailability.length ? typedAvailability : declaredInvitableTypes
          seatStatus = {
            label: `席位状态：可邀请${availableTypes.length ? ` · ${availableTypes.join(' / ')}` : ` ${aggregateAvailable} 个`}`,
            color: 'success',
          }
        } else {
          seatStatus = {
            label: '席位状态：满席 · 可用 0',
            color: 'error',
          }
        }

        const rowRefreshing = businessWorkspaceRefreshingIds.includes(account.id)
        return (
          <Tooltip title={(
            <div>
              {workspace?.team_plan && <div>工作区套餐：{workspace.team_plan}</div>}
              {seatStatus.reason && <div>{seatStatus.reason}</div>}
              {inviteCooldown.active && inviteCooldown.reason && (
                <div>邀请失败原因：{businessInviteCooldownReasonLabel(inviteCooldown.reason)}</div>
              )}
              {checkedAt && <div>席位数据：{formatTime(checkedAt)}</div>}
            </div>
          )}>
            <Space direction="vertical" size={2} style={{ alignItems: 'stretch' }}>
              <Tag
                color={ownerSeatType === 'prolite' ? 'magenta' : ownerSeatType === 'default' ? 'blue' : 'default'}
                style={{ margin: 0 }}
              >
                母号：{ownerSeatType === 'prolite' ? '高级席位' : ownerSeatType === 'default' ? '普通席位' : '席位类型未知'}
              </Tag>
              {seat?.known && (
                <Tag
                  color={Number(aggregateAvailable || 0) <= 0 ? 'red' : Number(aggregateAvailable || 0) <= 1 ? 'orange' : 'success'}
                  style={{ margin: 0 }}
                >
                  总席位：已用 {countLabel(nonNegativeNumber(seat.used))}/{countLabel(nonNegativeNumber(seat.total))}
                  {' · '}可用 {countLabel(aggregateAvailable)}
                </Tag>
              )}
              {seat && seatTag('default', normal)}
              {seat && showAdvanced && seatTag('prolite', advanced)}
              <Tag color={seatStatus.color} style={{ margin: 0, whiteSpace: 'normal' }}>{seatStatus.label}</Tag>
              <BusinessInviteQuotaSummary quota={inviteQuota} seatTypes={businessInviteQuotaSeatTypes(seat)} />
              {inviteCooldown.active && (
                <Tag color="orange" style={{ margin: 0, whiteSpace: 'normal' }}>
                  邀请失败冷却 · {businessInviteCooldownCountdown(inviteCooldown.until, replenishmentNow)}
                </Tag>
              )}
              <Space size={4} wrap>
                <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                  数据：{formatTime(checkedAt)}
                </Typography.Text>
                <Tooltip title="刷新成员/席位">
                <span>
                <Button
                  type="text"
                  size="small"
                  icon={<ReloadOutlined />}
                  loading={rowRefreshing}
                  disabled={businessWorkspacePageRefreshing || Boolean(source?.source_missing)}
                  aria-label={`刷新 ${account.email} 的成员/席位`}
                  style={{ height: 24, width: 24, color: token.colorTextSecondary }}
                  onClick={(event) => {
                    event.stopPropagation()
                    void refreshBusinessWorkspace(account)
                  }}
                />
                </span>
                </Tooltip>
              </Space>
            </Space>
          </Tooltip>
        )
      },
    }] : []),
    ...((accountType === 'regular' || (accountType === 'member' && memberPlan === 'team')) ? [{
      title: '登录状态',
      key: 'login_status',
      width: businessMotherView ? 185 : 135,
      render: (_: unknown, account: GptPlanAccount) => {
        const source = memberSourceOf(account, memberSourceOverrides[account.id])
        const isBusinessMother = businessMotherView
          && String(source?.source_pool || account.source_pool || '').trim().toLowerCase() === 'gpt_business'
        if (isBusinessMother) return (
          <BusinessSessionStatus
            compact
            health={businessWorkspaceOf(source)?.session_health}
            checking={businessSessionCheckingIds.includes(account.id)}
            disabled={Boolean(source?.source_missing) || loginId === account.id}
            onCheck={() => { void checkBusinessSession(account) }}
          />
        )
        const status = loginStatusOf(account)
        const meta = {
          logged_in: { color: 'success', label: account.login_status_label || '已登录' },
          not_logged_in: { color: 'default', label: account.login_status_label || '未登录' },
          failed: { color: 'error', label: account.login_status_label || '登录失败' },
          unknown: { color: 'default', label: account.login_status_label || '未知' },
        }[status]
        return (
          <Space direction="vertical" size={1}>
            <Tag color={meta.color}>{meta.label}</Tag>
            {account.has_cookie && account.cookie_valid === false && <Tag color="warning">Cookie 已过期</Tag>}
            {account.last_login_error && (
              <Tooltip title={account.last_login_error}>
                <Typography.Text type="danger" style={{ fontSize: 11 }}>上次登录失败</Typography.Text>
              </Tooltip>
            )}
          </Space>
        )
      },
    }] : []),
    ...(accountType !== 'refunded' && !businessMemberTab ? [{
      title: '邮箱能力',
      key: 'mail',
      width: 130,
      render: (_: unknown, account: GptPlanAccount) => (
        <Space direction="vertical" size={1}>
          <Tag color={hasMailCredentials(account) ? (account.mail_access_type_color || 'blue') : 'default'}>
            {account.mail_access_type_label || account.mail_access_type || (hasMailCredentials(account) ? '可取件' : '缺少凭证')}
          </Tag>
          {(account.last_mail_error || account.last_mail_check_error) ? (
            <Tooltip title={account.last_mail_error || account.last_mail_check_error}>
              <Typography.Text type="danger" style={{ fontSize: 11 }}>上次取件失败</Typography.Text>
            </Tooltip>
          ) : (account.last_mail_fetch_at || account.last_mail_check_at) ? (
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              {formatTime(account.last_mail_fetch_at || account.last_mail_check_at)}
            </Typography.Text>
          ) : null}
        </Space>
      ),
    }] : []),
    ...(accountType === 'member' && !businessMemberTab ? [{
      title: '下次取件',
      key: 'next_mail_check',
      width: 135,
      render: (_: unknown, account: GptPlanAccount) => {
        if (account.enabled === false) return <Tag>未监控</Tag>
        if (!account.last_mail_check_at) return <Tag color="processing">待首次检查</Tag>
        const lastCheckedAt = new Date(account.last_mail_check_at).getTime()
        if (Number.isNaN(lastCheckedAt)) return '—'
        const diff = lastCheckedAt + MAIL_MONITOR_INTERVAL_MS - mailMonitorNow
        const remainingMs = ((diff % MAIL_MONITOR_INTERVAL_MS) + MAIL_MONITOR_INTERVAL_MS) % MAIL_MONITOR_INTERVAL_MS
        const remainingSeconds = Math.floor(remainingMs / 1000)
        const minutes = String(Math.floor(remainingSeconds / 60)).padStart(2, '0')
        const seconds = String(remainingSeconds % 60).padStart(2, '0')
        const overdue = diff < 0
        const errored = Boolean(account.last_mail_check_error)
        return (
          <Tooltip title={(
            <div>
              <div>上次检查：{formatTime(account.last_mail_check_at)}</div>
              <div>下次预计：{formatTime(new Date(lastCheckedAt + MAIL_MONITOR_INTERVAL_MS).toISOString())}</div>
              {overdue && <div style={{ color: token.colorWarning }}>已超时，等待后台下一轮回包</div>}
              {errored && <div style={{ color: token.colorError }}>上次错误：{account.last_mail_check_error}</div>}
            </div>
          )}>
            <Tag
              color={errored ? 'error' : overdue ? 'warning' : 'success'}
              style={{ margin: 0, fontFamily: 'monospace' }}
            >
              {minutes}:{seconds}
            </Tag>
          </Tooltip>
        )
      },
    }] : []),
    {
      title: accountType === 'refunded' ? '原始 PRO 升级' : '升级/结账',
      key: 'checkout',
      width: 210,
      ...(accountType === 'refunded' ? {
        sorter: true,
        sortOrder: refundedUpgradeTimeOrder === 'asc' ? 'ascend' as const : 'descend' as const,
        sortDirections: ['descend' as const, 'ascend' as const, 'descend' as const],
      } : {}),
      render: (_: unknown, account: GptPlanAccount) => {
        // plan_upgraded_at 是后端统一裁定的权威升级时间；前端不再对多个
        // 兼容字段自行排序，以免把 checkout 创建时间误当成订阅生效时间。
        const upgradedAt = account.plan_upgraded_at
        const canonicalPlan = account.member_plan || memberPlanKey(planTypeOf(account))
        const upgradedLabel = accountType === 'refunded'
          ? '原始 PRO 升级'
          : canonicalPlan === 'team'
            ? 'BUSINESS 升级'
            : canonicalPlan === 'pro' ? 'PRO 升级' : '套餐升级'
        const region = account.last_checkout_region
          || [account.last_checkout_country, account.last_checkout_currency].filter(Boolean).join('/')
        const hasDetails = upgradedAt
          || account.payment_card_last4
          || account.last_checkout_at
          || account.last_checkout_plan
          || account.last_checkout_status
          || region
        if (!hasDetails) return '—'
        return (
          <Space direction="vertical" size={1}>
            {upgradedAt && (
              <Typography.Text style={{ fontSize: 12 }}>
                {upgradedLabel}：{formatTime(upgradedAt)}
              </Typography.Text>
            )}
            <Space size={4} wrap>
              {account.payment_card_last4 && (
                <Tag style={{ margin: 0 }}>卡 ****{account.payment_card_last4}</Tag>
              )}
              {account.last_checkout_plan && (
                <Tag color="blue" style={{ margin: 0 }}>{account.last_checkout_plan}</Tag>
              )}
              {account.last_checkout_status && (() => {
                const status = String(account.last_checkout_status).toLowerCase()
                const refundedNeedsReview = (
                  accountType === 'refunded'
                  || account.account_type === 'refunded'
                ) && refundedUpgradeNeedsManualReview(status)
                const meta = refundedNeedsReview
                  ? { label: '等待人工确认', color: 'warning' }
                  : CHECKOUT_STATUS_META[status]
                return (
                  <Tag color={meta?.color || 'default'} style={{ margin: 0 }}>
                    {meta?.label || account.last_checkout_status}
                  </Tag>
                )
              })()}
              {region && <Tag style={{ margin: 0 }}>{region}</Tag>}
            </Space>
            {account.last_checkout_at && (
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                最近结账：{formatTime(account.last_checkout_at)}
              </Typography.Text>
            )}
          </Space>
        )
      },
    },
    ...(!businessMemberTab ? [noteColumn] : []),
    {
      title: '操作',
      key: 'actions',
      width: businessMotherView || (accountType === 'member' && ['pro', 'plus', 'go'].includes(memberPlan)) ? 280 : 500,
      fixed: businessMotherView && compactBusinessTable ? undefined : 'right' as const,
      onHeaderCell: businessMotherView ? () => ({ style: { background: token.colorBgContainer } }) : undefined,
      onCell: businessMotherView ? (account: GptPlanAccount) => ({ style: {
        background: focusTarget?.planAccountId === account.id ? token.colorPrimaryBg : token.colorBgContainer,
      } }) : undefined,
      render: (_: unknown, account: GptPlanAccount) => {
        const source = memberSourceOf(account, memberSourceOverrides[account.id])
        const sourcePool = String(source?.source_pool || account.source_pool || '').trim().toLowerCase()
        const isBusinessMother = sourcePool === 'gpt_business'
        const rowBusinessBinding = normalizeBusinessMemberDeviceBinding(
          source?.business_device_binding || {},
        )
        const microsoftMailbox = String(account.mail_provider || '').trim().toLowerCase() === 'outlook'
        const canLoginMicrosoftMailbox = microsoftMailbox && Boolean(account.has_password)
        const microsoftMailboxLoginTip = !microsoftMailbox
          ? '邮箱登录仅支持微软邮箱'
          : account.has_password
            ? '打开浏览器登录微软网页版邮箱'
            : '该账号缺少邮箱密码，无法登录微软邮箱'
        const canExportMemberMailCredential = microsoftMailbox && Boolean(account.has_password)
        const memberMailCredentialExportTip = !microsoftMailbox
          ? '仅 Outlook 邮箱支持导出邮箱密码'
          : account.has_password
            ? '复制为：Outlook 邮箱----Outlook 密码'
            : '该账号缺少 Outlook 邮箱密码'
        const mailActions = [
          <Tooltip key="ms-web-login" title={microsoftMailboxLoginTip}>
            <span>
              <Button
                size="small"
                icon={<LoginOutlined />}
                loading={msLoginingId === account.id}
                disabled={!canLoginMicrosoftMailbox || (msLoginingId !== null && msLoginingId !== account.id)}
                onClick={() => { void loginMicrosoftMailbox(account) }}
              >
                邮箱登录
              </Button>
            </span>
          </Tooltip>,
          ...(accountType !== 'regular' && (alertSummary[account.id] || 0) > 0 ? [
            <Tooltip key="mail-alerts" title={`查看 ${alertSummary[account.id]} 封封禁报警邮件`}>
              <Badge count={alertSummary[account.id]} size="small" offset={[-3, 3]}>
                <Button
                  type="text"
                  danger
                  size="small"
                  icon={<BellOutlined />}
                  aria-label={`查看 ${account.email} 的封禁报警`}
                  onClick={() => { void openMailAlerts(account) }}
                />
              </Badge>
            </Tooltip>,
          ] : []),
          ...(accountType !== 'regular' && (inboxSummary[account.id] || 0) > 0 ? [
            <Tooltip key="mail-inbox" title={`查看 ${inboxSummary[account.id]} 封未读邮件`}>
              <Badge count={inboxSummary[account.id]} size="small" offset={[-3, 3]}>
                <Button
                  type="text"
                  size="small"
                  icon={<MailOutlined />}
                  style={{ color: token.colorPrimary }}
                  aria-label={`查看 ${account.email} 的未读邮件`}
                  onClick={() => { void openMailInbox(account) }}
                />
              </Badge>
            </Tooltip>,
          ] : []),
          ...(accountType !== 'regular' ? [
            <Tooltip key="check-mail-now" title="立即检查邮件">
              <Button
                type="text"
                size="small"
                icon={<ThunderboltOutlined />}
                loading={checkingMailAccountId === account.id}
                disabled={checkingMailAccountId !== null && checkingMailAccountId !== account.id}
                aria-label={`立即检查 ${account.email} 的邮件`}
                onClick={() => { void checkMailNow(account) }}
              />
            </Tooltip>,
          ] : []),
          ...(isBusinessMother ? [
            <Tooltip
              key="business-device-binding"
              title={rowBusinessBinding.bound
                ? '查看、切换或解除母号设备绑定'
                : '为 BUSINESS 母号绑定 CPA / SUB 设备'}
            >
              <Button
                size="small"
                icon={<LinkOutlined />}
                onClick={() => openBusinessBindingEditor(account)}
              >
                {rowBusinessBinding.bound
                  ? `${businessMemberBindingLabel(rowBusinessBinding)} · 修改绑定`
                  : '绑定设备'}
              </Button>
            </Tooltip>,
          ] : []),
        ]
        // BUSINESS mothers use a compact presentation only. All callbacks and
        // availability rules remain the same as the original account controls.
        const compactMotherActions = businessMotherView && isBusinessMother
        const compactMemberActions = accountType === 'member'
          && ['pro', 'plus', 'go'].includes(memberPlan) && !isBusinessMother
        const motherMailTools: MenuProps['items'] = [
          {
            key: 'mother-mail-login',
            icon: msLoginingId === account.id ? <Spin size="small" /> : <LoginOutlined />,
            label: <Tooltip title={microsoftMailboxLoginTip}><span>邮箱登录</span></Tooltip>,
            disabled: !canLoginMicrosoftMailbox || msLoginingId !== null,
          },
          {
            key: 'mother-check-mail',
            icon: checkingMailAccountId === account.id ? <Spin size="small" /> : <ThunderboltOutlined />,
            label: '立即检查邮件',
            disabled: checkingMailAccountId !== null,
          },
        ]
        const motherBindingItem = {
          key: 'mother-binding', icon: <LinkOutlined />,
          label: <Tooltip title={rowBusinessBinding.bound ? businessMemberBindingLabel(rowBusinessBinding) : undefined}>
            <span>{rowBusinessBinding.bound ? '修改设备绑定' : '绑定设备'}</span>
          </Tooltip>,
        }
        const handleMotherUtility = (key: string) => {
          if (key === 'mother-mail-login') void loginMicrosoftMailbox(account)
          if (key === 'mother-check-mail') void checkMailNow(account)
          if (key === 'mother-binding') openBusinessBindingEditor(account)
        }
        if (account.dead || account.dangerous) {
          const appealActions = accountType === 'member'
            ? <GptPlanAppealActions account={account} onChange={() => { void loadAccounts(true) }} /> : null
          const motherAuditAction = !standalone && isBusinessMother ? (
            <Button size="small"
              onClick={event => { event.stopPropagation(); setAuditMotherId(account.id) }}>母号记录</Button>
          ) : null
          if (compactMotherActions || compactMemberActions) return (
            <div data-business-mother-actions={compactMotherActions ? 'true' : undefined}
              data-plan-member-actions={compactMemberActions ? 'true' : undefined} data-dead="true">
              <Space size={4} wrap>
                {appealActions}
                {motherAuditAction}
                <Dropdown trigger={['click']} placement="bottomRight" menu={{
                  items: [
                    { type: 'group', key: 'mail-tools', label: '邮箱操作', children: motherMailTools },
                    ...(!standalone && compactMotherActions ? [
                      { type: 'divider' as const },
                      { type: 'group' as const, key: 'device-tools', label: '设备管理', children: [motherBindingItem] },
                    ] : []),
                  ],
                  onClick: ({ key }) => handleMotherUtility(key),
                }}>
                  <Button size="small" aria-label={`更多${compactMotherActions ? '母号' : '账号'}操作 · ${account.email}`}>更多 <DownOutlined /></Button>
                </Dropdown>
              </Space>
            </div>
          )
          return <Space size={4} wrap>{appealActions}{motherAuditAction}{mailActions}</Space>
        }
        const securityStateAvailable = account.chatgpt_security != null
        const accountSecurity = account.chatgpt_security || {}
        const securityPasswordReady = accountSecurity.password_state === 'configured'
          && accountSecurity.has_password === true
        const securityMfaReady = accountSecurity.mfa_state === 'enabled'
          && accountSecurity.has_totp === true
        const securityCredentialsReadable = accountSecurity.credentials_readable !== false
        const savedSecurityPair = accountSecurity.has_password === true
          && accountSecurity.has_totp === true
          && securityCredentialsReadable
        const securityMfaState = String(accountSecurity.mfa_state || '').trim().toLowerCase()
        const securityMfaExpected = accountSecurity.has_totp === true
          || ['pending', 'enabled', 'unmanaged'].includes(securityMfaState)
        const securityLoginReady = ['configured', 'imported_unverified'].includes(accountSecurity.password_state || '')
          && accountSecurity.has_password === true
          && accountSecurity.has_totp === true
          && securityCredentialsReadable
        const savedPasswordLogin = standalone && canLoginWithSavedPassword(accountSecurity)
        const chatGptLoginDisabledReason = account.enabled === false
          ? '该账号已禁用，不能登录'
          : loginId !== null
            ? loginId === account.id
              ? '该账号正在登录'
              : '已有另一个账号正在登录'
            : !securityStateAvailable || securityMfaState === 'unknown'
              ? '账号安全状态读取失败，已停止登录，请刷新后重试'
            : securityMfaExpected && !securityCredentialsReadable
              ? '该账号的密码或 Authenticator 密钥无法解密，请先修复安全设置'
              : securityMfaExpected && !securityLoginReady
                ? '该账号已启用或正在启用 2FA，但本地缺少已确认的密码或 Authenticator 密钥'
                : !securityMfaExpected && !hasMailCredentials(account) && !savedPasswordLogin
                  ? '该账号未启用 2FA，且缺少可用邮箱凭据，无法获取登录验证码'
                  : ''
        const canCopyAccountSecurity = securityPasswordReady
          && securityMfaReady
          && securityCredentialsReadable
        const securitySetupDisabledReason = account.enabled === false
          ? '该账号已禁用，不能设置密码与 2FA'
          : securitySetupBusyId !== null
            ? securitySetupBusyId === account.id
              ? '该账号正在设置密码与 2FA'
              : '已有另一个密码与 2FA 设置任务正在执行'
            : ''
        const securityCopyDisabledReason = !securityCredentialsReadable
          ? '本地加密安全凭据无法读取'
          : !securityPasswordReady
            ? 'ChatGPT 密码尚未设置完成'
            : !securityMfaReady
              ? 'Authenticator 2FA 尚未开启或未确认'
              : securityExportingId !== null && securityExportingId !== account.id
                ? '正在复制另一个账号的安全凭据'
                : ''
        const upgrading = (upgradeStarting && upgradeAccount?.id === account.id)
          || upgradeTask?.accountId === account.id
        const refundedUpgradeAwaitingManual = (
          accountType === 'refunded'
          || account.account_type === 'refunded'
        ) && (
          refundedUpgradeNeedsManualReview(account.last_checkout_status)
          || refundedUpgradeReview?.accountId === account.id
        )
        const refundedUpgradeConfirming = refundedUpgradeConfirmBusyKey.startsWith(`${account.id}:`)
        const upgradeDisabledReason = (account.dead || account.dangerous)
          ? '该账号已标记为 Dead，不能发起升级'
          : account.enabled === false
            ? '该账号已禁用，不能发起升级'
            : refundedMigrationBusyKey
              ? '正在迁移已退款账号，请稍候'
            : ''
        const proUpgradeDisabledReason = upgradeDisabledReason
          || (refundedUpgradeAwaitingManual ? '请先人工确认上一次 PRO 升级结果' : '')
          || (upgradeBrowserConfigLoading ? '正在读取统一升级配置' : '')
          || (upgradeBrowserConfigSaving ? '正在保存统一升级配置' : '')
          || (upgradeStarting ? '正在启动 PRO 升级，请稍候' : '')
          || (upgradeTask
            ? (upgradeTask.accountId === account.id
              ? '该账号的 PRO 升级任务正在执行'
              : '已有一个 PRO 升级任务正在执行')
            : '')
        const businessInviteState = businessInviteButtonState(
          account,
          source,
          businessChildrenByAccount[account.id],
          replenishmentNow,
        )
        const listedCapabilities = isBusinessMother
          ? source?.capabilities || account.member_capabilities || account.capabilities
          : account.member_capabilities || account.capabilities || source?.capabilities
        const hasListedCapabilities = Boolean(
          listedCapabilities
          && typeof listedCapabilities === 'object'
          && Object.keys(listedCapabilities).length > 0,
        )
        const sourceMissing = Boolean(source?.source_missing ?? account.source_missing)
        // BUSINESS 母号暂时仍由原工作区门面提供成员/席位能力；其他会员账号
        // 完全按套餐管理本地记录和账号能力执行。
        const sourceUnavailableReason = isBusinessMother && sourceMissing
          ? String(source?.source_error || account.source_error || 'BUSINESS 母号工作区记录不可用')
          : ''
        const refunded = accountType === 'refunded'
          || account.account_type === 'refunded'
          || String(
            isBusinessMother
              ? source?.refund_status || account.refund_status || ''
              : account.refund_status || source?.refund_status || '',
          ) === 'refunded_pending_credit'
        const refundedReuseRisk = Boolean(
          refunded
          && (
            account.dead
            || account.dangerous
            || account.policy_warning
          )
        )
        const showRefundedReuseActions = Boolean(
          refunded
          && !refundedReuseRisk
        )
        const showUpgradeActions = !standalone && (accountType === 'regular' || showRefundedReuseActions)
        const exhaustedProQuota = accountType === 'member'
          && !refunded
          && isExhaustedProMember(account, source)
        const hasCodexRt = Boolean(
          isBusinessMother
            ? source?.has_codex_rt ?? account.has_codex_rt
            : account.has_codex_rt ?? source?.has_codex_rt,
        )
        const oauthCapability = memberCapabilityOf(account, source, 'oauth')
        const fileCapability = memberCapabilityOf(account, source, 'oauth_file')
        // BUSINESS 母号不直接同步凭证；设备页也不再管理母号或 BUSINESS 子号。
        // PRO / GO / PLUS 等非母号仍保持原来的 RT 下载能力。
        const showOAuthFileDownloads = hasCodexRt && fileCapability.supported === true
        const syncCapability = memberCapabilityOf(account, source, 'sync_device')
        const usageCapability = memberCapabilityOf(account, source, 'device_usage')
        const refundCapability = memberCapabilityOf(account, source, 'refund')
        const burnCapability = memberCapabilityOf(account, source, 'pro_refund_burn')
        const linkedDevices = linkedMemberDevices(source)
        const formats = new Set(
          (Array.isArray(fileCapability.formats) ? fileCapability.formats : ['cpa', 'sub2api'])
            .map((format) => String(format).trim().toLowerCase()),
        )
        const globallyBusy = Boolean(
          memberActionBusyKey
          || deviceSyncing
          || deviceUsageBusyKey
          || refundedMigrationBusyKey
          || businessBurnStarting
          || businessBurnTask?.status === 'running',
        )
        const capabilityReason = (capability: MemberCapability, fallback: string) => (
          sourceUnavailableReason || String(capability.reason || fallback)
        )
        const oauthDisabled = Boolean(
          sourceUnavailableReason
          || refunded
          || oauthCapability.supported !== true
          || globallyBusy
          || (isBusinessMother && hasCodexRt),
        )
        const oauthReason = refunded
          ? '已退款账号不再重新获取 RT；已有 RT 仍可下载凭证'
          : isBusinessMother && hasCodexRt
            ? 'BUSINESS 母号暂时不支持重新获取 RT'
          : globallyBusy
            ? '已有账号任务正在执行'
            : capabilityReason(oauthCapability, '该账号当前不支持获取 RT')
        const fileBaseDisabled = Boolean(
          sourceUnavailableReason || !hasCodexRt || fileCapability.supported !== true || globallyBusy,
        )
        const fileReason = !hasCodexRt
          ? '该账号尚无 RT，请先获取 RT'
          : globallyBusy
            ? '已有账号任务正在执行'
            : capabilityReason(fileCapability, '该账号当前不支持下载凭证')
        const syncDisabled = Boolean(
          sourceUnavailableReason
          || refunded
          || syncCapability.supported !== true
          || globallyBusy
          || isBusinessMother,
        )
        const syncReason = refunded
          ? '已退款账号不能再同步到设备'
          : isBusinessMother
            ? 'BUSINESS 母号不支持直接同步设备'
          : globallyBusy
            ? '已有账号任务正在执行'
            : capabilityReason(syncCapability, '该账号当前不支持设备同步')
        const usageDisabled = Boolean(
          sourceUnavailableReason || refunded || usageCapability.supported !== true || globallyBusy,
        )
        const usageReason = refunded
          ? '已退款账号不能主动查询设备额度'
          : globallyBusy
            ? '已有账号任务正在执行'
            : capabilityReason(usageCapability, '该账号当前不支持设备额度查询')
        const refundDisabled = Boolean(
          sourceUnavailableReason || refunded || refundCapability.supported !== true || globallyBusy,
        )
        const refundReason = refunded
          ? '该账号已退款，不能重复发起退款'
          : globallyBusy
            ? '已有账号任务正在执行'
            : capabilityReason(refundCapability, '该账号当前不支持退款')
        const burnDisabled = Boolean(
          sourceUnavailableReason
          || sourcePool !== 'gpt_business'
          || refunded
          || burnCapability.supported !== true
          || globallyBusy,
        )
        const burnReason = refunded
          ? '已退款 BUSINESS 母号不能发起 PRO 焚决'
          : globallyBusy
            ? '已有账号任务正在执行'
            : capabilityReason(burnCapability, '该 BUSINESS 母号当前不支持 PRO 焚决')
        const accountMenuLabel = (label: string, reason: string, disabled: boolean) => (
          <Tooltip title={disabled ? reason : undefined} placement="left">
            <span>{label}</span>
          </Tooltip>
        )
        const memberAccountMenu: MenuProps = {
          items: [
            {
              key: 'oauth',
              icon: <SafetyOutlined />,
              label: accountMenuLabel(hasCodexRt ? '重新获取 RT' : '获取 RT', oauthReason, oauthDisabled),
              disabled: oauthDisabled,
            },
            ...(showOAuthFileDownloads ? [
              ...(!isBusinessMother ? [
                {
                  key: 'download-cpa',
                  icon: <DownloadOutlined />,
                  label: accountMenuLabel('下载 CPA 凭证', fileReason, fileBaseDisabled || !formats.has('cpa')),
                  disabled: fileBaseDisabled || !formats.has('cpa'),
                },
                {
                  key: 'download-sub2api',
                  icon: <DownloadOutlined />,
                  label: accountMenuLabel('下载 SUB 凭证', fileReason, fileBaseDisabled || !formats.has('sub2api')),
                  disabled: fileBaseDisabled || !formats.has('sub2api'),
                },
              ] : []),
            ] : []),
            { type: 'divider' },
            {
              key: 'sync-device',
              icon: <CloudUploadOutlined />,
              label: accountMenuLabel('同步到 CPA / SUB', syncReason, syncDisabled),
              disabled: syncDisabled,
            },
            ...(linkedDevices.length ? linkedDevices.map((device) => ({
              key: `device-usage|${device.deviceRef}`,
              icon: <ReloadOutlined />,
              label: accountMenuLabel(
                `查询 ${device.provider === 'cpa' ? 'CPA' : 'SUB'} 额度 · ${device.name}`,
                usageReason,
                usageDisabled,
              ),
              disabled: usageDisabled,
            })) : [{
              key: 'device-usage-unlinked',
              icon: <ReloadOutlined />,
              label: accountMenuLabel('查询设备额度 · 尚未同步', '请先把账号同步到 CPA / SUB 设备', true),
              disabled: true,
            }]),
            ...(sourcePool === 'gpt_business' ? [{
              key: 'pro-refund-burn',
              danger: true,
              icon: <FireOutlined />,
              label: accountMenuLabel('焚决退款 PRO', burnReason, burnDisabled),
              disabled: burnDisabled,
            }] : []),
            {
              key: 'refund',
              danger: true,
              icon: <RollbackOutlined />,
              label: accountMenuLabel('申请退款', refundReason, refundDisabled),
              disabled: refundDisabled,
            },
          ],
          onClick: ({ key }) => {
            if (key === 'oauth') void startMemberTask(account, 'oauth')
            if (key === 'download-cpa') void downloadMemberOAuthFile(account, 'cpa')
            if (key === 'download-sub2api') void downloadMemberOAuthFile(account, 'sub2api')
            if (key === 'sync-device') void openMemberDeviceSync(account)
            if (key === 'pro-refund-burn') openBusinessBurn(account)
            if (key.startsWith('device-usage|')) {
              const deviceRef = key.slice('device-usage|'.length)
              const device = linkedDevices.find((item) => item.deviceRef === deviceRef)
              if (device) void fetchMemberDeviceUsage(account, device)
            }
            if (key === 'refund') {
              setRefundManual(false)
              setRefundAccount(account)
            }
          },
        }
        if (compactMotherActions || compactMemberActions) {
          const sourceActions = (memberAccountMenu.items || []).filter(item => !standalone || (item && 'key' in item && item.key === 'oauth'))
          const riskKeys = new Set(['refund', 'pro-refund-burn'])
          const riskActions = !refunded
            ? sourceActions.filter((item) => item && 'key' in item && riskKeys.has(String(item.key)))
            : []
          const credentialActions = !refunded
            ? sourceActions.filter((item) => item && item.type !== 'divider' && 'key' in item
              && !riskKeys.has(String(item.key)) && !(compactMemberActions && item.key === 'oauth'))
            : []
          const reuseActions: MenuProps['items'] = [
            ...(showUpgradeActions ? [
              { key: 'mother-upgrade-pro', label: '升级 PRO', icon: <RocketOutlined />,
                disabled: !!proUpgradeDisabledReason || upgrading },
              { key: 'mother-upgrade-pro-5x', label: '升级 PRO 5X', icon: <RocketOutlined />,
                disabled: !!proUpgradeDisabledReason || upgrading },
              { key: 'mother-upgrade-business', label: '获取 BUSINESS 支付链接', icon: <LinkOutlined />,
                disabled: !!upgradeDisabledReason || upgrading || businessDefaultCouponLoading || businessDefaultCouponSaving },
            ] : []),
            ...(showRefundedReuseActions ? [{ key: 'mother-migrate', label: '迁移账号', icon: <SyncOutlined />,
              disabled: Boolean(account.enabled === false || refundedMigrationBusyKey || upgrading
                || refundedUpgradeAwaitingManual || refundedUpgradeConfirming),
              children: (['pro', 'business', 'plus', 'go'] as RefundedMigrationTarget[]).map((target) => ({
                key: `mother-migrate-${target}`, label: `迁移至 ${REFUNDED_MIGRATION_META[target].label}`,
              })),
            }] : []),
            ...(refundedUpgradeAwaitingManual ? [
              { key: 'mother-upgrade-success', label: '确认升级成功', disabled: Boolean(refundedUpgradeConfirmBusyKey) },
              { key: 'mother-upgrade-failed', label: '确认未升级', disabled: Boolean(refundedUpgradeConfirmBusyKey) },
            ] : []),
          ]
          const moreItems: MenuProps['items'] = [
            { type: 'group', key: 'security-tools', label: '账号安全', children: [
              ...(!(standalone && savedSecurityPair) ? [{
                key: 'mother-security',
                icon: securitySetupBusyId === account.id ? <Spin size="small" /> : <SafetyOutlined />,
                label: accountMenuLabel('设置密码与 2FA', securitySetupDisabledReason, !!securitySetupDisabledReason),
                disabled: Boolean(securitySetupDisabledReason),
              }] : []),
              {
                key: 'mother-copy-security',
                icon: securityExportingId === account.id ? <Spin size="small" /> : <CopyOutlined />,
                label: accountMenuLabel('复制账号 / 密码 / 2FA', securityCopyDisabledReason, !canCopyAccountSecurity || securityExportingId !== null),
                disabled: !canCopyAccountSecurity || securityExportingId !== null,
              },
            ] },
            { type: 'divider' },
            { type: 'group', key: 'mail-tools', label: '邮箱操作', children: [
              ...motherMailTools,
              { key: 'mother-export-mail',
                icon: mailCredentialExportingId === account.id ? <Spin size="small" /> : <CopyOutlined />,
                label: accountMenuLabel('导出邮箱密码', memberMailCredentialExportTip, !canExportMemberMailCredential || mailCredentialExportingId !== null),
                disabled: !canExportMemberMailCredential || mailCredentialExportingId !== null },
            ] },
            ...(!standalone && compactMotherActions ? [
              { type: 'divider' as const },
              { type: 'group' as const, key: 'device-tools', label: '设备管理', children: [motherBindingItem] },
            ] : []),
            // Preserve less-used capability entries and their individual gates;
            // an unavailable source must not disable the other menu groups.
            ...(credentialActions.length ? [{ key: 'mother-credentials', label: '凭证与额度', children: credentialActions }] : []),
            ...(reuseActions.length ? [{ type: 'group' as const, key: 'reuse-tools', label: '升级与迁移', children: reuseActions }] : []),
            { type: 'divider' },
            { type: 'group', key: 'risk-tools', label: '风险操作', children: [
              ...riskActions,
              ...(compactMotherActions ? [{
                key: 'mother-batch-leave',
                label: '全部子号退出空间',
                danger: true,
                icon: <RollbackOutlined />,
                disabled: businessChildBatchTaskRunning,
              }] : []),
              { key: 'mother-delete', label: '删除账号', danger: true,
                icon: deletingId === account.id ? <Spin size="small" /> : <DeleteOutlined />,
                disabled: deletingId === account.id },
            ] },
          ]
          const moreBusy = (!hasListedCapabilities && memberCapabilityLoadingId === account.id)
            || securitySetupBusyId === account.id || securityExportingId === account.id
            || mailCredentialExportingId === account.id || msLoginingId === account.id
            || checkingMailAccountId === account.id || deletingId === account.id
            || upgrading || refundedUpgradeConfirming || refundedMigrationBusyKey.startsWith(`${account.id}:`)
            || memberActionBusyKey.startsWith(`${account.id}-`) || downloadBusyKey.startsWith(`${account.id}-`)
            || deviceUsageBusyKey.startsWith(`${account.id}-`)
            || (businessBurnAccount?.id === account.id && (businessBurnStarting || businessBurnTask?.status === 'running'))
          const buttonStyle = { height: 28, padding: '0 8px', fontSize: 12, borderRadius: 6 }
          return (
            <div data-business-mother-actions={compactMotherActions ? 'true' : undefined}
              data-plan-member-actions={compactMemberActions ? 'true' : undefined}
              style={{ display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap', flexWrap: 'wrap' }}>
              {compactMotherActions ? <Tooltip title={businessChildRtTask?.status === 'running'
                ? '已有邀请后的子号 RT 任务正在运行' : businessInviteState.reason || '邀请子号'}>
                <span>
                  <Button size="small" type="primary" icon={<UsergroupAddOutlined />} style={buttonStyle}
                    disabled={businessInviteState.disabled || businessInviting || businessChildRtTask?.status === 'running'}
                    onClick={() => openBusinessInvite(account)}>
                    邀请子号
                  </Button>
                </span>
              </Tooltip> : <Tooltip title={oauthDisabled ? oauthReason : hasCodexRt ? '重新获取该账号的 RT' : '获取该账号的 RT'}>
                <span>
                  <Button size="small" type="primary" icon={<SafetyOutlined />} style={buttonStyle}
                    loading={memberActionBusyKey === `${account.id}-oauth`}
                    disabled={oauthDisabled} onClick={() => { void startMemberTask(account, 'oauth') }}>
                    {hasCodexRt ? '重新获取 RT' : '获取 RT'}
                  </Button>
                </span>
              </Tooltip>}
              <Tooltip title={chatGptLoginDisabledReason || (savedPasswordLogin ? '使用已保存的 GPT 密码登录并核验账号' : securityMfaExpected
                ? '使用 ChatGPT 密码 + Authenticator 2FA 登录并识别真实套餐'
                : '使用邮箱验证码登录并识别真实套餐')}>
                <span>
                  <Button size="small" icon={<LoginOutlined />} style={buttonStyle}
                    loading={loginId === account.id} disabled={Boolean(chatGptLoginDisabledReason)}
                    onClick={() => { void loginAccount(account) }}>{standalone && accountSecurity.password_state === 'imported_unverified' ? '登录核验' : '登录'}</Button>
                </span>
              </Tooltip>
              <Dropdown trigger={['click']} placement="bottomRight"
                onOpenChange={(open) => {
                  if (open && !refunded && !sourceUnavailableReason && !hasListedCapabilities) {
                    void refreshMemberCapabilities(account, true)
                  }
                }}
                menu={{ items: moreItems, style: { width: 248, maxHeight: 'calc(100vh - 80px)', overflowY: 'auto' },
                  onClick: (info) => {
                    const { key } = info
                    handleMotherUtility(key)
                    if (key === 'mother-security') void setupAccountSecurity(account, securityBrowserMode)
                    if (key === 'mother-copy-security') void copyAccountSecurity(account)
                    if (key === 'mother-export-mail') void copyMemberMailCredential(account)
                    if (key === 'mother-upgrade-pro') void startUpgradePro(account)
                    if (key === 'mother-upgrade-pro-20x') void startUpgradePro(account, 'pro_20x')
                    if (key === 'mother-upgrade-pro-5x') void startUpgradePro(account, 'pro_5x')
                    if (key === 'mother-upgrade-business') openBusinessCheckout(account)
                    if (key.startsWith('mother-migrate-')) confirmRefundedMigration(account, key.slice('mother-migrate-'.length) as RefundedMigrationTarget)
                    if (key === 'mother-upgrade-success' || key === 'mother-upgrade-failed') {
                      const success = key === 'mother-upgrade-success'
                      modal.confirm({
                        title: success ? '确认该账号已成功升级 PRO？' : '确认该账号未升级？',
                        content: success ? '确认后才会将账号迁入 PRO，并更新升级时间。' : '本次只记录人工结论，不会标记为 PRO 失败。',
                        okText: success ? '确认成功' : '确认未升级', cancelText: '取消',
                        onOk: () => confirmRefundedUpgrade(account, success),
                      })
                    }
                    if (key === 'mother-batch-leave') {
                      modal.confirm({
                        title: `确认退出 ${account.email} 的全部子号？`,
                        content: '后端会重新读取该母号当前已加入空间的成员，逐个退出并持续自动核对。待接受邀请不会包含在本任务中。',
                        okText: '确认全部退出',
                        cancelText: '取消',
                        okButtonProps: { danger: true },
                        onOk: () => startBusinessMotherBatchLeave(account),
                      })
                    }
                    if (key === 'mother-delete') modal.confirm({
                      title: `删除 ${account.email}？`,
                      content: '只删除套餐管理中的账号记录，此操作不可恢复。',
                      okText: '删除', cancelText: '取消', okButtonProps: { danger: true },
                      onOk: () => deleteAccount(account),
                    })
                    memberAccountMenu.onClick?.(info)
                  },
                }}>
                <Button size="small" style={buttonStyle} aria-label={`更多${compactMotherActions ? '母号' : '账号'}操作 · ${account.email}`}>
                  {moreBusy ? <Spin size="small" /> : null} 更多 <DownOutlined />
                </Button>
              </Dropdown>
              {compactMemberActions && exhaustedProQuota && <Tooltip title="设备记录额度已耗尽，可申请退款。">
                <Tag color="error" style={{ margin: 0 }}>额度 0% · 可退款</Tag>
              </Tooltip>}
            </div>
          )
        }
        return (
        <Space size={4} wrap>
          {exhaustedProQuota && (
            <Tooltip title="设备最后一次持久化额度为 limit_reached=true；远端账号已清理，可进入退款流程。">
              <Tag color="error" style={{ margin: 0 }}>额度 0% · 可退款</Tag>
            </Tooltip>
          )}
          <Tooltip title={chatGptLoginDisabledReason || (
            savedPasswordLogin ? '使用已保存的 GPT 密码登录并核验账号' : securityMfaExpected
              ? '使用 ChatGPT 密码 + Authenticator 2FA 登录并识别真实套餐'
              : '使用邮箱验证码登录并识别真实套餐'
          )}>
            <span>
              <Button
                size="small"
                icon={<LoginOutlined />}
                loading={loginId === account.id}
                disabled={Boolean(chatGptLoginDisabledReason)}
                onClick={() => { void loginAccount(account) }}
              >
                {standalone && accountSecurity.password_state === 'imported_unverified' ? '登录核验' : '登录'}
              </Button>
            </span>
          </Tooltip>
          {!(standalone && savedSecurityPair) && <Tooltip title={securitySetupDisabledReason
            || `设置或重新设置 ChatGPT 密码与 Authenticator 2FA（使用页面顶部统一配置的${securityBrowserMode === 'headed' ? '有头' : '无头'}模式）`}>
            <span>
              <Button
                size="small"
                icon={<SafetyOutlined />}
                loading={securitySetupBusyId === account.id}
                disabled={Boolean(securitySetupDisabledReason)}
                onClick={() => { void setupAccountSecurity(account, securityBrowserMode) }}
              >
                设置密码与 2FA
              </Button>
            </span>
          </Tooltip>}
          <Tooltip title={securityCopyDisabledReason || '复制格式：账号--密码--2FA'}>
            <span>
              <Button
                size="small"
                icon={<CopyOutlined />}
                loading={securityExportingId === account.id}
                disabled={!canCopyAccountSecurity
                  || (securityExportingId !== null && securityExportingId !== account.id)}
                onClick={() => { void copyAccountSecurity(account) }}
              >
                复制账号--密码--2FA
              </Button>
            </span>
          </Tooltip>
          {accountType === 'member' && (
            <Tooltip title={memberMailCredentialExportTip}>
              <span>
                <Button
                  size="small"
                  icon={<CopyOutlined />}
                  loading={mailCredentialExportingId === account.id}
                  disabled={!canExportMemberMailCredential
                    || (mailCredentialExportingId !== null && mailCredentialExportingId !== account.id)}
                  onClick={() => { void copyMemberMailCredential(account) }}
                >
                  导出
                </Button>
              </span>
            </Tooltip>
          )}
          {refundedUpgradeAwaitingManual && (
            <Space size={4} wrap>
              <Tag color="warning" style={{ margin: 0 }}>等待人工确认</Tag>
              <Popconfirm
                title="确认该账号已成功升级 PRO？"
                description="确认后才会将账号迁入 PRO，并更新升级时间。"
                okText="确认成功"
                cancelText="取消"
                onConfirm={() => confirmRefundedUpgrade(account, true)}
              >
                <Button
                  size="small"
                  type="primary"
                  loading={refundedUpgradeConfirmBusyKey === `${account.id}:success`}
                  disabled={Boolean(refundedUpgradeConfirmBusyKey)}
                >
                  确认升级成功
                </Button>
              </Popconfirm>
              <Popconfirm
                title="确认该账号未升级？"
                description="本次只记录人工结论，不会标记为 PRO 失败。"
                okText="确认未升级"
                cancelText="取消"
                onConfirm={() => confirmRefundedUpgrade(account, false)}
              >
                <Button
                  size="small"
                  loading={refundedUpgradeConfirmBusyKey === `${account.id}:not-upgraded`}
                  disabled={Boolean(refundedUpgradeConfirmBusyKey)}
                >
                  确认未升级
                </Button>
              </Popconfirm>
            </Space>
          )}
          {showUpgradeActions && (
            <Tooltip title={upgradeDisabledReason || undefined}>
              <span>
                <Dropdown
                  disabled={!!upgradeDisabledReason}
                  trigger={['click']}
                  menu={{
                    items: [
                      {
                        key: 'pro',
                        icon: <RocketOutlined />,
                        label: '升级 PRO',
                        disabled: !!proUpgradeDisabledReason,
                      },
                      {
                        key: 'pro_5x',
                        icon: <RocketOutlined />,
                        label: '升级 PRO 5X',
                        disabled: !!proUpgradeDisabledReason,
                      },
                      {
                        key: 'business',
                        icon: <LinkOutlined />,
                        label: '获取 BUSINESS 支付链接',
                        disabled: !!upgradeDisabledReason || businessDefaultCouponLoading || businessDefaultCouponSaving,
                      },
                    ],
                    onClick: ({ key }) => {
                      if (key === 'pro' || key === 'pro_20x') void startUpgradePro(account, 'pro_20x')
                      if (key === 'pro_5x') void startUpgradePro(account, 'pro_5x')
                      if (key === 'business') openBusinessCheckout(account)
                    },
                  }}
                >
                  <Button size="small" type="primary" loading={upgrading} disabled={!!upgradeDisabledReason}>
                    升级 <DownOutlined />
                  </Button>
                </Dropdown>
              </span>
            </Tooltip>
          )}
          {showRefundedReuseActions && (
            <Dropdown
              trigger={['click']}
              disabled={Boolean(
                account.enabled === false
                || refundedMigrationBusyKey
                || upgrading
                || refundedUpgradeAwaitingManual
                || refundedUpgradeConfirming
              )}
              menu={{
                items: (['pro', 'business', 'plus', 'go'] as RefundedMigrationTarget[]).map((target) => ({
                  key: target,
                  icon: <SyncOutlined />,
                  label: `迁移至 ${REFUNDED_MIGRATION_META[target].label}`,
                })),
                onClick: ({ key }) => {
                  confirmRefundedMigration(account, key as RefundedMigrationTarget)
                },
              }}
            >
              <Button
                size="small"
                icon={<SyncOutlined />}
                loading={refundedMigrationBusyKey.startsWith(`${account.id}:`)}
                disabled={Boolean(
                  account.enabled === false
                  || refundedMigrationBusyKey
                  || upgrading
                  || refundedUpgradeAwaitingManual
                  || refundedUpgradeConfirming
                )}
              >
                迁移 <DownOutlined />
              </Button>
            </Dropdown>
          )}
          {accountType !== 'regular' && (
            sourcePool === 'gpt_business' && (
              <Tooltip title={businessChildRtTask?.status === 'running'
                ? '已有邀请后的子号 RT 任务正在运行'
                : businessInviteState.reason}>
                <span>
                  <Button
                    size="small"
                    type="primary"
                    icon={<UsergroupAddOutlined />}
                    disabled={businessInviteState.disabled || businessInviting || businessChildRtTask?.status === 'running'}
                    onClick={() => openBusinessInvite(account)}
                  >
                    邀请子号
                  </Button>
                </span>
              </Tooltip>
            )
          )}
          {!standalone && accountType !== 'regular' && !refunded && (
            <Tooltip title={sourceUnavailableReason || (isBusinessMother ? 'BUSINESS 母号操作' : '按当前账号能力执行')}>
              <span>
                <Dropdown
                  trigger={['click']}
                  disabled={Boolean(sourceUnavailableReason)}
                  onOpenChange={(open) => {
                    // 新接口已在列表中批量注入实时能力；仅兼容旧响应缺字段时懒加载，
                    // 正常打开菜单不再额外请求或显示转圈。
                    if (open && !sourceUnavailableReason && !hasListedCapabilities) {
                      void refreshMemberCapabilities(account, true)
                    }
                  }}
                  menu={memberAccountMenu}
                >
                  <Button
                    size="small"
                    loading={(!hasListedCapabilities && memberCapabilityLoadingId === account.id)
                      || memberActionBusyKey.startsWith(`${account.id}-`)
                      || downloadBusyKey.startsWith(`${account.id}-`)
                      || deviceUsageBusyKey.startsWith(`${account.id}-`)
                      || (businessBurnAccount?.id === account.id
                        && (businessBurnStarting || businessBurnTask?.status === 'running'))}
                    disabled={Boolean(sourceUnavailableReason)}
                  >
                    账号操作 <DownOutlined />
                  </Button>
                </Dropdown>
              </span>
            </Tooltip>
          )}
          {mailActions}
          <Popconfirm
            title={`删除 ${account.email}？`}
            description="只删除套餐管理中的账号记录，此操作不可恢复。"
            okText="删除"
            okButtonProps={{ danger: true }}
            onConfirm={() => deleteAccount(account)}
          >
            <Button type="text" danger size="small" icon={<DeleteOutlined />} loading={deletingId === account.id} />
          </Popconfirm>
        </Space>
        )
      },
    },
  ]

  const businessChildCatalogColumns: NonNullable<TableProps<BusinessChildCatalogRow>['columns']> = [
    {
      title: '子号名称 / 邮箱',
      key: 'child',
      width: 290,
      render: (_: unknown, row: BusinessChildCatalogRow) => (
        <Space direction="vertical" size={2}>
          {row.child_name
            && row.child_name.trim().toLowerCase()
              !== String(row.child_email || row.email || '').trim().toLowerCase() && (
            <Typography.Text strong>{row.child_name}</Typography.Text>
          )}
          <Space size={5} wrap>
            <Typography.Text style={{ fontFamily: 'monospace' }}>
              {row.child_email || row.email || '(无邮箱)'}
            </Typography.Text>
            {(row.child_email || row.email) && (
              <Tooltip title="复制子号邮箱">
                <CopyOutlined
                  style={{ cursor: 'pointer', color: token.colorTextTertiary }}
                  onClick={() => {
                    void navigator.clipboard.writeText(String(row.child_email || row.email || ''))
                    message.success('子号邮箱已复制')
                  }}
                />
              </Tooltip>
            )}
          </Space>
          <Space size={4} wrap>
            <Tag color={row._managed ? 'purple' : 'default'} style={{ margin: 0 }}>
              {row._managed ? '账号池子号' : '手动邮箱'}
            </Tag>
            <Tag
              color={businessChildSeatType(row) === 'prolite' ? 'magenta' : businessChildSeatType(row) === 'default' ? 'blue' : 'default'}
              style={{ margin: 0 }}
            >
              {businessSeatTypeLabel(businessChildSeatType(row))}
            </Tag>
            <Tag color={row._kind === 'member' ? 'success' : row._kind === 'invite' ? 'orange' : 'default'} style={{ margin: 0 }}>
              {row._kind === 'member' ? '已加入' : row._kind === 'invite' ? '待接受' : '待同步'}
            </Tag>
            <BusinessDeadStamp dead={row.dangerous} detectedAt={row.dangerous_detected_at} />
            {row.policy_warning && <Tag color="warning" style={{ margin: 0 }}>政策告警</Tag>}
          </Space>
        </Space>
      ),
    },
    {
      title: '所属母号',
      key: 'parent',
      width: 280,
      render: (_: unknown, row: BusinessChildCatalogRow) => (
        <Space direction="vertical" size={2}>
          <Button
            type="link"
            size="small"
            icon={<TeamOutlined />}
            data-business-child-parent-link="true"
            style={{ height: 22, padding: 0, fontFamily: 'monospace', justifyContent: 'flex-start' }}
            onClick={() => openBusinessMotherFromCatalog(row)}
          >
            {row.parent_email || `母号 #${row.parent_account_id}`}
          </Button>
          {row.parent_note && (
            <Typography.Text type="secondary" ellipsis={{ tooltip: row.parent_note }} style={{ maxWidth: 250, fontSize: 12 }}>
              备注：{row.parent_note}
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: '2FA',
      key: 'mfa',
      width: 135,
      render: (_: unknown, row: BusinessChildCatalogRow) => {
        if (!row._managed) return <Tag>不支持</Tag>
        const state = String(row.chatgpt_security?.mfa_state || 'unknown').trim().toLowerCase()
        const meta = state === 'enabled'
          ? { color: 'success', label: '已开启' }
          : state === 'pending'
            ? { color: 'processing', label: '确认中' }
            : state === 'failed'
              ? { color: 'error', label: '设置失败' }
              : state === 'unmanaged'
                ? { color: 'warning', label: '需处理 · 远端已开启' }
                : ['not_configured', 'disabled', 'off', 'none'].includes(state)
                  ? { color: 'default', label: '未开启' }
                  : { color: 'default', label: '未知' }
        return <Tag color={meta.color}>{meta.label}</Tag>
      },
    },
    {
      title: 'RT',
      key: 'rt',
      width: 255,
      render: (_: unknown, row: BusinessChildCatalogRow) => {
        if (!row._managed || !positiveInteger(row.pro_account_id ?? row.child_id)) {
          return <Tag>不支持 RT</Tag>
        }
        const parent = {
          id: row.parent_account_id,
          email: row.parent_email,
          source_pool: 'gpt_business',
        } as GptPlanAccount
        const childId = positiveInteger(row.pro_account_id ?? row.child_id)
        const healthReason = row.enabled === false || row.deactivated || row.dangerous
          ? '子号已停用或标记为 Dead，不能导出或同步凭证'
          : row.policy_warning
            ? '子号存在政策告警，不能导出或同步凭证'
            : String(row.refund_status || '').trim()
              ? '子号已进入退款流程，不能导出或同步凭证'
              : ''
        const actionCapability = (name: 'oauth_file' | 'sync_device') => {
          const value = row.actions?.[name]
          if (typeof value === 'boolean') return { supported: value, reason: '' }
          const capability = asRecord(value)
          return {
            supported: capability.supported === true,
            reason: String(capability.reason || ''),
          }
        }
        const downloadCapability = actionCapability('oauth_file')
        const syncCapability = actionCapability('sync_device')
        const hasListedActions = Boolean(row.actions && Object.keys(row.actions).length)
        const canDownloadCredential = Boolean(
          row.has_codex_rt && childId && !healthReason
          && (!hasListedActions || downloadCapability.supported),
        )
        const canSyncCredential = Boolean(
          row.has_codex_rt && childId && !healthReason
          && (!hasListedActions || syncCapability.supported),
        )
        return (
          <Space direction="vertical" size={3}>
            <Tag color={row.has_codex_rt ? 'success' : 'default'} style={{ margin: 0 }}>
              {row.has_codex_rt ? 'RT 已获取' : 'RT 未获取'}
            </Tag>
            {row.codex_rt_acquired_at && (
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                {formatTime(row.codex_rt_acquired_at)}
              </Typography.Text>
            )}
            {row.has_codex_rt && (
              <Space.Compact size="small">
                <Tooltip title={canDownloadCredential ? '下载 OAuth 凭证' : healthReason || downloadCapability.reason}>
                  <Button
                    size="small"
                    icon={<DownloadOutlined />}
                    loading={downloadBusyKey === `business-child-${parent.id}-${childId}-cpa`}
                    disabled={!canDownloadCredential}
                    onClick={() => { void downloadBusinessChildOAuthFile(parent, row, 'cpa') }}
                  >
                    {standalone ? 'OAuth' : 'CPA'}
                  </Button>
                </Tooltip>
                <Tooltip title={canDownloadCredential ? '下载 SUB 凭证' : healthReason || downloadCapability.reason}>
                  <Button
                    size="small"
                    icon={<DownloadOutlined />}
                    loading={downloadBusyKey === `business-child-${parent.id}-${childId}-sub2api`}
                    disabled={!canDownloadCredential}
                    onClick={() => { void downloadBusinessChildOAuthFile(parent, row, 'sub2api') }}
                  >
                    SUB
                  </Button>
                </Tooltip>
                {!standalone && <Tooltip title={canSyncCredential ? '同步到 CPA / SUB 设备' : healthReason || syncCapability.reason}>
                  <Button
                    size="small"
                    icon={<CloudUploadOutlined />}
                    disabled={!canSyncCredential || deviceSyncing}
                    onClick={() => { void openBusinessChildDeviceSync(parent, row) }}
                  >
                    同步
                  </Button>
                </Tooltip>}
              </Space.Compact>
            )}
          </Space>
        )
      },
    },
    {
      title: '邀请时间',
      dataIndex: 'invited_at',
      key: 'invited_at',
      width: 175,
      render: (value: string | undefined) => formatTime(value),
    },
    {
      title: '上架时间',
      dataIndex: 'nv_listed_at',
      key: 'nv_listed_at',
      width: 175,
      render: (_: unknown, row: BusinessChildCatalogRow) => {
        const listingTime = businessChildNvListingTime(row)
        const missing = listingTime === '未记录' || listingTime === '未上架'
        return (
          <Tooltip title={missing
            ? '未记录已确认的 NV 上架时间'
            : `NV 上架请求时间；确认时间：${formatTime(row.nv_listing_confirmed_at)}`}>
            <Typography.Text type={missing ? 'secondary' : undefined}>
              {listingTime}
            </Typography.Text>
          </Tooltip>
        )
      },
    },
    {
      title: '出售状态',
      dataIndex: 'sale_status',
      key: 'sale_status',
      width: 145,
      render: (value: BusinessChildSaleStatus | undefined, row: BusinessChildCatalogRow) => {
        const refunded = value === 'refunded' || value === 'partial_refund'
        const sold = value === 'sold'
        const listed = value === 'listed'
        const deletionReady = row.deletion_ready === true
          || row.can_delete === true
          || (sold && String(row.warranty_status || '').trim().toLowerCase() === 'expired')
        return (
          <Space size={4} wrap>
            <Tag
              color={refunded ? 'warning' : deletionReady ? 'error' : sold ? 'success' : listed ? 'processing' : 'default'}
              style={{ margin: 0 }}
            >
              {refunded ? value === 'partial_refund' ? 'NV 部分退款，待处理' : 'NV 已退款' : deletionReady ? '可删除' : sold ? '已出售' : listed ? '已上架' : '未上架'}
            </Tag>
            <Tooltip title={refunded ? 'NV 已确认退款，不可通过出售状态编辑覆盖' : '编辑出售状态、时间与质保'}>
              <Button
                type="text"
                size="small"
                icon={<EditOutlined />}
                disabled={refunded}
                aria-label={`编辑 ${row.child_email || row.email || '子号'} 的出售状态与质保`}
                onClick={() => openBusinessChildSaleEditor(row)}
              />
            </Tooltip>
          </Space>
        )
      },
    },
    {
      title: '出售时间',
      dataIndex: 'sold_at',
      key: 'sold_at',
      width: 175,
      render: (value: string | null | undefined) => (
        <Typography.Text type={value ? undefined : 'secondary'}>
          {value ? formatTime(value) : '—'}
        </Typography.Text>
      ),
    },
    {
      title: '质保时间',
      key: 'warranty',
      width: 190,
      render: (_: unknown, row: BusinessChildCatalogRow) => {
        if (row.sale_status === 'refunded') return <Typography.Text type="secondary">NV 已退款，不再等待质保</Typography.Text>
        const hours = Math.max(0, Math.floor(Number(row.warranty_hours || 0)))
        const status = String(row.warranty_status || '').trim().toLowerCase()
        const historical5x = businessChildSeatType(row) === 'prolite' && !row.nv_team5x_warranty_until && hours > 0
          && Number.isFinite(Date.parse(row.nv_listed_at || row.sold_at || ''))
        if (!historical5x && (businessChildSeatType(row) === 'prolite' || row.nv_team5x_warranty_until)) {
          return <Space direction="vertical" size={2}>
            <Typography.Text>5X 固定截止</Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              {row.nv_team5x_warranty_until ? `截止：${formatTime(row.nv_team5x_warranty_until)}` : '截止时间待同步'}
            </Typography.Text>
          </Space>
        }
        const meta = !row.sold_at
          ? { color: 'default', label: '未开始' }
          : hours <= 0
            ? { color: 'default', label: '未设置质保' }
            : status === 'expired'
              ? { color: 'error', label: '已过保' }
              : { color: 'success', label: '质保中' }
        return (
          <Space direction="vertical" size={2}>
            <Space size={4} wrap>
              <Typography.Text>{historical5x ? `历史质保 ${hours} 小时` : `${hours} 小时`}</Typography.Text>
              <Tag color={meta.color} style={{ margin: 0 }}>{meta.label}</Tag>
            </Space>
            {row.warranty_expires_at && (
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                到期：{formatTime(row.warranty_expires_at)}
              </Typography.Text>
            )}
          </Space>
        )
      },
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      fixed: 'right',
      render: (_: unknown, row: BusinessChildCatalogRow) => {
        const parent = {
          id: row.parent_account_id,
          email: row.parent_email,
          source_pool: 'gpt_business',
        } as GptPlanAccount
        return (
          <Space size={6} wrap>
            {renderBusinessChildNvListingButton(parent, row)}
            {renderBusinessChildActions(parent, row, true)}
          </Space>
        )
      },
    },
  ]

  const taskPercent = importTask?.total
    ? Math.min(100, Math.round((Number(importTask.processed || 0) / importTask.total) * 100))
    : 0

  const businessInviteView = businessInviteAccount
    ? businessChildrenByAccount[businessInviteAccount.id]
    : undefined
  const businessInviteSource = businessInviteAccount
    ? memberSourceOf(businessInviteAccount, memberSourceOverrides[businessInviteAccount.id])
    : null
  const activeBusinessInviteState = businessInviteAccount
    ? businessInviteButtonState(
      businessInviteAccount,
      businessInviteSource,
      businessInviteView,
      replenishmentNow,
    )
    : { disabled: true, reason: '', full: false }
  const businessInviteSeat = businessInviteView?.snapshot?.seat_summary
    || businessSeatSummaryOf(businessInviteSource)
  const businessInviteTargetSeatType = businessInviteTargetSeat(businessInviteSeat)
  const businessInviteOrdinaryAvailable = businessSeatAvailable(
    businessInviteSeat,
    businessSeatCapacity(businessInviteSeat, 'default'),
  ) || 0
  const businessInviteAdvancedAvailable = businessSeatAvailable(
    businessInviteSeat,
    businessSeatCapacity(businessInviteSeat, 'prolite'),
  ) || 0
  const businessInviteSelectedTypeAvailable = businessInviteSeatType === 'prolite'
    ? businessInviteAdvancedAvailable
    : businessInviteOrdinaryAvailable
  const businessInviteAccountId = businessInviteAccount?.id
  useEffect(() => {
    setBusinessInviteSelectedChildId(undefined)
    setBusinessInviteCandidates([])
    setBusinessInviteCandidatesLoading(false)
    if (standalone || !businessInviteAccountId || (businessInviteMailProvider === 'auto' && !seatMailDefaults)) return
    void loadBusinessChildCandidates(businessInviteAccountId, businessInviteMailProvider, businessInviteTargetSeatType)
    return () => { businessInviteCandidateGeneration.current += 1 }
  }, [businessInviteAccountId, businessInviteMailProvider, businessInviteTargetSeatType, loadBusinessChildCandidates, seatMailDefaults, seatMailRevision])
  const businessInviteQuota = businessInviteAccount
    ? businessInviteQuotaOf(
        businessInviteAccount,
        businessInviteSource,
        businessWorkspaceOf(businessInviteSource),
        businessInviteView?.snapshot,
        replenishmentNow,
      )
    : null
  const businessInviteCooldown = businessInviteAccount
    ? businessInviteCooldownOf(
      businessInviteAccount,
      businessInviteSource,
      businessWorkspaceOf(businessInviteSource),
      businessInviteView?.snapshot,
      replenishmentNow,
    )
    : { active: false, startedAt: '', until: '', reason: '' }
  const businessInviteManualEmailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    businessInviteManualEmail.trim(),
  )
  const filteredBusinessInviteCandidates = businessInviteCandidates.filter((candidate) => (
    businessInviteCandidateMatchesProvider(candidate, businessInviteMailProvider, businessInviteTargetSeatType, seatMailDefaults)
  ))
  const selectedBusinessInviteCandidate = businessInviteSelectedChildId
    ? filteredBusinessInviteCandidates.find((candidate) => (
      Number(candidate.pro_account_id) === businessInviteSelectedChildId
    ))
    : undefined
  const businessInviteSubmitDisabled = Boolean(
    !businessInviteAccount
    || businessInviteView?.loading
    || activeBusinessInviteState.disabled
    || (standalone
      ? businessInviteCount < 1 || businessInviteCount > businessInviteSelectedTypeAvailable
      : businessInviteMode === 'pool'
      ? businessInviteCandidatesLoading
        || filteredBusinessInviteCandidates.length === 0
        || (businessInviteSelectedChildId !== undefined && !selectedBusinessInviteCandidate)
      : !businessInviteManualEmailValid),
  )
  const businessMembersAccount = businessMembersAccountId === null
    ? null
    : accounts.find((account) => account.id === businessMembersAccountId) || null
  const businessMembersSource = businessMembersAccount
    ? memberSourceOf(businessMembersAccount, memberSourceOverrides[businessMembersAccount.id])
    : null
  const businessMembersView = businessMembersAccount
    ? businessChildrenByAccount[businessMembersAccount.id]
    : undefined
  const businessMembersInviteState = businessMembersAccount
    ? businessInviteButtonState(
        businessMembersAccount,
        businessMembersSource,
        businessMembersView,
        replenishmentNow,
      )
    : { disabled: true, reason: '', full: false }
  const renderBusinessDrawerActions = (stacked: boolean) => {
    if (!businessMembersAccount) return null
    return (
      <Space direction={stacked ? 'vertical' : 'horizontal'} wrap={!stacked} style={stacked ? { width: 220 } : undefined}>
        <Tooltip title={businessMembersInviteState.reason || '为当前 BUSINESS 母号邀请子号'}>
          <span style={stacked ? { display: 'block', width: '100%' } : undefined}>
            <Button
              block={stacked}
              type="primary"
              icon={<UsergroupAddOutlined />}
              disabled={businessMembersInviteState.disabled || businessInviting || businessChildRtTask?.status === 'running'}
              onClick={() => openBusinessInvite(businessMembersAccount)}
            >
              邀请子号
            </Button>
          </span>
        </Tooltip>
        <Button
          block={stacked}
          icon={<ReloadOutlined />}
          loading={businessWorkspaceRefreshingIds.includes(businessMembersAccount.id)}
          disabled={businessWorkspacePageRefreshing || Boolean(businessMembersSource?.source_missing)}
          onClick={() => { void refreshBusinessWorkspace(businessMembersAccount) }}
        >
          刷新成员/席位
        </Button>
      </Space>
    )
  }
  return (
    <div>
      {!standalone && <BusinessMotherAudit motherId={auditMotherId} onClose={() => setAuditMotherId(null)} />}
      <PageHeader
        title={businessOnly ? "BUSINESS 母号" : standalone ? "账号详情" : "GPT 套餐管理"}
        subtitle={businessOnly ? "管理工作区、普通与高级席位，以及母号下的全部受管子号" : "登录识别套餐，管理账号安全与邮件"}
        icon={<CrownOutlined />}
        extra={(
          <Space wrap>
            {!standalone && <Link to="/gmail"><Button>Gmail 母号 / 子号</Button></Link>}
            {!standalone && <Link to="/register?platform=chatgpt&mail_provider=gmail"><Button>注册 Gmail 子号</Button></Link>}
            {!standalone && <Button
              size="small"
              icon={<EditOutlined />}
              data-business-default-coupon-trigger="true"
              disabled={businessDefaultCouponLoading || businessDefaultCouponSaving}
              onClick={openBusinessDefaultCouponSettings}
            >
              BUSINESS 默认优惠码
            </Button>}
            <Tooltip title="统一用于普通账号、会员账号、已退款账号、BUSINESS 母号和子号的“设置密码与 2FA”；也用于批量邀请后的自动 2FA 和准备号池。任务启动时会固定当前模式，不影响已经运行的任务。">
              <Space size={4} wrap data-security-browser-mode="true">
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  2FA 浏览器：
                </Typography.Text>
                <Segmented
                  size="small"
                  value={securityBrowserMode}
                  options={[
                    { value: 'headless', label: '无头' },
                    { value: 'headed', label: '有头' },
                  ]}
                  onChange={updateSecurityBrowserMode}
                />
              </Space>
            </Tooltip>
            {mainTab === 'accounts' ? (
              <Space wrap>
            {businessBatchInviteTask && (
              <Button
                icon={<UsergroupAddOutlined />}
                loading={businessBatchTaskRunning}
                danger={businessBatchInviteTask.status === 'failed' || businessBatchInviteTask.outcome === 'failed'}
                onClick={() => setBusinessBatchInviteTaskOpen(true)}
              >
                批量邀请 · {businessBatchTaskRunning
                  ? `${businessBatchInviteTask.progress.completed_mothers}/${businessBatchInviteTask.progress.total_mothers || '—'}`
                  : businessBatchInviteTask.status === 'failed' || businessBatchInviteTask.outcome === 'failed'
                    ? '失败'
                    : businessBatchInviteTask.outcome === 'partial' || businessBatchInviteTask.hasFailures
                      ? '部分完成'
                      : '已完成'}
              </Button>
            )}
            {businessChildBatchTask && (
              <Button
                icon={businessChildBatchTask.action === 'oauth' ? <RocketOutlined />
                  : businessChildBatchTask.action === 'leave_workspace' ? <RollbackOutlined /> : <SafetyOutlined />}
                loading={businessChildBatchTaskRunning}
                danger={businessChildBatchTask.status === 'failed' || businessChildBatchTask.outcome === 'failed'}
                style={businessChildBatchTask.outcome === 'partial'
                  ? { borderColor: token.colorWarning, color: token.colorWarning }
                  : undefined}
                onClick={() => setBusinessChildBatchTaskOpen(true)}
              >
                子号批量{businessChildBatchTask.action === 'oauth' ? ' RT'
                  : businessChildBatchTask.action === 'leave_workspace' ? '退出空间' : ' 2FA'} · {
                  businessChildBatchTaskRunning
                    ? `${businessChildBatchTask.progress.completed}/${businessChildBatchTask.progress.total || '—'}`
                    : businessChildBatchTask.status === 'failed' || businessChildBatchTask.outcome === 'failed'
                      ? '失败'
                      : businessChildBatchTask.outcome === 'partial' || businessChildBatchTask.progress.failed > 0
                        ? '部分完成'
                        : '已完成'
                }
              </Button>
            )}
            {businessChildRtTask && (
              <Button
                icon={<ThunderboltOutlined />}
                loading={businessChildRtTask.status === 'running'}
                danger={businessChildRtTask.status === 'failed'}
                onClick={() => setBusinessChildRtTaskOpen(true)}
              >
                子号 RT · {businessChildRtTask.status === 'running'
                  ? '进行中'
                  : businessChildRtTask.status === 'success' ? '已完成' : '失败'}
              </Button>
            )}
            {!standalone && businessChildNvBatchTask && (
              <Button
                icon={businessChildNvBatchTask.status === 'running' && !businessChildNvBatchPollingStopped
                  ? <SyncOutlined spin /> : <CloudUploadOutlined />}
                danger={businessChildNvBatchTask.status === 'failed' || businessChildNvBatchPollingStopped}
                onClick={() => setBusinessChildNvBatchTaskOpen(true)}
                data-business-child-nv-batch-progress="true"
              >
                批量 NV · {businessChildNvBatchPollingStopped ? '读取已暂停'
                  : `${businessChildNvBatchTask.completed}/${businessChildNvBatchTask.total || '—'}`}
              </Button>
            )}
            {totalAlertUnread > 0 && (
              <Popover
                placement="bottomRight"
                trigger="click"
                title={`封禁报警 · 共 ${totalAlertUnread} 封`}
                content={(
                  <div style={{ maxHeight: 360, overflow: 'auto', minWidth: 280 }}>
                    {alertItems.filter((item) => item.unread_count > 0).map((item) => (
                      <div
                        key={`plan-alert-${item.id}`}
                        role="button"
                        tabIndex={0}
                        style={{
                          padding: '6px 8px',
                          cursor: 'pointer',
                          borderRadius: 4,
                          display: 'flex',
                          justifyContent: 'space-between',
                          gap: 8,
                          fontSize: 12,
                        }}
                        onMouseEnter={(event) => { event.currentTarget.style.background = token.colorFillTertiary }}
                        onMouseLeave={(event) => { event.currentTarget.style.background = 'transparent' }}
                        onClick={() => { void openMailAlerts(item) }}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            void openMailAlerts(item)
                          }
                        }}
                      >
                        <Space direction="vertical" size={0} style={{ flex: 1, minWidth: 0 }}>
                          <Typography.Text code ellipsis style={{ maxWidth: 230 }}>{item.email}</Typography.Text>
                          <Typography.Text
                            type="secondary"
                            ellipsis
                            title={gptPlanMailLocation(item)}
                            style={{ maxWidth: 230, fontSize: 11 }}
                          >
                            {gptPlanMailLocation(item)}
                          </Typography.Text>
                        </Space>
                        <Tag color="red" style={{ margin: 0 }}>{item.unread_count}</Tag>
                      </div>
                    ))}
                  </div>
                )}
              >
                <Badge count={totalAlertUnread} overflowCount={99}>
                  <Button danger icon={<BellOutlined />}>封禁报警</Button>
                </Badge>
              </Popover>
            )}
            {totalInboxUnread > 0 && (
              <Popover
                placement="bottomRight"
                trigger="click"
                title={`未读邮件 · 共 ${totalInboxUnread} 封`}
                content={(
                  <div style={{ maxHeight: 360, overflow: 'auto', minWidth: 280 }}>
                    {alertItems.filter((item) => item.inbox_unread_count > 0).map((item) => (
                      <div
                        key={`plan-inbox-${item.id}`}
                        role="button"
                        tabIndex={0}
                        style={{
                          padding: '6px 8px',
                          cursor: 'pointer',
                          borderRadius: 4,
                          display: 'flex',
                          justifyContent: 'space-between',
                          gap: 8,
                          fontSize: 12,
                        }}
                        onMouseEnter={(event) => { event.currentTarget.style.background = token.colorFillTertiary }}
                        onMouseLeave={(event) => { event.currentTarget.style.background = 'transparent' }}
                        onClick={() => { void openMailInbox(item) }}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            void openMailInbox(item)
                          }
                        }}
                      >
                        <Space direction="vertical" size={0} style={{ flex: 1, minWidth: 0 }}>
                          <Typography.Text code ellipsis style={{ maxWidth: 230 }}>{item.email}</Typography.Text>
                          <Typography.Text
                            type="secondary"
                            ellipsis
                            title={gptPlanMailLocation(item)}
                            style={{ maxWidth: 230, fontSize: 11 }}
                          >
                            {gptPlanMailLocation(item)}
                          </Typography.Text>
                        </Space>
                        <Tag color="blue" style={{ margin: 0 }}>{item.inbox_unread_count}</Tag>
                      </div>
                    ))}
                  </div>
                )}
              >
                <Badge count={totalInboxUnread} overflowCount={99}>
                  <Button icon={<MailOutlined />}>未读邮件</Button>
                </Badge>
              </Popover>
            )}
            {!standalone && (accountType === 'regular' || accountType === 'refunded') && (
              <Space size={6} wrap>
                <UpgradeBrowserConfigControls
                  config={upgradeBrowserConfig}
                  loading={upgradeBrowserConfigLoading}
                  saving={upgradeBrowserConfigSaving}
                  proxyLoading={roxyLoading}
                  proxies={roxyProxies}
                  disabled={upgradeStarting || !!upgradeTask}
                  onChange={(next) => { void updateUpgradeBrowserConfig(next.browserBackend, next.roxyProxyId) }}
                  onRefreshProxies={() => { void loadRoxyProxies() }}
                />
                <Tooltip title="PRO 价格与币种使用此结账区；PH 区可能执行 Free → GO → PRO。选择指纹代理时后端会优先跟随代理国家。账单地址仍使用固定的美国 Oregon 地址。">
                  <Select
                    style={{ width: 170 }}
                    value={`${checkoutRegion.country}|${checkoutRegion.currency}`}
                    loading={checkoutRegionSaving}
                    disabled={checkoutRegionSaving}
                    options={(() => {
                      const current = `${checkoutRegion.country}|${checkoutRegion.currency}`
                      const options = CHECKOUT_REGION_PRESETS.map((item) => ({
                        value: `${item.country}|${item.currency}`,
                        label: `PRO 结账区：${item.label}`,
                      }))
                      if (!options.some((item) => item.value === current)) {
                        options.unshift({ value: current, label: `PRO 结账区：${checkoutRegion.country}/${checkoutRegion.currency}` })
                      }
                      return options
                    })()}
                    onChange={(value: string) => {
                      const [country, currency] = value.split('|')
                      void saveCheckoutRegion(country, currency)
                    }}
                  />
                </Tooltip>
              </Space>
            )}
            {businessMotherView && (
              <Tooltip title="顺序刷新当前页 BUSINESS 母号的远端成员与席位；只在点击时请求">
                <Button
                  icon={<ReloadOutlined />}
                  loading={businessWorkspacePageRefreshing}
                  disabled={businessWorkspacePageRefreshing || loading}
                  onClick={() => { void refreshCurrentBusinessWorkspacePage() }}
                >
                  刷新成员/席位
                </Button>
              </Tooltip>
            )}
            {!standalone && businessMemberTab && (
              <Tooltip title="配置 NexusVault 库存 API Key 与手动查询 Cookie；凭据只写入后端且不会回显">
                <Button
                  data-nvtokens-config-trigger="true"
                  icon={<SafetyOutlined />}
                  onClick={openNvTokensConfig}
                >
                  NV 设置
                </Button>
              </Tooltip>
            )}
            {!standalone && businessChildView && (
              <Tooltip title="仅核对已确认 NV 上架的本地记录；不受母号状态、Dead、当前搜索或筛选条件影响，仅在 NV 确认已出库后更新出售时间与质保">
                <Button
                  data-nvtokens-sales-refresh="true"
                  icon={<SyncOutlined />}
                  loading={businessChildNvSalesRefreshing}
                  disabled={businessChildCatalogLoading || businessChildNvSalesRefreshing}
                  onClick={() => { void refreshBusinessChildNvSales() }}
                >
                  刷新出库状态
                </Button>
              </Tooltip>
            )}
            {!standalone && businessChildView && businessChildNvSalesResult && (
              <Button
                data-nvtokens-sales-result-trigger="true"
                onClick={() => setBusinessChildNvSalesResultOpen(true)}
              >
                查看出库核对结果
              </Button>
            )}
            <Button
              icon={<ReloadOutlined />}
              loading={businessChildView ? businessChildCatalogLoading : loading}
              disabled={businessChildView && businessChildNvSalesRefreshing}
              onClick={() => {
                if (businessChildView) void loadBusinessChildCatalog()
                else reload()
              }}
            >
              刷新列表
            </Button>
            {(!standalone || businessOnly) && <Button type="primary" icon={<PlusOutlined />} onClick={() => setImportOpen(true)}>导入 BUSINESS 母号</Button>}
              </Space>
            ) : mainTab === 'cards' ? (
              <Tooltip title="一键更新所有支付账号:每账号一个线程并发,更新 开卡数量 / 余额 / 支付数量 / 待退款数量(读 ether.fi)。账号多会较慢">
                <Button
                  icon={<DollarOutlined />}
                  loading={refreshingAllBalance}
                  onClick={refreshAllBalance}
                >
                  一键更新支付账号
                </Button>
              </Tooltip>
            ) : null}
          </Space>
        )}
      />

      {!standalone && <Tabs
        activeKey={mainTab}
        onChange={(key) => {
          if (focusTarget && key !== 'accounts') dismissFocusTarget()
          if (key !== 'accounts') setBusinessMembersAccountId(null)
          setMainTab(key as 'accounts' | 'preparation' | 'cards' | 'proxy')
        }}
        items={[
          { key: 'accounts', label: '账号' },
          { key: 'preparation', label: '准备号池' },
          { key: 'cards', label: '银行卡 / 支付信息' },
          { key: 'proxy', label: '代理 IP' },
        ]}
        style={{ marginBottom: -8 }}
      />}

      {mainTab === 'cards' && <CardsPage apiPrefix="/gpt-plans" />}
      {mainTab === 'proxy' && <CpaProxyPanel apiPrefix="/gpt-plans" />}
      {mainTab === 'preparation' && <GptPlanPreparationPanel browserMode={securityBrowserMode}
        mailFetchingAccountId={mailLoading && !mailBusinessChildTarget ? mailAccount?.id ?? null : null}
        onFetchMail={({ account_id, email }) => { void fetchMail({ id: account_id, email }, 10) }} />}

      {mainTab === 'accounts' && (<>
      {!standalone && <Card size="small" styles={{ body: { padding: '0 16px' } }} style={{ marginBottom: 12 }}>
        <Tabs
          activeKey={accountType}
          size="large"
          tabBarStyle={{ marginBottom: 0 }}
          items={[
            { key: 'regular', label: `普通账号 ${accountCounts.regular}` },
            { key: 'member', label: `会员账号 ${accountCounts.member}` },
            { key: 'refunded', label: `已退款 ${accountCounts.refunded}` },
          ]}
          onChange={(value) => {
            if (focusTarget) dismissFocusTarget()
            setBusinessMembersAccountId(null)
            const nextAccountType = value as AccountType
            setAccountType(nextAccountType)
            if (
              nextAccountType === 'refunded'
              || (nextAccountType === 'member' && memberPlan !== 'team')
            ) setLoginStatus(undefined)
            setPage(1)
          }}
        />
      </Card>}

      <Card size="small" style={{ marginBottom: 12 }}>
        <Space direction="vertical" size={10} style={{ width: '100%' }}>
          {!standalone && accountType === 'member' && (
            <Segmented
              block
              value={memberPlan}
              options={MEMBER_PLAN_TAB_ORDER.map((key) => ({
                  value: key,
                  label: `${MEMBER_PLAN_META[key].label} ${accountCounts.memberPlans[key]}`,
                }))}
              onChange={(value) => {
                if (focusTarget) dismissFocusTarget()
                setBusinessMembersAccountId(null)
                const nextMemberPlan = value as MemberPlan
                setMemberPlan(nextMemberPlan)
                if (nextMemberPlan !== 'team') setLoginStatus(undefined)
                setPage(1)
              }}
            />
          )}
          {businessMemberTab && !standalone && (
            <Segmented
              block
              value={businessCatalogView}
              data-business-catalog-view="true"
              options={[
                { value: 'mothers', label: '母号列表' },
                { value: 'children', label: `子号列表 ${businessChildCatalogTotal || ''}`.trim() },
              ]}
              onChange={(value) => {
                if (focusTarget) dismissFocusTarget()
                setBusinessMembersAccountId(null)
                setBusinessCatalogView(value as BusinessCatalogView)
                setSelectedBusinessAccountIds([])
                setSelectedBusinessChildMembershipIds([])
                setBusinessSelectAllMatching(false)
                setLoginStatus(undefined)
                setBusinessSeatFilter(undefined)
                setPage(1)
              }}
            />
          )}
          <Space wrap>
          {focusTarget && (
            <Tag color="processing" closable onClose={dismissFocusTarget}>
              已定位：{accounts.find((row) => row.id === focusTarget.planAccountId)?.email || `账号 #${focusTarget.planAccountId}`}
              {(focusTarget.childAccountId || focusTarget.membershipId) ? ' · BUSINESS 子号' : ''}
            </Tag>
          )}
          <Input.Search
            allowClear
            value={keywordInput}
            prefix={<SearchOutlined />}
            placeholder={businessChildView ? '搜索子号或母号邮箱' : '搜索邮箱'}
            style={{ width: 260 }}
            onChange={(event) => setKeywordInput(event.target.value)}
            onSearch={(value) => {
              if (focusTarget) dismissFocusTarget()
              setKeyword(value.trim())
              setPage(1)
            }}
          />
          {(accountType === 'regular' || businessMotherView) && (
            <Select
              allowClear
              placeholder="登录状态"
              style={{ width: 150 }}
              value={loginStatus}
              options={[
                { value: 'logged_in', label: '已登录' },
                { value: 'not_logged_in', label: '未登录' },
              ]}
              onChange={(value) => {
                if (focusTarget) dismissFocusTarget()
                setLoginStatus(value)
                setPage(1)
              }}
            />
          )}
          {businessMotherView && (
            <Tooltip title="按数据库中最近一次席位快照筛选，不会在筛选时请求远端；登录、Dead 或邀请冷却等操作条件仍以账号行提示为准。">
              <Select
                allowClear
                placeholder="席位状态：全部"
                style={{ width: 170 }}
                value={businessSeatFilter}
                data-business-seat-filter="true"
                options={[
                  { value: 'available', label: '有空闲席位' },
                  { value: 'full', label: '无空闲席位' },
                  { value: 'unknown', label: '席位未知' },
                ]}
                onChange={(value: BusinessSeatFilter | undefined) => {
                  if (focusTarget) dismissFocusTarget()
                  setBusinessSeatFilter(value)
                  setPage(1)
                }}
              />
            </Tooltip>
          )}
          {businessMemberTab && !standalone && (
            <Select
              allowClear
              placeholder={businessChildView ? '母号用途：全部' : '用途：全部'}
              style={{ width: businessChildView ? 165 : 145 }}
              value={businessChildView
                ? businessChildParentUsageFilter
                : businessUsageFilter}
              data-business-usage-filter="true"
              options={[
                { value: 'unassigned', label: '未标注' },
                { value: 'sale', label: '出售' },
                { value: 'self_use', label: '自用' },
                { value: 'transit', label: '中转' },
              ]}
              onChange={(value: BusinessUsageFilter | undefined) => {
                if (focusTarget) dismissFocusTarget()
                if (businessChildView) setBusinessChildParentUsageFilter(value)
                else setBusinessUsageFilter(value)
                setPage(1)
              }}
            />
          )}
          {!standalone && businessChildView && (
            <Select<BusinessChildSaleFilter>
              value={businessChildSaleFilter}
              style={{ width: 175 }}
              data-business-child-sale-filter="true"
              options={[
                { value: 'all', label: '出售状态：全部' },
                { value: 'unlisted', label: '出售状态：未上架' },
                { value: 'listed', label: '出售状态：已上架' },
                { value: 'sold', label: '出售状态：已出售' },
                { value: 'refunded', label: '出售状态：NV 已退款' },
                { value: 'partial_refund', label: '出售状态：NV 部分退款' },
              ]}
              onChange={(value) => {
                if (focusTarget) dismissFocusTarget()
                setBusinessChildSaleFilter(value)
                setPage(1)
              }}
            />
          )}
          {businessChildView && (
            <Select<BusinessChildTwoFactorFilter>
              value={businessChildTwoFactorFilter}
              style={{ width: 170 }}
              data-business-child-2fa-filter="true"
              options={[
                { value: 'all', label: '2FA：全部' },
                { value: 'enabled', label: '2FA：已开启' },
                { value: 'not_enabled', label: '2FA：未开启' },
                { value: 'needs_attention', label: '2FA：需处理' },
              ]}
              onChange={(value) => {
                if (focusTarget) dismissFocusTarget()
                setBusinessChildTwoFactorFilter(value)
                setPage(1)
              }}
            />
          )}
          {businessChildView && (
            <Select<BusinessChildRtFilter>
              value={businessChildRtFilter}
              style={{ width: 150 }}
              data-business-child-rt-filter="true"
              options={[
                { value: 'all', label: 'RT：全部' },
                { value: 'acquired', label: 'RT：已获取' },
                { value: 'missing', label: 'RT：未获取' },
              ]}
              onChange={(value) => {
                if (focusTarget) dismissFocusTarget()
                setBusinessChildRtFilter(value)
                setPage(1)
              }}
            />
          )}
          {businessMotherView
            && (businessSeatFilter || businessUsageFilter) && (
              <Typography.Text type="secondary">
                当前筛选：{total} 个母号
              </Typography.Text>
            )}
          {businessChildView ? (
            <Typography.Text type="secondary">
              当前筛选：{businessChildCatalogTotal} 个子号
            </Typography.Text>
          ) : stats && (
            <Typography.Text type="secondary">
              全部 {stats.total || 0} 个
              {(accountType === 'regular' || (accountType === 'member' && memberPlan === 'team'))
                && ` · 已登录 ${stats.logged_in || 0} · 未登录 ${stats.not_logged_in || 0}`}
              {stats.dead ? ` · Dead ${stats.dead}` : ''}
            </Typography.Text>
          )}
          </Space>
          {businessChildView && (
            <div
              data-business-child-batch-selection="true"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 8,
                paddingTop: 10,
                borderTop: `1px solid ${token.colorBorderSecondary}`,
              }}
            >
              <Space size={8} wrap>
                <Typography.Text strong>
                  已选择 {selectedBusinessChildMembershipIds.length} 个子号
                </Typography.Text>
                {selectedBusinessChildMembershipIds.length > 0 && (
                  <Button
                    type="link"
                    size="small"
                    onClick={() => setSelectedBusinessChildMembershipIds([])}
                  >
                    清空选择
                  </Button>
                )}
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  任务严格一个号一个号处理，单号失败后继续下一个
                </Typography.Text>
              </Space>
              <Space size={8} wrap>
                <Popconfirm
                  title="确认批量设置密码与 2FA？"
                  description={`将严格按顺序处理已选择的 ${selectedBusinessChildMembershipIds.length} 个子号。`}
                  disabled={businessChildBatchTaskRunning || selectedBusinessChildMembershipIds.length === 0}
                  onConfirm={() => { void startBusinessChildBatchAction('setup_security') }}
                >
                  <Button
                    icon={<SafetyOutlined />}
                    loading={businessChildBatchStarting && businessChildBatchTask?.action === 'setup_security'}
                    disabled={businessChildBatchTaskRunning || selectedBusinessChildMembershipIds.length === 0}
                    data-business-child-batch-security="true"
                  >
                    批量设置密码与 2FA
                  </Button>
                </Popconfirm>
                <Popconfirm
                  title="确认批量获取 RT？"
                  description={`将严格按顺序处理已选择的 ${selectedBusinessChildMembershipIds.length} 个子号；已有 RT 的账号会跳过。`}
                  disabled={businessChildBatchTaskRunning || selectedBusinessChildMembershipIds.length === 0}
                  onConfirm={() => { void startBusinessChildBatchAction('oauth') }}
                >
                  <Button
                    type="primary"
                    icon={<RocketOutlined />}
                    loading={businessChildBatchStarting && businessChildBatchTask?.action === 'oauth'}
                    disabled={businessChildBatchTaskRunning || selectedBusinessChildMembershipIds.length === 0}
                    data-business-child-batch-rt="true"
                  >
                    批量获取 RT
                  </Button>
                </Popconfirm>
                <Popconfirm
                  title={`确认让 ${businessChildBatchLeaveIds.length} 个成员退出空间？`}
                  description={`可退出 ${businessChildBatchLeaveIds.length} 个，不可退出 ${businessChildBatchLeaveSkipped} 个将跳过。按勾选顺序逐个执行；待邀请不会自动撤销，退出后成员将失去空间访问权限。`}
                  okText="确认批量退出"
                  cancelText="取消"
                  okButtonProps={{ danger: true }}
                  disabled={businessChildBatchTaskRunning || businessChildBatchLeaveIds.length === 0}
                  onConfirm={() => { void startBusinessChildBatchAction('leave_workspace') }}
                >
                  <Button
                    danger
                    icon={<RollbackOutlined />}
                    loading={businessChildBatchStarting && businessChildBatchTask?.action === 'leave_workspace'}
                    disabled={businessChildBatchTaskRunning || businessChildBatchLeaveIds.length === 0}
                    data-business-child-batch-leave="true"
                  >
                    批量退出空间
                  </Button>
                </Popconfirm>
                {businessChildBatchTask && (
                  <Button
                    loading={businessChildBatchTaskRunning}
                    danger={businessChildBatchTask.status === 'failed'
                      || businessChildBatchTask.outcome === 'failed'}
                    style={businessChildBatchTask.outcome === 'partial'
                      ? { borderColor: token.colorWarning, color: token.colorWarning }
                      : undefined}
                    onClick={() => setBusinessChildBatchTaskOpen(true)}
                  >
                    查看批量任务 · {businessChildBatchTask.progress.completed}/{businessChildBatchTask.progress.total || '—'}
                  </Button>
                )}
                {!standalone && <Button
                  icon={<CloudUploadOutlined />}
                  disabled={selectedBusinessChildMembershipIds.length === 0
                    || businessChildNvBatchStarting || businessChildNvBatchTask?.status === 'running'}
                  onClick={openBusinessChildNvBatchListing}
                  data-business-child-nv-batch-listing="true"
                >
                  批量上架 NV
                </Button>}
              </Space>
            </div>
          )}
          {businessMotherView && (
            <div
              data-business-batch-selection="true"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 8,
                paddingTop: 10,
                borderTop: `1px solid ${token.colorBorderSecondary}`,
              }}
            >
              <Space size={8} wrap>
                <Typography.Text strong>
                  {businessSelectAllMatching
                    ? `已选择当前筛选全部 ${total} 个母号（跨分页）`
                    : `已选择 ${selectedBusinessAccountIds.length} 个母号`}
                </Typography.Text>
                {businessSeatFilter === 'available' && total > 0 && !businessSelectAllMatching && (
                  <Button
                    type="link"
                    size="small"
                    data-business-select-all-matching="true"
                    onClick={() => {
                      setSelectedBusinessAccountIds([])
                      setBusinessSelectAllMatching(true)
                    }}
                  >
                    全选当前筛选全部 {total} 个（跨分页）
                  </Button>
                )}
                {(businessSelectAllMatching || selectedBusinessAccountIds.length > 0) && (
                  <Button
                    type="link"
                    size="small"
                    onClick={() => {
                      setSelectedBusinessAccountIds([])
                      setBusinessSelectAllMatching(false)
                    }}
                  >
                    清空选择
                  </Button>
                )}
              </Space>
              <Space size={8} wrap>
                <Space size={4} wrap>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    子号邮箱类型：
                  </Typography.Text>
                  <Segmented
                    size="small"
                    value={businessBatchInviteMailProvider}
                    options={standalone ? [{ value: 'gmail', label: 'Gmail' }] : BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS}
                    disabled={businessBatchTaskRunning}
                    data-business-batch-mail-provider="true"
                    onChange={(value) => {
                      setBusinessBatchInviteMailProvider(value as BusinessInviteMailProvider)
                    }}
                  />
                </Space>
                <Space size={5} wrap>
                  <Switch
                    size="small"
                    checked={businessBatchInvitePostSecurity}
                    disabled={businessBatchTaskRunning}
                    data-business-batch-post-security="true"
                    onChange={setBusinessBatchInvitePostSecurity}
                  />
                  <Tooltip title="先检查已有密码与 2FA，已完成则跳过，仅缺失时设置">
                    <Typography.Text style={{ fontSize: 12 }}>邀请后检查密码 / 2FA</Typography.Text>
                  </Tooltip>
                </Space>
                <Space size={5} wrap>
                  <Switch
                    size="small"
                    checked={businessBatchInvitePostRt}
                    disabled={businessBatchTaskRunning}
                    data-business-batch-post-rt="true"
                    onChange={setBusinessBatchInvitePostRt}
                  />
                  <Typography.Text style={{ fontSize: 12 }}>邀请后获取 RT</Typography.Text>
                </Space>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {standalone ? '从可用的 Gmail 普通账号中选择；' : '准备号优先，不足时普通号补充；'}{businessInviteMailProviderHint(businessBatchInviteMailProvider, undefined, seatMailDefaults)}。每个子号完成邀请
                  {businessBatchInvitePostSecurity ? '、2FA' : ''}
                  {businessBatchInvitePostRt ? '、RT' : ''}
                  后再处理下一个；仅处理有空闲席位且当前邀请额度仍有剩余的母号
                </Typography.Text>
                {!standalone && <BusinessInviteMailProviderSettings />}
                <Popconfirm
                  title="确认批量邀请子号？"
                  description={`将处理${businessSelectAllMatching ? `当前筛选全部 ${total}` : `已选择的 ${selectedBusinessAccountIds.length}`} 个母号，子号邮箱类型为「${businessInviteMailProviderLabel(businessBatchInviteMailProvider)}」（${businessInviteMailProviderHint(businessBatchInviteMailProvider, undefined, seatMailDefaults)}），${standalone ? '从可用 Gmail 普通账号中选择' : '准备号优先、不足时普通号补充'}，按剩余席位逐个邀请${businessBatchInvitePostSecurity ? '，检查密码 / 2FA（已完成则跳过）' : ''}${businessBatchInvitePostRt ? '，邀请后获取 RT' : ''}；每个子号完成全部步骤后再处理下一个。`}
                  okText="确认启动"
                  cancelText="取消"
                  disabled={businessBatchTaskRunning || businessBatchSelectionCount <= 0 || (businessBatchInviteMailProvider === 'auto' && !seatMailDefaults)}
                  onConfirm={() => { void startBusinessBatchInvite() }}
                >
                  <Button
                    type="primary"
                    icon={<UsergroupAddOutlined />}
                    loading={businessBatchInviteStarting}
                    disabled={businessBatchTaskRunning || businessBatchSelectionCount <= 0 || (businessBatchInviteMailProvider === 'auto' && !seatMailDefaults)}
                    data-business-batch-invite-trigger="true"
                  >
                    批量邀请子号
                  </Button>
                </Popconfirm>
              </Space>
            </div>
          )}
          {accountType === 'refunded' && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              当前按原始 PRO 升级时间{refundedUpgradeTimeOrder === 'asc' ? '正序' : '倒序'}；点击该列标题可切换，未记录时间的账号始终排在最后。
            </Typography.Text>
          )}
        </Space>
      </Card>

      {importTask && (
        <Alert
          style={{ marginBottom: 12 }}
          type={importTask.status === 'failed' ? 'error' : importTask.status === 'done' ? 'success' : 'info'}
          showIcon
          closable={importTask.status === 'done' || importTask.status === 'failed'}
          onClose={() => { setImportTask(null); setImportTaskId('') }}
          message={importTask.status === 'done'
            ? '账号导入完成'
            : importTask.status === 'failed'
              ? '账号导入失败'
              : '正在后台导入账号'}
          description={(
            <Space direction="vertical" size={4} style={{ width: '100%' }}>
              <Progress
                percent={taskPercent}
                status={importTask.status === 'failed' ? 'exception' : importTask.status === 'done' ? 'success' : 'active'}
                size="small"
              />
              <Typography.Text type="secondary">
                {importTask.processed || 0}/{importTask.total || 0} · 成功 {importTask.success || 0} · 失败 {importTask.failed || 0}
              </Typography.Text>
              {!!importTask.errors?.length && <Typography.Text type="danger">{importTask.errors[0]}</Typography.Text>}
            </Space>
          )}
        />
      )}

      <Card styles={{ body: { padding: 0 } }}>
        {businessChildView ? (
          <Table<BusinessChildCatalogRow>
            data-business-child-catalog-table="true"
            rowKey={(row) => Number(row.membership_id)}
            loading={businessChildCatalogLoading}
            dataSource={businessChildCatalogRows}
            columns={standalone ? businessChildCatalogColumns.filter(column => !['nv_listed_at', 'sale_status', 'sold_at', 'warranty'].includes(String(column.key))) : businessChildCatalogColumns}
            rowSelection={{
              preserveSelectedRowKeys: false,
              fixed: true,
              columnWidth: 44,
              selectedRowKeys: selectedBusinessChildMembershipIds,
              getCheckboxProps: (row) => {
                const leaveEligibility = businessChildLeaveWorkspaceEligibility(row)
                const managedPoolChild = Boolean(positiveInteger(row.membership_id)
                  && positiveInteger(row.pro_account_id ?? row.child_id) && row._managed)
                const allowed = managedPoolChild || businessChildBatchEligibility(row).allowed || leaveEligibility.allowed
                return {
                  disabled: businessChildBatchTaskRunning || !allowed,
                  title: allowed ? '选择该子号' : leaveEligibility.reason || '该成员当前没有可用批量操作',
                }
              },
              onChange: (keys) => setSelectedBusinessChildMembershipIds(
                keys.map(Number).filter((id) => Number.isInteger(id) && id > 0),
              ),
            }}
            scroll={{ x: 1850 }}
            onRow={(row) => ({
              'data-business-child-membership-id': positiveInteger(row.membership_id) || undefined,
              'data-business-child-parent-account-id': row.parent_account_id,
            } as HTMLAttributes<HTMLTableRowElement>)}
            pagination={{
              current: page,
              pageSize,
              total: businessChildCatalogTotal,
              showSizeChanger: true,
              showTotal: (value) => `共 ${value} 个子号`,
              onChange: (nextPage, nextSize) => { setPage(nextPage); setPageSize(nextSize) },
            }}
            locale={{ emptyText: <Empty description="当前筛选下暂无 BUSINESS 子号" /> }}
          />
        ) : (
        <Table<GptPlanAccount>
          rowKey="id"
          loading={loading}
          dataSource={accounts}
          columns={standalone ? columns.filter(column => !['rotation_revenue', 'default_payment_method', 'checkout'].includes(column.key)) : columns}
          rowSelection={businessMotherView ? {
            preserveSelectedRowKeys: true,
            fixed: true,
            columnWidth: 44,
            selectedRowKeys: businessSelectAllMatching
              ? accounts.filter(businessAccountHasAvailableSeat).map((account) => account.id)
              : selectedBusinessAccountIds,
            getCheckboxProps: (account) => {
              const hasAvailableSeat = businessAccountHasAvailableSeat(account)
              const inviteState = businessInviteButtonState(
                account,
                memberSourceOf(account),
                undefined,
                replenishmentNow,
              )
              return {
                disabled: businessSelectAllMatching || !hasAvailableSeat,
                title: businessSelectAllMatching
                  ? '已全选当前筛选结果；请先清空选择再单独调整'
                  : hasAvailableSeat ? '选择该母号' : inviteState.reason || '该母号没有数据库已知的空闲席位或邀请额度',
              }
            },
            onChange: (keys) => {
              if (businessSelectAllMatching) return
              setSelectedBusinessAccountIds(
                keys.map(Number).filter((id) => Number.isInteger(id) && id > 0),
              )
            },
          } : undefined}
          onChange={handleAccountTableChange}
          onRow={(account) => ({
            style: focusTarget?.planAccountId === account.id
              ? {
                  background: token.colorPrimaryBg,
                  boxShadow: `inset 3px 0 ${token.colorPrimary}`,
                  transition: 'background 0.3s ease-in-out',
                }
              : { transition: 'background 0.3s ease-in-out' },
          })}
          scroll={{
            // Match the actual visible widths, including the selection column;
            // hidden security columns must not leave fixed cells misaligned.
            x: businessMotherView
              ? columns.reduce((width, column) => width + (Number(column.width) || 0), 44)
              : accountType === 'regular'
              ? 1470
              : accountType === 'refunded'
                ? 1080
                : memberPlan === 'team' ? 1605 : 1435,
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showTotal: (value) => `共 ${value} 个账号`,
            onChange: (nextPage, nextSize) => { setPage(nextPage); setPageSize(nextSize) },
          }}
          locale={{ emptyText: <Empty description="暂无 GPT 套餐账号，请先批量导入" /> }}
        />
        )}
      </Card>

      <Drawer
        title={businessMembersAccount ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, whiteSpace: 'nowrap' }}>
            <TeamOutlined style={{ flex: '0 0 auto' }} />
            <Typography.Text strong style={{ flex: '0 0 auto', whiteSpace: 'nowrap' }}>
              BUSINESS 母号详情
            </Typography.Text>
            {!compactBusinessLayout && (
              <Typography.Text code copyable ellipsis style={{ minWidth: 0, maxWidth: 620 }}>
                {businessMembersAccount.email}
              </Typography.Text>
            )}
          </div>
        ) : 'BUSINESS 母号详情'}
        open={Boolean(businessMembersAccount)}
        placement="right"
        width={compactBusinessLayout ? '100vw' : 'min(1320px, calc(100vw - 48px))'}
        styles={{
          header: compactBusinessLayout ? { padding: '12px 10px' } : undefined,
          body: { padding: compactBusinessLayout ? 10 : 16 },
        }}
        extra={businessMembersAccount && !compactBusinessLayout
          ? renderBusinessDrawerActions(false)
          : undefined}
        onClose={() => setBusinessMembersAccountId(null)}
      >
        {businessMembersAccount && (
          <div data-business-members-drawer="true">
            {compactBusinessLayout && (
              <div style={{ minWidth: 0, marginBottom: 12 }}>
                <Typography.Paragraph
                  code
                  copyable
                  ellipsis
                  style={{ margin: '0 0 10px', maxWidth: '100%' }}
                >
                  {businessMembersAccount.email}
                </Typography.Paragraph>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {renderBusinessDrawerActions(false)}
                </div>
              </div>
            )}
            {renderBusinessDrawerOverview(businessMembersAccount)}
            {renderBusinessChildren(businessMembersAccount)}
          </div>
        )}
      </Drawer>

      <Modal
        title="子号出售状态与质保"
        open={Boolean(businessChildSaleEditor)}
        width={520}
        okText="保存"
        cancelText="取消"
        confirmLoading={businessChildSaleSaving}
        onOk={() => { void saveBusinessChildSale() }}
        onCancel={() => {
          if (!businessChildSaleSaving) setBusinessChildSaleEditor(null)
        }}
      >
        {businessChildSaleEditor && (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Alert
              type="info"
              showIcon
              message={businessChildSaleEditor.child_email || businessChildSaleEditor.email || 'BUSINESS 子号'}
              description={`所属母号：${businessChildSaleEditor.parent_email || `#${businessChildSaleEditor.parent_account_id}`}`}
            />
            <div>
              <Typography.Text strong>出售状态</Typography.Text>
              <Segmented
                block
                style={{ marginTop: 6 }}
                value={businessChildSaleStatusDraft}
                options={[
                  { value: 'unlisted', label: '未上架' },
                  { value: 'listed', label: '已上架' },
                  { value: 'sold', label: '已出售' },
                ]}
                disabled={businessChildSaleSaving}
                onChange={(value) => {
                  const nextStatus = value as BusinessChildSaleStatus
                  setBusinessChildSaleStatusDraft(nextStatus)
                  if (nextStatus !== 'sold') {
                    setBusinessChildSoldAtDraft('')
                  } else if (!businessChildSoldAtDraft) {
                    const now = new Date()
                    setBusinessChildSoldAtDraft(
                      new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 16),
                    )
                  }
                }}
              />
            </div>
            <div>
              <Typography.Text strong>出售时间</Typography.Text>
              <Space.Compact block style={{ marginTop: 6 }}>
                <Input
                  type="datetime-local"
                  value={businessChildSoldAtDraft}
                  disabled={businessChildSaleSaving || businessChildSaleStatusDraft !== 'sold'}
                  onChange={(event) => setBusinessChildSoldAtDraft(event.target.value)}
                />
                <Button
                  disabled={businessChildSaleSaving || businessChildSaleStatusDraft !== 'sold'}
                  onClick={() => {
                    const now = new Date()
                    setBusinessChildSoldAtDraft(
                      new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 16),
                    )
                  }}
                >
                  现在
                </Button>
                <Button
                  disabled={businessChildSaleSaving || businessChildSaleStatusDraft !== 'sold' || !businessChildSoldAtDraft}
                  onClick={() => {
                    setBusinessChildSoldAtDraft('')
                    setBusinessChildSaleStatusDraft('unlisted')
                  }}
                >
                  清除并设为未上架
                </Button>
              </Space.Compact>
            </div>
            <div>
              <Typography.Text strong>质保时长（小时）</Typography.Text>
              <div style={{ marginTop: 6 }}>
                <InputNumber
                  min={0}
                  max={87600}
                  precision={0}
                  value={businessChildWarrantyDraft}
                  disabled={businessChildSaleSaving}
                  style={{ width: '100%' }}
                  addonAfter="小时"
                  onChange={(value) => setBusinessChildWarrantyDraft(
                    Math.max(0, Math.floor(Number(value || 0))),
                  )}
                />
              </div>
              <Typography.Text type="secondary" style={{ display: 'block', marginTop: 6, fontSize: 12 }}>
                标记“已出售”时必须记录出售时间，质保从该时间开始计算；切换为“未上架”或“已上架”会清除出售时间。
                0 小时表示不设置质保。
              </Typography.Text>
            </div>
          </Space>
        )}
      </Modal>

      <Modal
        title="NexusVault 设置"
        open={nvTokensConfigOpen}
        width={520}
        okText="保存"
        cancelText="取消"
        confirmLoading={nvTokensConfigSaving}
        okButtonProps={{ disabled: nvTokensConfigLoading }}
        maskClosable={!nvTokensConfigSaving}
        closable={!nvTokensConfigSaving}
        onOk={() => { void saveNvTokensConfig() }}
        onCancel={() => {
          if (nvTokensConfigSaving) return
          setNvTokensApiKeyDraft('')
          setNvTokensQueryCookieDraft('')
          setNvTokensConfigOpen(false)
        }}
      >
        <Spin spinning={nvTokensConfigLoading}>
          <Space
            direction="vertical"
            size={16}
            style={{ width: '100%' }}
            data-nvtokens-config-modal="true"
          >
            <Alert
              type={nvTokensConfig.api_key_configured ? 'success' : 'warning'}
              showIcon
              message={nvTokensConfig.api_key_configured ? '库存 API Key 已配置' : '尚未配置库存 API Key'}
              description="后端只返回是否已配置，不会把现有密钥发送到浏览器。"
            />
            <Alert
              type={nvTokensConfig.query_session_configured ? 'success' : 'warning'}
              showIcon
              message={nvTokensConfig.query_session_configured ? '手动查询 Cookie 已配置' : '尚未配置手动查询 Cookie'}
              description="用于查询 NV 出库状态和市场行情；启用自动售号后会定时查询。只有手动提交改价时才修改对应卡片价格。"
            />
            <div>
              <Typography.Text strong>服务地址</Typography.Text>
              <Input
                value={nvTokensConfig.base_url || 'https://nvtokens.com'}
                disabled
                style={{ marginTop: 6 }}
              />
            </div>
            <div>
              <Typography.Text strong>库存 API Key</Typography.Text>
              <Input.Password
                value={nvTokensApiKeyDraft}
                disabled={nvTokensConfigLoading || nvTokensConfigSaving}
                autoComplete="new-password"
                placeholder={nvTokensConfig.api_key_configured
                  ? '留空则保留现有密钥；输入新值将覆盖'
                  : '请输入 NV 库存 API Key'}
                style={{ marginTop: 6 }}
                onChange={(event) => setNvTokensApiKeyDraft(event.target.value)}
              />
            </div>
            <div>
              <Typography.Text strong>查询 Cookie（只写）</Typography.Text>
              <Input.Password
                data-nvtokens-query-cookie="true"
                value={nvTokensQueryCookieDraft}
                disabled={nvTokensConfigLoading || nvTokensConfigSaving}
                autoComplete="new-password"
                placeholder={nvTokensConfig.query_session_configured
                  ? '留空则保留现有 Cookie；输入新值将覆盖'
                  : '粘贴已登录 nvtokens.com 的 Cookie'}
                style={{ marginTop: 6 }}
                onChange={(event) => setNvTokensQueryCookieDraft(event.target.value)}
              />
              <Typography.Text type="secondary" style={{ display: 'block', marginTop: 6, fontSize: 12 }}>
                用于出库、行情查询及手动改价；后端加密保存且只返回是否已配置，不会回显 Cookie 原文。
              </Typography.Text>
            </div>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              API Key 与查询 Cookie 均不会写入 localStorage、URL 或子号请求；使用时由后端读取。
            </Typography.Text>
          </Space>
        </Spin>
      </Modal>

      <Modal
        title="NV 出库核对结果"
        open={businessChildNvSalesResultOpen && Boolean(businessChildNvSalesResult)}
        width={900}
        onCancel={() => setBusinessChildNvSalesResultOpen(false)}
        footer={<Button type="primary" onClick={() => setBusinessChildNvSalesResultOpen(false)}>关闭</Button>}
      >
        {businessChildNvSalesResult && (() => {
          const result = businessChildNvSalesResult
          return (
            <Space direction="vertical" size={12} style={{ width: '100%' }} data-nvtokens-sales-result="true">
              <Typography.Text strong>{businessChildNvSalesSummary(result)}</Typography.Text>
              <Typography.Text type="secondary">核对范围：全部已确认 NV 上架的本地记录，含已出售订单的退款复核；不受母号状态、Dead、当前搜索或筛选条件影响。</Typography.Text>
              <Typography.Text type="secondary">本次更新出售状态 {result.sold_updated} 条 · 质保到期可删除 {result.deletion_ready} 条</Typography.Text>
              {!result.classified && (
                <Alert
                  type="warning"
                  showIcon
                  message="当前后端未提供库存分类"
                  description="旧版本只返回未匹配总数，无法区分待售、远端未找到和需复核。请重启更新后的后端，再手动刷新出库状态。"
                />
              )}
              {result.classified && !result.legacy_classified && (
                <Alert
                  type="warning"
                  showIcon
                  message="当前后端 NV 上架核验尚未升级"
                  description="本次返回缺少 NV 上架确认分类，不能据此判定 NV 异常。请重启更新后的后端，再手动刷新出库状态。"
                />
              )}
              {result.classified && result.legacy_classified && Number(result.not_found) > 0 && (
                <Alert
                  type="warning"
                  showIcon
                  message={`本次有 ${result.not_found} 条记录未找到对应的 NV 上架记录，请查看下方明细`}
                  description="未找到对应上架记录不等于已出库；这些账号保留原有本地上架状态，不会自动下架，也不会自动重试上架。"
                />
              )}
              <Table<BusinessChildNvSalesDetail>
                size="small"
                rowKey={(item) => `${item.membership_id}:${item.email}`}
                dataSource={result.details}
                pagination={result.details.length > 10 ? { pageSize: 10, showSizeChanger: false } : false}
                scroll={{ x: 720, y: 420 }}
                columns={[
                  {
                    title: '子号邮箱', dataIndex: 'email', width: 290,
                    render: (email: string) => <Typography.Text code copyable={Boolean(email)}>{email || '未记录邮箱'}</Typography.Text>,
                  },
                  {
                    title: '查询状态', dataIndex: 'status', width: 170,
                    filters: Object.entries(BUSINESS_CHILD_NV_SALES_STATUS_LABELS).map(([value, text]) => ({ value, text })),
                    onFilter: (value, item) => item.status === value,
                    render: (status: BusinessChildNvSalesStatus) => (
                      <Tag color={status === 'sold' ? 'success' : status === 'pending_sale' ? 'blue' : status === 'not_found' || status === 'needs_review' ? 'warning' : 'default'}>
                        {BUSINESS_CHILD_NV_SALES_STATUS_LABELS[status]}
                      </Tag>
                    ),
                  },
                  {
                    title: '说明', dataIndex: 'reason',
                    render: (reason: string) => <Typography.Text>{reason || '—'}</Typography.Text>,
                  },
                ]}
                locale={{ emptyText: result.classified ? '本次没有待核对的已确认 NV 上架记录' : '当前后端未提供账号分类明细' }}
              />
            </Space>
          )
        })()}
      </Modal>

      <Modal
        title="上架 NexusVault"
        open={Boolean(businessChildNvListingTarget)}
        width={540}
        okText="确认上架"
        cancelText="取消"
        maskClosable={!businessChildNvListingSaving}
        closable={!businessChildNvListingSaving}
        confirmLoading={businessChildNvListingSaving}
        okButtonProps={{
          disabled: businessChildNvPriceDraft == null
            || !Number.isFinite(Number(businessChildNvPriceDraft))
            || Number(businessChildNvPriceDraft) <= 0
            || (businessChildNvNeedsWarranty && !businessChildNvWarrantyUntil(businessChildNvWarrantyUntilDraft)),
        }}
        onOk={() => { void saveBusinessChildNvListing() }}
        onCancel={() => {
          if (!businessChildNvListingSaving) setBusinessChildNvListingTarget(null)
        }}
      >
        {businessChildNvListingTarget && (
          <Space
            direction="vertical"
            size={16}
            style={{ width: '100%' }}
            data-business-child-nv-listing-modal="true"
          >
            <Alert
              type="info"
              showIcon
              message={businessChildNvListingTarget.child.email || 'BUSINESS 子号'}
              description={`所属母号：${businessChildNvListingTarget.account.email || `#${businessChildNvListingTarget.account.id}`}`}
            />
            <div>
              <Typography.Text strong>上架价格</Typography.Text>
              <InputNumber
                autoFocus
                min={0.01}
                max={1_000_000}
                precision={2}
                step={0.01}
                value={businessChildNvPriceDraft}
                disabled={businessChildNvListingSaving}
                placeholder="请输入价格"
                addonBefore="¥"
                addonAfter="人民币"
                style={{ width: '100%', marginTop: 6 }}
                onChange={(value) => setBusinessChildNvPriceDraft(
                  value == null ? null : Number(value),
                )}
              />
            </div>
            {businessChildNvNeedsWarranty ? <BusinessChildNvWarrantyInput value={businessChildNvWarrantyUntilDraft}
              disabled={businessChildNvListingSaving} onChange={setBusinessChildNvWarrantyUntilDraft} /> : <div>
              <Typography.Text strong>质保时长</Typography.Text>
              <InputNumber
                precision={0}
                value={1}
                disabled
                addonAfter="小时"
                style={{ width: '100%', marginTop: 6 }}
              />
              <Typography.Text type="secondary" style={{ display: 'block', marginTop: 6, fontSize: 12 }}>
                普通 TEAM 为“质保首登（1小时）”。
              </Typography.Text>
            </div>}
            <Alert
              type="warning"
              showIcon
              message="确认后将真实入池"
              description="后端会依次上传 SUB 凭证、绑定邮箱密码与长期 2FA 密钥，并按当前价格入池。只有 NV 明确返回发布成功后，本地状态才会改为“已上架”；NV API Key 仅保存在后端，不会传到浏览器。"
            />
          </Space>
        )}
      </Modal>

      <Modal
        title="批量上架 NV"
        open={Boolean(businessChildNvBatchTargets)}
        width={580}
        okText="确认批量上架"
        cancelText="取消"
        confirmLoading={businessChildNvBatchStarting}
        maskClosable={!businessChildNvBatchStarting}
        closable={!businessChildNvBatchStarting}
        okButtonProps={{ disabled: businessChildNvBatchPriceDraft == null
          || !Number.isFinite(Number(businessChildNvBatchPriceDraft))
          || Number(businessChildNvBatchPriceDraft) < 0.01
          || Number(businessChildNvBatchPriceDraft) > 1_000_000
          || (businessChildNvBatchNeedsWarranty && !businessChildNvWarrantyUntil(businessChildNvBatchWarrantyUntilDraft)) }}
        onOk={() => { void startBusinessChildNvBatchListing() }}
        onCancel={() => { if (!businessChildNvBatchStarting) setBusinessChildNvBatchTargets(null) }}
      >
        <Space direction="vertical" size={16} style={{ width: '100%' }} data-business-child-nv-batch-settings="true">
          <Typography.Text strong>已选择 {businessChildNvBatchTargets?.length || 0} 个子号</Typography.Text>
          <div style={{ maxHeight: 180, overflow: 'auto' }}>
            {businessChildNvBatchTargets?.map((item) => (
              <div key={item.membership_id}><Typography.Text code>{item.email}</Typography.Text></div>
            ))}
          </div>
          <div>
            <Typography.Text strong>统一上架价格（每个账号）</Typography.Text>
            <InputNumber
              autoFocus
              aria-label="批量 NV 上架价格"
              min={0.01}
              max={1_000_000}
              precision={2}
              step={0.01}
              value={businessChildNvBatchPriceDraft}
              disabled={businessChildNvBatchStarting}
              placeholder="请输入价格"
              addonBefore="¥"
              addonAfter="人民币"
              style={{ width: '100%', marginTop: 6 }}
              onChange={(value) => setBusinessChildNvBatchPriceDraft(value == null ? null : Number(value))}
            />
          </div>
          {businessChildNvBatchNeedsWarranty ? <BusinessChildNvWarrantyInput value={businessChildNvBatchWarrantyUntilDraft}
            disabled={businessChildNvBatchStarting} onChange={setBusinessChildNvBatchWarrantyUntilDraft} /> : <div>
            <Typography.Text strong>质保时长</Typography.Text>
            <InputNumber value={1} disabled addonAfter="小时" style={{ width: '100%', marginTop: 6 }} />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>普通 TEAM 为“质保首登（1小时）”。</Typography.Text>
          </div>}
          <Alert
            type="info"
            showIcon
            message="确认后逐个上架，单号失败后继续下一个"
            description="所有选中子号使用相同价格，5X 使用本次填写的截止时间；已上架、已售出或不符合条件的账号将显示具体结果。提交后可关闭进度窗口，后台继续执行。"
          />
        </Space>
      </Modal>

      <Modal
        title="批量上架 NV · 任务进度"
        open={businessChildNvBatchTaskOpen && Boolean(businessChildNvBatchTask)}
        width={940}
        onCancel={() => setBusinessChildNvBatchTaskOpen(false)}
        footer={(
          <Space>
            {businessChildNvBatchPollingStopped && (
              <Button onClick={() => {
                setBusinessChildNvBatchPollingStopped(false)
                setBusinessChildNvBatchPollingError('')
                setBusinessChildNvBatchPollEpoch((current) => current + 1)
              }}>重试读取进度</Button>
            )}
            {(businessChildNvBatchTask?.status !== 'running' || businessChildNvBatchUnavailable) && (
              <Button onClick={() => {
                try { sessionStorage.removeItem(BUSINESS_CHILD_NV_BATCH_TASK_STORAGE_KEY) } catch { /* ignore */ }
                setBusinessChildNvBatchTask(null)
                setBusinessChildNvBatchTaskOpen(false)
                setBusinessChildNvBatchPollingError('')
                setBusinessChildNvBatchPollingStopped(false)
                setBusinessChildNvBatchUnavailable(false)
              }}>清除此任务记录</Button>
            )}
            <Button type="primary" onClick={() => setBusinessChildNvBatchTaskOpen(false)}>
              {businessChildNvBatchTask?.status === 'running' && !businessChildNvBatchUnavailable ? '关闭，后台继续执行' : '关闭'}
            </Button>
          </Space>
        )}
      >
        {businessChildNvBatchTask && (() => {
          const task = businessChildNvBatchTask
          const hasFailures = task.status === 'failed' || task.failed > 0
          const running = task.status === 'running'
          return (
            <Space direction="vertical" size={12} style={{ width: '100%' }} data-business-child-nv-batch-task="true">
              <Card size="small">
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Space wrap>
                    <Tag color={businessChildNvBatchPollingStopped ? 'warning' : running ? 'processing' : hasFailures ? 'error' : 'success'}>
                      {businessChildNvBatchPollingStopped ? '进度读取已暂停'
                        : running ? '逐个上架中' : hasFailures ? '处理结束，有失败项' : '处理完成'}
                    </Tag>
                    <Typography.Text strong>已完成 {task.completed}/{task.total || '—'}</Typography.Text>
                    <Typography.Text type="secondary">成功 {task.succeeded} · 失败 {task.failed} · 跳过 {task.skipped}</Typography.Text>
                  </Space>
                  <Progress
                    percent={task.percent}
                    status={businessChildNvBatchPollingStopped ? 'normal' : hasFailures ? 'exception' : running ? 'active' : 'success'}
                  />
                </Space>
              </Card>
              {businessChildNvBatchPollingError && <Alert type="warning" showIcon message={businessChildNvBatchPollingError} />}
              {task.error && <Alert type="error" showIcon message="任务错误" description={task.error} />}
              <Typography.Text type="secondary">点击账号行或展开按钮查看该账号日志；关闭窗口后可从页面顶部“批量 NV”查看进度。</Typography.Text>
              <Table<BusinessChildNvBatchItem>
                size="small"
                pagination={false}
                rowKey="membership_id"
                dataSource={task.items}
                scroll={{ x: 700, y: 420 }}
                expandable={{
                  expandRowByClick: true,
                  expandedRowRender: (item) => (
                    <pre style={{ margin: 0, maxHeight: 260, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                      {item.logs.join('\n') || '暂无日志'}
                    </pre>
                  ),
                }}
                columns={[
                  { title: '子号', dataIndex: 'email', width: 270, render: (email: string) => <Typography.Text code>{email || '未知子号'}</Typography.Text> },
                  {
                    title: '状态', key: 'status', width: 120,
                    render: (_: unknown, item: BusinessChildNvBatchItem) => (
                      <Tag color={businessBatchStatusColor(item.status)}>{businessChildNvBatchStatusLabel(item.status)}</Tag>
                    ),
                  },
                  {
                    title: '进度 / 原因', key: 'result',
                    render: (_: unknown, item: BusinessChildNvBatchItem) => (
                      <Space direction="vertical" size={2}>
                        <Typography.Text>{item.stage || businessChildNvBatchStatusLabel(item.status)}</Typography.Text>
                        {item.error && <Typography.Text type={item.status === 'failed' ? 'danger' : 'secondary'}>{item.error}</Typography.Text>}
                      </Space>
                    ),
                  },
                ]}
                locale={{ emptyText: businessChildNvBatchPollingStopped ? '暂未读取到账号明细，请重试读取进度' : '正在读取账号明细' }}
              />
              <Collapse size="small" items={[{
                key: 'logs', label: `任务日志（${task.logs.length}）`,
                children: <pre style={{ maxHeight: 240, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{task.logs.join('\n') || '暂无日志'}</pre>,
              }]} />
            </Space>
          )
        })()}
      </Modal>

      <Modal
        title={businessChildBatchTask?.action === 'oauth' ? '批量获取子号 RT'
          : businessChildBatchTask?.action === 'leave_workspace' ? '批量退出 BUSINESS 空间' : '批量设置子号密码与 2FA'}
        open={businessChildBatchTaskOpen && Boolean(businessChildBatchTask)}
        width={940}
        maskClosable={false}
        destroyOnHidden={false}
        onCancel={() => setBusinessChildBatchTaskOpen(false)}
        footer={businessChildBatchTask && !businessChildBatchTaskRunning ? (
          <Space>
            <Button
              onClick={() => {
                try { localStorage.removeItem(BUSINESS_CHILD_BATCH_TASK_STORAGE_KEY) } catch { /* ignore */ }
                businessChildBatchGenerationRef.current += 1
                setBusinessChildBatchTask(null)
                setBusinessChildBatchTaskOpen(false)
              }}
            >
              清除此任务记录
            </Button>
            <Button type="primary" onClick={() => setBusinessChildBatchTaskOpen(false)}>关闭</Button>
          </Space>
        ) : (
          <Button type="primary" onClick={() => setBusinessChildBatchTaskOpen(false)}>
            后台继续执行并关闭
          </Button>
        )}
      >
        {businessChildBatchTask && (() => {
          const task = businessChildBatchTask
          const failed = task.status === 'failed' || String(task.outcome || '').toLowerCase() === 'failed'
          const partial = String(task.outcome || '').toLowerCase() === 'partial'
            || (!failed && task.progress.failed > 0)
          const terminal = ['done', 'failed', 'completed', 'success'].includes(task.status)
          const actionLabel = businessChildBatchActionLabel(task.action)
          const stepKeys = task.action === 'leave_workspace' ? ['leave_workspace', 'remove']
            : task.action === 'oauth' ? ['oauth', 'rt'] : ['setup_security', 'security']
          return (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="info"
                showIcon
                message={`严格串行：一个子号完成${actionLabel}后，再处理下一个`}
                description={task.action === 'leave_workspace'
                  ? '后端会重新核验成员归属；退出结果暂未确认时使用原操作编号自动核对并继续。任务已持久化，关闭窗口或重启服务不会丢失进度。'
                  : '前端提示仅用于快速筛选；任务执行时后端会重新核验成员归属、账号状态与操作资格。关闭窗口不会中止后台任务。'}
              />
              <Card size="small">
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Space wrap>
                    <Tag color={failed ? 'error' : partial ? 'warning' : terminal ? 'success' : 'processing'}>
                      {failed ? '任务失败' : partial ? '部分完成' : terminal ? '处理完成' : '逐个处理中'}
                    </Tag>
                    <Typography.Text strong>
                      已完成 {task.progress.completed}/{task.progress.total || '—'}
                    </Typography.Text>
                    <Typography.Text type="secondary">
                      成功 {task.progress.success} · 失败 {task.progress.failed} · 跳过 {task.progress.skipped}
                    </Typography.Text>
                    {task.action === 'setup_security' && (
                      <Tag>
                        2FA 浏览器：{task.browserMode === 'headed' ? '有头' : '无头'}
                      </Tag>
                    )}
                    {task.action === 'leave_workspace' && Boolean(task.attempts) && (
                      <Tag>执行第 {task.attempts} 轮</Tag>
                    )}
                    {!terminal && task.nextRetryAt && (
                      <Typography.Text type="warning">
                        下次自动核对：{formatTime(task.nextRetryAt)}
                      </Typography.Text>
                    )}
                  </Space>
                  <Progress
                    percent={task.progress.percent}
                    status={failed ? 'exception' : partial ? 'normal' : terminal ? 'success' : 'active'}
                    strokeColor={partial ? token.colorWarning : undefined}
                  />
                </Space>
              </Card>
              {task.pollingError && (
                <Alert type="warning" showIcon message="状态读取暂时失败，正在自动重试" description={task.pollingError} />
              )}
              {task.error && <Alert type="error" showIcon message="任务错误" description={task.error} />}
              <Table<BusinessChildBatchActionItem>
                size="small"
                pagination={false}
                rowKey={(item) => item.membershipId}
                dataSource={task.items}
                scroll={{ x: 760 }}
                columns={[
                  {
                    title: '子号',
                    dataIndex: 'email',
                    width: 250,
                    render: (value: string) => <Typography.Text code>{value || '未知子号'}</Typography.Text>,
                  },
                  {
                    title: '状态',
                    key: 'status',
                    width: 130,
                    render: (_: unknown, item: BusinessChildBatchActionItem) => (
                      <Tag color={businessBatchStatusColor(item.status)}>
                        {task.action === 'leave_workspace'
                          ? ['success', 'succeeded'].includes(item.status) ? '已退出空间'
                            : ['failed', 'error'].includes(item.status) ? '退出失败'
                              : ['running', 'processing'].includes(item.status) ? '退出中'
                                : item.status === 'skipped' ? '已跳过' : '排队中'
                          : item.statusLabel === '邀请成功' && ['success', 'succeeded'].includes(item.status)
                          ? `${actionLabel}成功`
                          : item.statusLabel}
                      </Tag>
                    ),
                  },
                  {
                    title: '当前步骤',
                    key: 'step',
                    width: 210,
                    render: (_: unknown, item: BusinessChildBatchActionItem) => {
                      const candidates = stepKeys.map((key) => item.steps[key]).filter(Boolean)
                      const step = candidates.find((candidate) => ['running', 'processing', 'queued', 'pending'].includes(candidate.status))
                        || candidates.find((candidate) => ['failed', 'error'].includes(candidate.status))
                        || [...candidates].reverse().find((candidate) => candidate.status !== 'not_requested')
                        || candidates[0]
                        || Object.values(item.steps)[0]
                      return step ? (
                        <Tooltip title={step.error || step.label}>
                          <Tag color={businessBatchStatusColor(step.status)}>{step.label}</Tag>
                        </Tooltip>
                      ) : <Typography.Text type="secondary">等待开始</Typography.Text>
                    },
                  },
                  {
                    title: '结果 / 日志',
                    key: 'result',
                    render: (_: unknown, item: BusinessChildBatchActionItem) => (
                      <Space direction="vertical" size={2}>
                        {item.error && <Typography.Text type="danger">{item.error}</Typography.Text>}
                        {item.logs.length ? (
                          <Popover
                            trigger="click"
                            title={`${item.email || '子号'} · 执行日志`}
                            content={<pre style={{ maxWidth: 520, maxHeight: 280, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{item.logs.join('\n')}</pre>}
                          >
                            <Button type="link" size="small">查看日志（{item.logs.length}）</Button>
                          </Popover>
                        ) : !item.error && <Typography.Text type="secondary">—</Typography.Text>}
                      </Space>
                    ),
                  },
                ]}
                locale={{ emptyText: businessChildBatchTaskRunning ? <Spin tip="正在生成子号任务清单" /> : '没有账号明细' }}
              />
              <Collapse
                size="small"
                items={[{
                  key: 'logs',
                  label: `任务日志（${task.logs.length}）`,
                  children: (
                    <pre style={{
                      margin: 0,
                      maxHeight: 240,
                      overflow: 'auto',
                      padding: 10,
                      borderRadius: 6,
                      background: token.colorFillQuaternary,
                      color: token.colorText,
                      whiteSpace: 'pre-wrap',
                      overflowWrap: 'anywhere',
                      fontSize: 12,
                    }}>
                      {task.logs.length ? task.logs.join('\n') : '等待任务日志…'}
                    </pre>
                  ),
                }]}
              />
            </Space>
          )
        })()}
      </Modal>

      <Modal
        title="批量邀请子号"
        open={businessBatchInviteTaskOpen && Boolean(businessBatchInviteTask)}
        width={980}
        maskClosable={false}
        destroyOnHidden={false}
        onCancel={() => setBusinessBatchInviteTaskOpen(false)}
        footer={businessBatchInviteTask && !businessBatchTaskRunning ? (
          <Space>
            <Button
              onClick={() => {
                try { localStorage.removeItem(BUSINESS_BATCH_INVITE_TASK_STORAGE_KEY) } catch { /* ignore */ }
                businessBatchInviteGenerationRef.current += 1
                setBusinessBatchInviteTask(null)
                setBusinessBatchInviteTaskOpen(false)
              }}
            >
              清除此任务记录
            </Button>
            <Button type="primary" onClick={() => setBusinessBatchInviteTaskOpen(false)}>关闭</Button>
          </Space>
        ) : (
          <Button type="primary" onClick={() => setBusinessBatchInviteTaskOpen(false)}>
            后台继续执行并关闭
          </Button>
        )}
      >
        {businessBatchInviteTask && (() => {
          const task = businessBatchInviteTask
          const outcome = String(task.outcome || '').trim().toLowerCase()
          const failedOutcome = task.status === 'failed' || outcome === 'failed'
          const partialOutcome = outcome === 'partial'
          const terminal = ['done', 'failed'].includes(task.status)
          const progressStatus = failedOutcome
            ? 'exception' as const
            : terminal ? 'success' as const : 'active' as const
          return (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="info"
                showIcon
                message={task.workflow === 'prepare_then_batch'
                  ? `先并发准备全部 Gmail 子号 · ${businessSeatTypeLabel(task.seatType)}`
                  : `母号按任务清单顺序逐个处理 · 子号邮箱类型：${businessInviteMailProviderLabel(task.candidateMailProvider)}`}
                description={task.workflow === 'prepare_then_batch'
                  ? '每个待注册子号绑定不同的可用代理，并发完成密码注册与 Authenticator 2FA；全部准备成功后统一批量邀请，随后自动逐个获取 RT。失败会从数据库已确认阶段自动继续，服务重启后也会恢复。'
                  : `同一时间只处理一个母号，不会并发发送邀请。${standalone ? '从可用的 Gmail 普通账号中自动选号；没有符合条件的账号时等待补充' : task.candidateMailProvider === 'auto'
                  ? '每次按实际席位和共享默认邮箱配置选择新子号；已选中的子号保持原来源，准备号优先、同邮箱类型普通号补充，缺货时等待补充'
                  : `只会在 ${businessInviteMailProviderLabel(task.candidateMailProvider)} 候选中自动选号，准备号优先、不足时同类型普通号补充；不可用或 Dead 候选只会换用同类型候选，不会跨邮箱类型`
                }。每个子号顺序执行邀请${task.postSetupSecurity ? '、检查密码 / 2FA（已完成则跳过）' : ''}${task.postAcquireRt ? '、获取 RT' : ''}，完成后才处理下一个。关闭窗口后任务会在当前服务进程中继续执行。`}
              />
              <Card size="small">
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Space wrap style={{ justifyContent: 'space-between', width: '100%' }}>
                    <Space wrap>
                      <Tag color={failedOutcome ? 'error' : partialOutcome ? 'warning' : terminal ? 'success' : 'processing'}>
                        {failedOutcome
                          ? '全部失败'
                          : partialOutcome ? '部分完成' : terminal ? '已完成' : '顺序执行中'}
                      </Tag>
                      <Tag color="blue">
                        子号邮箱类型：{businessInviteMailProviderLabel(task.candidateMailProvider)}
                      </Tag>
                      {task.postSetupSecurity && (
                        <Tag>
                          2FA 浏览器：{task.securityBrowserMode === 'headed' ? '有头' : '无头'}
                        </Tag>
                      )}
                      {task.workflow === 'prepare_then_batch' && task.phase && (
                        <Tag color={task.phase === 'retry' ? 'warning' : 'processing'}>
                          阶段：{{ prepare: '准备子号', invite: '批量邀请', rt: '获取 RT', retry: '等待重试', done: '已完成', failed: '失败' }[task.phase] || task.phase}
                        </Tag>
                      )}
                      {task.workflow === 'prepare_then_batch' && Boolean(task.attempts) && (
                        <Tag>执行第 {task.attempts} 轮</Tag>
                      )}
                      <Typography.Text strong>
                        母号 {task.progress.completed_mothers}/{task.progress.total_mothers || '—'}
                      </Typography.Text>
                      <Typography.Text type="secondary">
                        邀请成功 {task.progress.successful_invites}
                        {' · '}后处理异常 {task.progress.partial_invites}
                        {' · '}失败 {task.progress.failed_invites}
                        {' · '}跳过 {task.progress.skipped_invites}
                      </Typography.Text>
                    </Space>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {task.taskId ? `任务 ${task.taskId}` : '正在创建任务'}
                    </Typography.Text>
                  </Space>
                  <Progress
                    percent={task.progress.percent}
                    status={progressStatus}
                    format={(percent) => `${percent || 0}%`}
                  />
                  <Space wrap>
                    <Typography.Text type="secondary">当前母号：</Typography.Text>
                    {task.currentAccountEmail ? (
                      <Typography.Text code>{task.currentAccountEmail}</Typography.Text>
                    ) : terminal ? (
                      <Typography.Text>无</Typography.Text>
                    ) : (
                      <Typography.Text>等待开始下一母号</Typography.Text>
                    )}
                    {task.startedAt && (
                      <Typography.Text type="secondary">开始：{formatTime(task.startedAt)}</Typography.Text>
                    )}
                    {task.finishedAt && (
                      <Typography.Text type="secondary">完成：{formatTime(task.finishedAt)}</Typography.Text>
                    )}
                    {!terminal && task.nextRetryAt && (
                      <Typography.Text type="warning">下次自动重试：{formatTime(task.nextRetryAt)}</Typography.Text>
                    )}
                  </Space>
                </Space>
              </Card>
              {task.pollingError && (
                <Alert
                  type="warning"
                  showIcon
                  message="状态读取暂时失败，正在自动重试"
                  description={task.pollingError}
                />
              )}
              {task.error && <Alert type="error" showIcon message="任务错误" description={task.error} />}
              <div>
                <Typography.Title level={5} style={{ margin: '0 0 8px' }}>母号处理进度</Typography.Title>
                {task.mothers.length ? (
                  <Collapse
                    accordion
                    size="small"
                    items={task.mothers.map((mother) => ({
                      key: String(mother.account_id),
                      label: (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', width: '100%' }}>
                          <Typography.Text code style={{ minWidth: 220 }}>{mother.email}</Typography.Text>
                          <Tag color={businessBatchStatusColor(mother.status)} style={{ margin: 0 }}>
                            {mother.status_label || businessBatchStatusLabel(mother.status)}
                          </Tag>
                          <Progress
                            percent={mother.percent}
                            size="small"
                            status={mother.status === 'failed' ? 'exception' : undefined}
                            style={{ flex: '1 1 180px', minWidth: 150, maxWidth: 260, margin: 0 }}
                          />
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            计划 {mother.planned_invites}
                            {' · '}完成 {mother.completed_invites}
                            {' · '}成功 {mother.successful_invites}
                            {' · '}后处理异常 {mother.partial_invites}
                            {' · '}失败 {mother.failed_invites}
                            {' · '}跳过 {mother.skipped_invites}
                          </Typography.Text>
                        </div>
                      ),
                      children: (
                        <Space direction="vertical" size={8} style={{ width: '100%' }}>
                          {mother.current_invite && (
                            <Alert
                              type="info"
                              showIcon
                              message={`当前邀请：${mother.current_invite.email || `第 ${mother.current_invite.index || 1} 个子号`}`}
                              description={mother.current_invite.status_label || businessBatchStatusLabel(mother.current_invite.status)}
                            />
                          )}
                          {mother.error && <Alert type="error" showIcon message="该母号处理失败" description={mother.error} />}
                          <Table<BusinessBatchInvitationProgress>
                            rowKey={(invitation) => `${mother.account_id}-${invitation.index}-${invitation.pro_account_id || invitation.email || 'pending'}`}
                            size="small"
                            pagination={false}
                            dataSource={mother.invitations}
                            columns={[
                              {
                                title: '序号',
                                dataIndex: 'index',
                                width: 70,
                                render: (value: number) => value || '—',
                              },
                              {
                                title: '子号',
                                dataIndex: 'email',
                                render: (value?: string) => value
                                  ? <Typography.Text code>{value}</Typography.Text>
                                  : <Typography.Text type="secondary">自动选择中</Typography.Text>,
                              },
                              {
                                title: '状态',
                                key: 'status',
                                width: 130,
                                render: (_: unknown, invitation: BusinessBatchInvitationProgress) => (
                                  <Tag color={businessBatchStatusColor(invitation.status)}>
                                    {invitation.status_label || businessBatchStatusLabel(invitation.status)}
                                  </Tag>
                                ),
                              },
                              {
                                title: '步骤',
                                key: 'steps',
                                width: 340,
                                render: (_: unknown, invitation: BusinessBatchInvitationProgress) => {
                                  const orderedSteps = task.workflow === 'prepare_then_batch'
                                    ? ([['prepare', '注册 / 密码 / 2FA'], ['invite', '统一邀请'], ['rt', 'RT']] as const)
                                    : ([['invite', '邀请'], ['security', '密码与 2FA'], ['rt', 'RT']] as const)
                                  return (
                                    <Space size={4} wrap>
                                      {orderedSteps.map(([key, label]) => {
                                        const step = invitation.steps[key]
                                        const presentation = businessBatchStepPresentation(key, step)
                                        return (
                                          <Tooltip key={key} title={step?.error || presentation.label}>
                                            <Tag color={presentation.color} style={{ margin: 0 }}>
                                              {label} · {presentation.label}
                                            </Tag>
                                          </Tooltip>
                                        )
                                      })}
                                    </Space>
                                  )
                                },
                              },
                              {
                                title: '结果',
                                key: 'result',
                                width: 260,
                                render: (_: unknown, invitation: BusinessBatchInvitationProgress) => invitation.error
                                  ? <Typography.Text type="danger">{invitation.error}</Typography.Text>
                                  : <Typography.Text type="secondary">{invitation.finished_at ? formatTime(invitation.finished_at) : '—'}</Typography.Text>,
                              },
                            ]}
                            locale={{ emptyText: '尚未生成邀请明细' }}
                          />
                        </Space>
                      ),
                    }))}
                  />
                ) : (
                  <div style={{ padding: 20, textAlign: 'center' }}>
                    {businessBatchTaskRunning ? <Spin tip="正在生成母号执行清单" /> : <Empty description="没有母号处理明细" />}
                  </div>
                )}
              </div>
              <Collapse
                size="small"
                defaultActiveKey={['logs']}
                items={[{
                  key: 'logs',
                  label: `实时任务日志（${task.logs.length}）`,
                  children: (
                    <pre style={{
                      margin: 0,
                      maxHeight: 260,
                      overflow: 'auto',
                      padding: 10,
                      borderRadius: 6,
                      background: token.colorFillQuaternary,
                      color: token.colorText,
                      whiteSpace: 'pre-wrap',
                      overflowWrap: 'anywhere',
                      fontSize: 12,
                    }}>
                      {task.logs.length ? task.logs.join('\n') : '等待任务日志…'}
                    </pre>
                  ),
                }]}
              />
            </Space>
          )
        })()}
      </Modal>

      <Modal
        title={`邀请子号${businessInviteAccount?.email ? ` · ${businessInviteAccount.email}` : ''}`}
        open={!!businessInviteAccount}
        width={720}
        maskClosable={false}
        okText={standalone ? '开始准备并批量邀请' : '发送邀请'}
        confirmLoading={businessInviting}
        okButtonProps={{
          disabled: businessInviteSubmitDisabled,
        }}
        onOk={() => { void submitBusinessInvite() }}
        onCancel={() => {
          if (businessInviting) return
          setBusinessInviteAccount(null)
          setBusinessInviteManualEmail('')
        }}
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          {businessInviteView?.loading && !businessInviteView.snapshot ? (
            <div style={{ textAlign: 'center', padding: 16 }}><Spin tip="正在读取数据库席位与成员快照" /></div>
          ) : (
            <Space wrap>
              <Tag color={activeBusinessInviteState.disabled ? 'warning' : 'success'}>
                席位状态：可用 {nonNegativeNumber(businessInviteSeat?.available) ?? '未知'}
              </Tag>
              {businessInviteQuota && <div data-business-invite-modal-quota="true">
                <BusinessInviteQuotaSummary quota={businessInviteQuota} />
              </div>}
              {businessInviteCooldown.active && (
                <Tooltip title={businessInviteCooldownReasonLabel(businessInviteCooldown.reason)}>
                  <Tag color="orange">
                    邀请失败冷却 · {businessInviteCooldownCountdown(
                      businessInviteCooldown.until,
                      replenishmentNow,
                    )}
                  </Tag>
                </Tooltip>
              )}
            </Space>
          )}
          {businessInviteView?.error && <Alert type="error" showIcon message={businessInviteView.error} />}
          {activeBusinessInviteState.disabled && !businessInviteView?.loading && (
            <Alert
              type="warning"
              showIcon
              message={activeBusinessInviteState.reason}
            />
          )}
          {businessInviteProgress.stage !== 'idle' && (
            <Alert
              type={businessInviteProgress.stage === 'failed' ? 'error' : businessInviteProgress.stage === 'success' ? 'success' : 'info'}
              showIcon
              message={(() => {
                switch (businessInviteProgress.stage) {
                  case 'preflight': return '阶段 1/3：复核邀请条件'
                  case 'inviting': return '阶段 2/3：核验并发送邀请'
                  case 'refreshing': return '阶段 3/3：确认成员与席位'
                  case 'success': return '邀请流程已完成'
                  case 'failed': return '邀请流程已停止'
                  default: return '等待开始'
                }
              })()}
              description={businessInviteProgress.detail || (businessInviting ? '正在处理…' : '可重新发起邀请')}
            />
          )}
          {standalone ? (
            <Space direction="vertical" size={12} style={{ width: '100%' }} data-prepared-batch-invite="true">
              <div>
                <Typography.Text strong>子号席位类型</Typography.Text>
                <div style={{ marginTop: 8 }}>
                  <Segmented
                    value={businessInviteSeatType}
                    options={[
                      { value: 'default', label: `普通席位（剩余 ${businessInviteOrdinaryAvailable}）`, disabled: businessInviteOrdinaryAvailable <= 0 },
                      { value: 'prolite', label: `高级席位（剩余 ${businessInviteAdvancedAvailable}）`, disabled: businessInviteAdvancedAvailable <= 0 },
                    ]}
                    onChange={(value) => {
                      const next = value as BusinessSeatType
                      const available = next === 'prolite' ? businessInviteAdvancedAvailable : businessInviteOrdinaryAvailable
                      setBusinessInviteSeatType(next)
                      setBusinessInviteCount((current) => Math.max(1, Math.min(current, available || 1)))
                    }}
                  />
                </div>
              </div>
              <div>
                <Typography.Text strong>子号数量</Typography.Text>
                <InputNumber
                  min={1}
                  max={Math.max(1, businessInviteSelectedTypeAvailable)}
                  value={businessInviteCount}
                  disabled={businessInviteSelectedTypeAvailable <= 0}
                  style={{ width: '100%', marginTop: 8 }}
                  onChange={(value) => setBusinessInviteCount(Math.max(1, Number(value) || 1))}
                />
              </div>
              <Alert
                type="info"
                showIcon
                message="先准备全部子号，再统一批量邀请"
                description="系统自动选择 Gmail 子号。未注册的子号会分别使用不同的已检测代理并发完成密码注册和 Authenticator 2FA；全部准备成功后母号只调用一次批量邀请接口，随后自动逐个获取 RT。任务和阶段进度会持久保存，服务重启后继续。"
              />
            </Space>
          ) : <>
          <Space wrap>
            <Segmented
              value={businessInviteMode}
              options={standalone ? [{ label: 'Gmail 普通账号（支持 RT）', value: 'pool' }] : [
                { label: '健康未占用账号（支持 RT）', value: 'pool' },
                { label: '手动输入邮箱（不支持 RT）', value: 'manual' },
              ]}
              onChange={(value) => {
                setBusinessInviteMode(value as 'pool' | 'manual')
                setBusinessInviteSelectedChildId(undefined)
                setBusinessInviteManualEmail('')
              }}
            />
            {businessInviteMode === 'pool' && (
              <Tag color="blue">{standalone ? "Gmail 普通账号" : "准备号优先 · 普通号补充"}</Tag>
            )}
          </Space>
          {businessInviteMode === 'pool' ? (
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <Segmented
                value={businessInviteMailProvider}
                options={standalone ? [{ value: 'gmail', label: 'Gmail' }] : BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS}
                onChange={(value) => {
                  const nextProvider = value as BusinessInviteMailProvider
                  setBusinessInviteMailProvider(nextProvider)
                  setBusinessInviteSelectedChildId((currentId) => {
                    if (!currentId) return undefined
                    const selected = businessInviteCandidates.find((child) => (
                      Number(child.pro_account_id) === currentId
                    ))
                    return selected && businessInviteCandidateMatchesProvider(selected, nextProvider, businessInviteTargetSeatType, seatMailDefaults)
                      ? currentId
                      : undefined
                  })
                }}
              />
              <Typography.Text type="secondary">{businessInviteMailProviderHint(businessInviteMailProvider, businessInviteTargetSeatType, seatMailDefaults)}</Typography.Text>
              {!standalone && <BusinessInviteMailProviderSettings />}
              <Select
                showSearch
                allowClear
                optionFilterProp="label"
                loading={businessInviteCandidatesLoading}
                disabled={businessInviteMailProvider === 'auto' && !businessInviteTargetSeatType}
                placeholder={businessInviteCandidatesLoading
                  ? '正在加载可选子号…'
                  : businessInviteMailProvider === 'auto' && !businessInviteTargetSeatType
                    ? '本次席位待确认，将由后端按实际席位选择子号'
                    : '留空自动选择子号，也可指定一个候选子号'}
                value={businessInviteSelectedChildId}
                onChange={(value) => {
                  setBusinessInviteSelectedChildId(value ? Number(value) : undefined)
                }}
                style={{ width: '100%' }}
                options={filteredBusinessInviteCandidates.map((child) => ({
                  value: Number(child.pro_account_id),
                  label: businessInviteCandidateLabel(child),
                }))}
                notFoundContent={businessInviteCandidatesLoading
                  ? <Spin size="small" />
                  : '所选邮箱类型暂无候选账号'}
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {standalone ? '留空时从可用的 Gmail 普通账号中自动选择子号；' : '留空时按当前邮箱类型自动选择子号，准备号优先、普通号补充；'}选择具体子号时仅邀请该账号。发送前会核验子号会话、资格和席位，清空选择可恢复自动选号。
              </Typography.Text>
              {filteredBusinessInviteCandidates.length === 0 && !businessInviteCandidatesLoading && <Typography.Text type="warning">当前来源没有可邀请子号。Gmail 需先完成 GPT 注册并配置可用收件授权。{standalone ? <><Link to="/">导入 Gmail 普通账号</Link> · <Link to="/register">注册 Gmail 子号</Link></> : <><Link to="/gmail">管理 Gmail</Link> · <Link to="/register?platform=chatgpt&mail_provider=gmail">注册 Gmail 子号</Link></>}</Typography.Text>}
            </Space>
          ) : (
            <Input
              value={businessInviteManualEmail}
              placeholder="输入一个子号邮箱"
              status={businessInviteManualEmail && !businessInviteManualEmailValid ? 'error' : undefined}
              onChange={(event) => {
                setBusinessInviteManualEmail(event.target.value)
              }}
            />
          )}
          </>}
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {standalone
              ? '选择的席位类型对本批次全部子号生效；数量不能超过该类型的已确认空位。'
              : '席位类型由母号数据库快照与后端实时安全复核决定；页面不提供手动改席位入口。'}
          </Typography.Text>
        </Space>
      </Modal>

      <Modal
        title={`${businessChildRtTask?.reacquire ? '重新获取 RT' : '获取 RT'}${businessChildRtTask?.childEmail ? ` · ${businessChildRtTask.childEmail}` : ''}`}
        open={businessChildRtTaskOpen && !!businessChildRtTask}
        width={720}
        maskClosable={false}
        onCancel={() => setBusinessChildRtTaskOpen(false)}
        footer={businessChildRtTask?.status === 'running' ? (
          <Button type="primary" onClick={() => setBusinessChildRtTaskOpen(false)}>
            后台继续运行并关闭
          </Button>
        ) : (
          <Space>
            <Button onClick={() => setBusinessChildRtTaskOpen(false)}>关闭</Button>
            <Button type="primary" onClick={() => {
              setBusinessChildRtTaskOpen(false)
              setBusinessChildRtTask(null)
            }}>
              清除记录
            </Button>
          </Space>
        )}
      >
        {businessChildRtTask && (
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Alert
              type="info"
              showIcon
              message={`正在为 BUSINESS 子号${businessChildRtTask.reacquire ? '重新' : ''}获取 RT`}
              description="邀请前账号检查已完成，本任务直接执行 Codex OAuth；完成后自动刷新子号状态。"
            />
            <Space wrap>
              <Tag color={businessChildRtTask.status === 'success'
                ? 'success'
                : businessChildRtTask.status === 'failed' ? 'error' : 'processing'}>
                {businessChildRtTask.status === 'success'
                  ? 'RT 已就绪'
                  : businessChildRtTask.status === 'failed' ? '获取失败' : '获取中'}
              </Tag>
              <Typography.Text type="secondary">阶段：{businessChildRtTask.stage || 'queued'}</Typography.Text>
              {businessChildRtTask.status === 'running' && <Spin size="small" />}
            </Space>
            {businessChildRtTask.error && (
              <Alert type="error" showIcon message="RT 获取失败" description={businessChildRtTask.error} />
            )}
            <pre style={{
              margin: 0,
              minHeight: 150,
              maxHeight: 320,
              overflow: 'auto',
              padding: 12,
              borderRadius: 6,
              background: token.colorFillQuaternary,
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
              fontSize: 12,
            }}>
              {businessChildRtTask.logs.length
                ? businessChildRtTask.logs.join('\n')
                : businessChildRtTask.status === 'running' ? '等待安全日志…' : '（无可展示日志）'}
            </pre>
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              日志仅展示脱敏后的任务进度，不显示 Token、Cookie、密码或验证码。
            </Typography.Text>
          </Space>
        )}
      </Modal>

      <Modal
        title="BUSINESS 默认优惠码"
        open={businessDefaultCouponOpen}
        width={520}
        okText="保存默认值"
        cancelText="关闭"
        confirmLoading={businessDefaultCouponSaving}
        closable={!businessDefaultCouponSaving}
        maskClosable={!businessDefaultCouponSaving}
        okButtonProps={{ disabled: businessDefaultCouponLoading
          || Boolean(businessDefaultCouponLoadError)
          || !businessDefaultCouponDraft.trim()
          || businessDefaultCouponDraft.trim().length > 200
          || businessDefaultCouponDraft.trim() === businessDefaultCoupon }}
        onOk={() => { void saveBusinessDefaultCoupon() }}
        onCancel={closeBusinessDefaultCouponSettings}
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }} data-business-default-coupon-settings="true">
          <Typography.Text type="secondary">
            保存后，下次为任意账号打开 BUSINESS 支付链接弹框时自动填入。单次结账中修改优惠码不会更改这里的默认值。
          </Typography.Text>
          {businessDefaultCouponLoading && <Space><Spin size="small" /><Typography.Text>正在读取已保存的默认优惠码…</Typography.Text></Space>}
          {businessDefaultCouponLoadError && (
            <Alert
              type="error"
              showIcon
              message="读取默认优惠码失败"
              description={businessDefaultCouponLoadError}
              action={<Button size="small" disabled={businessDefaultCouponSaving} onClick={() => { void loadBusinessDefaultCoupon() }}>重试读取</Button>}
            />
          )}
          {businessDefaultCouponSaveError && <Alert type="error" showIcon message={businessDefaultCouponSaveError} />}
          <Input
            aria-label="BUSINESS 默认优惠码"
            maxLength={200}
            showCount
            value={businessDefaultCouponDraft}
            disabled={businessDefaultCouponLoading || businessDefaultCouponSaving || Boolean(businessDefaultCouponLoadError)}
            placeholder="请输入默认优惠码"
            onChange={(event) => {
              setBusinessDefaultCouponDraft(event.target.value)
              setBusinessDefaultCouponSaveError('')
            }}
          />
          {businessDefaultCoupon !== null && (
            <Typography.Text type="secondary">
              {businessDefaultCouponLoadError ? '上次确认已保存：' : '当前已保存：'}<Typography.Text code>{businessDefaultCoupon}</Typography.Text>
            </Typography.Text>
          )}
        </Space>
      </Modal>

      <Modal
        title={`获取 BUSINESS 支付链接${businessAccount ? ` · ${businessAccount.email}` : ''}`}
        open={!!businessAccount}
        width={660}
        maskClosable={false}
        okText={businessUrl ? '重新生成' : '生成支付链接'}
        confirmLoading={businessLoading}
        okButtonProps={{ disabled: businessCouponLoading || Boolean(businessCouponLoadError)
          || businessDefaultCouponSaving || !businessCoupon.trim() || businessCoupon.trim().length > 200 }}
        onOk={() => { void generateBusinessCheckout() }}
        onCancel={closeBusinessCheckout}
      >
        <Space direction="vertical" size={11} style={{ width: '100%' }}>
          <Alert
            type="info"
            showIcon
            message="生成支付链接不代表 BUSINESS 已升级成功"
            description="完成付款后，请点击该账号的“登录”重新识别套餐；系统检测到 BUSINESS/TEAM 后才会移入会员账号的 TEAM 分类。"
          />
          <div>
            <Typography.Text strong>空间名称 <Typography.Text type="danger">*</Typography.Text></Typography.Text>
            <Input
              style={{ marginTop: 5 }}
              value={businessWorkspace}
              placeholder="workspace 名称，如 my-team"
              onChange={(event) => setBusinessWorkspace(event.target.value)}
            />
          </div>
          <div>
            <Typography.Text strong>优惠码</Typography.Text>
            {businessCouponLoading && <Space style={{ display: 'flex', marginTop: 5 }}><Spin size="small" /><Typography.Text type="secondary">正在读取最新默认优惠码…</Typography.Text></Space>}
            {businessCouponLoadError && (
              <Alert
                style={{ marginTop: 5 }}
                type="error"
                showIcon
                message={businessCouponLoadError}
                action={<Button size="small" onClick={() => { void loadBusinessCheckoutCoupon() }}>重试读取</Button>}
              />
            )}
            <Input
              aria-label="本次 BUSINESS 优惠码"
              style={{ marginTop: 5 }}
              value={businessCoupon}
              maxLength={200}
              disabled={businessCouponLoading || Boolean(businessCouponLoadError) || businessLoading}
              placeholder="promo code / 优惠码"
              onChange={(event) => setBusinessCoupon(event.target.value)}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>可修改本次优惠码，仅用于当前支付链接，不改变已保存的默认值。</Typography.Text>
          </div>
          <div>
            <Typography.Text strong>席位类型</Typography.Text>
            <Segmented
              block
              style={{ marginTop: 6 }}
              value={businessSeatType}
              options={[
                { label: '普通席位', value: 'default' },
                { label: '高级席位（1 普通 + 1 高级）', value: 'prolite' },
              ]}
              onChange={(value) => setBusinessSeatType(value as 'default' | 'prolite')}
            />
          </div>
          <Space wrap>
            <Typography.Text>席位数量</Typography.Text>
            <InputNumber
              min={2}
              max={999}
              disabled={businessSeatType === 'prolite'}
              value={businessSeatType === 'prolite' ? 2 : businessSeats}
              onChange={(value) => setBusinessSeats(Number(value) || 2)}
            />
            <Typography.Text>国家</Typography.Text>
            <Input style={{ width: 82 }} value={businessCountry} onChange={(event) => setBusinessCountry(event.target.value)} />
            <Typography.Text>货币</Typography.Text>
            <Input style={{ width: 82 }} value={businessCurrency} onChange={(event) => setBusinessCurrency(event.target.value)} />
          </Space>
          {businessSeatType === 'prolite' && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              高级席位使用一步 checkout：普通席位 1 个 + 高级席位 1 个，总计 2 个。
            </Typography.Text>
          )}
          <Space direction="vertical" size={7}>
            <Space>
              <Switch
                checked={businessAutoFill}
                onChange={(checked) => {
                  setBusinessAutoFill(checked)
                  if (!checked) setBusinessAutoSubmit(false)
                }}
              />
              <Typography.Text>打开付款页并自动填卡</Typography.Text>
            </Space>
            <Space>
              <Switch
                checked={businessAutoSubmit}
                disabled={!businessAutoFill}
                onChange={setBusinessAutoSubmit}
              />
              <Typography.Text type={businessAutoSubmit ? 'danger' : undefined}>
                自动点击订阅（开启后会提交真实扣款，默认关闭）
              </Typography.Text>
            </Space>
          </Space>
          {businessAutoFill && (
            <div>
              <Typography.Text strong>付款卡（可选）</Typography.Text>
              <Typography.Paragraph type="secondary" style={{ margin: '2px 0 6px', fontSize: 12 }}>
                留空时使用共享卡池第一张可用卡。
              </Typography.Paragraph>
              <Input.TextArea
                rows={3}
                value={businessCardText}
                onChange={(event) => setBusinessCardText(event.target.value)}
                placeholder={'Card Number: 4937242023477384\nValid Thru: 07/29\nCVV: 819'}
              />
            </div>
          )}
          {businessUrl && (
            <Alert
              type="success"
              showIcon
              message="支付链接已生成"
              description={(
                <Space direction="vertical" size={7} style={{ width: '100%' }}>
                  <Typography.Link href={businessUrl} target="_blank" style={{ wordBreak: 'break-all' }}>
                    {businessUrl}
                  </Typography.Link>
                  <Space wrap>
                    <Button size="small" type="primary" onClick={() => window.open(businessUrl, '_blank', 'noopener,noreferrer')}>
                      打开付款页
                    </Button>
                    <Button
                      size="small"
                      icon={<CopyOutlined />}
                      onClick={() => {
                        void navigator.clipboard.writeText(businessUrl)
                        message.success('支付链接已复制')
                      }}
                    >
                      复制链接
                    </Button>
                    {!!businessResult?.filled_card && <Tag>已填卡 {String(businessResult.filled_card)}</Tag>}
                  </Space>
                </Space>
              )}
            />
          )}
        </Space>
      </Modal>

      <Modal
        title={`申请退款${refundAccount ? ` · ${refundAccount.email}` : ''}`}
        open={!!refundAccount}
        width={540}
        maskClosable={false}
        okText="确认启动退款"
        okButtonProps={{ danger: true }}
        onCancel={() => setRefundAccount(null)}
        onOk={() => {
          const account = refundAccount
          if (!account) return
          setRefundAccount(null)
          void startMemberTask(account, 'refund', {
            refund_manual: refundManual,
            // 套餐管理退款固定使用可见浏览器；后端也会再次强制校验。
            headless: false,
          })
        }}
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Alert
            type="warning"
            showIcon
            message="退款会操作真实订阅"
            description="自动和人工模式都会打开可见浏览器。自动模式会发送退款诉求；人工模式只打开客服界面，由你自行沟通。任务启动后可在日志弹框查看进度。"
          />
          <div>
            <Typography.Text strong>退款方式</Typography.Text>
            <Segmented
              block
              style={{ marginTop: 8 }}
              value={refundManual ? 'manual' : 'automatic'}
              options={[
                { label: '自动退款（默认）', value: 'automatic' },
                { label: '人工退款（只打开界面）', value: 'manual' },
              ]}
              onChange={(value) => setRefundManual(value === 'manual')}
            />
          </div>
        </Space>
      </Modal>

      <Modal
        title={`焚决退款 PRO${businessBurnAccount ? ` · 母号 ${businessBurnAccount.email}` : ''}`}
        open={!!businessBurnAccount}
        width={760}
        maskClosable={false}
        closable={businessBurnTask?.status !== 'running' && !businessBurnStarting}
        okText={businessBurnTask?.status === 'running' ? '处理中' : '开始焚决'}
        okButtonProps={{
          danger: true,
          disabled: businessBurnCandidatesLoading
            || businessBurnSelectedIds.length === 0
            || businessBurnMaxSelect <= 0
            || businessBurnTask?.status === 'running',
        }}
        cancelButtonProps={{ disabled: businessBurnTask?.status === 'running' || businessBurnStarting }}
        confirmLoading={businessBurnStarting || businessBurnTask?.status === 'running'}
        onOk={() => { void startBusinessBurn() }}
        onCancel={() => {
          if (businessBurnTask?.status === 'running' || businessBurnStarting) return
          businessBurnGenerationRef.current += 1
          if (businessBurnTimerRef.current !== undefined) window.clearTimeout(businessBurnTimerRef.current)
          businessBurnTimerRef.current = undefined
          setBusinessBurnAccount(null)
          setBusinessBurnCandidates([])
          setBusinessBurnSelectedIds([])
          setBusinessBurnTask(null)
          setBusinessBurnStartSummary(null)
        }}
      >
        {businessBurnAccount && (() => {
          const liveAccount = accounts.find((item) => item.id === businessBurnAccount.id) || businessBurnAccount
          const source = memberSourceOf(liveAccount, memberSourceOverrides[liveAccount.id])
          const workspace = businessWorkspaceOf(source)
          const inviteCooldown = businessInviteCooldownOf(
            liveAccount,
            source,
            workspace,
            businessChildrenByAccount[liveAccount.id]?.snapshot,
            replenishmentNow,
          )
          const running = businessBurnTask?.status === 'running' || businessBurnStarting
          const progress = businessBurnTask?.progress
          const percent = progress?.total
            ? Math.min(100, Math.round((progress.done / progress.total) * 100))
            : 0
          return (
            <Space direction="vertical" size={10} style={{ width: '100%' }}>
              <Alert
                type="warning"
                showIcon
                message="该操作会真实取消所选 PRO 账号的订阅"
                description="系统将依次邀请进入本 BUSINESS、登录入群、去除个人空间使订阅失效，并按选择踢出后标记待退款。焚决只负责掉订阅；后续退款申请仍通过 PRO 账号的退款入口执行。"
              />
              <Space wrap>
                {inviteCooldown.active && (
                  <Tooltip title={businessInviteCooldownReasonLabel(inviteCooldown.reason)}>
                    <Tag color="orange" style={{ margin: 0 }}>
                      邀请失败冷却 · {businessInviteCooldownCountdown(
                        inviteCooldown.until,
                        replenishmentNow,
                      )}
                    </Tag>
                  </Tooltip>
                )}
                <Typography.Text type="secondary">
                  服务端本次最多允许选择 {businessBurnMaxSelect} 个
                </Typography.Text>
                <Space size={5}>
                  <Switch size="small" checked={businessBurnKick} disabled={running} onChange={setBusinessBurnKick} />
                  <Typography.Text>完成后踢出</Typography.Text>
                </Space>
              </Space>
              {businessBurnStartSummary && (
                <Alert
                  type="info"
                  showIcon
                  message={`已提交 ${businessBurnStartSummary.requested} 个 · 实际进入任务 ${businessBurnStartSummary.targets} 个`}
                  description="接口明确拒绝邀请时冷却 1 天；其他请求异常保持短时退避。预计恢复时间以母号记录为准。"
                />
              )}
              <Table<BusinessBurnCandidate>
                rowKey="id"
                size="small"
                loading={businessBurnCandidatesLoading}
                dataSource={businessBurnCandidates}
                pagination={{ pageSize: 10, size: 'small', hideOnSinglePage: true }}
                rowSelection={{
                  selectedRowKeys: businessBurnSelectedIds,
                  getCheckboxProps: () => ({ disabled: running || businessBurnMaxSelect <= 0 }),
                  onChange: (keys) => {
                    const selected = keys.map(Number).filter(Number.isFinite)
                    if (businessBurnMaxSelect > 0 && selected.length > businessBurnMaxSelect) {
                      message.warning(`本母号本次最多选择 ${businessBurnMaxSelect} 个 PRO 账号`)
                    }
                    setBusinessBurnSelectedIds(
                      businessBurnMaxSelect > 0 ? selected.slice(0, businessBurnMaxSelect) : [],
                    )
                  },
                }}
                columns={[
                  {
                    title: '可焚决 PRO 账号',
                    dataIndex: 'email',
                    render: (email: string) => <Typography.Text style={{ fontFamily: 'monospace' }}>{email}</Typography.Text>,
                  },
                  {
                    title: 'PRO 升级时间',
                    dataIndex: 'subscribed_at',
                    width: 190,
                    render: (value?: string) => formatTime(value),
                  },
                ]}
                locale={{ emptyText: '当前没有可焚决的 PRO 账号' }}
              />
              {businessBurnTask && (
                <Space direction="vertical" size={6} style={{ width: '100%' }}>
                  <Space wrap>
                    <Tag color={businessBurnTask.status === 'done' ? 'success' : businessBurnTask.status === 'failed' ? 'error' : 'processing'}>
                      {businessBurnTask.status === 'done' ? '已完成' : businessBurnTask.status === 'failed' ? '失败' : '执行中'}
                    </Tag>
                    {progress && (
                      <Typography.Text type="secondary">
                        已处理 {progress.done}/{progress.total} · 掉订阅成功 {progress.burned}
                      </Typography.Text>
                    )}
                  </Space>
                  {businessBurnTask.status === 'running' && <Progress percent={percent} size="small" status="active" />}
                  {businessBurnTask.error && <Alert type="error" showIcon message={businessBurnTask.error} />}
                  {!!businessBurnTask.logs.length && (
                    <div style={{ maxHeight: 180, overflow: 'auto', borderRadius: 6, padding: 8, background: token.colorFillQuaternary, fontFamily: 'monospace', fontSize: 11 }}>
                      {businessBurnTask.logs.map((line, index) => <div key={`${index}-${line}`}>{line}</div>)}
                    </div>
                  )}
                </Space>
              )}
            </Space>
          )
        })()}
      </Modal>

      <Modal
        title={`BUSINESS 母号设备绑定${businessBindingAccount ? ` · ${businessBindingAccount.email}` : ''}`}
        open={!!businessBindingAccount}
        width={620}
        maskClosable={false}
        destroyOnHidden
        onCancel={closeBusinessBindingEditor}
        footer={(
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
            <div>
              {businessBinding?.bound && (
                <Popconfirm
                  title="确认解除设备绑定？"
                  description="只解除本地归属关系，不会删除、迁移或上传设备中的账号。"
                  okText="确认解除"
                  cancelText="取消"
                  onConfirm={() => { void removeBusinessBindingEditor() }}
                >
                  <Button danger loading={businessBindingSaving}>解除绑定</Button>
                </Popconfirm>
              )}
            </div>
            <Space>
              <Button onClick={closeBusinessBindingEditor} disabled={businessBindingSaving}>关闭</Button>
              <Button
                type="primary"
                icon={<LinkOutlined />}
                loading={businessBindingSaving}
                disabled={businessBindingLoading
                  || businessBinding?.eligible_for_new_binding === false
                  || businessBinding?.can_bind === false
                  || !businessBindingSelectedRef
                  || businessBindingSelectedRef === businessBinding?.device_ref}
                onClick={() => { void saveBusinessBindingEditor() }}
              >
                {businessBinding?.bound ? '切换绑定' : '保存绑定'}
              </Button>
            </Space>
          </div>
        )}
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Alert
            type="info"
            showIcon
            message="只维护 BUSINESS 母号与设备的本地归属"
            description="绑定、切换或解绑不会触发账号迁移、自动调度、邀请子号、RT 获取或凭证上传。"
          />
          {(businessBinding?.eligible_for_new_binding === false || businessBinding?.can_bind === false) && (
            <Alert
              type="warning"
              showIcon
              message="当前母号不可新增或切换设备"
              description={(() => {
                const blockers = Array.isArray(businessBinding.binding_blockers)
                  ? businessBinding.binding_blockers.map((item) => {
                    if (typeof item === 'string') return item
                    const row = asRecord(item)
                    return String(row.message || row.label || row.code || '')
                  }).filter(Boolean)
                  : []
                return blockers.join('；') || '已有绑定仍可查看和解除。'
              })()}
            />
          )}
          <Space size={5} wrap>
            <Typography.Text type="secondary">当前绑定：</Typography.Text>
            <Tag color={businessBinding?.bound ? 'blue' : 'default'}>
              {businessMemberBindingLabel(businessBinding)}
            </Tag>
          </Space>
          <Select
            showSearch
            allowClear
            optionFilterProp="label"
            style={{ width: '100%' }}
            placeholder={businessBindingLoading ? '正在读取设备…' : '选择 CPA / SUB 设备'}
            loading={businessBindingLoading}
            disabled={businessBinding?.eligible_for_new_binding === false || businessBinding?.can_bind === false}
            value={businessBindingSelectedRef}
            options={businessBindingDevices.map((device) => ({
              value: device.deviceRef,
              label: `[${device.provider === 'cpa' ? 'CPA' : 'SUB'}] ${device.name}`,
              disabled: !device.enabled,
            }))}
            onChange={setBusinessBindingSelectedRef}
          />
          {!businessBindingLoading && businessBindingDevices.length === 0 && (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无已配置的 CPA / SUB 设备" />
          )}
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            切换设备只修改本地绑定目标；设备账号与额度仍由 CPA / SUB 设备页面单独刷新。
          </Typography.Text>
        </Space>
      </Modal>

      <Modal
        title={`同步设备${deviceAccount
          ? ` · ${deviceAccount.email}`
          : businessChildDeviceTarget?.child.email
            ? ` · ${businessChildDeviceTarget.child.email}`
            : ''}`}
        open={Boolean(deviceAccount || businessChildDeviceTarget)}
        width={560}
        maskClosable={false}
        okText="同步"
        confirmLoading={deviceSyncing}
        okButtonProps={{ disabled: !selectedDeviceRef || deliveryDevicesLoading }}
        onCancel={() => {
          if (!deviceSyncing) {
            setDeviceAccount(null)
            setBusinessChildDeviceTarget(null)
          }
        }}
        onOk={() => {
          if (businessChildDeviceTarget) void syncBusinessChildDevice()
          else void syncMemberDevice()
        }}
      >
        <Space direction="vertical" size={10} style={{ width: '100%' }}>
          <Alert
            type="info"
            showIcon
            message="选择已配置的 CPA / SUB 设备"
            description={businessChildDeviceTarget
              ? '设备列表来自统一设备管理；后端会再次核验母子归属、正式成员状态、RT 与设备协议。'
              : '设备列表来自统一设备管理；后端会再次核验账号类型、RT 与设备协议。'}
          />
          {deviceAccount && (() => {
            const source = memberSourceOf(deviceAccount, memberSourceOverrides[deviceAccount.id])
            const links = linkedMemberDevices(source)
            if (!links.length) return null
            return (
              <Space size={5} wrap>
                <Typography.Text type="secondary">当前关联：</Typography.Text>
                {links.map((device) => (
                  <Tag key={device.deviceRef} color={device.provider === 'cpa' ? 'blue' : 'purple'}>
                    {device.provider === 'cpa' ? 'CPA' : 'SUB'} · {device.name}
                  </Tag>
                ))}
              </Space>
            )
          })()}
          {businessChildDeviceTarget && (() => {
            const links = linkedBusinessChildDevices(businessChildDeviceTarget.child)
            if (!links.length) return null
            return (
              <Space size={5} wrap>
                <Typography.Text type="secondary">当前关联：</Typography.Text>
                {links.map((device) => (
                  <Tag key={device.deviceRef} color={device.provider === 'cpa' ? 'blue' : 'purple'}>
                    {device.provider === 'cpa' ? 'CPA' : 'SUB'} · {device.name}
                  </Tag>
                ))}
              </Space>
            )
          })()}
          <Select
            showSearch
            optionFilterProp="label"
            style={{ width: '100%' }}
            placeholder={deliveryDevicesLoading ? '正在读取设备…' : '选择设备'}
            loading={deliveryDevicesLoading}
            value={selectedDeviceRef}
            options={deliveryDevices.map((device) => ({
              value: device.deviceRef,
              label: `[${device.provider === 'cpa' ? 'CPA' : 'SUB'}] ${device.name}`,
              disabled: !device.enabled,
            }))}
            onChange={setSelectedDeviceRef}
          />
          {!deliveryDevicesLoading && deliveryDevices.length === 0 && (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无符合能力且已配置的设备" />
          )}
        </Space>
      </Modal>

      <Modal
        title={memberDeviceUsage
          ? `${memberDeviceUsage.provider === 'cpa' ? 'CPA' : 'SUB'} 额度 · ${memberDeviceUsage.email}`
          : '设备额度'}
        open={!!memberDeviceUsage}
        width={600}
        footer={<Button type="primary" onClick={() => setMemberDeviceUsage(null)}>关闭</Button>}
        onCancel={() => setMemberDeviceUsage(null)}
      >
        {memberDeviceUsage && (() => {
          const rows = memberUsageRows(memberDeviceUsage.usage)
          const limited = nestedBoolean(memberDeviceUsage.usage, 'limit_reached') === true
          return (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Space wrap>
                <Tag color={memberDeviceUsage.provider === 'cpa' ? 'blue' : 'purple'}>
                  {memberDeviceUsage.provider === 'cpa' ? 'CPA' : 'SUB'}
                </Tag>
                <Typography.Text code>{memberDeviceUsage.deviceRef}</Typography.Text>
                {limited && <Tag color="error">额度用尽</Tag>}
              </Space>
              {rows.length ? rows.map((row) => (
                <div key={row.label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <Typography.Text style={{ width: 38 }}>{row.label}</Typography.Text>
                  <Progress
                    percent={row.remaining}
                    status={row.remaining < 20 ? 'exception' : 'normal'}
                    strokeColor={row.remaining >= 20 && row.remaining <= 40
                      ? '#faad14'
                      : row.remaining > 40 ? '#52c41a' : undefined}
                    style={{ flex: 1, margin: 0 }}
                    format={(value) => `剩余 ${value}%`}
                  />
                  <Tag color={row.remaining < 20 ? 'red' : row.remaining <= 40 ? 'orange' : 'green'}>
                    剩余
                  </Tag>
                </div>
              )) : (
                <Alert
                  type={limited ? 'error' : 'info'}
                  showIcon
                  message={limited ? '设备报告额度已用尽' : '设备未返回可识别的额度百分比'}
                />
              )}
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                额度来自设备实时查询结果；低于 20% 时标红。
              </Typography.Text>
            </Space>
          )
        })()}
      </Modal>

      <Modal
        title={securitySetupTask
          ? `设置密码与 Authenticator 2FA · ${securitySetupTask.email}`
          : '设置密码与 Authenticator 2FA'}
        open={!!securitySetupTask}
        width={760}
        maskClosable={false}
        onCancel={() => setSecuritySetupTask(null)}
        footer={(
          <Button type="primary" onClick={() => setSecuritySetupTask(null)}>
            {securitySetupTask?.status === 'running' ? '后台继续运行并关闭' : '关闭'}
          </Button>
        )}
      >
        {securitySetupTask && (
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Space wrap>
              <Tag color={securitySetupTask.status === 'done'
                ? 'success'
                : securitySetupTask.status === 'failed' ? 'error' : 'processing'}>
                {securitySetupTask.status === 'done'
                  ? '已完成'
                  : securitySetupTask.status === 'failed' ? '失败' : '运行中'}
              </Tag>
              {securitySetupTask.status === 'running' && <Spin size="small" />}
              <Typography.Text type="secondary">
                子步骤：{securityStageLabel(securitySetupTask.securityProgress)}
              </Typography.Text>
              <Tag>
                2FA 浏览器：{securitySetupTask.browserMode === 'headed' ? '有头' : '无头'}
              </Tag>
            </Space>
            <ChatGptSecurityProgress progress={securitySetupTask.securityProgress} />
            {securitySetupTask.error && (
              <Alert
                type="error"
                showIcon
                message="密码与 2FA 设置失败"
                description={securitySetupTask.error}
              />
            )}
            <pre style={{
              margin: 0,
              minHeight: 220,
              maxHeight: 430,
              overflow: 'auto',
              padding: 12,
              borderRadius: 6,
              background: token.colorFillQuaternary,
              color: token.colorText,
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
              fontSize: 12,
            }}>
              {securitySetupTask.logs.length
                ? securitySetupTask.logs.join('\n')
                : securitySetupTask.status === 'running' ? '等待安全任务日志…' : '（无日志）'}
            </pre>
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              日志仅展示脱敏后的执行进度，不显示密码、Authenticator 密钥或验证码。
            </Typography.Text>
          </Space>
        )}
      </Modal>

      <Modal
        title={businessChildSecuritySetupTask
          ? `子号设置密码与 Authenticator 2FA · ${businessChildSecuritySetupTask.email}`
          : '子号设置密码与 Authenticator 2FA'}
        open={!!businessChildSecuritySetupTask}
        width={760}
        maskClosable={false}
        onCancel={() => setBusinessChildSecuritySetupTask(null)}
        footer={(
          <Button type="primary" onClick={() => setBusinessChildSecuritySetupTask(null)}>
            {businessChildSecuritySetupTask?.status === 'running' ? '后台继续运行并关闭' : '关闭'}
          </Button>
        )}
      >
        {businessChildSecuritySetupTask && (
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Space wrap>
              <Tag color={businessChildSecuritySetupTask.status === 'done'
                ? 'success'
                : businessChildSecuritySetupTask.status === 'failed' ? 'error' : 'processing'}>
                {businessChildSecuritySetupTask.status === 'done'
                  ? '已完成'
                  : businessChildSecuritySetupTask.status === 'failed' ? '失败' : '运行中'}
              </Tag>
              {businessChildSecuritySetupTask.status === 'running' && <Spin size="small" />}
              <Typography.Text type="secondary">
                子步骤：{securityStageLabel(businessChildSecuritySetupTask.securityProgress)}
              </Typography.Text>
              <Tag>
                2FA 浏览器：{businessChildSecuritySetupTask.browserMode === 'headed' ? '有头' : '无头'}
              </Tag>
            </Space>
            <ChatGptSecurityProgress progress={businessChildSecuritySetupTask.securityProgress} />
            {businessChildSecuritySetupTask.error && (
              <Alert
                type="error"
                showIcon
                message="子号密码与 2FA 设置失败"
                description={businessChildSecuritySetupTask.error}
              />
            )}
            <pre style={{
              margin: 0,
              minHeight: 220,
              maxHeight: 430,
              overflow: 'auto',
              padding: 12,
              borderRadius: 6,
              background: token.colorFillQuaternary,
              color: token.colorText,
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
              fontSize: 12,
            }}>
              {businessChildSecuritySetupTask.logs.length
                ? businessChildSecuritySetupTask.logs.join('\n')
                : businessChildSecuritySetupTask.status === 'running' ? '等待子号安全任务日志…' : '（无日志）'}
            </pre>
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              日志仅展示脱敏后的执行进度，不显示密码、Authenticator 密钥或验证码。
            </Typography.Text>
          </Space>
        )}
      </Modal>

      <Modal
        title={memberTask
          ? `${memberTask.action === 'oauth' ? '获取 RT' : '退款'}日志 · ${memberTask.email}`
          : '账号任务日志'}
        open={!!memberTask}
        width={760}
        maskClosable={false}
        onCancel={() => setMemberTask(null)}
        footer={(
          <Button type="primary" onClick={() => setMemberTask(null)}>
            {memberTask?.status === 'running' ? '后台继续运行并关闭' : '关闭'}
          </Button>
        )}
      >
        {memberTask && (
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Space wrap>
              <Tag color={memberTask.status === 'done' ? 'success' : memberTask.status === 'failed' ? 'error' : 'processing'}>
                {memberTask.status === 'done' ? '已完成' : memberTask.status === 'failed' ? '失败' : '运行中'}
              </Tag>
              {memberTask.status === 'running' && <Spin size="small" />}
              <Typography.Text type="secondary">阶段：{memberTask.stage || 'starting'}</Typography.Text>
              {memberTask.taskId && <Typography.Text type="secondary">任务：{memberTask.taskId}</Typography.Text>}
            </Space>
            {memberTask.error && (
              <Alert type="error" showIcon message="任务失败" description={memberTask.error} />
            )}
            <pre style={{
              margin: 0,
              minHeight: 220,
              maxHeight: 430,
              overflow: 'auto',
              padding: 12,
              borderRadius: 6,
              background: token.colorFillQuaternary,
              whiteSpace: 'pre-wrap',
              overflowWrap: 'anywhere',
              fontSize: 12,
            }}>
              {memberTask.logs.length
                ? memberTask.logs.join('\n')
                : memberTask.status === 'running' ? '等待任务日志…' : '（无日志）'}
            </pre>
          </Space>
        )}
      </Modal>

      <Modal
        title={businessOnly ? "导入 BUSINESS 母号" : "批量导入 GPT 套餐账号"}
        open={importOpen}
        width={680}
        maskClosable={false}
        closable={!importLoading}
        confirmLoading={importLoading}
        okText="开始导入"
        onOk={() => { void submitImport() }}
        onCancel={() => { if (!importLoading) setImportOpen(false) }}
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message={businessOnly ? "导入为 BUSINESS 母号，登录后读取真实席位" : "导入后套餐默认为未检测"}
          description={businessOnly
            ? '支持导入当前系统下载的母号迁移包。导入后请执行登录和刷新工作区，系统将读取真实套餐、普通/高级席位及成员。'
            : '点击账号的“登录”后，系统会从真实登录会话识别并保存套餐。'}
        />
        {businessOnly && (
          <Space direction="vertical" size={6} style={{ width: '100%', marginBottom: 12 }}>
            <Typography.Text strong>从当前系统迁移</Typography.Text>
            <input
              type="file"
              accept=".json,application/json"
              disabled={importLoading}
              onChange={(event) => {
                void loadBusinessMotherBundle(event.currentTarget.files?.[0])
                event.currentTarget.value = ''
              }}
            />
            <Typography.Text type="secondary">迁移包自带邮箱类型，不会导入 Cookie 或旧席位快照。</Typography.Text>
          </Space>
        )}
        {businessOnly && <Select value={motherImportMailProvider} onChange={setMotherImportMailProvider} style={{ width: 230, marginBottom: 12 }} options={[
          { value: 'outlook', label: 'Outlook 邮箱' }, { value: 'gmail', label: 'Gmail 邮箱' }, { value: 'icloud', label: 'iCloud 邮箱' },
        ]} />}
        <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
          每行一个账号，使用 <Typography.Text code>----</Typography.Text> 分隔：
          <br />
          <Typography.Text code>{businessOnly ? '邮箱----GPT密码----2FA密钥（可省略）' : '邮箱----密码----刷新令牌----Client ID'}</Typography.Text>
          <br />
          也支持仅导入 <Typography.Text code>邮箱----密码</Typography.Text>。{businessOnly && ' Outlook 邮箱还支持四段 OAuth 资料：邮箱----密码----刷新令牌----Client ID；选择迁移包时无需手动选择邮箱类型。'}
        </Typography.Paragraph>
        <Input.TextArea
          value={importText}
          disabled={importLoading}
          autoSize={{ minRows: 9, maxRows: 18 }}
          style={{ fontFamily: 'monospace', fontSize: 12 }}
          placeholder={businessOnly ? "email@example.com----GPTpassword----TOTPsecret" : "example@outlook.com----password----refresh_token----client_id"}
          onChange={(event) => setImportText(event.target.value)}
        />
      </Modal>

      <Modal
        title={(
          <Space>
            <BellOutlined />
            <span>封禁报警 - {alertAccount?.email || ''}</span>
            <Tag color="error">{alertList.length} 封</Tag>
          </Space>
        )}
        open={alertOpen}
        width={780}
        styles={{ body: { maxHeight: '70vh', overflow: 'auto' } }}
        onCancel={() => setAlertOpen(false)}
        footer={(
          <Space style={{ width: '100%', justifyContent: 'space-between' }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              打开此窗口已自动清除该账号的封禁报警未读状态
            </Typography.Text>
            <Space>
              <Button
                disabled={!alertAccount}
                onClick={() => {
                  if (!alertAccount) return
                  setAlertOpen(false)
                  openFullInboxForAlertTarget(alertAccount)
                }}
              >
                查看完整收件箱
              </Button>
              <Button type="primary" onClick={() => setAlertOpen(false)}>关闭</Button>
            </Space>
          </Space>
        )}
      >
        {alertLoading ? (
          <div style={{ padding: 60, textAlign: 'center' }}><Spin tip="正在加载封禁报警…" /></div>
        ) : alertList.length === 0 ? (
          <Empty description="暂无封禁报警" />
        ) : (
          <Collapse
            accordion
            defaultActiveKey={alertList[0]?.id ? [alertList[0].id] : []}
            items={alertList.map((item, index) => ({
              key: item.id || String(index),
              label: (
                <Space direction="vertical" size={1} style={{ width: '100%' }}>
                  <Space style={{ width: '100%', justifyContent: 'space-between' }}>
                    <Typography.Text strong ellipsis style={{ maxWidth: 500 }}>{item.subject || '(无主题)'}</Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 11 }}>{formatTime(item.time)}</Typography.Text>
                  </Space>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    来自：{item.from || '(未知)'}{item.folder ? ` · ${item.folder}` : ''}
                  </Typography.Text>
                </Space>
              ),
              children: (
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    检测时间：{formatTime(item.detected_at)}
                  </Typography.Text>
                  <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: 0 }}>
                    {item.preview || '(无预览，请查看完整收件箱)'}
                  </Typography.Paragraph>
                </Space>
              ),
            }))}
          />
        )}
      </Modal>

      <Modal
        title={(
          <Space>
            <MailOutlined />
            <span>未读邮件 - {inboxAccount?.email || ''}</span>
            <Tag color="processing">{inboxList.length} 封</Tag>
          </Space>
        )}
        open={inboxOpen}
        width={780}
        styles={{ body: { maxHeight: '70vh', overflow: 'auto' } }}
        onCancel={() => setInboxOpen(false)}
        footer={(
          <Space style={{ width: '100%', justifyContent: 'space-between' }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              打开此窗口已将该账号的未读邮件标记为已读
            </Typography.Text>
            <Space>
              <Button
                disabled={!inboxAccount}
                onClick={() => {
                  if (!inboxAccount) return
                  setInboxOpen(false)
                  openFullInboxForAlertTarget(inboxAccount)
                }}
              >
                查看完整收件箱
              </Button>
              <Button type="primary" onClick={() => setInboxOpen(false)}>关闭</Button>
            </Space>
          </Space>
        )}
      >
        {inboxLoading ? (
          <div style={{ padding: 60, textAlign: 'center' }}><Spin tip="正在加载未读邮件…" /></div>
        ) : inboxList.length === 0 ? (
          <Empty description="暂无未读邮件" />
        ) : (
          <Collapse
            accordion
            defaultActiveKey={inboxList[0]?.id ? [inboxList[0].id] : []}
            items={inboxList.map((item, index) => ({
              key: item.id || String(index),
              label: (
                <Space direction="vertical" size={1} style={{ width: '100%' }}>
                  <Space style={{ width: '100%', justifyContent: 'space-between' }}>
                    <Typography.Text strong ellipsis style={{ maxWidth: 500 }}>{item.subject || '(无主题)'}</Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 11 }}>{formatTime(item.time)}</Typography.Text>
                  </Space>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    来自：{item.from || '(未知)'}{item.folder ? ` · ${item.folder}` : ''}
                  </Typography.Text>
                </Space>
              ),
              children: (
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    检测时间：{formatTime(item.detected_at)}
                  </Typography.Text>
                  <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: 0 }}>
                    {item.preview || '(无预览，请查看完整收件箱)'}
                  </Typography.Paragraph>
                </Space>
              ),
            }))}
          />
        )}
      </Modal>

      </>)}

      <Modal
        title={(
          <Space>
            <InboxOutlined />
            <span>取件 - {mailAccount?.email || ''}</span>
            {mailMethod && <Tag color={mailMethod === 'graph' ? 'success' : 'blue'}>{mailMethod.toUpperCase()}</Tag>}
          </Space>
        )}
        open={mailOpen}
        width={820}
        styles={{ body: { maxHeight: '70vh', overflow: 'auto' } }}
        onCancel={closeMail}
        footer={(
          <Space style={{ width: '100%', justifyContent: 'space-between' }}>
            <Space>
              <Typography.Text type="secondary">条数</Typography.Text>
              <InputNumber min={1} max={50} size="small" value={mailLimit} onChange={(value) => setMailLimit(Number(value) || 10)} />
              <Button
                size="small"
                icon={<ReloadOutlined />}
                loading={mailLoading}
                onClick={() => {
                  if (mailBusinessChildTarget) {
                    void fetchBusinessChildMail(
                      mailBusinessChildTarget.account,
                      mailBusinessChildTarget.child,
                      mailLimit,
                    )
                  } else if (mailAccount) {
                    void fetchMail(mailAccount, mailLimit)
                  }
                }}
              >
                重新取件
              </Button>
            </Space>
            <Button onClick={closeMail}>关闭</Button>
          </Space>
        )}
      >
        {mailLoading ? (
          <div style={{ padding: 60, textAlign: 'center' }}><Spin tip="正在从邮箱拉取最新邮件…" /></div>
        ) : mailError ? (
          <Alert type="error" showIcon message="获取邮件失败" description={mailError} />
        ) : mailMessages.length === 0 ? (
          <Empty description="暂无邮件" />
        ) : (
          <Collapse
            accordion
            defaultActiveKey={mailMessages[0]?.id ? [mailMessages[0].id] : ['0']}
            items={mailMessages.map((mail, index) => ({
              key: mail.id || String(index),
              label: (
                <Space direction="vertical" size={1} style={{ width: '100%' }}>
                  <Space style={{ width: '100%', justifyContent: 'space-between' }}>
                    <Typography.Text strong ellipsis style={{ maxWidth: 500 }}>{mail.subject || '(无主题)'}</Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 11 }}>{formatTime(mail.time)}</Typography.Text>
                  </Space>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    来自：{mail.from || '(未知)'}{mail.folder ? ` · ${mail.folder}` : ''}
                  </Typography.Text>
                </Space>
              ),
              children: mail.is_html ? (
                <iframe
                  title={`mail-${mail.id || index}`}
                  sandbox=""
                  referrerPolicy="no-referrer"
                  srcDoc={safeMailHtml(mail.body || mail.preview || '')}
                  style={{ width: '100%', minHeight: 300, border: `1px solid ${token.colorBorderSecondary}`, borderRadius: 6, background: '#fff' }}
                />
              ) : (
                <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: 0 }}>
                  {mail.body || mail.preview || '(无内容)'}
                </Typography.Paragraph>
              ),
            }))}
          />
        )}
      </Modal>
    </div>
  )
}
