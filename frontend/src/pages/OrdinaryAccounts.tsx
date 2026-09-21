import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Alert, App, Button, Card, Input, InputNumber, Modal, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import { ImportOutlined, PlayCircleOutlined, ReloadOutlined } from '@ant-design/icons'
import PageHeader from '@/components/PageHeader'
import { TaskLogPanel } from '@/components/TaskLogPanel'
import { apiFetch } from '@/lib/utils'
import { gmailAliasCanResume, gmailAliasSelectable, gmailAliasUnavailableReason, gmailPlanPath, gmailRegistrationStage, gmailRegistrationStatus, gmailRegistrationUnavailableReason, type GmailRegistrationAlias, type GmailRegistrationSource } from '@/lib/gmailRegistration'
import { buildChatGPTRegistrationRequestAdapter } from '@/lib/chatgptRegistrationRequestAdapter'
import { gmailWorkspaceRegistrationGroup } from '@/lib/gmailWorkspaceAccountState'
import { parseRegistrationProxyOptions, registrationProxyError, type RegistrationProxyOption } from '@/lib/registrationProxy'

interface Alias extends GmailRegistrationAlias { created_at?: string; registration_verification?: string }
const taskStorageKey = 'gmail-business-registration-task'
const errorText = (error: unknown) => error instanceof Error ? error.message : String(error)

export default function OrdinaryAccounts({ registrationEntry = false }: { registrationEntry?: boolean }) {
  const { message } = App.useApp()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const presetSource = Number(params.get('gmail_source_id')) || undefined
  const [sources, setSources] = useState<GmailRegistrationSource[]>([])
  const [aliases, setAliases] = useState<Alias[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const generation = useRef(0)
  const [keyword, setKeyword] = useState('')
  const [sourceId, setSourceId] = useState<number | undefined>(presetSource)
  const [state, setState] = useState('all')
  const [selected, setSelected] = useState<number[]>(() => (params.get('gmail_alias_ids') || '').split(',').map(Number).filter(id => id > 0))
  const [registerOpen, setRegisterOpen] = useState(registrationEntry)
  const [starting, setStarting] = useState(false)
  const [executor, setExecutor] = useState('headless')
  const [proxyKey, setProxyKey] = useState<string>()
  const [proxyLabel, setProxyLabel] = useState('')
  const [proxyOptions, setProxyOptions] = useState<RegistrationProxyOption[]>([])
  const [proxyLoading, setProxyLoading] = useState(false)
  const [proxyLoaded, setProxyLoaded] = useState(false)
  const [proxyLoadError, setProxyLoadError] = useState('')
  const [registrationSubmitError, setRegistrationSubmitError] = useState('')
  const proxyGeneration = useRef(0)
  const [security, setSecurity] = useState(true)
  const [concurrency, setConcurrency] = useState(1)
  const [taskId, setTaskId] = useState(() => sessionStorage.getItem(taskStorageKey) || '')
  const [taskOpen, setTaskOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [importData, setImportData] = useState('')
  const [importing, setImporting] = useState(false)
  const [importError, setImportError] = useState('')
  const [verifyingId, setVerifyingId] = useState<number | null>(null)

  const reload = useCallback(async () => {
    const request = ++generation.current
    setLoading(true); setError('')
    try {
      const [sourceResult, aliasResult] = await Promise.all([apiFetch('/gmail/sources'), apiFetch('/gmail/aliases')])
      if (request !== generation.current) return
      setSources(sourceResult.items || []); setAliases(aliasResult.items || [])
    } catch (reason) { if (request === generation.current) setError(errorText(reason)) }
    finally { if (request === generation.current) setLoading(false) }
  }, [])
  useEffect(() => { void reload(); return () => { generation.current += 1 } }, [reload])
  useEffect(() => {
    let active = true
    apiFetch('/config').then(config => {
      if (!active) return
      if (['protocol', 'headless', 'headed'].includes(config.default_executor)) setExecutor(config.default_executor)
    }).catch(() => {})
    return () => { active = false }
  }, [])
  const reloadProxyOptions = useCallback(async () => {
    const request = ++proxyGeneration.current
    setProxyLoading(true)
    try {
      const items = parseRegistrationProxyOptions(await apiFetch('/proxies/registration-options'))
      if (request !== proxyGeneration.current) return
      setProxyOptions(items); setProxyLoadError(''); setProxyLoaded(true)
      return items
    } catch (reason) {
      if (request === proxyGeneration.current) setProxyLoadError(errorText(reason))
    } finally { if (request === proxyGeneration.current) setProxyLoading(false) }
  }, [])
  useEffect(() => {
    if (!registerOpen) return
    void reloadProxyOptions()
    const timer = window.setInterval(() => void reloadProxyOptions(), 15000)
    return () => { window.clearInterval(timer); proxyGeneration.current += 1 }
  }, [registerOpen, reloadProxyOptions])
  const sourceById = useMemo(() => new Map(sources.map(source => [source.id, source])), [sources])
  const isRegistered = (alias: Alias) => gmailWorkspaceRegistrationGroup(alias) === 'registered'
  const unavailable = (alias: Alias) => {
    const source = sourceById.get(alias.source_id)
    return gmailAliasUnavailableReason(alias) || (source ? gmailRegistrationUnavailableReason(source) : 'Gmail 母号不可用')
      || (!gmailAliasSelectable(alias) ? '当前子号不可注册或已被任务占用' : '')
  }
  const filtered = aliases.filter(alias => (!sourceId || alias.source_id === sourceId)
    && (!keyword || `${alias.email} ${sourceById.get(alias.source_id)?.email || ''}`.toLowerCase().includes(keyword.toLowerCase()))
    && (state === 'all' || gmailWorkspaceRegistrationGroup(alias) === state))
  const selectedAliases = selected.map(id => aliases.find(alias => alias.id === id)).filter((alias): alias is Alias => Boolean(alias))
  const registrationTargets = selectedAliases.length ? selectedAliases : filtered.filter(alias => !unavailable(alias) && !gmailAliasCanResume(alias))
  const registrationError = selected.length !== selectedAliases.length ? '部分所选子号已不存在，请重新选择'
    : registrationTargets.find(alias => unavailable(alias)) ? unavailable(registrationTargets.find(alias => unavailable(alias))!)
      : !registrationTargets.length ? '当前没有可注册子号；请先导入 Gmail 子号迁移包。' : ''
  const proxyError = registrationProxyError(proxyOptions, proxyKey, proxyLoadError, proxyLoaded)
  const proxySelectOptions = proxyOptions.map(option => ({ value: option.key, label: `${option.kind === 'subscription' ? '订阅' : '手动'} · ${option.label}` }))
  if (proxyKey && !proxyOptions.some(option => option.key === proxyKey)) proxySelectOptions.push({ value: proxyKey, label: `${proxyLabel || proxyKey}（已不可用）` })
  const startRegistration = async () => {
    if (starting || loading || error || registrationError || proxyLoading || proxyError) return
    setStarting(true); setRegistrationSubmitError('')
    try {
      const currentProxyOptions = await reloadProxyOptions()
      if (!currentProxyOptions) throw new Error('无法刷新可用代理，请重试；尚未启动注册任务。')
      const currentProxyError = registrationProxyError(currentProxyOptions, proxyKey, '', true)
      if (currentProxyError) throw new Error(currentProxyError)
      const extra = buildChatGPTRegistrationRequestAdapter('chatgpt', 'refresh_token')!.extendExtra({
        mail_provider: 'gmail', gmail_alias_ids: registrationTargets.map(alias => alias.id),
        gmail_source_id: sourceId, _gmail_retry: registrationTargets.some(gmailAliasCanResume),
        chatgpt_security_after_register: security ? '1' : '0',
      })
      const result = await apiFetch('/tasks/register', { method: 'POST', body: JSON.stringify({ platform: 'chatgpt', count: registrationTargets.length, concurrency, executor_type: executor, proxy_key: proxyKey, extra }) })
      if (!result.task_id) throw new Error('服务端未返回任务 ID')
      setTaskId(result.task_id); sessionStorage.setItem(taskStorageKey, result.task_id)
      setTaskOpen(true); setRegisterOpen(false); setSelected([]); void reload()
    } catch (reason) { setRegistrationSubmitError(errorText(reason)); void reloadProxyOptions() } finally { setStarting(false) }
  }
  const submitImport = async () => {
    if (importing || !importData.trim()) return
    setImporting(true); setImportError('')
    try {
      const result = await apiFetch('/workspace/ordinary/import-gmail-bundle', { method: 'POST', body: JSON.stringify({ data: importData, registration_status: 'unregistered' }) })
      setImportData(''); setImportOpen(false); message.success(`已保存 ${result.total ?? result.items?.length ?? 0} 个普通账号`); void reload()
    } catch (reason) { setImportError(errorText(reason)) } finally { setImporting(false) }
  }
  const verifyImportedAccount = async (alias: Alias) => {
    if (!alias.gpt_plan_account_id || verifyingId !== null) return
    setVerifyingId(alias.id)
    try {
      const result = await apiFetch(`/gpt-plans/accounts/${alias.gpt_plan_account_id}/login`, { method: 'POST', body: JSON.stringify({}) })
      if (result.ok === false) throw new Error(result.error || '登录失败')
      message.success('登录核验完成'); await reload()
    } catch (reason) { message.error(errorText(reason)); void reload() }
    finally { setVerifyingId(null) }
  }
  return <>
    <PageHeader title="普通账号" subtitle="导入 Gmail 子号迁移包，统一完成 GPT 注册、2FA 与 BUSINESS 邀请" extra={<Space wrap>
      <Button icon={<ImportOutlined />} onClick={() => { setImportError(''); setImportOpen(true) }}>导入 Gmail 子号</Button>
      {taskId && <Button onClick={() => setTaskOpen(true)}>查看注册任务</Button>}
      <Button type="primary" icon={<PlayCircleOutlined />} onClick={() => setRegisterOpen(true)}>注册 / 继续所选</Button>
    </Space>} />
    <Space wrap style={{ marginBottom: 16 }}><Tag>全部 {aliases.length}</Tag><Tag color="success">已注册 {aliases.filter(isRegistered).length}</Tag><Tag>未注册 / 待处理 {aliases.filter(alias => !isRegistered(alias)).length}</Tag></Space>
    {error && <Alert type="error" showIcon message="账号列表读取失败" description={error} style={{ marginBottom: 16 }} />}
    <Card>
      <Space wrap style={{ marginBottom: 16 }}>
        <Input.Search allowClear placeholder="搜索普通账号或接码来源" value={keyword} onChange={event => setKeyword(event.target.value)} style={{ width: 260 }} />
        <Select allowClear showSearch optionFilterProp="label" placeholder="全部接码来源" value={sourceId} onChange={value => { setSourceId(value); setSelected([]) }} style={{ width: 250 }} options={sources.map(source => ({ value: source.id, label: source.email }))} />
        <Select value={state} onChange={value => { setState(value); setSelected([]) }} style={{ width: 160 }} options={[{ value: 'all', label: '全部注册状态' }, { value: 'unregistered', label: '未注册' }, { value: 'registered', label: '已注册' }, { value: 'pending', label: '进行中 / 需处理' }]} />
        <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void reload()}>刷新</Button>
      </Space>
      <Table<Alias> rowKey="id" loading={loading} dataSource={filtered} scroll={{ x: 1050 }} rowSelection={{ selectedRowKeys: selected, onChange: keys => setSelected(keys.map(Number)), getCheckboxProps: alias => ({ disabled: Boolean(unavailable(alias)), title: unavailable(alias) || undefined }) }} pagination={{ pageSize: 20, showSizeChanger: true, showTotal: total => `共 ${total} 个账号` }} locale={{ emptyText: '暂无普通账号，请导入由源项目生成的 Gmail 子号迁移包。' }} columns={[
        { title: '普通账号 / Gmail 别名', dataIndex: 'email', width: 300, render: (email: string) => <Typography.Text copyable>{email}</Typography.Text> },
        { title: '接码来源', width: 250, render: (_, alias) => sourceById.get(alias.source_id)?.email || `接码资源 #${alias.source_id}` },
        { title: 'GPT 注册状态', width: 290, render: (_, alias) => { const status = gmailRegistrationStatus(alias.registration_status); return <Space direction="vertical" size={3}>
          <Tag color={status.color}>{status.label}</Tag>
          {alias.registration_stage === 'imported_registered_unverified' && <Typography.Text type="warning">已导入资料 · 等待登录验证</Typography.Text>}
          {alias.registration_stage && alias.registration_stage !== 'imported_registered_unverified' && <Typography.Text type="secondary">{gmailRegistrationStage(alias.registration_stage)}</Typography.Text>}
          {alias.registration_error && <Typography.Text type="danger">{alias.registration_error}</Typography.Text>}
        </Space> } },
        { title: '操作', width: 220, render: (_, alias) => <Space wrap>
          {alias.registration_verification === 'declared' && alias.gpt_plan_account_id && <Button size="small" loading={verifyingId === alias.id} disabled={verifyingId !== null && verifyingId !== alias.id} onClick={() => void verifyImportedAccount(alias)}>登录核验</Button>}
          {gmailPlanPath(alias) && <Button size="small" onClick={() => navigate(gmailPlanPath(alias)!)}>账号详情</Button>}
          {gmailAliasSelectable(alias) && <Button size="small" disabled={Boolean(unavailable(alias))} onClick={() => { setSelected([alias.id]); setRegisterOpen(true) }}>{gmailAliasCanResume(alias) ? '继续任务' : '注册 GPT'}</Button>}
          {alias.registration_task_id && <Button size="small" onClick={() => { setTaskId(alias.registration_task_id!); setTaskOpen(true) }}>任务进度</Button>}
        </Space> },
      ]} />
    </Card>
    <Modal title="注册 Gmail 普通账号" open={registerOpen} onCancel={() => { if (!starting) setRegisterOpen(false) }} onOk={() => void startRegistration()} okText={`启动 ${registrationTargets.length} 个账号`} confirmLoading={starting} okButtonProps={{ disabled: loading || proxyLoading || Boolean(error || registrationError || proxyError) }} width={660}>
      <Space direction="vertical" style={{ width: '100%' }} size={16}>
        <Alert showIcon type={registrationError ? 'warning' : 'info'} message={registrationError || `将处理 ${registrationTargets.length} 个${selected.length ? '所选' : '当前筛选下未注册'} Gmail 别名`} description={!registrationError ? '注册成功后自动同步账号；失败或暂停的账号可选择后继续原步骤。' : undefined} />
        <Space wrap>注册方式 <Select aria-label="注册方式" value={executor} onChange={setExecutor} disabled={starting} style={{ width: 230 }} options={[{ value: 'headless', label: '无头浏览器（默认）' }, { value: 'protocol', label: '纯协议' }, { value: 'headed', label: '有头浏览器（需桌面环境）' }]} />并发 <InputNumber min={1} max={10} value={concurrency} disabled={starting} onChange={value => setConcurrency(value || 1)} /></Space>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Typography.Text>注册代理（必选，仅显示检测通过的节点）</Typography.Text>
          <Select aria-label="注册代理" showSearch optionFilterProp="label" placeholder="请选择已验证代理" value={proxyKey} loading={proxyLoading} disabled={starting} onChange={value => { setProxyKey(value); setProxyLabel(proxySelectOptions.find(option => option.value === value)?.label || value); setRegistrationSubmitError('') }} style={{ width: '100%' }} options={proxySelectOptions.map(option => ({ ...option, disabled: !proxyOptions.some(item => item.key === option.value) }))} notFoundContent="暂无检测通过的代理" />
          <Space><Button icon={<ReloadOutlined />} loading={proxyLoading} disabled={starting} onClick={() => void reloadProxyOptions()}>刷新可用代理</Button><Button disabled={starting} onClick={() => navigate('/proxies')}>前往代理管理</Button></Space>
          {proxyError && <Alert showIcon type={proxyLoadError ? 'error' : 'warning'} message={proxyError} />}
        </Space>
        {registrationSubmitError && <Alert showIcon type="error" message="注册任务未启动" description={registrationSubmitError} />}
        <Space><Switch checked={security} onChange={setSecurity} />注册后设置 GPT 密码与 Authenticator 2FA</Space>
      </Space>
    </Modal>
    <Modal title="导入 Gmail 普通账号迁移包" open={importOpen} onCancel={() => { if (!importing) { setImportOpen(false); setImportData('') } }} onOk={() => void submitImport()} confirmLoading={importing} okButtonProps={{ disabled: !importData.trim() }} width={700}>
      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <Alert showIcon type="info" message="导入源项目按 Gmail 母号生成的子号迁移包" description="系统只保存一份共享接码授权，并自动关联包内全部子号；已注册状态、GPT 密码和 2FA 按迁移包导入。" />
        <input type="file" accept="application/json,.json" disabled={importing} onChange={event => {
          const file = event.target.files?.[0]
          if (!file) return
          if (file.size > 1024 * 1024) { setImportError('迁移包超过 1 MB'); return }
          void file.text().then(text => { setImportData(text); setImportError('') }).catch(() => setImportError('迁移包读取失败'))
          event.currentTarget.value = ''
        }} />
        <Typography.Text type="secondary">也可以直接粘贴 ordinary-gmail.v1 JSON 内容。</Typography.Text>
        <Input.TextArea value={importData} onChange={event => setImportData(event.target.value)} rows={8} autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false} />
        {importError && <Alert type="error" showIcon message={importError} />}
      </Space>
    </Modal>
    <Modal title="GPT 注册任务" open={taskOpen} onCancel={() => setTaskOpen(false)} footer={<Button onClick={() => setTaskOpen(false)}>关闭</Button>} width={960}>
      {taskId && <><Typography.Paragraph copyable>{taskId}</Typography.Paragraph><TaskLogPanel key={taskId} taskId={taskId} maxLines={400} onDone={() => void reload()} /></>}
    </Modal>
  </>
}
