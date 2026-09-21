import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Alert, App, Button, Card, Descriptions, Form, Input, Select, Space, Tag, Typography } from 'antd'
import { apiFetch, setToken } from '@/lib/utils'

export default function WorkspaceSettings() {
  const { message } = App.useApp()
  const navigate = useNavigate()
  const [form] = Form.useForm()
  const [smsForm] = Form.useForm()
  const [passwordForm] = Form.useForm()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [passwordSaving, setPasswordSaving] = useState(false)
  const [smsSaving, setSmsSaving] = useState(false)
  const [smsTesting, setSmsTesting] = useState(false)
  const [smsBalance, setSmsBalance] = useState<string | null>(null)
  const [smsProvider, setSmsProvider] = useState('')
  const [smsError, setSmsError] = useState('')
  const [hasPassword, setHasPassword] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    Promise.all([apiFetch('/config'), apiFetch('/auth/status')]).then(([config, auth]) => {
      if (!active) return
      form.setFieldsValue({ default_proxy: config.default_proxy || '', default_executor: config.default_executor || 'headless' })
      smsForm.setFieldsValue({
        smsbower_api_key: config.smsbower_api_key || '',
        smsbower_base_url: config.smsbower_base_url || '',
        smsbower_service: config.smsbower_service || 'dr',
        smsbower_countries: config.smsbower_countries || config.smsbower_country || '39',
        smsbower_max_price: config.smsbower_max_price || '0.08',
        smsbower_proxy: config.smsbower_proxy || '',
        smsbower_max_attempts: config.smsbower_max_attempts || '3',
        smsbower_otp_timeout_seconds: config.smsbower_otp_timeout_seconds || '180',
        smsbower_poll_interval_seconds: config.smsbower_poll_interval_seconds || '5',
        chatgpt_rt_allow_phone_verification: config.chatgpt_rt_allow_phone_verification || '1',
      })
      setHasPassword(Boolean(auth.has_password))
    }).catch(reason => { if (active) setError(String(reason)) }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [form, smsForm])

  const testSmsBalance = async () => {
    setSmsTesting(true)
    setSmsError('')
    try {
      const result = await apiFetch('/smsbower/balance')
      setSmsBalance(String(result.balance))
      const status = await apiFetch('/smsbower/balance-status')
      setSmsProvider(String(status.provider || 'SMSBower'))
      message.success('接码平台连接正常')
    } catch (reason) {
      setSmsBalance(null)
      setSmsError(String(reason))
      message.error(String(reason))
    } finally {
      setSmsTesting(false)
    }
  }
  return <Space direction="vertical" size={20} style={{ width: '100%', maxWidth: 850 }}>
    <Typography.Title level={3}>项目设置</Typography.Title>
    {error && <Alert type="error" showIcon message={error} />}
    <Card title="注册与网络" loading={loading}>
      <Form form={form} layout="vertical" onFinish={async values => {
        setSaving(true)
        try { await apiFetch('/config', { method: 'PUT', body: JSON.stringify({ data: values }) }); message.success('设置已保存') }
        catch (reason) { message.error(String(reason)) } finally { setSaving(false) }
      }}>
        <Alert type="info" showIcon style={{ marginBottom: 20 }} message="注册任务必须选择检测通过的代理" description="请先在代理管理中添加手动代理或更新订阅，并完成 ChatGPT 检测；注册弹窗会列出当前可用节点。" action={<Button onClick={() => navigate('/proxies')}>代理管理</Button>} />
        <Form.Item name="default_executor" label="默认注册方式" extra="默认使用无头浏览器，适用于 Linux 服务器；有头浏览器需要图形桌面环境。"><Select options={[{ value: 'headless', label: '无头浏览器（默认）' }, { value: 'protocol', label: '纯协议' }, { value: 'headed', label: '有头浏览器（需桌面环境）' }]} /></Form.Item>
        <Form.Item name="default_proxy" label="其他账号操作的默认代理" extra="仅供登录等其他操作使用；注册任务使用弹窗中选择的已验证代理。"><Input placeholder="例如 http://127.0.0.1:7890，留空使用该操作的默认网络" autoComplete="off" /></Form.Item>
        <Button htmlType="submit" type="primary" loading={saving}>保存设置</Button>
      </Form>
    </Card>
    <Card title="手机号接码与 RT 验证" loading={loading}>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 20 }}
        message="用于 ChatGPT OAuth 获取 RT 时出现 add_phone 手机号验证"
        description="配置后系统会自动取号并轮询短信。国家按从左到右的顺序尝试；取号可能产生费用。API Key 留空表示关闭接码能力。"
      />
      <Form form={smsForm} layout="vertical" onFinish={async values => {
        setSmsSaving(true)
        setSmsError('')
        try {
          const countries = String(values.smsbower_countries || '').split(',').map((item: string) => item.trim()).filter(Boolean).join(',')
          const data = { ...values, smsbower_countries: countries, smsbower_country: countries.split(',')[0] || '' }
          await apiFetch('/config', { method: 'PUT', body: JSON.stringify({ data }) })
          message.success('手机号接码配置已保存')
        } catch (reason) {
          setSmsError(String(reason))
          message.error(String(reason))
        } finally {
          setSmsSaving(false)
        }
      }}>
        <Form.Item name="smsbower_api_key" label="SMSBower API Key" extra="在 SMSBower 或兼容 sms-activate 协议的平台后台获取。">
          <Input.Password placeholder="输入 API Key；留空关闭" autoComplete="new-password" />
        </Form.Item>
        <Form.Item name="smsbower_base_url" label="接码 API 地址（可选）" extra="留空使用 SMSBower；兼容平台可填写自己的 handler_api.php 地址。">
          <Input placeholder="https://smsbower.page/stubs/handler_api.php" autoComplete="off" />
        </Form.Item>
        <Space size={16} wrap style={{ width: '100%' }}>
          <Form.Item name="smsbower_service" label="服务码" style={{ minWidth: 180 }} rules={[{ required: true }]}>
            <Input placeholder="dr" />
          </Form.Item>
          <Form.Item name="smsbower_countries" label="国家码轮换顺序" style={{ minWidth: 260 }} rules={[{ required: true }]}>
            <Input placeholder="39,187" />
          </Form.Item>
          <Form.Item name="smsbower_max_price" label="单号最高价格（USD）" style={{ minWidth: 210 }} rules={[{ required: true, pattern: /^\d+(\.\d+)?$/, message: '请输入有效金额' }]}>
            <Input placeholder="0.08" />
          </Form.Item>
        </Space>
        <Form.Item name="smsbower_proxy" label="接码接口代理（可选）">
          <Input placeholder="http://user:password@host:port" autoComplete="off" />
        </Form.Item>
        <Space size={16} wrap style={{ width: '100%' }}>
          <Form.Item name="smsbower_max_attempts" label="每个国家取号次数" style={{ minWidth: 210 }} rules={[{ required: true, pattern: /^(?:[1-9]|10)$/, message: '请输入 1–10' }]}>
            <Input placeholder="3" />
          </Form.Item>
          <Form.Item name="smsbower_otp_timeout_seconds" label="短信等待秒数" style={{ minWidth: 210 }} rules={[{ required: true, pattern: /^\d+$/, message: '请输入整数秒数' }]}>
            <Input placeholder="180" />
          </Form.Item>
          <Form.Item name="smsbower_poll_interval_seconds" label="短信轮询间隔（秒）" style={{ minWidth: 210 }} rules={[{ required: true, pattern: /^(?:[2-9]|1[0-5])$/, message: '请输入 2–15' }]}>
            <Input placeholder="5" />
          </Form.Item>
        </Space>
        <Form.Item name="chatgpt_rt_allow_phone_verification" label="获取 RT 时允许手机号验证">
          <Select options={[{ value: '1', label: '允许自动接码' }, { value: '0', label: '禁止申请手机号' }]} />
        </Form.Item>
        {smsError && <Alert type="error" showIcon message="接码平台检查失败" description={smsError} style={{ marginBottom: 16 }} />}
        {smsBalance !== null && <Descriptions size="small" column={2} bordered style={{ marginBottom: 16 }}>
          <Descriptions.Item label="平台"><Tag color="blue">{smsProvider || 'SMSBower'}</Tag></Descriptions.Item>
          <Descriptions.Item label="当前余额">{smsBalance}</Descriptions.Item>
        </Descriptions>}
        <Space>
          <Button htmlType="submit" type="primary" loading={smsSaving}>保存接码配置</Button>
          <Button loading={smsTesting} onClick={testSmsBalance}>检测连接与余额</Button>
        </Space>
      </Form>
    </Card>
    <Card title={hasPassword ? '后台访问密码已启用' : '设置后台访问密码'}>
      {hasPassword ? <Typography.Text type="secondary">当前项目已启用密码保护。</Typography.Text> : <Form form={passwordForm} layout="vertical" onFinish={async values => {
        setPasswordSaving(true)
        try {
          const result = await apiFetch('/auth/setup', { method: 'POST', body: JSON.stringify({ password: values.password }) })
          setToken(result.access_token); setHasPassword(true); passwordForm.resetFields(); message.success('访问密码已设置')
        } catch (reason) { message.error(String(reason)) } finally { setPasswordSaving(false) }
      }}>
        <Form.Item name="password" label="新密码" rules={[{ required: true }, { min: 8, message: '请至少输入 8 位' }]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Form.Item name="confirm" label="确认密码" dependencies={['password']} rules={[{ required: true }, ({ getFieldValue }) => ({ validator(_, value) { return value === getFieldValue('password') ? Promise.resolve() : Promise.reject(new Error('两次密码不一致')) } })]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Button htmlType="submit" type="primary" loading={passwordSaving}>启用访问密码</Button>
      </Form>}
    </Card>
  </Space>
}
