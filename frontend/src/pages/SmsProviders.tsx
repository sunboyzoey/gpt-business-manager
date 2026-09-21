import { useCallback, useEffect, useState } from 'react'
import { App, Button, Card, Col, Form, Input, InputNumber, Row, Select, Space, Table, Tag, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { apiFetch } from '@/lib/utils'

type Provider = { code: string; label: string; configured: boolean }
type Activation = {
  id: number; provider: string; phone: string; service: string; country: string
  state: string; code_received: boolean; created_at?: string
}

const stateColor: Record<string, string> = {
  allocated: 'processing', waiting: 'processing', ok: 'success', completed: 'success',
  cancelled: 'default', failed: 'error',
}

export default function SmsProviders() {
  const { message } = App.useApp()
  const [providers, setProviders] = useState<Provider[]>([])
  const [activations, setActivations] = useState<Activation[]>([])
  const [providerCode, setProviderCode] = useState('smsbower')
  const [loading, setLoading] = useState(false)
  const [form] = Form.useForm()

  const load = useCallback(async () => {
    const [providerData, activationData] = await Promise.all([
      apiFetch('/sms/providers'), apiFetch('/sms/activations?limit=100'),
    ])
    setProviders(providerData.items || [])
    setActivations(activationData.items || [])
  }, [])

  useEffect(() => { load().catch(error => message.error(String(error))) }, [load, message])

  const save = async (values: { api_key?: string; base_url?: string; proxy?: string }) => {
    setLoading(true)
    try {
      await apiFetch(`/sms/providers/${providerCode}`, {
        method: 'PUT', body: JSON.stringify(values),
      })
      message.success('短信供应商配置已加密保存')
      form.setFieldValue('api_key', '')
      await load()
    } finally { setLoading(false) }
  }

  const test = async (code: string) => {
    setLoading(true)
    try {
      const result = await apiFetch(`/sms/providers/${code}/test`, { method: 'POST', body: '{}' })
      message.success(`${code} 连接成功，余额 ${result.balance}`)
    } finally { setLoading(false) }
  }

  const acquire = async (values: { provider: string; service: string; country: string; max_price: number }) => {
    setLoading(true)
    try {
      await apiFetch('/sms/activations', {
        method: 'POST', body: JSON.stringify({ ...values, max_price: String(values.max_price) }),
      })
      message.success('取号成功，激活记录已保存')
      await load()
    } finally { setLoading(false) }
  }

  return <Space direction="vertical" size={18} style={{ width: '100%' }}>
    <div>
      <Typography.Title level={3} style={{ marginBottom: 4 }}>短信接码</Typography.Title>
      <Typography.Text type="secondary">统一配置供应商、测试余额并查看持久化激活记录。API Key 只加密存储，不会在页面回显。</Typography.Text>
    </div>
    <Row gutter={[16, 16]}>
      {providers.map(item => <Col xs={24} md={12} key={item.code}><Card title={item.label} extra={<Tag color={item.configured ? 'green' : 'default'}>{item.configured ? '已配置' : '未配置'}</Tag>}>
        <Space><Button onClick={() => { setProviderCode(item.code); form.resetFields() }}>编辑配置</Button><Button disabled={!item.configured} loading={loading} onClick={() => test(item.code)}>测试余额</Button></Space>
      </Card></Col>)}
    </Row>
    <Card title={`配置 ${providers.find(item => item.code === providerCode)?.label || providerCode}`}>
      <Form form={form} layout="vertical" onFinish={save}>
        <Row gutter={16}>
          <Col xs={24} md={8}><Form.Item name="api_key" label="API Key"><Input.Password placeholder="留空则保留现有密钥" autoComplete="new-password" /></Form.Item></Col>
          <Col xs={24} md={8}><Form.Item name="base_url" label="API 地址（可空）"><Input placeholder="使用供应商默认地址" /></Form.Item></Col>
          <Col xs={24} md={8}><Form.Item name="proxy" label="代理（可空）"><Input placeholder="http://user:pass@host:port" /></Form.Item></Col>
        </Row>
        <Button type="primary" htmlType="submit" loading={loading}>保存配置</Button>
      </Form>
    </Card>
    <Card title="取号测试">
      <Form layout="inline" initialValues={{ provider: 'smsbower', service: 'dr', country: '187', max_price: 0.16 }} onFinish={acquire}>
        <Form.Item name="provider" label="供应商"><Select style={{ width: 150 }} options={providers.map(item => ({ value: item.code, label: item.label }))} /></Form.Item>
        <Form.Item name="service" label="服务"><Input style={{ width: 100 }} /></Form.Item>
        <Form.Item name="country" label="国家码"><Input style={{ width: 100 }} /></Form.Item>
        <Form.Item name="max_price" label="最高价"><InputNumber min={0} precision={4} /></Form.Item>
        <Form.Item><Button type="primary" htmlType="submit" loading={loading}>取号</Button></Form.Item>
      </Form>
    </Card>
    <Card title="激活记录" extra={<Button icon={<ReloadOutlined />} onClick={() => load()}>刷新</Button>}>
      <Table rowKey="id" dataSource={activations} pagination={{ pageSize: 20 }} columns={[
        { title: 'ID', dataIndex: 'id', width: 80 },
        { title: '供应商', dataIndex: 'provider' },
        { title: '手机号', dataIndex: 'phone' },
        { title: '服务', dataIndex: 'service' },
        { title: '国家', dataIndex: 'country' },
        { title: '状态', dataIndex: 'state', render: value => <Tag color={stateColor[value] || 'default'}>{value}</Tag> },
        { title: '已收码', dataIndex: 'code_received', render: value => value ? '是' : '否' },
        { title: '创建时间', dataIndex: 'created_at' },
      ]} />
    </Card>
  </Space>
}
