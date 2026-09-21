import { useEffect, useState } from 'react'
import { Alert, App, Button, Form, Modal, Select, Space, Spin, Typography } from 'antd'
import { Link } from 'react-router-dom'
import { SettingOutlined } from '@ant-design/icons'
import { useBusinessInviteMailProviderSettings } from '@/hooks/useBusinessInviteMailProviderSettings'
import { BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS, type BusinessInviteMailProviderDefaults } from '@/lib/businessInviteMailProvider'

const options = BUSINESS_INVITE_MAIL_PROVIDER_OPTIONS.filter(option => option.value !== 'auto')

export default function BusinessInviteMailProviderSettings() {
  const { message } = App.useApp()
  const settings = useBusinessInviteMailProviderSettings()
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState<BusinessInviteMailProviderDefaults | null>(null)
  useEffect(() => {
    if (open && !draft && settings.defaults && !settings.loading) setDraft({ ...settings.defaults })
  }, [open, draft, settings.defaults, settings.loading])

  const save = async () => {
    if (!draft) return
    try {
      await settings.save(draft)
      message.success('席位默认邮箱已保存，新选择的子号立即使用新配置')
      setOpen(false)
    } catch {
      // Keep the draft and show the shared server error without success feedback.
    }
  }

  return <>
    <Button size="small" icon={<SettingOutlined />} onClick={() => { setDraft(null); setOpen(true); void settings.reload() }}>配置席位默认邮箱</Button>
    <Modal title="席位默认邮箱" open={open} onCancel={() => { if (!settings.saving) setOpen(false) }}
      onOk={() => void save()} okText="保存并生效" cancelText="取消" confirmLoading={settings.saving}
      okButtonProps={{ disabled: !draft || settings.loading || Boolean(settings.error) }} cancelButtonProps={{ disabled: settings.saving }}
      maskClosable={!settings.saving} closable={!settings.saving}>
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Alert type="info" showIcon message="BUSINESS 邀请邮箱规则"
          description="选择“按席位默认”时使用此配置；明确指定的邮箱类型保持不变。保存后只影响新选择的子号，已绑定子号继续原流程。" />
        {settings.error && <Alert type="error" showIcon message="席位默认邮箱未确认" description={settings.error}
          action={<Button size="small" onClick={() => { setDraft(null); void settings.reload() }}>重新读取</Button>} />}
        {settings.loading ? <Spin aria-label="读取席位默认邮箱" /> : draft && <Form layout="vertical">
          <Form.Item label="普通席位默认邮箱">
            <Select aria-label="普通席位默认邮箱" value={draft.default} options={options} disabled={settings.saving || Boolean(settings.error)}
              onChange={value => setDraft(previous => previous ? { ...previous, default: value } : previous)} />
          </Form.Item>
          <Form.Item label="高级席位（5X）默认邮箱">
            <Select aria-label="高级席位（5X）默认邮箱" value={draft.prolite} options={options} disabled={settings.saving || Boolean(settings.error)}
              onChange={value => setDraft(previous => previous ? { ...previous, prolite: value } : previous)} />
          </Form.Item>
        </Form>}
        <Typography.Text type="secondary">Gmail 子号及共享接码授权通过 <Link to="/" onClick={() => setOpen(false)}>普通账号</Link> 导入；未注册子号可由系统自动准备。</Typography.Text>
      </Space>
    </Modal>
  </>
}
