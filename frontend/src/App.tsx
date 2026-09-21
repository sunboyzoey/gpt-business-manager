import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { Alert, App as AntdApp, Button, ConfigProvider, Layout, Space, Spin, Tabs, Typography } from 'antd'
import { GlobalOutlined, MoonOutlined, PhoneOutlined, SettingOutlined, SunOutlined, TeamOutlined, UserOutlined } from '@ant-design/icons'
import zhCN from 'antd/es/locale/zh_CN'
import GptPlans from '@/pages/GptPlans'
import Login from '@/pages/Login'
import OrdinaryAccounts from '@/pages/OrdinaryAccounts'
import Proxies from '@/pages/Proxies'
import WorkspaceSettings from '@/pages/WorkspaceSettings'
import SmsProviders from '@/pages/SmsProviders'
import { darkTheme, lightTheme } from '@/theme'

function Workspace() {
  const navigate = useNavigate()
  const location = useLocation()
  const [ready, setReady] = useState(false)
  const [error, setError] = useState('')
  const [mode, setMode] = useState(() => localStorage.getItem('gmail-business-theme') || 'light')
  useEffect(() => {
    const controller = new AbortController()
    fetch('/api/auth/status', { signal: controller.signal }).then(async response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const state = await response.json()
      if (!state.authenticated) navigate('/login', { replace: true })
      else setReady(true)
    }).catch(reason => { if (!controller.signal.aborted) setError(String(reason)) })
    return () => controller.abort()
  }, [navigate])
  useEffect(() => {
    localStorage.setItem('gmail-business-theme', mode)
    document.documentElement.classList.toggle('light', mode === 'light')
  }, [mode])
  const main = location.pathname === '/' || location.pathname === '/business'
  return <ConfigProvider locale={zhCN} theme={mode === 'light' ? lightTheme : darkTheme}><AntdApp>
    <Layout style={{ minHeight: '100vh' }}>
      <Layout.Header style={{ height: 'auto', lineHeight: 'normal', padding: '20px 28px', background: mode === 'light' ? '#fff' : '#141820', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div><Typography.Title level={4} style={{ margin: 0 }}>Gmail · BUSINESS 管理</Typography.Title><Typography.Text type="secondary">Gmail 普通账号与多席位工作区</Typography.Text></div>
        <Space wrap>
          {!main && <Button onClick={() => navigate('/')}>返回账号</Button>}
          <Button icon={<GlobalOutlined />} onClick={() => navigate('/proxies')}>代理管理</Button>
          <Button icon={<PhoneOutlined />} onClick={() => navigate('/sms')}>短信接码</Button>
          <Button icon={<SettingOutlined />} onClick={() => navigate('/settings')}>设置</Button>
          <Button aria-label="切换明暗主题" icon={mode === 'light' ? <MoonOutlined /> : <SunOutlined />} onClick={() => setMode(mode === 'light' ? 'dark' : 'light')} />
        </Space>
      </Layout.Header>
      <Layout.Content style={{ padding: '20px 28px 40px', minWidth: 0 }}>
        {error ? <Alert type="error" showIcon message="无法连接独立项目服务" description={error} action={<Button onClick={() => window.location.reload()}>重试</Button>} /> : !ready ? <Spin /> : <>
          {main && <Tabs size="large" activeKey={location.pathname} onChange={navigate} items={[
            { key: '/', label: <Space><UserOutlined />普通账号</Space> },
            { key: '/business', label: <Space><TeamOutlined />BUSINESS 母号</Space> },
          ]} />}
          <Routes>
            <Route path="/" element={<OrdinaryAccounts />} />
            <Route path="/register" element={<OrdinaryAccounts registrationEntry />} />
            <Route path="/business" element={<GptPlans key="business" businessOnly standalone />} />
            <Route path="/gpt-plans" element={<GptPlans key="detail" standalone />} />
            <Route path="/proxies" element={<Proxies />} />
            <Route path="/settings" element={<WorkspaceSettings />} />
            <Route path="/sms" element={<SmsProviders />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </>}
      </Layout.Content>
    </Layout>
  </AntdApp></ConfigProvider>
}

export default function App() {
  return <BrowserRouter><Routes><Route path="/login" element={<Login />} /><Route path="/*" element={<Workspace />} /></Routes></BrowserRouter>
}
