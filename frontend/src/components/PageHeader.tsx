import { Typography, Space, theme } from 'antd'
import type { ReactNode } from 'react'

const { Text } = Typography

interface PageHeaderProps {
  title: string
  subtitle?: string
  icon?: ReactNode
  extra?: ReactNode
}

export default function PageHeader({ title, subtitle, icon, extra }: PageHeaderProps) {
  const { token: t } = theme.useToken()
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
      marginBottom: 24,
    }}>
      <div>
        <h1 style={{
          fontSize: 24, fontWeight: 700, margin: 0,
          display: 'flex', alignItems: 'center', gap: 8,
          color: t.colorText,
        }}>
          {icon}
          {title}
        </h1>
        {subtitle && (
          <Text type="secondary" style={{ marginTop: 4, display: 'block', fontSize: 13 }}>
            {subtitle}
          </Text>
        )}
      </div>
      {extra && <Space>{extra}</Space>}
    </div>
  )
}
