import { theme } from 'antd'

// ── 设计规范常量 ──────────────────────────────────────

/** 统一间距体系 (4px 倍数) */
export const SPACING = {
  xs: 4,
  sm: 8,
  md: 16,
  lg: 24,
  xl: 32,
} as const

/** 状态色映射 */
export const STATUS_TAG_COLORS: Record<string, string> = {
  registered: 'blue',
  trial: 'gold',
  subscribed: 'green',
  expired: 'orange',
  invalid: 'red',
}

// ── Ant Design 主题配置 ──────────────────────────────

const sharedToken = {
  borderRadius: 10,
  borderRadiusLG: 12,
  fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
}

const darkTheme = {
  token: {
    ...sharedToken,
    colorPrimary: '#6366f1',
    colorBgBase: '#0f1117',
    colorTextBase: '#e8eaed',
    colorBgContainer: '#181a24',
    colorBgElevated: '#1e2030',
    colorBorder: 'rgba(255,255,255,0.08)',
    colorBorderSecondary: 'rgba(255,255,255,0.05)',
    colorText: '#e8eaed',
    colorTextSecondary: '#9ca3b4',
    colorTextTertiary: '#6b7280',
    colorTextQuaternary: '#4b5563',
    colorBgLayout: '#0b0d14',
    colorBgSpotlight: 'rgba(99,102,241,0.15)',
    colorFillAlter: 'rgba(255,255,255,0.03)',
    colorFillSecondary: 'rgba(255,255,255,0.06)',
    colorSuccessBg: 'rgba(16,185,129,0.08)',
    colorSuccessBorder: 'rgba(16,185,129,0.2)',
    colorErrorBg: 'rgba(239,68,68,0.08)',
    colorErrorBorder: 'rgba(239,68,68,0.2)',
    colorWarningBg: 'rgba(245,158,11,0.08)',
    colorWarningBorder: 'rgba(245,158,11,0.2)',
  },
  components: {
    Layout: {
      siderBg: '#12141e',
      triggerBg: '#12141e',
      triggerColor: '#e8eaed',
    },
    Card: {
      colorBgContainer: '#181a24',
      paddingLG: 20,
    },
    Table: {
      headerBg: 'rgba(255,255,255,0.02)',
      rowHoverBg: 'rgba(99,102,241,0.04)',
    },
    Menu: {
      itemBg: 'transparent',
      itemSelectedBg: 'rgba(99,102,241,0.12)',
      itemSelectedColor: '#818cf8',
      itemHoverBg: 'rgba(255,255,255,0.04)',
    },
  },
  algorithm: theme.darkAlgorithm,
}

const lightTheme = {
  token: {
    ...sharedToken,
    colorPrimary: '#4f46e5',
    colorBgBase: '#ffffff',
    colorTextBase: '#0f172a',
    colorBgContainer: '#ffffff',
    colorBgElevated: '#ffffff',
    colorBorder: 'rgba(0,0,0,0.08)',
    colorBorderSecondary: 'rgba(0,0,0,0.04)',
    colorText: '#0f172a',
    colorTextSecondary: '#475569',
    colorTextTertiary: '#94a3b8',
    colorTextQuaternary: '#cbd5e1',
    colorBgLayout: '#f1f5f9',
    colorFillAlter: 'rgba(0,0,0,0.02)',
    colorFillSecondary: 'rgba(0,0,0,0.04)',
  },
  components: {
    Layout: {
      siderBg: '#ffffff',
      triggerBg: '#ffffff',
      triggerColor: '#0f172a',
    },
    Card: {
      paddingLG: 20,
    },
    Table: {
      headerBg: 'rgba(0,0,0,0.01)',
      rowHoverBg: 'rgba(79,70,229,0.03)',
    },
    Menu: {
      itemBg: 'transparent',
      itemSelectedBg: 'rgba(79,70,229,0.08)',
      itemSelectedColor: '#4f46e5',
      itemHoverBg: 'rgba(0,0,0,0.03)',
    },
  },
  algorithm: theme.defaultAlgorithm,
}

export { darkTheme, lightTheme }
