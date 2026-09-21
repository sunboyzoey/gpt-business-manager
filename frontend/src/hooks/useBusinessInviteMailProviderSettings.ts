import { useEffect, useSyncExternalStore } from 'react'
import { apiFetch } from '@/lib/utils'
import { createBusinessInviteMailProviderSettings } from '@/lib/businessInviteMailProviderSettings'

const sharedSettings = createBusinessInviteMailProviderSettings(apiFetch)

export function useBusinessInviteMailProviderSettings() {
  const snapshot = useSyncExternalStore(sharedSettings.subscribe, sharedSettings.getSnapshot)
  useEffect(() => {
    void sharedSettings.load()
    const refreshOnReturn = () => {
      if (document.visibilityState === 'visible' && !sharedSettings.getSnapshot().loading) void sharedSettings.load(true)
    }
    window.addEventListener('focus', refreshOnReturn)
    document.addEventListener('visibilitychange', refreshOnReturn)
    return () => {
      window.removeEventListener('focus', refreshOnReturn)
      document.removeEventListener('visibilitychange', refreshOnReturn)
    }
  }, [])
  return { ...snapshot, reload: () => sharedSettings.load(true), save: sharedSettings.save }
}
