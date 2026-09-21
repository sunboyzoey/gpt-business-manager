interface GmailRegistrationEvidence {
  registration_status?: string
  registered_at?: string | null
  registration_verification?: string
}

/** A local plan-directory association is not evidence of a registered identity. */
export function gmailWorkspaceRegistrationGroup(alias: GmailRegistrationEvidence): 'registered' | 'unregistered' | 'pending' {
  if (alias.registered_at
    || ['registered', 'sync_pending'].includes(alias.registration_status || '')
    || ['declared', 'verified'].includes(alias.registration_verification || '')) return 'registered'
  return !alias.registration_status || alias.registration_status === 'unregistered' ? 'unregistered' : 'pending'
}

interface ImportedLoginSecurity {
  password_state?: string
  mfa_state?: string
  has_password?: boolean
  has_totp?: boolean
  credentials_readable?: boolean
}

/** Saved passwords can be used without bypassing known or unreadable MFA. */
export function canLoginWithSavedPassword(security: ImportedLoginSecurity): boolean {
  return ['imported_unverified', 'configured'].includes(security.password_state || '')
    && security.has_password === true
    && security.credentials_readable === true
    && security.has_totp === false
    && security.mfa_state === 'not_configured'
}
