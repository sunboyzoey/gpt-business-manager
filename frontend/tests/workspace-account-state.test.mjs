import assert from 'node:assert/strict'
import test from 'node:test'
import { canLoginWithSavedPassword, gmailWorkspaceRegistrationGroup } from '../src/lib/gmailWorkspaceAccountState.ts'

test('a plan association does not turn an imported unregistered alias into a registered account', () => {
  const inventory = [
    { email: 'mother+new@gmail.com', gpt_plan_account_id: 101, registration_status: 'unregistered', registration_verification: 'unregistered' },
    { email: 'mother+existing@gmail.com', gpt_plan_account_id: 102, registration_status: 'registered', registration_verification: 'declared' },
    { email: 'mother+busy@gmail.com', gpt_plan_account_id: 103, registration_status: 'registering' },
    { email: 'mother+ready@gmail.com', registration_status: 'sync_pending', registered_at: '2026-09-16T12:00:00Z' },
  ]
  assert.deepEqual(inventory.map(gmailWorkspaceRegistrationGroup), ['unregistered', 'registered', 'pending', 'registered'])
  assert.deepEqual(inventory.filter(row => gmailWorkspaceRegistrationGroup(row) === 'unregistered').map(row => row.email), ['mother+new@gmail.com'])
  assert.equal(inventory.filter(row => gmailWorkspaceRegistrationGroup(row) === 'registered').length, 2)
  assert.equal(gmailWorkspaceRegistrationGroup({ gpt_plan_account_id: 104 }), 'unregistered')
})

test('completed registration stays registered during a later security recovery', () => {
  assert.equal(gmailWorkspaceRegistrationGroup({ registration_status: 'paused', registered_at: '2026-09-16T12:00:00Z' }), 'registered')
  assert.equal(gmailWorkspaceRegistrationGroup({ registration_verification: 'verified' }), 'registered')
})

const imported = { password_state: 'imported_unverified', has_password: true, credentials_readable: true, has_totp: false, mfa_state: 'not_configured' }
test('a readable imported password without MFA can be explicitly verified', () => {
  assert.equal(canLoginWithSavedPassword(imported), true)
})

test('imported-password verification does not bypass missing MFA or unreadable credentials', () => {
  for (const mfa_state of ['pending', 'enabled', 'unmanaged', 'unknown', 'imported_unverified']) {
    assert.equal(canLoginWithSavedPassword({ ...imported, mfa_state }), false, mfa_state)
  }
  for (const changed of [{ has_totp: true }, { has_password: false }, { credentials_readable: false }, { credentials_readable: undefined }, { mfa_state: undefined }, { password_state: 'pending' }]) {
    assert.equal(canLoginWithSavedPassword({ ...imported, ...changed }), false)
  }
})

test('a verified password-only account remains able to log in again', () => {
  assert.equal(canLoginWithSavedPassword({ ...imported, password_state: 'configured' }), true)
})
