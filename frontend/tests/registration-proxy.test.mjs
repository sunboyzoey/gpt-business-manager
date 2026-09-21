import assert from 'node:assert/strict'
import test from 'node:test'
import { parseRegistrationProxyOptions, registrationProxyError } from '../src/lib/registrationProxy.ts'

const manual = { key: 'manual:1', label: 'US proxy', kind: 'manual' }
const subscription = { key: 'subscription:US node', label: 'US node', kind: 'subscription' }

test('registration requires a selection from the current verified options', () => {
  const items = parseRegistrationProxyOptions({ items: [manual, subscription] })
  assert.equal(registrationProxyError(items, manual.key, '', true), '')
  assert.equal(registrationProxyError(items, subscription.key, '', true), '')
  assert.match(registrationProxyError(items, undefined, '', true), /请选择/)
  assert.match(registrationProxyError([], undefined, '', true), /暂无/)
  assert.match(registrationProxyError(items, 'manual:deleted', '', true), /已不可用/)
  assert.match(registrationProxyError([subscription], manual.key, '', true), /已不可用/)
})

test('loading and errors cannot accidentally authorize cached options', () => {
  assert.match(registrationProxyError([manual], manual.key, '', false), /正在读取/)
  assert.match(registrationProxyError([manual], manual.key, 'HTTP 503', true), /读取失败.*503/)
  for (const invalid of [null, {}, { items: {} }, { items: [{ ...manual, key: '' }] }, { items: [{ ...manual, kind: 'unknown' }] }]) {
    assert.throws(() => parseRegistrationProxyOptions(invalid), /格式无效/)
  }
})
