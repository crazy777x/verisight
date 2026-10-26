import test from 'node:test'
import assert from 'node:assert/strict'
import { classifyQrPayload } from '../lib/qrformat'

test('classifies a valid JSON payload without calling it government-authenticated', () => {
  const result = classifyQrPayload('{"name":"Test User","id":"ABC123"}')
  assert.equal(result.format, 'json')
  assert.match(result.detail, /does not identify or authenticate the issuer/)
})

test('classifies a web link without treating the destination as proof', () => {
  const result = classifyQrPayload('https://example.gov/check?id=123')
  assert.equal(result.format, 'url')
  assert.match(result.detail, /not proof/)
})

test('keeps unsupported payloads opaque instead of calling them fake', () => {
  const result = classifyQrPayload('\u0001\u0002\u0080')
  assert.equal(result.format, 'opaque')
  assert.match(result.detail, /No issuer-specific decoder/)
})
