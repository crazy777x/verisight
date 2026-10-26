import test from 'node:test'
import assert from 'node:assert/strict'
import { inspectPanQr } from '../lib/pan-qr'
import { buildVerdict } from '../lib/verdict'
import { base, camera, printed } from './helpers'

test('PAN QR compares recognizable JSON fields with printed values', () => {
  const result = inspectPanQr('{"pan":"ABCDE1234F","name":"Test User"}', { pan: 'ABCDE1234F', name: 'TEST USER' })
  assert.equal(result.formatLabel, 'JSON object')
  assert.equal(result.pan.result, 'match')
  assert.equal(result.name.result, 'match')
})

test('PAN QR compares key/value fields and handles mismatches without asserting forgery', () => {
  const result = inspectPanQr('PAN=ABCDE1234F|NAME=Different Person', { pan: 'ZZZZZ9999Z', name: 'TEST USER' })
  assert.equal(result.pan.result, 'mismatch')
  assert.equal(result.name.result, 'mismatch')
})

test('PAN QR leaves unknown, unreadable, or conflicting fields unverified', () => {
  const unknown = inspectPanQr('encrypted payload', { pan: 'ABCDE1234F', name: 'TEST USER' })
  assert.equal(unknown.pan.result, 'unread')
  const conflicting = inspectPanQr('{"pan":"ABCDE1234F","panNo":"ZZZZZ9999Z"}', { pan: 'ABCDE1234F', name: 'TEST USER' })
  assert.equal(conflicting.pan.result, 'ambiguous')
})

test('PAN QR mismatch is a review signal only; a matching payload does not authenticate the issuer', () => {
  const matching = buildVerdict(base({
    kind: 'pan',
    printed: { ...printed, aadhaarNo: '', pan: 'ABCDE1234F', panKeyword: true },
    qr: { text: '{"pan":"ABCDE1234F","name":"TEST USER"}', bytes: new Uint8Array(32), page: 0, engine: 'test' },
    qrAadhaar: null,
    qrRows: [],
    qrSig: null,
    isPdf: false,
    meta: camera,
  }))
  assert.ok(matching.findings.some((finding) => finding.code === 'UNVERIFIED'))
  assert.ok(!matching.findings.some((finding) => finding.title.includes('differs from printed')))

  const mismatch = buildVerdict(base({
    kind: 'pan',
    printed: { ...printed, aadhaarNo: '', pan: 'ABCDE1234F', panKeyword: true },
    qr: { text: '{"pan":"ZZZZZ9999Z","name":"Other Person"}', bytes: new Uint8Array(32), page: 0, engine: 'test' },
    qrAadhaar: null,
    qrRows: [],
    qrSig: null,
    isPdf: false,
    meta: camera,
  }))
  assert.ok(mismatch.findings.some((finding) => finding.code === 'QR_MISMATCH' && finding.severity === 'medium'))
  assert.equal(mismatch.level, 'SUSPICIOUS')
})
