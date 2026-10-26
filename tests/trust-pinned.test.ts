// Runs with the leaf certificate pinned (see package.json "test" script: env var is set for this file only)
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, createPrivateKey, sign } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { LEAF_DER, LEAF_KEY_PEM } from './fixtures'
import { parseCert } from '../lib/asn1'

const fp = createHash('sha256').update(Buffer.from(LEAF_DER, 'base64')).digest('hex')
process.env.NEXT_PUBLIC_UIDAI_TRUSTED_SHA256 = fp
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { verifyAadhaarSignature, decodeAadhaarQr }: typeof import('../lib/analysis') = require('../lib/analysis')

test('with the certificate PINNED the same signature becomes "verified"', async () => {
  const FF = Buffer.from([255])
  const f = ['V2', '3', '1'.repeat(20), 'Test User', '01-01-1990', 'M', 'a', 'b', '', 'c', 'd', '460001', 'e', 'f', 'g', 'h', 'i']
  const body = Buffer.concat([...f.map((x) => Buffer.concat([Buffer.from(x), FF])), Buffer.alloc(40, 7)])
  const sig = sign('sha256', body, createPrivateKey(LEAF_KEY_PEM))
  const q = (await decodeAadhaarQr(BigInt('0x' + gzipSync(Buffer.concat([body, sig])).toString('hex')).toString(10)))!
  const r = await verifyAadhaarSignature(q, { ...parseCert(new Uint8Array(Buffer.from(LEAF_DER, 'base64'))), derSha256: fp })
  assert.equal(r.state, 'verified')
})
