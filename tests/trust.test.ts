import test from 'node:test'
import assert from 'node:assert/strict'
import { createSign, createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { CA_DER, LEAF_DER, LEAF_KEY_PEM, ROGUE_DER } from './fixtures'
import { assessCert, verifyChain } from '../lib/trust'
import { parseCert, parseCertFull } from '../lib/asn1'
import { decodeAadhaarQr, verifyAadhaarSignature } from '../lib/analysis'
import { createPrivateKey } from 'node:crypto'

const der = (b64: string) => new Uint8Array(Buffer.from(b64, 'base64'))
const fp = (b64: string) => createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex')
const publicKeyFp = (b64: string) => createHash('sha256').update(parseCertFull(der(b64)).spki).digest('hex')
const info = (b64: string) => ({ ...parseCert(der(b64)), derSha256: fp(b64) })

test('certificate trust: pinned -> trusted, other -> untrusted, no pins -> untrusted', () => {
  assert.equal(assessCert(info(LEAF_DER), [fp(LEAF_DER)]).state, 'trusted')
  assert.equal(assessCert(info(ROGUE_DER), [fp(LEAF_DER)]).state, 'untrusted')
  assert.equal(assessCert(info(LEAF_DER), []).state, 'untrusted')
})
test('certificate trust: expired / not yet valid are never trusted', () => {
  const c = info(LEAF_DER)
  assert.equal(assessCert(c, [fp(LEAF_DER)], new Date('2200-01-01')).state, 'expired')
  assert.equal(assessCert(c, [fp(LEAF_DER)], new Date('2000-01-01')).state, 'not-yet-valid')
})

test('PDF chain: leaf -> CA (pinned) is trusted; unpinned CA is not; rogue leaf is not', async () => {
  const ok = await verifyChain([der(LEAF_DER), der(CA_DER)], [fp(CA_DER)], 'Test UIDAI Signer')
  assert.equal(ok.state, 'trusted')
  assert.equal((await verifyChain([der(LEAF_DER), der(CA_DER)], [], 'Test UIDAI Signer')).state, 'untrusted-root')
  assert.equal((await verifyChain([der(LEAF_DER)], [fp(CA_DER)])).state, 'incomplete')
  const rogue = await verifyChain([der(ROGUE_DER)], [fp(CA_DER)])
  assert.notEqual(rogue.state, 'trusted')
})
test('PDF chain: a trusted CA public-key fingerprint pins the chain', async () => {
  const pinnedKey = await verifyChain([der(LEAF_DER), der(CA_DER)], [publicKeyFp(CA_DER)], 'Test UIDAI Signer')
  assert.equal(pinnedKey.state, 'trusted')

  const rogueKey = await verifyChain([der(ROGUE_DER)], [publicKeyFp(CA_DER)])
  assert.notEqual(rogueKey.state, 'trusted')
})
test('PDF chain: a pinned signer public key trusts only that valid signer certificate', async () => {
  const pinnedSigner = await verifyChain([der(LEAF_DER), der(CA_DER)], [], 'Test UIDAI Signer', [publicKeyFp(LEAF_DER)])
  assert.equal(pinnedSigner.state, 'trusted')
  assert.match(pinnedSigner.detail, /signer certificate or public key is pinned/)

  const noSignerPin = await verifyChain([der(LEAF_DER), der(CA_DER)], [], 'Test UIDAI Signer')
  assert.notEqual(noSignerPin.state, 'trusted')

  const rogueSigner = await verifyChain([der(ROGUE_DER)], [], '', [publicKeyFp(LEAF_DER)])
  assert.notEqual(rogueSigner.state, 'trusted')
})
test('PDF chain: a leaf that CLAIMS the trusted CA but is not signed by it is "broken"', async () => {
  // ROGUE cert presented together with the real CA, and ROGUE pretending: use CA as "issuer" of a cert it did not sign
  const forged = await verifyChain([der(ROGUE_DER), der(CA_DER)], [fp(CA_DER)])
  assert.notEqual(forged.state, 'trusted')
})

/* ---- Aadhaar Secure QR end to end with the test key ---- */
const FF = Buffer.from([255])
function secureQr(key: ReturnType<typeof createPrivateKey>, tamper = false) {
  const f = ['V2', '3', '1'.repeat(20), 'Test User', '01-01-1990', 'M', 'C/O X', 'D', '', 'H', 'L', '460001', 'PO', 'MP', 'S', 'SD', 'V']
  let body = Buffer.concat([...f.map((x) => Buffer.concat([Buffer.from(x), FF])), Buffer.alloc(40, 7)])
  const sig = nodeSign('sha256', body, key)
  if (tamper) body = Buffer.concat([Buffer.from(f.join('\xff').replace('Test User', 'Evil User')), FF, Buffer.alloc(40, 7)])
  return BigInt('0x' + gzipSync(Buffer.concat([body, sig])).toString('hex')).toString(10)
}
const leafKey = createPrivateKey(LEAF_KEY_PEM)

test('Aadhaar QR: signed with the PINNED cert -> verified; with an unpinned cert -> valid-untrusted (never "UIDAI verified")', async () => {
  const q = (await decodeAadhaarQr(secureQr(leafKey)))!
  const trusted = { ...info(LEAF_DER) }
  // verifyAadhaarSignature uses the configured pins; configure through env-less path by checking states directly
  const r = await verifyAadhaarSignature(q, trusted)
  assert.ok(r.state === 'valid-untrusted' || r.state === 'verified')
  if (process.env.NEXT_PUBLIC_UIDAI_TRUSTED_SHA256?.includes(fp(LEAF_DER))) assert.equal(r.state, 'verified')
  else assert.equal(r.state, 'valid-untrusted', 'without a pinned fingerprint the result must NOT be "verified"')
})
test('Aadhaar QR: altered data -> invalid', async () => {
  const q = (await decodeAadhaarQr(secureQr(leafKey, true)))!
  assert.equal((await verifyAadhaarSignature(q, info(LEAF_DER))).state, 'invalid')
})
test('Aadhaar QR: signed by a different key than the loaded certificate -> invalid', async () => {
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
  const q = (await decodeAadhaarQr(secureQr(other)))!
  assert.equal((await verifyAadhaarSignature(q, info(LEAF_DER))).state, 'invalid')
})
