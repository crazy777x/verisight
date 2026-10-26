import test from 'node:test'
import assert from 'node:assert/strict'
import { buildVerdict } from '../lib/verdict'
import { HARD_LOCK_RISK, REVIEW_RISK, actionFor } from '../lib/policy'
import { base, camera, noChain, region, screenshot, printed, qrHit } from './helpers'

/** Expected behaviour per finding. PASS = below review, REVIEW = supervisor, FAIL = SAFE-LOCK. */
const level = (r: number) => (r >= HARD_LOCK_RISK ? 'FAIL' : r >= REVIEW_RISK ? 'REVIEW' : 'PASS')
const risk = (o: Parameters<typeof base>[0]) => buildVerdict(base(o)).risk
const verifiedQr = { state: 'verified' as const, certSubject: 'UIDAI', certNotAfter: '', certFp: '' }

test('baseline: an Aadhaar NOT verified by UIDAI shows REVIEW and the reason', () => {
  const v = buildVerdict(base({}))
  assert.equal(level(v.risk), 'REVIEW')
  assert.match(v.headline, /^REVIEW/)
  assert.ok(v.findings.some((finding) => finding.code === 'UNVERIFIED' && /signature state is "no-cert"/.test(finding.detail)))
})
test('an Aadhaar verified by a trusted UIDAI signature passes', () => {
  assert.equal(level(risk({ qrSig: { state: 'verified', certSubject: 'UIDAI', certNotAfter: '', certFp: '' } })), 'PASS')
})
test('unverified Aadhaar + edited/cloned areas is still REVIEW (not low)', () => {
  const r = risk({ isPdf: false, meta: screenshot, tamper: { ...base().tamper, regions: [region(1, ['NAME']), region(2, ['DOB']), region(3), region(4)] } })
  assert.ok(r >= REVIEW_RISK)
})

test('invalid signature with a TRUSTED certificate -> FAIL (lock)', () => {
  assert.equal(level(risk({ qrSig: { state: 'invalid', certTrusted: true, reason: 'x' } })), 'FAIL')
})
test('invalid signature with an UNTRUSTED certificate -> REVIEW only (may be the wrong certificate)', () => {
  assert.equal(level(risk({ qrSig: { state: 'invalid', certTrusted: false, reason: 'x' } })), 'REVIEW')
})
test('valid signature but untrusted certificate is NOT "authenticated"', () => {
  const v = buildVerdict(base({ qrSig: { state: 'valid-untrusted', certSubject: 'x', certNotAfter: '', certFp: '', why: 'not pinned' } }))
  assert.ok(!/AUTHENTIC/.test(v.headline))
  assert.equal(level(v.risk), 'REVIEW') // not verified by a trusted signature = manual review
})
test('valid signature + trusted certificate -> AUTHENTIC', () => {
  const v = buildVerdict(base({ qrSig: { state: 'verified', certSubject: 'UIDAI', certNotAfter: '', certFp: '' } }))
  assert.match(v.headline, /AUTHENTIC/)
})
test('QR and printed data mismatch without trusted QR signature -> REVIEW, not FAKE', () => {
  const r = risk({ qrRows: [{ label: 'Name', qr: 'A B', printed: 'C D', res: 'mismatch' }] })
  assert.ok(r >= REVIEW_RISK && r < HARD_LOCK_RISK, `risk ${r}`)
})
test('trusted UIDAI QR signature plus high-confidence printed mismatch -> FAKE', () => {
  const v = buildVerdict(base({
    qrSig: verifiedQr,
    qrRows: [{ label: 'Name', qr: 'SIGNED NAME', printed: 'OTHER NAME', res: 'mismatch' }],
  }))
  assert.equal(v.level, 'LIKELY_FORGED')
  assert.match(v.headline, /^FAIL/)
  assert.ok(v.findings.some((finding) => finding.code === 'SIGNED_DATA_MISMATCH' && finding.severity === 'critical'))
})
test('broken PDF signature (content changed after signing) -> REVIEW, high priority (>=60)', () => {
  const r = risk({ pdfSig: { present: true, count: 1, digestOk: false, sigOk: true, coversWholeFile: true, signer: '', issuer: '', validTo: '', detail: 'changed', chain: noChain } })
  assert.ok(r >= 60 && r < HARD_LOCK_RISK + 1, `risk ${r}`)
  assert.notEqual(level(r), 'PASS')
})
test('PDF signature valid but signer not trusted -> not authentic, not accused', () => {
  const v = buildVerdict(base({ pdfSig: { present: true, count: 1, digestOk: true, sigOk: true, coversWholeFile: true, signer: 'Anyone', issuer: 'Anyone', validTo: '', detail: '', chain: { state: 'untrusted-root', detail: 'self-signed', chain: ['Anyone'] } } }))
  assert.ok(!/AUTHENTIC/.test(v.headline))
  assert.equal(level(v.risk), 'REVIEW') // not verified by a trusted signature = manual review
})
test('PDF with signer chain to a pinned root -> AUTHENTIC', () => {
  const v = buildVerdict(base({
    kind: 'mrz',
    pdfSig: { present: true, count: 1, digestOk: true, sigOk: true, coversWholeFile: true, signer: 'S', issuer: 'R', validTo: '', detail: '', chain: { state: 'trusted', detail: 'ok', chain: ['S', 'R'] } },
  }))
  assert.match(v.headline, /AUTHENTIC/)
})
test('A trusted PDF signature alone does not verify the Aadhaar Secure QR', () => {
  const v = buildVerdict(base({
    pdfSig: { present: true, count: 1, digestOk: true, sigOk: true, coversWholeFile: true, signer: 'S', issuer: 'R', validTo: '', detail: '', chain: { state: 'trusted', detail: 'ok', chain: ['S', 'R'] } },
    qrSig: { state: 'no-cert' },
  }))
  assert.notEqual(v.headline, 'AUTHENTIC · UIDAI SIGNATURE VERIFIED')
  assert.ok(v.findings.some((finding) => finding.code === 'UNVERIFIED'))
})
test('a trusted Aadhaar PDF signature does not hide QR-to-print mismatches', () => {
  const v = buildVerdict(base({
    pdfSig: { present: true, count: 1, digestOk: true, sigOk: true, coversWholeFile: true, signer: 'S', issuer: 'R', validTo: '', detail: '', chain: { state: 'trusted', detail: 'ok', chain: ['S', 'R'] } },
    qrRows: [{ label: 'Name', qr: 'OTHER USER', printed: 'TEST USER', res: 'mismatch' }],
  }))
  assert.ok(v.findings.some((finding) => finding.code === 'QR_MISMATCH'))
  assert.notEqual(v.headline, 'AUTHENTIC · UIDAI SIGNATURE VERIFIED')
})
test('broken certificate chain -> REVIEW', () => {
  const r = risk({ pdfSig: { present: true, count: 1, digestOk: true, sigOk: true, coversWholeFile: true, signer: '', issuer: '', validTo: '', detail: '', chain: { state: 'broken', detail: 'forged chain', chain: [] } } })
  assert.equal(level(r), 'REVIEW')
})
test('invalid Aadhaar checksum -> REVIEW (suspicious; OCR can misread a digit)', () => {
  const r = risk({ aadhaarValid: false, isPdf: false, meta: camera, qr: qrHit })
  assert.equal(level(r), 'REVIEW')
})
test('ELA anomaly alone on a camera photo -> supporting evidence only (never review / lock)', () => {
  const r = risk({ qrSig: verifiedQr, isPdf: false, meta: camera, tamper: { ...base().tamper, regions: [region(1, ['NAME']), region(2, ['DOB']), region(3), region(4)] }, ela: { ...base().ela, anomaly: true, anomalousBlocks: 5 } })
  assert.ok(r > 0 && r < REVIEW_RISK, `risk ${r}`)
})
test('ELA anomaly on a screenshot is advisory and tiny', () => {
  const r = risk({ qrSig: verifiedQr, isPdf: false, meta: screenshot, tamper: { ...base().tamper, regions: [region(1, ['A']), region(2), region(3), region(4)] } })
  assert.ok(r < REVIEW_RISK)
})
test('editor named in metadata alone -> manual REVIEW (never LOCK on metadata alone)', () => {
  const r = risk({ qrSig: verifiedQr, meta: { ...camera, editorTags: ['Photoshop'] }, isPdf: false })
  assert.ok(r >= REVIEW_RISK && r < HARD_LOCK_RISK, `risk ${r}`)
})
test('AI-generation metadata marker -> manual review, not automatic lock', () => {
  assert.equal(level(risk({ meta: { ...camera, aiMarkers: ['Midjourney'] }, isPdf: false })), 'REVIEW')
})
test('QR artwork with no data on a large clear image -> REVIEW (critical review)', () => {
  const r = risk({ qr: null, qrAadhaar: null, qrRows: [], isPdf: false, meta: camera, qrPattern: { present: true, finders: 3, box: { x: 0, y: 0, w: 0.3, h: 0.3 }, page: 0 }, qrPx: 600 })
  assert.equal(level(r), 'REVIEW')
})
test('QR unreadable because the screenshot is tiny -> review, not a fake finding', () => {
  const r = risk({ qrSig: verifiedQr, qr: null, qrAadhaar: null, qrRows: [], isPdf: false, meta: screenshot, qrPattern: { present: true, finders: 3, box: { x: 0, y: 0, w: 0.1, h: 0.1 }, page: 0 }, qrPx: 120 })
  assert.ok(r >= REVIEW_RISK && r < HARD_LOCK_RISK, `risk ${r}`)
})
test('MRZ rules apply to passports only', () => {
  const m = [{ label: 'Document No.', value: 'x', sum: 1, computed: 6, stated: 'T', valid: false }] as any
  assert.ok(!buildVerdict(base({ mrz: m })).findings.some((f) => f.code === 'MRZ_CHECKSUM'))
  assert.ok(buildVerdict(base({ kind: 'mrz', mrz: m, printed: { ...printed } })).findings.some((f) => f.code === 'MRZ_CHECKSUM'))
})
test('policy table: only verified signature failures and signed-data mismatch can LOCK on their own', () => {
  const locks: string[] = []
  for (const code of ['SIG_INVALID', 'SIGNED_DATA_MISMATCH', 'AI_GENERATED', 'QR_MISMATCH', 'DOC_SIG_BROKEN', 'AADHAAR_CHECKSUM', 'MRZ_CHECKSUM', 'ELA_ANOMALY', 'META_SUSPECT'] as const)
    for (const sev of ['critical', 'high', 'medium'] as const) if (actionFor(code, sev) === 'LOCK') locks.push(`${code}/${sev}`)
  assert.deepEqual(locks.sort(), ['SIGNED_DATA_MISMATCH/critical', 'SIG_INVALID/critical'])
})

test('a PAN card with no issuer signature available goes to manual REVIEW, not low risk', () => {
  assert.equal(level(risk({ kind: 'pan', qr: null, qrAadhaar: null, qrRows: [], meta: camera, isPdf: false })), 'REVIEW')
})
test('a decoded non-Aadhaar QR explains its payload shape without claiming issuer authentication', () => {
  const verdict = buildVerdict(base({
    kind: 'pan',
    qr: { text: '{"name":"TEST USER","pan":"ABCDE1234F"}', bytes: new Uint8Array(32), page: 0, engine: 'test' },
    qrAadhaar: null,
    qrRows: [],
    qrSig: null,
    isPdf: false,
    meta: camera,
  }))
  const finding = verdict.findings.find((item) => item.code === 'UNVERIFIED')
  assert.ok(finding)
  assert.match(finding.detail, /payload shape: JSON object/)
  assert.match(finding.detail, /does not identify or authenticate the issuer/)
})
test('UIDAI Aadhaar QR trust cannot authenticate a non-Aadhaar document', () => {
  const verdict = buildVerdict(base({
    kind: 'pan',
    printed: { ...printed, aadhaarNo: '', pan: 'ABCDE1234F', panKeyword: true },
    aadhaarValid: null,
    qrSig: verifiedQr,
    isPdf: false,
    meta: camera,
  }))
  assert.notEqual(verdict.headline, 'AUTHENTIC · UIDAI SIGNATURE VERIFIED')
  assert.ok(verdict.findings.some((finding) => finding.code === 'UNVERIFIED'))
})
