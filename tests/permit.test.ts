import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  classifyUrl, compareQrPrinted, emptyFields, evaluateValidity, extractPermitFields, findDuplicates, LIVE_NOT_VERIFIED, parseDateTime, parsePermitQr,
  runPermitChecks, sha256hex, toB64u, verifyEnvelope, type IssuerStatusProvider, type LiveState, type PermitFields, type PermitInput,
} from '../lib/permit'
import { docTypesForPurpose, evaluateSelection, suggestDocType, DOC_TYPES, PURPOSES } from '../lib/purposes'
import { validateUpload, MAX_UPLOAD_BYTES } from '../lib/upload'

/* ---------- synthetic fixtures (no real person, no real permit) ---------- */
const NOW = Date.parse('2026-10-15T10:00:00+05:30') // a Thursday, 10:00 IST
const good: Partial<PermitFields> = {
  permitNo: 'BP-2026-004711', category: 'Daily Movement Pass', issuingAuthority: 'Test District Office', holderName: 'Asha Test Verma',
  issueDate: '2026-10-01', validFrom: '2026-10-01', validTo: '2026-12-31',
}
async function keyPair() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))
  return { kp, spki, fp: await sha256hex(spki) }
}
async function envelope(payload: object, k: Awaited<ReturnType<typeof keyPair>>, tamper = false) {
  const p = toB64u(new TextEncoder().encode(JSON.stringify(payload)))
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.kp.privateKey, new TextEncoder().encode(p)))
  const p2 = tamper ? toB64u(new TextEncoder().encode(JSON.stringify({ ...payload, validTo: '2030-01-01' }))) : p
  return `VSP1.${p2}.${toB64u(sig)}.${toB64u(k.spki)}`
}
const qrOf = (f: Partial<PermitFields>) => ({ permitNo: f.permitNo, name: f.holderName, validFrom: f.validFrom, validTo: f.validTo, issuer: f.issuingAuthority })
const base = (over: Partial<PermitInput> = {}): PermitInput => ({
  purpose: 'border-resident', docType: 'daily-movement-pass', fields: good, reviewed: true, extraction: { ran: true },
  qrPayloads: null, nowMs: NOW, trustedKeys: [], ...over,
})
const provider = (state: LiveState, authoritative = true): IssuerStatusProvider => ({ name: 'TEST ISSUER (test only)', authoritative, check: async () => ({ state }) })

/* ---------- 1. a fully verified synthetic permit (needs trusted signature + issuer + live ACTIVE) ---------- */
test('1 valid synthetic permit with trusted signature, matching print and ACTIVE test issuer -> VERIFIED', async () => {
  const k = await keyPair()
  const r = await runPermitChecks(base({ qrPayloads: [await envelope(qrOf(good), k)], trustedKeys: [k.fp], provider: provider('active') }))
  assert.equal(r.overall, 'VERIFIED')
})
test('1b same permit but no live issuer -> NOT verified, label shown', async () => {
  const k = await keyPair()
  const r = await runPermitChecks(base({ qrPayloads: [await envelope(qrOf(good), k)], trustedKeys: [k.fp] }))
  assert.equal(r.overall, 'UNVERIFIABLE')
  assert.equal(r.liveLabel, LIVE_NOT_VERIFIED)
})
test('1c a future printed expiry alone never gives ACTIVE / VERIFIED', async () => {
  const r = await runPermitChecks(base())
  assert.notEqual(r.overall, 'VERIFIED')
  assert.equal(r.live.state, 'unavailable')
})

/* ---------- 2-5 dates ---------- */
test('2 expired permit -> EXPIRED', async () => {
  const r = await runPermitChecks(base({ fields: { ...good, validTo: '2026-10-14' } }))
  assert.equal(r.overall, 'EXPIRED')
})
test('2b the whole expiry day is still valid (date-only expiry = end of day)', () => {
  assert.equal(evaluateValidity({ ...good, validTo: '2026-10-15' }, NOW).state, 'valid-printed')
  assert.equal(evaluateValidity({ ...good, validTo: '2026-10-15T09:59:00+05:30' }, NOW).state, 'expired')
})
test('3 not-yet-valid permit -> REVIEW_REQUIRED (not marked expired or valid)', async () => {
  const r = await runPermitChecks(base({ fields: { ...good, validFrom: '2026-11-01', validTo: '2026-12-01' } }))
  assert.equal(evaluateValidity({ ...good, validFrom: '2026-11-01', validTo: '2026-12-01' }, NOW).state, 'not-yet-valid')
  assert.equal(r.overall, 'REVIEW_REQUIRED')
})
test('4 invalid date range -> INVALID', async () => {
  const r = await runPermitChecks(base({ fields: { ...good, validFrom: '2026-12-01', validTo: '2026-11-01' } }))
  assert.equal(r.overall, 'INVALID')
})
test('4b 30 Feb is not a date; unreadable date -> review, not forged', async () => {
  assert.ok('error' in parseDateTime('2026-02-30'))
  assert.ok('error' in parseDateTime('31/04/2026'))
  const r = await runPermitChecks(base({ fields: { ...good, validTo: '31/04/2026' } }))
  assert.equal(r.overall, 'REVIEW_REQUIRED')
})
test('5 missing expiry -> UNVERIFIABLE', async () => {
  const r = await runPermitChecks(base({ fields: { ...good, validTo: '' } }))
  assert.equal(r.overall, 'UNVERIFIABLE')
})
test('5b DD-MM-YYYY, explicit offsets and tz assumption are reported', () => {
  const p = parseDateTime('15-10-2026 10:00', 330)
  assert.ok('ms' in p && p.ms === NOW)
  const z = parseDateTime('2026-10-15T04:30:00Z')
  assert.ok('ms' in z && z.ms === NOW && z.hadZone)
  assert.equal(evaluateValidity(good, NOW).tzAssumed, true)
})

/* ---------- 6-12 QR / signature ---------- */
test('6 malformed (truncated) QR -> REVIEW_REQUIRED', async () => {
  for (const q of ['{"permitNo":"BP-1","name":"A', 'VSP1.abc.def']) {
    const r = await runPermitChecks(base({ qrPayloads: [q] }))
    assert.equal(r.overall, 'REVIEW_REQUIRED', q)
  }
})
test('7 two different QR codes -> ambiguity, REVIEW_REQUIRED', async () => {
  const r = await runPermitChecks(base({ qrPayloads: ['permitNo=BP-1;name=A B C', 'permitNo=BP-2;name=D E F'] }))
  assert.equal(r.overall, 'REVIEW_REQUIRED')
  assert.match(r.rows.find((x) => x.key === 'qr')!.text, /different codes/)
})
test('7b the same code seen twice is not ambiguous', async () => {
  const q = 'permitNo=BP-2026-004711;name=Asha Test Verma'
  const r = await runPermitChecks(base({ qrPayloads: [q, q] }))
  assert.doesNotMatch(r.rows.find((x) => x.key === 'qr')!.text, /different codes/)
})
test('8 QR / printed NAME mismatch -> REVIEW_REQUIRED', async () => {
  const r = await runPermitChecks(base({ qrPayloads: [JSON.stringify(qrOf({ ...good, holderName: 'Rohit Other Sharma' }))] }))
  assert.equal(r.overall, 'REVIEW_REQUIRED')
  assert.ok(r.compare.find((c) => c.field === 'holderName')?.res === 'mismatch')
})
test('9 QR / printed PERMIT NUMBER mismatch (one digit) -> REVIEW_REQUIRED', async () => {
  const r = await runPermitChecks(base({ qrPayloads: [JSON.stringify(qrOf({ ...good, permitNo: 'BP-2026-004712' }))] }))
  assert.equal(r.overall, 'REVIEW_REQUIRED')
  assert.equal(r.compare.find((c) => c.field === 'permitNo')?.res, 'mismatch')
})
test('9b name order / case / punctuation differences still match', () => {
  const rows = compareQrPrinted({ holderName: 'VERMA, ASHA TEST' }, { holderName: 'Asha Test Verma' })
  assert.equal(rows[0].res, 'match')
})
test('10 invalid signature (payload altered after signing) -> INVALID', async () => {
  const k = await keyPair()
  const r = await runPermitChecks(base({ qrPayloads: [await envelope(qrOf(good), k, true)], trustedKeys: [k.fp], provider: provider('active') }))
  assert.equal(r.overall, 'INVALID')
})
test('11 valid signature from a key that is NOT pinned -> untrusted, never VERIFIED', async () => {
  const k = await keyPair()
  const other = await keyPair()
  const r = await runPermitChecks(base({ qrPayloads: [await envelope(qrOf(good), k)], trustedKeys: [other.fp], provider: provider('active') }))
  assert.notEqual(r.overall, 'VERIFIED')
  assert.equal(r.rows.find((x) => x.key === 'issuer')!.state, 'warn')
  assert.equal((await verifyEnvelope(await envelope(qrOf(good), k), [other.fp])).state, 'valid-untrusted')
})
test('12 unknown issuer (no trust list configured) -> never VERIFIED', async () => {
  const k = await keyPair()
  const r = await runPermitChecks(base({ qrPayloads: [await envelope(qrOf(good), k)], provider: provider('active') }))
  assert.notEqual(r.overall, 'VERIFIED')
  assert.equal(r.rows.find((x) => x.key === 'issuer')!.state, 'unavailable')
})
test('12b an unsigned plain-JSON QR proves nothing about the issuer', async () => {
  const r = await runPermitChecks(base({ qrPayloads: [JSON.stringify(qrOf(good))], provider: provider('active') }))
  assert.equal(r.overall, 'UNVERIFIABLE')
})

/* ---------- 13-15, 28 issuer status ---------- */
test('13 revoked permit confirmed by an authoritative test issuer -> REVOKED', async () => {
  assert.equal((await runPermitChecks(base({ provider: provider('revoked') }))).overall, 'REVOKED')
})
test('14 suspended permit confirmed by an authoritative test issuer -> SUSPENDED', async () => {
  assert.equal((await runPermitChecks(base({ provider: provider('suspended') }))).overall, 'SUSPENDED')
})
test('13b a NON-authoritative provider saying "revoked" is ignored (cannot be spoofed into a verdict)', async () => {
  const r = await runPermitChecks(base({ provider: provider('revoked', false) }))
  assert.notEqual(r.overall, 'REVOKED')
  assert.equal(r.live.state, 'unavailable')
})
test('15 issuer service unavailable / throws / times out -> not verified, no crash', async () => {
  const bad: IssuerStatusProvider = { name: 'down', authoritative: true, check: async () => { throw new Error('503') } }
  const r = await runPermitChecks(base({ provider: bad }))
  assert.equal(r.live.state, 'unavailable')
  assert.equal(r.liveLabel, LIVE_NOT_VERIFIED)
  assert.equal(r.overall, 'UNVERIFIABLE')
})
test('28 live issuer status unavailable keeps the other checks independent', async () => {
  const r = await runPermitChecks(base())
  assert.equal(r.rows.find((x) => x.key === 'dates')!.state, 'pass')
  assert.equal(r.rows.find((x) => x.key === 'live')!.state, 'unavailable')
})

/* ---------- 20 duplicates ---------- */
test('20 duplicate permit number on a different holder is a review INDICATOR, not forgery', async () => {
  const reg = [{ permitNo: 'BP-2026-004711', holder: 'Someone Else Entirely', qrHash: '', fileDigest: 'aaa', at: NOW - 1000 }]
  const r = await runPermitChecks(base({ registry: reg, fileDigest: 'bbb' }))
  assert.equal(r.overall, 'REVIEW_REQUIRED')
  assert.match(r.rows.find((x) => x.key === 'dups')!.text, /not proof of forgery/)
  assert.match(r.rows.find((x) => x.key === 'dups')!.text, /THIS browser only/)
})
test('20b same permit + same holder, new file = info only; repeated file = info only', () => {
  const reg = [{ permitNo: 'BP-2026-004711', holder: 'Asha Test Verma', qrHash: 'q', fileDigest: 'aaa', at: 1 }]
  const d = findDuplicates({ permitNo: 'bp 2026 004711', holder: 'Verma Asha Test', qrHash: 'q', fileDigest: 'aaa' }, reg)
  assert.ok(d.length > 0 && d.every((x) => x.level === 'info'))
})
test('20c same QR payload on a different permit number -> review indicator', () => {
  const reg = [{ permitNo: 'BP-1', holder: 'A B C', qrHash: 'q', fileDigest: 'x', at: 1 }]
  assert.ok(findDuplicates({ permitNo: 'BP-2', holder: 'A B C', qrHash: 'q', fileDigest: 'y' }, reg).some((d) => d.code === 'DUP_QR_CONFLICT'))
})

/* ---------- 21-23 file validation ---------- */
const PDF = new TextEncoder().encode('%PDF-1.7\n')
const JPG = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10])
test('21 corrupted file (content is not what the name says) is refused', () => {
  assert.equal(validateUpload('permit.pdf', 'application/pdf', 5000, Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8])).ok, false)
  assert.equal(validateUpload('permit.jpg', 'image/jpeg', 5000, PDF).ok, false)
  assert.equal(validateUpload('empty.pdf', 'application/pdf', 0, PDF).ok, false)
})
test('22 oversized file is refused; a good one passes', () => {
  assert.equal(validateUpload('a.pdf', 'application/pdf', MAX_UPLOAD_BYTES + 1, PDF).ok, false)
  assert.equal(validateUpload('a.pdf', 'application/pdf', 1000, PDF).ok, true)
  assert.equal(validateUpload('a.jpg', 'image/jpeg', 1000, JPG).ok, true)
})
test('23 unsupported file type is refused', () => {
  const r = validateUpload('macro.docm', 'application/vnd.ms-word', 1000, Uint8Array.from([0x50, 0x4b, 3, 4]))
  assert.equal(r.ok, false)
})

/* ---------- 24-27 document type / purpose ---------- */
test('24 missing required field -> UNVERIFIABLE and named', async () => {
  const r = await runPermitChecks(base({ fields: { ...good, holderName: '' } }))
  assert.equal(r.overall, 'UNVERIFIABLE')
  assert.ok(r.reasons.some((x) => /Holder name/.test(x)))
})
test('25 auto-detect is only a suggestion: ambiguous or empty text never forces a type', () => {
  const amb = suggestDocType('Daily movement pass and visitor pass')
  assert.equal(amb.id, null)
  assert.equal(amb.confidence, 'low')
  assert.equal(suggestDocType('hello world').confidence, 'none')
  assert.equal(suggestDocType('Income Tax Department Permanent Account Number').id, 'pan')
})
test('25b unknown / auto document type can never be VERIFIED', async () => {
  const k = await keyPair()
  for (const t of ['auto', 'other'] as const) {
    const r = await runPermitChecks(base({ docType: t, qrPayloads: [await envelope(qrOf(good), k)], trustedKeys: [k.fp], provider: provider('active') }))
    assert.notEqual(r.overall, 'VERIFIED', t)
  }
})
test('26 purpose / type combination with limited applicability is flagged, checks stay on', () => {
  const s = evaluateSelection('immigration', 'forestry-transit-permit')
  assert.equal(s.fit, 'limited')
  assert.ok(s.warnings.length > 0)
  assert.equal(s.checks.signature, 'applicable')
})
test('26b inapplicable checks are not-applicable, never failed; custom purpose never switches security checks off', () => {
  const imm = evaluateSelection('immigration', 'border-resident-pass')
  assert.equal(imm.checks['movement-rules'], 'not-applicable')
  const custom = evaluateSelection('custom', 'border-resident-pass')
  const general = evaluateSelection('general', 'border-resident-pass')
  for (const c of ['qr', 'signature', 'issuer-trust', 'forensics', 'duplicate'] as const) {
    assert.equal(custom.checks[c], 'applicable', c)
    assert.equal(general.checks[c], 'applicable', c)
  }
  assert.equal(evaluateSelection('police', 'aadhaar').checks['live-status'], 'unavailable') // no live source is ever pretended
})
test('26c catalogue: 14 purposes, every document type reachable from every purpose', () => {
  assert.equal(PURPOSES.length, 14)
  for (const p of PURPOSES) {
    const { primary, other } = docTypesForPurpose(p.id)
    const ids = new Set([...primary, ...other].map((d) => d.id))
    for (const d of DOC_TYPES.filter((x) => x.id !== 'auto' && x.id !== 'other')) assert.ok(ids.has(d.id), `${p.id} misses ${d.id}`)
  }
})
test('26d non-permit adapter: dates not applicable for Aadhaar, QR rows applicable', async () => {
  const r = await runPermitChecks(base({ docType: 'aadhaar', purpose: 'govt-office', fields: { holderName: 'Asha Test Verma' } }))
  assert.equal(r.rows.find((x) => x.key === 'dates')!.state, 'na')
})

/* ---------- 27 failed QR decode ---------- */
test('27 QR drawn but undecodable -> review, with the honest wording (not "forged")', async () => {
  const r = await runPermitChecks(base({ qrPayloads: [], qrDrawnButUnreadable: true }))
  assert.equal(r.overall, 'REVIEW_REQUIRED')
  assert.match(r.rows.find((x) => x.key === 'qr')!.text, /not proof of forgery/)
})
test('27b no QR at all on a permit is "not detected", not a forgery', async () => {
  const r = await runPermitChecks(base({ qrPayloads: [] }))
  assert.equal(r.overall, 'UNVERIFIABLE')
  assert.match(r.rows.find((x) => x.key === 'qr')!.text, /not detected/i)
})
test('27c QR verification on a PAN card is "unavailable", not failed', async () => {
  const r = await runPermitChecks(base({ docType: 'pan', purpose: 'police', fields: { holderName: 'Asha Test Verma' } }))
  assert.equal(r.rows.find((x) => x.key === 'qr')!.state, 'unavailable')
})

/* ---------- QR URL safety (SSRF) ---------- */
test('QR links are never fetched and unsafe ones are blocked', () => {
  for (const u of ['http://169.254.169.254/latest/meta-data', 'https://localhost/x', 'https://10.0.0.5/a', 'https://192.168.1.1', 'https://[::1]/', 'https://2130706433/', 'https://user:pw@example.com/', 'file:///etc/passwd', 'ftp://example.com', 'https://metadata.google.internal/']) {
    assert.equal(classifyUrl(u).blocked, true, u)
  }
  assert.equal(classifyUrl('https://example.gov.in/verify?id=1').blocked, false)
  const p = parsePermitQr('https://169.254.169.254/x')
  assert.equal(p.format, 'url')
  assert.ok(p.notes.join(' ').includes('never opens'))
})

/* ---------- movement rules ---------- */
test('movement: unauthorised entry point, outside daily window, single-entry reuse', async () => {
  const f = { ...good, entryPoints: 'Gate A', entries: 'single', dailyFrom: '06:00', dailyTo: '09:00' }
  const ev = { permitNo: f.permitNo!, checkpoint: 'Gate B', direction: 'entry' as const, atMs: NOW }
  const r = await runPermitChecks(base({ fields: f, movement: { event: ev, prior: [{ ...ev, checkpoint: 'Gate A' }] } }))
  const m = r.rows.find((x) => x.key === 'movement')!
  assert.equal(m.state, 'fail')
  assert.match(m.text, /not an authorised entry point/)
  assert.match(m.text, /daily validity window/)
  assert.match(m.text, /Single-entry/)
  assert.equal(r.overall, 'REVIEW_REQUIRED')
})
test('movement: day-of-week rule and midnight-wrapping window use the permit time zone', () => {
  assert.equal(evaluateValidity({ ...good, allowedDays: 'Mon,Tue' }, NOW).day, 'not-allowed') // NOW is a Thursday in IST
  assert.equal(evaluateValidity({ ...good, allowedDays: 'Thu' }, NOW).day, 'allowed')
  assert.equal(evaluateValidity({ ...good, dailyFrom: '22:00', dailyTo: '06:00' }, NOW).window, 'outside')
})
test('movement: nothing stated on the permit -> "not stated", never "passed"', async () => {
  const r = await runPermitChecks(base())
  assert.equal(r.rows.find((x) => x.key === 'movement')!.state, 'info')
})

/* ---------- forensics wiring ---------- */
test('forensics: supporting indicators never change the overall alone; review-level ones need a human', async () => {
  const sup = await runPermitChecks(base({ forensics: { ran: true, indicators: [{ title: 'ELA variation', detail: 'minor', strength: 'supporting' }] } }))
  assert.equal(sup.overall, 'UNVERIFIABLE')
  const rev = await runPermitChecks(base({ forensics: { ran: true, indicators: [{ title: 'Declared AI marker', detail: 'x', strength: 'review' }] } }))
  assert.equal(rev.overall, 'REVIEW_REQUIRED')
})
test('operator has not confirmed the fields -> REVIEW_REQUIRED', async () => {
  assert.equal((await runPermitChecks(base({ reviewed: false }))).overall, 'REVIEW_REQUIRED')
})

/* ---------- field extraction ---------- */
test('extraction: labelled lines only; two readings of one field are flagged, not guessed', () => {
  const ok = extractPermitFields('Pass No: BP-1\nName of holder: Asha Verma\nValid up to: 31-12-2026')
  assert.equal(ok.fields.permitNo, 'BP-1')
  assert.equal(ok.fields.validTo, '31-12-2026')
  assert.deepEqual(ok.missing, [])
  const amb = extractPermitFields('Pass No: BP-1\nPass No: BP-7\nName: A B')
  assert.ok(amb.ambiguous.includes('permitNo'))
  assert.equal(amb.fields.permitNo, undefined)
  assert.ok(extractPermitFields('random text').missing.includes('validTo'))
})

test('no result ever contains the word VERIFIED unless every condition passed', async () => {
  const k = await keyPair()
  const cases: Partial<PermitInput>[] = [{}, { qrPayloads: [JSON.stringify(qrOf(good))] }, { qrPayloads: [await envelope(qrOf(good), k)] }, { qrPayloads: [await envelope(qrOf(good), k)], trustedKeys: [k.fp] }]
  for (const c of cases) assert.notEqual((await runPermitChecks(base(c))).overall, 'VERIFIED')
  void emptyFields
})
