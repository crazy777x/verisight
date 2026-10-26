/* ============================================================
 * BORDER PASS & PERMIT VERIFICATION ENGINE
 *
 * Pure functions only (no DOM, no network) so every rule is unit-tested.
 *
 * Hard rules built into this file:
 *  - a printed expiry date in the future NEVER makes a permit "active";
 *  - with no authoritative issuer source the live status is "LIVE ISSUER STATUS NOT VERIFIED";
 *  - a readable / well-formed QR is not authenticity, and QR URLs are NEVER fetched;
 *  - a valid signature is only "trusted" when its key is on the pinned list;
 *  - duplicates are indicators (local prototype records only), never proof of forgery;
 *  - no official border-pass QR format is assumed. The only signed format understood is the
 *    VeriSight DEMO envelope (VSP1), which is NOT a government specification.
 * ============================================================ */
import { evaluateSelection, ADAPTERS, type CheckId, type Applicability, type DocTypeId, type PurposeId } from './purposes'
import { validateDocumentFields } from './document-rules'

export const LIVE_NOT_VERIFIED = 'LIVE ISSUER STATUS NOT VERIFIED'

export type PermitFields = {
  permitNo: string
  category: string
  issuingAuthority: string
  jurisdiction: string
  holderName: string
  idRef: string // reference of the associated identity document (masked by the operator)
  issueDate: string
  validFrom: string
  validTo: string
  dailyFrom: string // HH:MM
  dailyTo: string // HH:MM
  allowedDays: string // "Mon,Tue,..." or "1,2,3"
  entries: string // 'single' | 'multiple' | ''
  entryPoints: string // comma separated
  exitPoints: string
  area: string
  movementPurpose: string
  vehicleNo: string
  chassisNo: string
  engineNo: string
  cargo: string
  hsnCode: string
  quantity: string
  goodsValue: string
  departure: string
  destination: string
  organisation: string
  employeeId: string
  documentNo: string
  certificateId: string
  mrzText: string
}
export const FIELD_KEYS = [
  'permitNo', 'category', 'issuingAuthority', 'jurisdiction', 'holderName', 'idRef', 'issueDate', 'validFrom', 'validTo',
  'dailyFrom', 'dailyTo', 'allowedDays', 'entries', 'entryPoints', 'exitPoints', 'area', 'movementPurpose', 'vehicleNo', 'chassisNo',
  'engineNo', 'cargo', 'hsnCode', 'quantity', 'goodsValue', 'departure', 'destination', 'organisation', 'employeeId', 'documentNo', 'certificateId', 'mrzText',
] as const satisfies readonly (keyof PermitFields)[]
export const emptyFields = (): PermitFields => Object.fromEntries(FIELD_KEYS.map((k) => [k, ''])) as PermitFields

export const FIELD_LABEL: Record<keyof PermitFields, string> = {
  permitNo: 'Pass / permit number', category: 'Permit category', issuingAuthority: 'Issuing authority', jurisdiction: 'Issuing jurisdiction',
  holderName: 'Holder name', idRef: 'Linked ID reference', issueDate: 'Issue date', validFrom: 'Valid from', validTo: 'Valid until / expiry',
  dailyFrom: 'Daily window from (HH:MM)', dailyTo: 'Daily window to (HH:MM)', allowedDays: 'Permitted days', entries: 'Entries (single / multiple)',
  entryPoints: 'Authorised entry point(s)', exitPoints: 'Authorised exit point(s)', area: 'Permitted area', movementPurpose: 'Permitted purpose',
  vehicleNo: 'Vehicle registration number', chassisNo: 'Chassis / VIN', engineNo: 'Engine number', cargo: 'Cargo / goods description',
  hsnCode: 'HSN code', quantity: 'Goods quantity', goodsValue: 'Goods value', departure: 'Departure point', destination: 'Destination',
  organisation: 'Organisation / trader', employeeId: 'Employee / contractor ID', documentNo: 'Document number', certificateId: 'Certificate ID',
  mrzText: 'Machine-readable zone (MRZ)',
}

/* ------------------------------------------------------------
 * 1. DATES (real calendar check, explicit time zone)
 * ------------------------------------------------------------ */
export const DEFAULT_TZ_MIN = 330 // IST. It is an ASSUMPTION and the report says so.

export type ParsedDate = { ms: number; hadTime: boolean; hadZone: boolean } | { error: string }

export function parseDateTime(raw: string, tzMin = DEFAULT_TZ_MIN, edge: 'start' | 'end' = 'start'): ParsedDate {
  const s = raw.trim()
  if (!s) return { error: 'empty' }
  let y: number, mo: number, d: number, h: number | undefined, mi: number | undefined, sec: number | undefined, zone: string | undefined
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i)
  if (m) {
    ;[y, mo, d] = [+m[1], +m[2], +m[3]]
    ;[h, mi, sec] = [m[4] ? +m[4] : undefined, m[5] ? +m[5] : undefined, m[6] ? +m[6] : undefined]
    zone = m[7]
  } else {
    m = s.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})(?:[ T,]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i)
    if (!m) return { error: `"${s}" is not a recognised date` }
    ;[d, mo, y] = [+m[1], +m[2], +m[3]]
    ;[h, mi, sec] = [m[4] ? +m[4] : undefined, m[5] ? +m[5] : undefined, m[6] ? +m[6] : undefined]
    zone = m[7]
  }
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return { error: `"${s}" is not a real calendar date` }
  const probe = new Date(Date.UTC(y, mo - 1, d))
  if (probe.getUTCMonth() !== mo - 1 || probe.getUTCDate() !== d) return { error: `"${s}" is not a real calendar date` }
  const hadTime = h !== undefined
  const hh = h ?? (edge === 'end' ? 23 : 0)
  const mm = mi ?? (edge === 'end' ? 59 : 0)
  const ss = sec ?? (edge === 'end' ? 59 : 0)
  if (hh > 23 || mm > 59 || ss > 59) return { error: `"${s}" has an impossible time` }
  let off = tzMin
  if (zone) off = /^z$/i.test(zone) ? 0 : (zone[0] === '-' ? -1 : 1) * (+zone.slice(1, 3) * 60 + +zone.slice(-2))
  return { ms: Date.UTC(y, mo - 1, d, hh, mm, ss) - off * 60000, hadTime, hadZone: !!zone }
}
const isMs = (p: ParsedDate): p is Extract<ParsedDate, { ms: number }> => 'ms' in p

export type ValidityState = 'valid-printed' | 'expired' | 'not-yet-valid' | 'invalid-range' | 'missing-expiry' | 'unreadable'
export type ValidityResult = {
  state: ValidityState
  validFromMs?: number
  validToMs?: number
  tzAssumed: boolean
  window: 'inside' | 'outside' | 'not-stated' | 'unreadable'
  day: 'allowed' | 'not-allowed' | 'not-stated' | 'unreadable'
  notes: string[]
}

const DAY_NAMES = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
export function parseDays(s: string): number[] | null {
  const parts = s.toLowerCase().split(/[,;/ ]+/).map((x) => x.trim()).filter(Boolean)
  if (!parts.length) return []
  const out: number[] = []
  for (const p of parts) {
    const i = DAY_NAMES.findIndex((n) => p.startsWith(n))
    if (i >= 0) out.push(i)
    else if (/^[0-6]$/.test(p)) out.push(+p)
    else return null
  }
  return [...new Set(out)]
}
const hm = (s: string): number | null => {
  const m = s.trim().match(/^(\d{1,2}):(\d{2})$/)
  return m && +m[1] < 24 && +m[2] < 60 ? +m[1] * 60 + +m[2] : null
}

/** Validity by PRINTED dates only. This is never live status. */
export function evaluateValidity(f: Partial<PermitFields>, nowMs: number, tzMin = DEFAULT_TZ_MIN, tzGiven = false): ValidityResult {
  const notes: string[] = []
  const r: ValidityResult = { state: 'valid-printed', tzAssumed: !tzGiven, window: 'not-stated', day: 'not-stated', notes }
  if (r.tzAssumed) notes.push(`No time zone on the permit: UTC${tzMin >= 0 ? '+' : '-'}${String(Math.floor(Math.abs(tzMin) / 60)).padStart(2, '0')}:${String(Math.abs(tzMin) % 60).padStart(2, '0')} assumed.`)
  const to = (f.validTo ?? '').trim()
  const from = (f.validFrom ?? '').trim()
  const issue = (f.issueDate ?? '').trim()
  const pTo = to ? parseDateTime(to, tzMin, 'end') : null
  const pFrom = from ? parseDateTime(from, tzMin, 'start') : null
  const pIssue = issue ? parseDateTime(issue, tzMin, 'start') : null
  for (const [name, p] of [['Valid until', pTo], ['Valid from', pFrom], ['Issue date', pIssue]] as const) if (p && !isMs(p)) notes.push(`${name}: ${p.error}`)
  if ((pTo && !isMs(pTo)) || (pFrom && !isMs(pFrom)) || (pIssue && !isMs(pIssue))) return { ...r, state: 'unreadable' }
  if (!pTo) {
    notes.push('No expiry date: validity cannot be established.')
    return { ...r, state: 'missing-expiry' }
  }
  const t = pTo as Extract<ParsedDate, { ms: number }>
  const fr = pFrom ? (pFrom as Extract<ParsedDate, { ms: number }>) : null
  const is = pIssue ? (pIssue as Extract<ParsedDate, { ms: number }>) : null
  r.validToMs = t.ms
  if (fr) r.validFromMs = fr.ms
  if (fr && t.ms < fr.ms) {
    notes.push('Expiry is before the valid-from date.')
    return { ...r, state: 'invalid-range' }
  }
  if (is && is.ms > t.ms) {
    notes.push('Issue date is after the expiry date.')
    return { ...r, state: 'invalid-range' }
  }
  if (is && is.ms > nowMs + 5 * 60000) notes.push('Issue date is in the future (suspicious date combination).')
  if (is && fr && fr.ms + 86400000 < is.ms) notes.push('Valid-from is earlier than the issue date (suspicious date combination).')
  if (fr && nowMs < fr.ms) return { ...r, state: 'not-yet-valid' }
  if (nowMs > t.ms) return { ...r, state: 'expired' }

  // daily window / permitted days, evaluated in the permit's own time zone
  const local = new Date(nowMs + tzMin * 60000)
  const dFrom = f.dailyFrom?.trim() ?? ''
  const dTo = f.dailyTo?.trim() ?? ''
  if (dFrom || dTo) {
    const a = hm(dFrom)
    const b = hm(dTo)
    if (a === null || b === null) {
      r.window = 'unreadable'
      notes.push('Daily window is not in HH:MM form.')
    } else {
      const cur = local.getUTCHours() * 60 + local.getUTCMinutes()
      const inside = a <= b ? cur >= a && cur <= b : cur >= a || cur <= b
      r.window = inside ? 'inside' : 'outside'
    }
  }
  if ((f.allowedDays ?? '').trim()) {
    const days = parseDays(f.allowedDays!)
    if (days === null) {
      r.day = 'unreadable'
      notes.push('Permitted days could not be read.')
    } else r.day = days.includes(local.getUTCDay()) ? 'allowed' : 'not-allowed'
  }
  return r
}

/* ------------------------------------------------------------
 * 2. LOCATION / MOVEMENT RULES
 * ------------------------------------------------------------ */
export type MovementEvent = { permitNo: string; checkpoint: string; direction: 'entry' | 'exit'; atMs: number }
export type MovementResult = { state: 'ok' | 'violation' | 'not-stated' | 'not-checkable'; findings: string[]; violations: string[] }

const norm = (s: string) => s.toUpperCase().replace(/[^A-Z0-9]+/g, ' ').trim()
const list = (s: string) => s.split(/[,;|]/).map((x) => norm(x)).filter(Boolean)

export function checkMovement(f: Partial<PermitFields>, ev: MovementEvent | null, prior: MovementEvent[], validity: ValidityResult): MovementResult {
  const findings: string[] = []
  const violations: string[] = []
  const entryPts = list(f.entryPoints ?? '')
  const exitPts = list(f.exitPoints ?? '')
  const single = (f.entries ?? '').toLowerCase().startsWith('single')
  const stated = entryPts.length || exitPts.length || single || validity.window !== 'not-stated' || validity.day !== 'not-stated' || (f.area ?? '').trim()
  if (!stated) return { state: 'not-stated', findings: ['The permit states no movement restrictions, so none could be checked.'], violations }
  if (validity.window === 'outside') violations.push('Present time is outside the daily validity window.')
  if (validity.day === 'not-allowed') violations.push('Today is not a permitted movement day.')
  if (!ev) {
    if (entryPts.length || exitPts.length || single) findings.push('No checkpoint event was recorded, so entry/exit point and entry-count rules were not checked.')
    return { state: violations.length ? 'violation' : 'not-checkable', findings, violations }
  }
  const cp = norm(ev.checkpoint)
  const pts = ev.direction === 'entry' ? entryPts : exitPts
  if (pts.length) {
    if (!cp) findings.push(`Checkpoint not entered: authorised ${ev.direction} point could not be checked.`)
    else if (!pts.some((p) => p === cp || cp.includes(p) || p.includes(cp))) violations.push(`"${ev.checkpoint}" is not an authorised ${ev.direction} point on this permit.`)
  }
  if (single && ev.direction === 'entry') {
    const used = prior.filter((p) => norm(p.permitNo) === norm(f.permitNo ?? '') && p.direction === 'entry').length
    if (used >= 1) violations.push('Single-entry permit already has a recorded entry (this browser\'s prototype records only, not an official record).')
  }
  return { state: violations.length ? 'violation' : 'ok', findings, violations }
}

/* ------------------------------------------------------------
 * 3. QR PAYLOADS
 * ------------------------------------------------------------ */
const ALIASES: Record<string, keyof PermitFields> = {
  permitno: 'permitNo', passno: 'permitNo', permitnumber: 'permitNo', passnumber: 'permitNo', number: 'permitNo', no: 'permitNo', id: 'permitNo',
  category: 'category', type: 'category', permittype: 'category', passtype: 'category',
  authority: 'issuingAuthority', issuer: 'issuingAuthority', issuedby: 'issuingAuthority', issuingauthority: 'issuingAuthority',
  jurisdiction: 'jurisdiction', district: 'jurisdiction', state: 'jurisdiction',
  name: 'holderName', holder: 'holderName', holdername: 'holderName', fullname: 'holderName',
  idref: 'idRef', idreference: 'idRef', linkedid: 'idRef',
  issued: 'issueDate', issue: 'issueDate', issuedate: 'issueDate', issuedon: 'issueDate',
  validfrom: 'validFrom', from: 'validFrom', start: 'validFrom',
  validto: 'validTo', validuntil: 'validTo', valid: 'validTo', expiry: 'validTo', expires: 'validTo', expirydate: 'validTo', to: 'validTo', end: 'validTo',
  dailyfrom: 'dailyFrom', dailyto: 'dailyTo', days: 'allowedDays', alloweddays: 'allowedDays',
  entries: 'entries', entrymode: 'entries',
  entrypoint: 'entryPoints', entrypoints: 'entryPoints', entry: 'entryPoints', exitpoint: 'exitPoints', exitpoints: 'exitPoints', exit: 'exitPoints',
  area: 'area', zone: 'area', purpose: 'movementPurpose', vehicle: 'vehicleNo', vehicleno: 'vehicleNo', regno: 'vehicleNo', registrationnumber: 'vehicleNo',
  chassis: 'chassisNo', chassisno: 'chassisNo', vin: 'chassisNo', enginenumber: 'engineNo', engineno: 'engineNo',
  cargo: 'cargo', goods: 'cargo', goodsdescription: 'cargo', hsn: 'hsnCode', hsncode: 'hsnCode', quantity: 'quantity', qty: 'quantity', value: 'goodsValue', goodsvalue: 'goodsValue',
  departure: 'departure', origin: 'departure', destination: 'destination', organisation: 'organisation', organization: 'organisation', trader: 'organisation', company: 'organisation',
  employeeid: 'employeeId', contractorid: 'employeeId', documentno: 'documentNo', documentnumber: 'documentNo', certificateno: 'certificateId', certificateid: 'certificateId', mrz: 'mrzText',
}
const aliasKey = (k: string) => ALIASES[k.toLowerCase().replace(/[^a-z]/g, '')]

function mapObject(o: Record<string, unknown>): Partial<PermitFields> {
  const out: Partial<PermitFields> = {}
  for (const [k, v] of Object.entries(o)) {
    const f = aliasKey(k)
    if (!f || v === null || v === undefined) continue
    if (typeof v === 'object' && !Array.isArray(v)) continue
    out[f] = Array.isArray(v) ? v.map(String).join(', ') : String(v)
  }
  return out
}

export type UrlVerdict = { host: string; blocked: boolean; reasons: string[] }

/** SSRF guard. VeriSight never fetches a URL found in a QR code; this only labels it for the operator. */
export function classifyUrl(raw: string): UrlVerdict {
  const reasons: string[] = []
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return { host: '', blocked: true, reasons: ['Not a valid URL'] }
  }
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (u.protocol !== 'https:') reasons.push(`Scheme "${u.protocol}" is not https`)
  if (u.username || u.password) reasons.push('URL contains credentials')
  if (isPrivateHost(host)) reasons.push('Host is local / private / metadata address')
  if (/xn--/.test(host)) reasons.push('Punycode host (possible look-alike)')
  return { host, blocked: reasons.length > 0, reasons }
}

export function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase()
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h === 'metadata.google.internal') return true
  if (/^\d+$/.test(h) || /^0x[0-9a-f]+$/i.test(h)) return true // decimal / hex integer IPv4 forms
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (v4) {
    const [a, b] = [+v4[1], +v4[2]]
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224
  }
  if (h.includes(':')) return h === '::1' || h === '::' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80') || h.startsWith('::ffff:')
  return false
}

export type QrFormat = 'envelope' | 'json' | 'keyvalue' | 'url' | 'malformed' | 'unsupported' | 'empty'
export type ParsedQr = { raw: string; format: QrFormat; fields: Partial<PermitFields>; notes: string[]; url?: UrlVerdict }

const b64u = (s: string): Uint8Array => {
  const t = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}
export const toB64u = (b: Uint8Array): string => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

export function parsePermitQr(raw: string): ParsedQr {
  const text = raw.trim()
  const base = { raw, fields: {} as Partial<PermitFields>, notes: [] as string[] }
  if (!text) return { ...base, format: 'empty', notes: ['QR decoded to an empty payload.'] }
  if (/^VSP1\./.test(text)) {
    const parts = text.split('.')
    if (parts.length !== 4 || parts.some((p) => !p)) return { ...base, format: 'malformed', notes: ['VeriSight demo envelope is truncated or has the wrong number of parts.'] }
    try {
      const obj = JSON.parse(dec(b64u(parts[1])))
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('payload is not an object')
      return { ...base, format: 'envelope', fields: mapObject(obj), notes: ['VeriSight DEMO envelope (not a government specification).'] }
    } catch (e) {
      return { ...base, format: 'malformed', notes: [`Envelope payload could not be decoded: ${(e as Error).message}`] }
    }
  }
  if (/^https?:\/\//i.test(text) || /^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    const url = classifyUrl(text)
    return { ...base, format: 'url', url, notes: ['QR holds a link. VeriSight never opens it: the page behind a link is not the document.', ...url.reasons] }
  }
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      const obj = JSON.parse(text)
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { ...base, format: 'unsupported', notes: ['JSON payload is not an object.'] }
      const fields = mapObject(obj)
      if (!Object.keys(fields).length) return { ...base, format: 'unsupported', notes: ['JSON payload has no permit fields VeriSight recognises.'] }
      return { ...base, format: 'json', fields, notes: ['Plain JSON payload: unsigned, so it proves nothing about the issuer.'] }
    } catch {
      return { ...base, format: 'malformed', notes: ['Payload looks like JSON but is truncated or corrupt.'] }
    }
  }
  const pairs = text.split(/[;|\n]+/).map((p) => p.split(/[=:](.+)/s).map((x) => x?.trim())).filter((p) => p.length >= 2 && p[0] && p[1])
  const fields: Partial<PermitFields> = {}
  for (const [k, v] of pairs) {
    const f = aliasKey(k)
    if (f) fields[f] = v
  }
  if (Object.keys(fields).length >= 2) return { ...base, format: 'keyvalue', fields, notes: ['key=value payload: unsigned, so it proves nothing about the issuer.'] }
  return { ...base, format: 'unsupported', notes: ['Payload is in a format VeriSight has no documented rule for. No official border-pass QR specification is assumed.'] }
}

export type EnvelopeSig = { state: 'invalid' | 'valid-untrusted' | 'valid-trusted'; keySha256: string; detail: string }
export type IssuerTrust = 'trusted' | 'untrusted' | 'unknown' | 'not-applicable'

export async function sha256hex(data: string | Uint8Array): Promise<string> {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data
  const h = await crypto.subtle.digest('SHA-256', buf as unknown as BufferSource)
  return Array.from(new Uint8Array(h)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * VSP1.<payload>.<signature>.<public key>  (all base64url, ECDSA P-256 / SHA-256, DEMO format).
 * The key travels inside the envelope, so the signature only proves integrity.
 * TRUST comes only from the pinned list of key fingerprints; an arbitrary embedded key is never trusted.
 */
export async function verifyEnvelope(raw: string, trustedKeySha256: string[]): Promise<EnvelopeSig> {
  const parts = raw.trim().split('.')
  if (parts.length !== 4) return { state: 'invalid', keySha256: '', detail: 'Malformed envelope.' }
  try {
    const spki = b64u(parts[3])
    const keySha256 = await sha256hex(spki)
    const key = await crypto.subtle.importKey('spki', spki as unknown as BufferSource, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64u(parts[2]) as unknown as BufferSource, new TextEncoder().encode(parts[1]) as unknown as BufferSource)
    if (!ok) return { state: 'invalid', keySha256, detail: 'Signature does not match the payload: the data was changed or signed with another key.' }
    const pinned = trustedKeySha256.map((x) => x.toLowerCase().replace(/[^0-9a-f]/g, '')).includes(keySha256)
    return pinned
      ? { state: 'valid-trusted', keySha256, detail: 'Signature is valid and the signing key is on the pinned trust list.' }
      : { state: 'valid-untrusted', keySha256, detail: 'Signature is valid but the signing key is NOT on the pinned trust list: it only proves the data was not altered since signing, not who signed it.' }
  } catch (e) {
    return { state: 'invalid', keySha256: '', detail: `Signature could not be verified: ${(e as Error).message}` }
  }
}

/* ------------------------------------------------------------
 * 4. QR <-> PRINTED CONSISTENCY
 * ------------------------------------------------------------ */
export type Cmp = 'match' | 'fuzzy' | 'mismatch' | 'unread'
export type CompareRow = { field: keyof PermitFields; label: string; qr: string; printed: string; res: Cmp }

function lev(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)])
  for (let j = 1; j <= b.length; j++) d[0][j] = j
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
  return d[a.length][b.length]
}
const alnum = (s: string) => s.toUpperCase().replace(/[^A-Z0-9]/g, '')
const nameKey = (s: string) => s.toUpperCase().replace(/[^A-Z ]/g, ' ').split(/\s+/).filter(Boolean).sort().join(' ')

export const COMPARE_FIELDS: (keyof PermitFields)[] = ['permitNo', 'holderName', 'validFrom', 'validTo', 'issueDate', 'vehicleNo', 'category']

export function compareQrPrinted(qr: Partial<PermitFields>, printed: Partial<PermitFields>, tzMin = DEFAULT_TZ_MIN): CompareRow[] {
  const rows: CompareRow[] = []
  for (const f of COMPARE_FIELDS) {
    const a = (qr[f] ?? '').trim()
    const b = (printed[f] ?? '').trim()
    if (!a && !b) continue
    let res: Cmp
    if (!a || !b) res = 'unread'
    else if (f === 'permitNo' || f === 'vehicleNo') res = alnum(a) === alnum(b) ? 'match' : 'mismatch' // an identifier is exact: one wrong digit is a different permit
    else if (f === 'validFrom' || f === 'validTo' || f === 'issueDate') {
      const pa = parseDateTime(a, tzMin, f === 'validTo' ? 'end' : 'start')
      const pb = parseDateTime(b, tzMin, f === 'validTo' ? 'end' : 'start')
      if (isMs(pa) && isMs(pb)) {
        const dayKey = (ms: number) => Math.floor((ms + tzMin * 60000) / 86400000)
        // when either side prints no time of day only the calendar day can be compared
        res = (pa.hadTime && pb.hadTime ? pa.ms === pb.ms : dayKey(pa.ms) === dayKey(pb.ms)) ? 'match' : 'mismatch'
      } else res = alnum(a) === alnum(b) ? 'match' : 'unread'
    } else if (f === 'holderName') {
      const x = nameKey(a)
      const y = nameKey(b)
      res = x === y ? 'match' : lev(x, y) <= 1 ? 'fuzzy' : 'mismatch'
    } else res = alnum(a) === alnum(b) ? 'match' : lev(alnum(a), alnum(b)) <= 1 ? 'fuzzy' : 'mismatch'
    rows.push({ field: f, label: FIELD_LABEL[f], qr: a, printed: b, res })
  }
  return rows
}

/* ------------------------------------------------------------
 * 5. DUPLICATE INDICATORS (local records only)
 * ------------------------------------------------------------ */
export type RegistryEntry = { permitNo: string; holder: string; qrHash: string; fileDigest: string; at: number }
export type DupIndicator = { code: 'DUP_PERMIT_CONFLICT' | 'DUP_QR_CONFLICT' | 'DUP_PERMIT_REPEAT' | 'DUP_FILE'; level: 'review' | 'info'; text: string }

export const DUP_SCOPE = 'Compared with records saved in THIS browser only. This is not a cross-checkpoint or national duplicate check.'

export function findDuplicates(cur: { permitNo: string; holder: string; qrHash: string; fileDigest: string }, registry: RegistryEntry[]): DupIndicator[] {
  const out: DupIndicator[] = []
  const pn = alnum(cur.permitNo)
  const holder = nameKey(cur.holder)
  for (const r of registry) {
    const samePermit = pn && alnum(r.permitNo) === pn
    if (samePermit && holder && nameKey(r.holder) && nameKey(r.holder) !== holder) out.push({ code: 'DUP_PERMIT_CONFLICT', level: 'review', text: `Permit number ${cur.permitNo} was saved earlier for a different holder ("${r.holder}"). An indicator for review, not proof of forgery.` })
    else if (samePermit && r.fileDigest !== cur.fileDigest) out.push({ code: 'DUP_PERMIT_REPEAT', level: 'info', text: `Permit number ${cur.permitNo} was checked before (different file). Repeat presentation can be legitimate.` })
    if (cur.qrHash && r.qrHash === cur.qrHash && !samePermit) out.push({ code: 'DUP_QR_CONFLICT', level: 'review', text: 'The same QR payload appears on a record with a different permit number.' })
    if (cur.fileDigest && r.fileDigest === cur.fileDigest) out.push({ code: 'DUP_FILE', level: 'info', text: 'This exact file was already checked in this browser.' })
  }
  const seen = new Set<string>()
  return out.filter((d) => (seen.has(d.code + d.text) ? false : (seen.add(d.code + d.text), true)))
}

/* ------------------------------------------------------------
 * 6. LIVE ISSUER STATUS (interface only: no government API is connected)
 * ------------------------------------------------------------ */
export type LiveState = 'active' | 'revoked' | 'suspended' | 'expired' | 'unknown' | 'unavailable'
export type LiveStatus = { state: LiveState; source: string; authoritative: boolean; checkedAt: number; detail: string }
export interface IssuerStatusProvider {
  name: string
  /** Only a provider that is a genuine, authorised issuer source may set this to true. */
  authoritative: boolean
  check(q: { permitNo: string; issuer: string }): Promise<{ state: LiveState; detail?: string }>
}

export const NO_ISSUER_PROVIDER: IssuerStatusProvider = {
  name: 'none configured',
  authoritative: false,
  check: async () => ({ state: 'unavailable', detail: 'No authorised issuer integration is connected to this prototype.' }),
}

export async function queryLiveStatus(p: IssuerStatusProvider | undefined, q: { permitNo: string; issuer: string }, nowMs: number, timeoutMs = 5000): Promise<LiveStatus> {
  const provider = p ?? NO_ISSUER_PROVIDER
  const unavailable = (detail: string): LiveStatus => ({ state: 'unavailable', source: provider.name, authoritative: false, checkedAt: nowMs, detail })
  if (!provider.authoritative) return unavailable('Provider is not an authoritative issuer source.')
  try {
    const res = await Promise.race([
      provider.check(q),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('issuer service timed out')), timeoutMs)),
    ])
    if (res.state === 'unavailable') return unavailable(res.detail ?? 'Issuer service unavailable.')
    return { state: res.state, source: provider.name, authoritative: true, checkedAt: nowMs, detail: res.detail ?? '' }
  } catch (e) {
    return unavailable(`Issuer service error: ${(e as Error).message}`)
  }
}

/* ------------------------------------------------------------
 * 7. FIELD EXTRACTION FROM OCR / PDF TEXT (labelled lines only, nothing is guessed)
 * ------------------------------------------------------------ */
const LABELS: [RegExp, keyof PermitFields][] = [
  [/(?:pass|permit)\s*(?:no|number|#)\.?/i, 'permitNo'],
  [/(?:name\s*of\s*holder|holder(?:'s)?\s*name|full\s*name|name)/i, 'holderName'],
  [/(?:issued\s*by|issuing\s*authority|authority)/i, 'issuingAuthority'],
  [/(?:valid\s*from|from\s*date|w\.?e\.?f\.?)/i, 'validFrom'],
  [/(?:valid\s*(?:up\s*)?(?:to|till|until)|expiry(?:\s*date)?|expires(?:\s*on)?|date\s*of\s*expiry)/i, 'validTo'],
  [/(?:date\s*of\s*issue|issue\s*date|issued\s*on)/i, 'issueDate'],
  [/(?:vehicle\s*(?:no|number|reg\w*)|registration\s*no)/i, 'vehicleNo'],
  [/(?:chassis|vin)(?:\s*(?:no|number))?/i, 'chassisNo'],
  [/engine\s*(?:no|number)/i, 'engineNo'],
  [/(?:entry\s*points?|point\s*of\s*entry)/i, 'entryPoints'],
  [/(?:exit\s*points?|point\s*of\s*exit)/i, 'exitPoints'],
  [/(?:category|type\s*of\s*(?:pass|permit))/i, 'category'],
  [/(?:jurisdiction|district)/i, 'jurisdiction'],
  [/(?:cargo|goods|commodity)/i, 'cargo'],
  [/(?:hsn|harmonized\s*system)(?:\s*(?:code|no))?/i, 'hsnCode'],
  [/(?:quantity|qty)/i, 'quantity'],
  [/(?:goods?\s*value|declared\s*value|invoice\s*value)/i, 'goodsValue'],
  [/(?:departure|origin|from\s*location)/i, 'departure'],
  [/(?:destination|to\s*location)/i, 'destination'],
  [/(?:employee|contractor)\s*(?:id|no|number)/i, 'employeeId'],
  [/(?:document|certificate)\s*(?:no|number|id)/i, 'documentNo'],
]
export type Extracted = { fields: Partial<PermitFields>; missing: (keyof PermitFields)[]; ambiguous: (keyof PermitFields)[] }

export function extractPermitFields(text: string, wanted: (keyof PermitFields)[] = ['permitNo', 'holderName', 'validTo']): Extracted {
  const fields: Partial<PermitFields> = {}
  const seen: Partial<Record<keyof PermitFields, string[]>> = {}
  for (const line of text.split(/\r?\n/)) {
    for (const [re, key] of LABELS) {
      const m = line.match(new RegExp(`^\\s*${re.source}\\s*[:\\-–]\\s*(.+?)\\s*$`, 'i'))
      if (m && m[1].length <= 120) (seen[key] ??= []).push(m[1])
    }
  }
  const ambiguous: (keyof PermitFields)[] = []
  for (const [k, vals] of Object.entries(seen) as [keyof PermitFields, string[]][]) {
    const uniq = [...new Set(vals.map((v) => v.trim()))]
    if (uniq.length > 1) ambiguous.push(k) // two different readings: do not pick one silently
    else fields[k] = uniq[0]
  }
  const cleanMrz = text.split(/\r?\n/).map((line) => line.toUpperCase().replace(/\s/g, '').replace(/[^A-Z0-9<]/g, ''))
  for (let i = 0; i < cleanMrz.length - 1; i++) {
    const first = cleanMrz[i]
    const second = cleanMrz[i + 1]
    if (/^[PV][A-Z<]/.test(first) && first.length === 44 && second.length === 44) {
      fields.mrzText = `${first}\n${second}`
      break
    }
    const third = cleanMrz[i + 2]
    if (/^[ACI][A-Z<]/.test(first) && first.length === 30 && second.length === 30 && third?.length === 30) {
      fields.mrzText = `${first}\n${second}\n${third}`
      break
    }
  }
  return { fields, ambiguous, missing: wanted.filter((k) => !fields[k] && !ambiguous.includes(k)) }
}

/* ------------------------------------------------------------
 * 8. DECISION LOGIC
 * ------------------------------------------------------------ */
export type Overall = 'VERIFIED' | 'INVALID' | 'EXPIRED' | 'REVOKED' | 'SUSPENDED' | 'REVIEW_REQUIRED' | 'UNVERIFIABLE'
export type RowState = 'pass' | 'fail' | 'warn' | 'info' | 'na' | 'unavailable'
export type StatusRow = { key: string; label: string; state: RowState; text: string }

export type ForensicIndicator = { title: string; detail: string; strength: 'supporting' | 'review' }

export type PermitInput = {
  purpose: PurposeId
  docType: DocTypeId
  fields: Partial<PermitFields>
  reviewed: boolean // operator confirmed the extracted fields (step 4)
  extraction: { ran: boolean; ambiguous?: (keyof PermitFields)[]; missing?: (keyof PermitFields)[] }
  /** null = no scan attempted, [] = scanned and none found */
  qrPayloads: string[] | null
  qrDrawnButUnreadable?: boolean
  nowMs: number
  tzMin?: number
  tzGiven?: boolean
  trustedKeys: string[]
  provider?: IssuerStatusProvider
  registry?: RegistryEntry[]
  fileDigest?: string
  forensics?: { ran: boolean; indicators: ForensicIndicator[] }
  movement?: { event: MovementEvent | null; prior: MovementEvent[] }
}

export type PermitReport = {
  overall: Overall
  headline: string
  reasons: string[]
  rows: StatusRow[]
  compare: CompareRow[]
  live: LiveStatus
  liveLabel: string | null
  checks: Record<CheckId, Applicability>
  limits: string
  warnings: string[]
  at: number
  purpose: PurposeId
  docType: DocTypeId
  qrHash: string
}

const PERMIT_ADAPTERS = new Set(['border-pass', 'travel-permit', 'vehicle-permit', 'cargo-trade', 'org-access'])
export const REQUIRED: (keyof PermitFields)[] = ['permitNo', 'holderName', 'validTo']

export const OVERALL_TEXT: Record<Overall, string> = {
  VERIFIED: 'VERIFIED: every check required by the policy passed, including trusted signature and live issuer status.',
  INVALID: 'INVALID: a reliable validation shows this document / permit is not valid.',
  EXPIRED: 'EXPIRED: reliable validity data shows the permit has expired.',
  REVOKED: 'REVOKED: a trusted issuer source confirms revocation.',
  SUSPENDED: 'SUSPENDED: a trusted issuer source confirms suspension.',
  REVIEW_REQUIRED: 'REVIEW REQUIRED: a human must look at this before any decision.',
  UNVERIFIABLE: 'UNVERIFIABLE: the available checks cannot establish authenticity or current status.',
}

export async function runPermitChecks(inp: PermitInput): Promise<PermitReport> {
  const tz = inp.tzMin ?? DEFAULT_TZ_MIN
  const sel = evaluateSelection(inp.purpose, inp.docType)
  const checks = sel.checks
  const f = inp.fields
  const rows: StatusRow[] = []
  const reasons: string[] = []
  const review: string[] = []
  const permitLike = PERMIT_ADAPTERS.has(sel.adapter)
  const on = (c: CheckId) => checks[c] === 'applicable'
  const push = (key: string, label: string, state: RowState, text: string) => rows.push({ key, label, state, text })

  /* extraction */
  const missing = permitLike ? REQUIRED.filter((k) => !(f[k] ?? '').trim()) : []
  if (!inp.extraction.ran) push('extraction', 'Field extraction', 'info', 'No automatic extraction was run: fields were entered by hand.')
  else if (inp.extraction.ambiguous?.length) push('extraction', 'Field extraction', 'warn', `Ambiguous reading for: ${inp.extraction.ambiguous.map((k) => FIELD_LABEL[k]).join(', ')}. Not guessed.`)
  else push('extraction', 'Field extraction', missing.length ? 'warn' : 'pass', missing.length ? `Missing: ${missing.map((k) => FIELD_LABEL[k]).join(', ')}` : 'Required fields present.')
  if (inp.extraction.ambiguous?.length) review.push('Some fields were read two different ways.')
  if (!inp.reviewed) review.push('The extracted fields have not been confirmed by the operator.')

  for (const check of validateDocumentFields(inp.docType, f)) {
    push(`document-${check.key}`, check.label, check.state, check.text)
    if (check.review) review.push(`${check.label} needs manual review.`)
  }

  /* QR */
  let parsed: ParsedQr[] = []
  let sig: EnvelopeSig | null = null
  let qrHash = ''
  let trust: IssuerTrust = 'not-applicable'
  let qrFields: Partial<PermitFields> = {}
  let compare: CompareRow[] = []
  let qrInvalidSig = false
  if (!on('qr')) {
    push('qr', 'QR / barcode', checks.qr === 'unavailable' ? 'unavailable' : 'na', checks.qr === 'unavailable' ? 'QR verification is not available for this document type.' : 'QR verification not applicable for this document type.')
    push('consistency', 'QR ↔ printed data', 'na', 'Not applicable.')
    push('signature', 'Digital signature', 'na', 'Not applicable.')
    push('issuer', 'Issuer trust', 'na', 'Not applicable.')
  } else if (inp.qrPayloads === null) {
    push('qr', 'QR / barcode', 'info', 'No QR scan was attempted.')
    push('consistency', 'QR ↔ printed data', 'na', 'No QR data to compare.')
    push('signature', 'Digital signature', 'na', 'No QR data.')
    push('issuer', 'Issuer trust', 'unavailable', 'Issuer identity not established (no QR / signature).')
    trust = 'unknown'
  } else if (inp.qrPayloads.length === 0) {
    const t = inp.qrDrawnButUnreadable ? 'A QR-shaped picture is present but nothing could be decoded. This can be caused by image quality: it is not proof of forgery.' : 'QR not detected. Some documents do not carry one.'
    push('qr', 'QR / barcode', inp.qrDrawnButUnreadable ? 'warn' : 'info', t)
    if (inp.qrDrawnButUnreadable) review.push('A QR is drawn on the document but could not be decoded.')
    push('consistency', 'QR ↔ printed data', 'na', 'No QR data to compare.')
    push('signature', 'Digital signature', 'na', 'No QR data.')
    push('issuer', 'Issuer trust', 'unavailable', 'Issuer identity not established (no QR / signature).')
    trust = 'unknown'
  } else {
    parsed = inp.qrPayloads.map(parsePermitQr)
    qrHash = await sha256hex(inp.qrPayloads.join('\n'))
    const distinct = new Set(inp.qrPayloads.map((p) => p.trim()))
    const bad = parsed.filter((p) => p.format === 'malformed' || p.format === 'empty')
    const unsupported = parsed.filter((p) => p.format === 'unsupported')
    const urls = parsed.filter((p) => p.format === 'url')
    const usable = parsed.filter((p) => p.format === 'envelope' || p.format === 'json' || p.format === 'keyvalue')
    if (distinct.size > 1) {
      push('qr', 'QR / barcode', 'warn', `${distinct.size} different codes found: ambiguous, no single payload was trusted.`)
      review.push('More than one different QR code on the document.')
    } else if (bad.length) {
      push('qr', 'QR / barcode', 'warn', `Malformed or truncated payload. ${bad[0].notes.join(' ')}`)
      review.push('QR payload is malformed or truncated.')
    } else if (urls.length && !usable.length) {
      push('qr', 'QR / barcode', 'info', `QR holds a link (${urls[0].url?.host || 'invalid'}${urls[0].url?.blocked ? ', blocked: ' + urls[0].url.reasons.join('; ') : ''}). It was NOT opened.`)
      if (urls[0].url?.blocked) review.push('QR link points to an unsafe or look-alike address.')
    } else if (unsupported.length && !usable.length) {
      push('qr', 'QR / barcode', 'info', `Decoded, but the format is unsupported. ${unsupported[0].notes.join(' ')}`)
    } else push('qr', 'QR / barcode', 'info', `Decoded (${usable[0]?.format}). A readable QR is not proof of authenticity.`)

    const single = distinct.size === 1 ? usable[0] : undefined
    if (single) {
      qrFields = single.fields
      compare = compareQrPrinted(qrFields, f, tz)
      const mism = compare.filter((c) => c.res === 'mismatch')
      const fuzzy = compare.filter((c) => c.res === 'fuzzy')
      push('consistency', 'QR ↔ printed data', mism.length ? 'fail' : fuzzy.length ? 'warn' : compare.some((c) => c.res === 'match') ? 'pass' : 'info', mism.length ? `Mismatch: ${mism.map((m) => m.label).join(', ')}` : fuzzy.length ? `Close but not identical: ${fuzzy.map((m) => m.label).join(', ')}` : compare.some((c) => c.res === 'match') ? 'Compared fields agree.' : 'Nothing comparable.')
      if (mism.length) review.push(`QR and printed data disagree: ${mism.map((m) => m.label).join(', ')}.`)
      if (fuzzy.length) review.push(`QR and printed data nearly match: ${fuzzy.map((m) => m.label).join(', ')}.`)
      if (single.format === 'envelope') {
        sig = await verifyEnvelope(single.raw, inp.trustedKeys)
        qrInvalidSig = sig.state === 'invalid'
        trust = sig.state === 'valid-trusted' ? 'trusted' : sig.state === 'valid-untrusted' ? (inp.trustedKeys.length ? 'untrusted' : 'unknown') : 'untrusted'
        push('signature', 'Digital signature', sig.state === 'invalid' ? 'fail' : sig.state === 'valid-trusted' ? 'pass' : 'warn', sig.detail)
        push('issuer', 'Issuer trust', trust === 'trusted' ? 'pass' : trust === 'unknown' ? 'unavailable' : 'warn', trust === 'trusted' ? 'Signing key is pinned.' : trust === 'unknown' ? 'No trusted issuer keys are configured: issuer is unknown.' : 'Signing key is not on the pinned list.')
      } else {
        trust = 'unknown'
        push('signature', 'Digital signature', 'na', 'This payload is not signed in any format VeriSight can verify.')
        push('issuer', 'Issuer trust', 'unavailable', 'Issuer identity cannot be established from an unsigned payload.')
      }
    } else {
      push('consistency', 'QR ↔ printed data', 'na', 'No single usable payload to compare.')
      push('signature', 'Digital signature', 'na', 'No single usable payload.')
      push('issuer', 'Issuer trust', 'unavailable', 'Issuer identity not established.')
      trust = 'unknown'
    }
  }

  /* dates */
  let validity: ValidityResult | null = null
  if (!on('date-validity')) push('dates', 'Dates / validity', 'na', 'Not applicable for this document type.')
  else {
    validity = evaluateValidity(f, inp.nowMs, tz, !!inp.tzGiven)
    const t: Record<ValidityState, [RowState, string]> = {
      'valid-printed': ['pass', 'Inside the printed validity period. This is NOT live status.'],
      expired: ['fail', 'Printed expiry date has passed.'],
      'not-yet-valid': ['warn', 'Printed valid-from date has not been reached yet.'],
      'invalid-range': ['fail', 'Date range is impossible.'],
      'missing-expiry': ['warn', 'No expiry date: validity cannot be established.'],
      unreadable: ['warn', 'A date could not be read.'],
    }
    push('dates', 'Dates / validity', t[validity.state][0], [t[validity.state][1], ...validity.notes].join(' '))
    if (validity.state === 'not-yet-valid') review.push('Permit is not valid yet.')
    if (validity.state === 'unreadable') review.push('A date on the permit could not be read.')
    if (validity.notes.some((n) => n.includes('suspicious'))) review.push('Suspicious date combination.')
  }

  /* live status */
  const live = await queryLiveStatus(inp.provider, { permitNo: f.permitNo ?? '', issuer: f.issuingAuthority ?? '' }, inp.nowMs)
  const liveLabel = live.state === 'unavailable' || live.state === 'unknown' ? LIVE_NOT_VERIFIED : null
  push('live', 'Live issuer status', live.state === 'active' ? 'pass' : live.state === 'revoked' || live.state === 'suspended' || live.state === 'expired' ? 'fail' : 'unavailable',
    live.state === 'unavailable' ? `${LIVE_NOT_VERIFIED}. ${live.detail}` : live.state === 'unknown' ? `${LIVE_NOT_VERIFIED}. Issuer source does not know this permit.` : `${live.state.toUpperCase()} according to ${live.source}.`)

  /* movement */
  let movement: MovementResult | null = null
  if (!on('movement-rules')) push('movement', 'Location & movement rules', 'na', 'Not applicable for this purpose / document.')
  else if (!validity) push('movement', 'Location & movement rules', 'info', 'Not checked.')
  else {
    movement = checkMovement(f, inp.movement?.event ?? null, inp.movement?.prior ?? [], validity)
    push('movement', 'Location & movement rules', movement.state === 'violation' ? 'fail' : movement.state === 'ok' ? 'pass' : 'info', [...movement.violations, ...movement.findings].join(' ') || 'Restrictions on the permit were respected.')
    if (movement.state === 'violation') review.push(...movement.violations)
  }

  /* duplicates */
  let dups: DupIndicator[] = []
  if (!on('duplicate')) push('dups', 'Duplicate indicators', 'na', 'Not applicable.')
  else {
    dups = findDuplicates({ permitNo: f.permitNo ?? '', holder: f.holderName ?? '', qrHash, fileDigest: inp.fileDigest ?? '' }, inp.registry ?? [])
    push('dups', 'Duplicate indicators', dups.some((d) => d.level === 'review') ? 'warn' : dups.length ? 'info' : 'pass', (dups.map((d) => d.text).join(' ') || 'None found.') + ' ' + DUP_SCOPE)
    for (const d of dups) if (d.level === 'review') review.push(d.text)
  }

  /* forensics (supporting evidence: never conclusive on its own) */
  if (!on('forensics')) push('forensics', 'Image / PDF forensics', 'na', 'Not applicable.')
  else if (!inp.forensics?.ran) push('forensics', 'Image / PDF forensics', 'info', 'Not run.')
  else {
    const rev = inp.forensics.indicators.filter((i) => i.strength === 'review')
    const sup = inp.forensics.indicators.filter((i) => i.strength === 'supporting')
    push('forensics', 'Image / PDF forensics', rev.length ? 'warn' : sup.length ? 'info' : 'pass',
      rev.length || sup.length ? [...rev, ...sup].map((i) => `${i.title}: ${i.detail}`).join(' ') + ' Heuristics can flag genuine scans, screenshots and recompressed files.' : 'No indicators found. That does not prove the document is genuine.')
    for (const i of rev) review.push(`Forensics: ${i.title}.`)
  }

  /* ---- overall: ordered, a confirmed failure can never be averaged away ---- */
  let overall: Overall
  const live_ok = live.authoritative
  if (live_ok && live.state === 'revoked') { overall = 'REVOKED'; reasons.push('Trusted issuer source reports REVOKED.') }
  else if (live_ok && live.state === 'suspended') { overall = 'SUSPENDED'; reasons.push('Trusted issuer source reports SUSPENDED.') }
  else if (qrInvalidSig) { overall = 'INVALID'; reasons.push('The QR signature does not verify: the signed data was altered or signed with another key.') }
  else if (validity?.state === 'invalid-range') { overall = 'INVALID'; reasons.push('The dates on the permit are impossible.') }
  else if ((live_ok && live.state === 'expired') || validity?.state === 'expired') { overall = 'EXPIRED'; reasons.push(live_ok && live.state === 'expired' ? 'Issuer source reports EXPIRED.' : 'Printed expiry date has passed.') }
  else if (review.length) { overall = 'REVIEW_REQUIRED'; reasons.push(...review) }
  else {
    const reasonsNot: string[] = []
    if (inp.docType === 'auto' || inp.docType === 'other') reasonsNot.push('Document type is unknown: only generic checks could run.')
    if (missing.length) reasonsNot.push(`Required field missing: ${missing.map((k) => FIELD_LABEL[k]).join(', ')}.`)
    if (validity?.state === 'missing-expiry') reasonsNot.push('No expiry date.')
    const sigNeeded = on('signature')
    const fullPass = sigNeeded && sig?.state === 'valid-trusted' && trust === 'trusted' && live_ok && live.state === 'active' && validity?.state === 'valid-printed' && !missing.length && inp.reviewed && inp.docType !== 'auto' && inp.docType !== 'other'
    if (fullPass) { overall = 'VERIFIED'; reasons.push('Trusted signature, pinned issuer, live status ACTIVE, dates valid, fields consistent.') }
    else {
      overall = 'UNVERIFIABLE'
      reasons.push(...reasonsNot)
      if (!live_ok || live.state !== 'active') reasons.push(`${LIVE_NOT_VERIFIED}.`)
      if (sigNeeded && sig?.state !== 'valid-trusted') reasons.push('No trusted cryptographic proof of authenticity.')
    }
  }

  return {
    overall,
    headline: OVERALL_TEXT[overall],
    reasons: [...new Set(reasons)],
    rows,
    compare,
    live,
    liveLabel,
    checks,
    limits: ADAPTERS[sel.adapter].limits,
    warnings: sel.warnings,
    at: inp.nowMs,
    purpose: inp.purpose,
    docType: inp.docType,
    qrHash,
  }
}
