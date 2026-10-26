export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export function hashString(input: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}

export function fnvHex(input: string): string {
  return hashString(input).toString(16).padStart(8, '0')
}

export function seededRandom(seed: number) {
  let t = seed
  return () => {
    t += 0x6d2b79f5
    let r = Math.imul(t ^ (t >>> 15), 1 | t)
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r)
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296
  }
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/* ---------- ICAO 9303 MRZ ---------- */

const MRZ_WEIGHTS = [7, 3, 1]

function mrzCharValue(c: string): number {
  if (c === '<') return 0
  if (/\d/.test(c)) return Number(c)
  return c.charCodeAt(0) - 55
}

export function mrzCheckDigit(field: string) {
  let sum = 0
  for (let i = 0; i < field.length; i++) {
    sum += mrzCharValue(field[i]) * MRZ_WEIGHTS[i % 3]
  }
  return { digit: sum % 10, sum }
}

export type MrzField = {
  label: string
  value: string
  stated: string
  computed: number
  sum: number
  valid: boolean
}

export function validateTD3(line2: string): MrzField[] {
  const make = (label: string, value: string, stated: string): MrzField => {
    const { digit, sum } = mrzCheckDigit(value)
    return { label, value, stated, computed: digit, sum, valid: String(digit) === stated }
  }
  const composite = line2.slice(0, 10) + line2.slice(13, 20) + line2.slice(21, 43)
  return [
    make('Document No.', line2.slice(0, 9), line2[9]),
    make('Date of Birth', line2.slice(13, 19), line2[19]),
    make('Date of Expiry', line2.slice(21, 27), line2[27]),
    make('Personal No.', line2.slice(28, 42), line2[42]),
    make('Composite', composite, line2[43]),
  ]
}

export function validateTD1(line1: string, line2: string): MrzField[] {
  const make = (label: string, value: string, stated: string): MrzField => {
    const { digit, sum } = mrzCheckDigit(value)
    return { label, value, stated, computed: digit, sum, valid: String(digit) === stated }
  }
  const composite = line1.slice(5, 30) + line2.slice(0, 7) + line2.slice(8, 15) + line2.slice(18, 29)
  return [
    make('Document No.', line1.slice(5, 14), line1[14]),
    make('Date of Birth', line2.slice(0, 6), line2[6]),
    make('Date of Expiry', line2.slice(8, 14), line2[14]),
    make('Composite', composite, line2[29]),
  ]
}

export const MRZ_SAMPLES = {
  clean: {
    line1: 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<',
    line2: 'L898902C36UTO7408122F1204159ZE184226B<<<<<10',
  },
  tampered: {
    line1: 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<',
    line2: 'L898902C36UTO7408122F1904159ZE184226B<<<<<10',
  },
}

export function riskLevel(score: number) {
  if (score >= 70) return { label: 'HIGH RISK', tone: 'danger' as const }
  if (score >= 40) return { label: 'ELEVATED', tone: 'warning' as const }
  return { label: 'LOW RISK', tone: 'success' as const }
}

/* ---------- QR ---------- */

export const QR_PUBLIC_KEY_FP = 'SHA256:7F:3A:C1:9E:04:B2:58:DD:61:0A:E7:93:4C:2F:88:1B'

export const QR_GENUINE_PAYLOAD = JSON.stringify(
  {
    docNo: 'X4821-7730-9912',
    name: 'ARJUN MEHTA',
    dob: '1989-03-14',
    gender: 'M',
    nationality: 'IND',
    expiry: '2031-06-30',
    issuer: 'UIDAI-RSA-2048-K7',
    sig: '2ae3709ea4171c23c047b81ed1507187',
  },
  null,
  2,
)

export const QR_TAMPERED_PAYLOAD = JSON.stringify(
  {
    docNo: 'X4821-7730-9912',
    name: 'ARJUN MEHTA',
    dob: '1984-03-14',
    gender: 'M',
    nationality: 'IND',
    expiry: '2036-06-30',
    issuer: 'UIDAI-RSA-2048-K7',
    sig: '2ae3709ea4171c23c047b81ed1507187',
  },
  null,
  2,
)

export const QR_PRINTED_TEXT: Record<string, string> = {
  docNo: 'X4821-7730-9912',
  name: 'ARJUN MEHTA',
  dob: '1989-03-14',
  gender: 'M',
  nationality: 'IND',
  expiry: '2031-06-30',
}

export const QR_FIELD_LABELS: Record<string, string> = {
  docNo: 'Document No.',
  name: 'Full Name',
  dob: 'Date of Birth',
  gender: 'Gender',
  nationality: 'Nationality',
  expiry: 'Expiry',
}

export function canonicalize(obj: Record<string, unknown>) {
  const keys = Object.keys(obj).sort()
  return JSON.stringify(Object.fromEntries(keys.map((k) => [k, obj[k]])))
}
