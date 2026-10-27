export type IdentityFields = {
  name?: string
  dob?: string
  gender?: string
  pincode?: string
}

export type IdentityComparison = {
  field: keyof IdentityFields
  label: string
  aadhaar: string
  document: string
  result: 'match' | 'mismatch' | 'partial' | 'unavailable'
}

const labels: Record<keyof IdentityFields, string> = {
  name: 'Name',
  dob: 'Date of birth',
  gender: 'Gender',
  pincode: 'PIN code',
}

function normalizeText(value: string) {
  return value
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toUpperCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .sort()
    .join(' ')
}

function normalizeGender(value: string) {
  const normalized = value.trim().toUpperCase()
  if (/^(M|MALE)$/.test(normalized)) return 'M'
  if (/^(F|FEMALE)$/.test(normalized)) return 'F'
  if (/^(T|TRANSGENDER|OTHER)$/.test(normalized)) return 'T'
  return normalizeText(value)
}

function dateParts(value: string): { year: string; full?: string } | null {
  const text = value.trim()
  if (/^\d{4}$/.test(text)) return { year: text }

  let match = text.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/)
  let year: number
  let month: number
  let day: number
  if (match) {
    year = Number(match[1])
    month = Number(match[2])
    day = Number(match[3])
  } else {
    match = text.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$/)
    if (!match) return null
    day = Number(match[1])
    month = Number(match[2])
    year = Number(match[3])
  }
  const date = new Date(Date.UTC(year, month - 1, day))
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null
  return { year: String(year), full: `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}` }
}

function compareValue(field: keyof IdentityFields, left: string, right: string): IdentityComparison['result'] {
  if (field === 'dob') {
    const a = dateParts(left)
    const b = dateParts(right)
    if (!a || !b) return 'mismatch'
    if (a.full && b.full) return a.full === b.full ? 'match' : 'mismatch'
    return a.year === b.year ? 'partial' : 'mismatch'
  }
  const a = field === 'gender' ? normalizeGender(left) : normalizeText(left)
  const b = field === 'gender' ? normalizeGender(right) : normalizeText(right)
  return a === b ? 'match' : 'mismatch'
}

export function compareIdentityFields(aadhaar: IdentityFields, document: IdentityFields): IdentityComparison[] {
  return (Object.keys(labels) as (keyof IdentityFields)[]).map((field) => {
    const left = aadhaar[field]?.trim() ?? ''
    const right = document[field]?.trim() ?? ''
    return {
      field,
      label: labels[field],
      aadhaar: left,
      document: right,
      result: !left || !right ? 'unavailable' : compareValue(field, left, right),
    }
  })
}
