import { classifyQrPayload } from './qrformat'

export type PanQrFieldCheck = {
  value: string
  printed: string
  result: 'match' | 'mismatch' | 'unread' | 'ambiguous'
}

export type PanQrInspection = {
  format: string
  formatLabel: string
  bytes: number
  pan: PanQrFieldCheck
  name: PanQrFieldCheck
}

const PAN_KEYS = new Set(['pan', 'panno', 'pannumber', 'permanentaccountnumber'])
const NAME_KEYS = new Set(['name', 'holdername', 'fullname', 'applicantname', 'cardholdername'])
const normalizeKey = (key: string) => key.toLowerCase().replace(/[^a-z]/g, '')
const normalizeValue = (value: string) => value.toUpperCase().replace(/[^A-Z0-9]/g, '')

function collectFields(payload: string) {
  const panValues: string[] = []
  const nameValues: string[] = []
  const add = (key: string, value: string) => {
    const normalized = normalizeKey(key)
    if (PAN_KEYS.has(normalized)) panValues.push(value.trim())
    if (NAME_KEYS.has(normalized)) nameValues.push(value.trim())
  }

  try {
    const root: unknown = JSON.parse(payload)
    const visit = (value: unknown, depth: number) => {
      if (!value || typeof value !== 'object' || depth > 8) return
      if (Array.isArray(value)) {
        for (const item of value) visit(item, depth + 1)
        return
      }
      for (const [key, item] of Object.entries(value)) {
        if (typeof item === 'string') add(key, item)
        else visit(item, depth + 1)
      }
    }
    visit(root, 0)
  } catch {
    for (const match of payload.matchAll(/<([A-Za-z][\w.-]*)[^>]*>([^<>]{1,200})<\/\1\s*>/g)) add(match[1], match[2])
    for (const match of payload.matchAll(/(?:^|[|;\r\n])\s*([A-Za-z][\w.-]{1,30})\s*[:=]\s*([^|;\r\n]{1,200})/g)) add(match[1], match[2])
  }

  const panTokens = payload.toUpperCase().match(/\b[A-Z]{5}\d{4}[A-Z]\b/g) ?? []
  return {
    panValues: [...new Set([...panValues, ...panTokens].map((value) => value.trim().toUpperCase()))],
    nameValues: [...new Set(nameValues)],
  }
}

function compare(values: string[], printed: string, normalize: (value: string) => string): PanQrFieldCheck {
  const distinct = [...new Set(values.map((value) => value.trim()).filter(Boolean))]
  if (distinct.length > 1) return { value: '', printed, result: 'ambiguous' }
  if (!distinct.length || !printed.trim()) return { value: distinct[0] ?? '', printed, result: 'unread' }
  return {
    value: distinct[0],
    printed,
    result: normalize(distinct[0]) === normalize(printed) ? 'match' : 'mismatch',
  }
}

/** Compares recognizable decoded QR fields only; payload shape is not issuer authentication. */
export function inspectPanQr(payload: string, printed: { pan: string; name: string }): PanQrInspection {
  const shape = classifyQrPayload(payload)
  const fields = collectFields(payload)
  return {
    format: shape.format,
    formatLabel: shape.label,
    bytes: new TextEncoder().encode(payload).length,
    pan: compare(fields.panValues, printed.pan, (value) => value.toUpperCase()),
    name: compare(fields.nameValues, printed.name, normalizeValue),
  }
}
