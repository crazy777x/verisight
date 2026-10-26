export type QrPayloadFormat = 'json' | 'xml' | 'url' | 'key-value' | 'mrz-like' | 'text' | 'opaque'

export type QrPayloadShape = {
  format: QrPayloadFormat
  label: string
  detail: string
}

/**
 * Classifies decoded payload syntax only. A QR standard or payload shape never
 * identifies its issuer or proves that a government signed it.
 */
export function classifyQrPayload(payload: string): QrPayloadShape {
  const text = payload.trim()
  if (!text) return { format: 'opaque', label: 'Empty payload', detail: 'The QR decoded but contained no text payload.' }

  try {
    const value: unknown = JSON.parse(text)
    if (value && typeof value === 'object') {
      return {
        format: 'json',
        label: Array.isArray(value) ? 'JSON array' : 'JSON object',
        detail: 'Valid JSON structure. This describes the payload format only; it does not identify or authenticate the issuer.',
      }
    }
  } catch {
    // Continue with other known payload shapes.
  }

  if (/^https?:\/\//i.test(text)) {
    try {
      const url = new URL(text)
      if (url.hostname && (url.protocol === 'https:' || url.protocol === 'http:')) {
        return {
          format: 'url',
          label: 'Web link',
          detail: `QR contains a ${url.protocol.slice(0, -1).toUpperCase()} URL. A link is not proof that its destination or issuer is genuine.`,
        }
      }
    } catch {
      // A malformed URL is classified by its remaining payload shape.
    }
  }

  if (/^</.test(text) && /<\/[\w:.-]+\s*>\s*$/.test(text)) {
    return {
      format: 'xml',
      label: 'XML-like payload',
      detail: 'The payload has XML-style tags. The tags are not authenticated and may be created by anyone.',
    }
  }

  if (/^[A-Z0-9<\r\n]+$/.test(text) && text.split(/\r?\n/).filter(Boolean).some((line) => line.length >= 30 && line.includes('<'))) {
    return {
      format: 'mrz-like',
      label: 'MRZ-like text',
      detail: 'Payload resembles machine-readable travel-document text. This does not verify the document or its issuer.',
    }
  }

  if (/^[\s\S]{1,4096}$/.test(text) && /(?:^|[|;\r\n])\s*[A-Za-z][\w.-]{1,30}\s*[:=]\s*[^|;\r\n]*/.test(text)) {
    return {
      format: 'key-value',
      label: 'Key/value fields',
      detail: 'Readable key/value fields were found. Field names and values are self-asserted unless a trusted signature or issuer record confirms them.',
    }
  }

  if (/^[\x20-\x7e\r\n\t]+$/.test(text)) {
    return {
      format: 'text',
      label: 'Plain text',
      detail: 'The QR contains readable text but no recognized structured payload shape. Readable content is not issuer authentication.',
    }
  }

  return {
    format: 'opaque',
    label: 'Opaque / binary payload',
    detail: 'The QR contains non-readable or unsupported data. No issuer-specific decoder or trusted signature rule is configured.',
  }
}
