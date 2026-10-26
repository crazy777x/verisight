/* Minimal DER / ASN.1 reader: enough for X.509 certs and PKCS#7 (PDF signatures). */
export type Node = { tag: number; cls: number; constructed: boolean; start: number; hdr: number; len: number; end: number; kids: Node[] | null }

export function parseDer(b: Uint8Array, off = 0, limit = b.length, depth = 0): Node {
  const start = off
  const t = b[off++]
  const cls = t >> 6
  const constructed = (t & 0x20) !== 0
  let tag = t & 0x1f
  if (tag === 0x1f) {
    tag = 0
    while (b[off] & 0x80) tag = (tag << 7) | (b[off++] & 0x7f)
    tag = (tag << 7) | b[off++]
  }
  let len = b[off++]
  if (len & 0x80) {
    const n = len & 0x7f
    len = 0
    for (let i = 0; i < n; i++) len = len * 256 + b[off++]
  }
  const hdr = off - start
  const end = off + len
  if (end > limit) throw new Error('ASN.1 length overflow')
  let kids: Node[] | null = null
  if (constructed && depth < 24) {
    kids = []
    let p = off
    while (p < end) {
      const k = parseDer(b, p, end, depth + 1)
      kids.push(k)
      p = k.end
    }
  }
  return { tag, cls, constructed, start, hdr, len, end, kids }
}

export const raw = (b: Uint8Array, n: Node) => b.slice(n.start, n.end)
export const content = (b: Uint8Array, n: Node) => b.slice(n.start + n.hdr, n.end)

export function oidOf(b: Uint8Array, n: Node): string {
  const c = content(b, n)
  const out: number[] = [Math.floor(c[0] / 40), c[0] % 40]
  let v = 0
  for (let i = 1; i < c.length; i++) {
    v = v * 128 + (c[i] & 0x7f)
    if (!(c[i] & 0x80)) {
      out.push(v)
      v = 0
    }
  }
  return out.join('.')
}

export const toHex = (u: Uint8Array) => Array.from(u).map((x) => x.toString(16).padStart(2, '0')).join('')
export function fromHex(h: string): Uint8Array {
  const clean = h.replace(/[^0-9a-fA-F]/g, '')
  const out = new Uint8Array(Math.floor(clean.length / 2))
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16)
  return out
}

/** PEM or DER -> DER bytes */
export function certToDer(data: Uint8Array): Uint8Array {
  const txt = new TextDecoder('latin1').decode(data)
  if (txt.includes('BEGIN CERTIFICATE')) {
    const b64 = txt.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
    const bin = atob(b64)
    return Uint8Array.from(bin, (c) => c.charCodeAt(0))
  }
  return data
}

export type CertInfo = { spki: Uint8Array; subjectCN: string; issuerCN: string; notBefore: string; notAfter: string; sha256?: string; derSha256?: string }

function cnOf(b: Uint8Array, name: Node): string {
  let cn = ''
  for (const rdn of name.kids ?? [])
    for (const atv of rdn.kids ?? [])
      if (atv.kids && oidOf(b, atv.kids[0]) === '2.5.4.3') cn = new TextDecoder().decode(content(b, atv.kids[1]))
  return cn
}
function timeOf(b: Uint8Array, n: Node): string {
  return new TextDecoder().decode(content(b, n))
}

export function parseCert(der: Uint8Array): CertInfo {
  const root = parseDer(der)
  const tbs = root.kids![0]
  const k = tbs.kids!
  let i = 0
  if (k[0].cls === 2 && k[0].tag === 0) i = 1 // explicit version
  // serial=i, sigAlg=i+1, issuer=i+2, validity=i+3, subject=i+4, spki=i+5
  const validity = k[i + 3].kids!
  return {
    spki: raw(der, k[i + 5]),
    issuerCN: cnOf(der, k[i + 2]),
    subjectCN: cnOf(der, k[i + 4]),
    notBefore: timeOf(der, validity[0]),
    notAfter: timeOf(der, validity[1]),
  }
}

export type CertFull = CertInfo & { tbs: Uint8Array; sigAlgOid: string; signature: Uint8Array; subjectDer: Uint8Array; issuerDer: Uint8Array }

/** Everything needed to check "was this certificate signed by that issuer?" */
export function parseCertFull(der: Uint8Array): CertFull {
  const root = parseDer(der)
  const tbs = root.kids![0]
  const k = tbs.kids!
  const i = k[0].cls === 2 && k[0].tag === 0 ? 1 : 0
  const info = parseCert(der)
  const sigBits = content(der, root.kids![2]) // BIT STRING: first byte = unused bits
  return {
    ...info,
    tbs: raw(der, tbs),
    sigAlgOid: oidOf(der, root.kids![1].kids![0]),
    signature: sigBits.slice(1),
    issuerDer: raw(der, k[i + 2]),
    subjectDer: raw(der, k[i + 4]),
  }
}

/** UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) -> Date */
export function parseAsn1Time(t: string): Date | null {
  const d = t.trim().replace(/Z$/, '')
  if (!/^\d{12}(\d{2})?$/.test(d)) return null
  const gen = d.length === 14 // GeneralizedTime YYYYMMDDHHMMSS, otherwise UTCTime YYMMDDHHMMSS
  const o = gen ? 2 : 0
  const year = gen ? +d.slice(0, 4) : +d.slice(0, 2) >= 50 ? 1900 + +d.slice(0, 2) : 2000 + +d.slice(0, 2)
  return new Date(Date.UTC(year, +d.slice(2 + o, 4 + o) - 1, +d.slice(4 + o, 6 + o), +d.slice(6 + o, 8 + o), +d.slice(8 + o, 10 + o), +d.slice(10 + o, 12 + o)))
}
