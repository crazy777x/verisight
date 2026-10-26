import { getJsQR, getOcr, getPdfJs, getZXing } from './loaders'
import type { OcrWord } from './tamper'
import { certToDer, content, fromHex, oidOf, parseCert, parseDer, raw, toHex, type CertInfo, type Node } from './asn1'
import { validateTD1, validateTD3, type MrzField } from './forensics'
import { AADHAAR_PDF_SIGNER_PINS, assessCert, verifyChain, type ChainResult } from './trust'
import { findDl, findEpic, findPan, hasDlKeywords, hasEpicKeywords, hasPanKeywords, plausibleName } from './docs'

const buf = (u: Uint8Array) => u as unknown as BufferSource

/* ============================================================
 * 1. FILE -> CANVAS PAGES
 * ============================================================ */
export type Loaded = {
  pages: HTMLCanvasElement[]
  isPdf: boolean
  isJpeg: boolean
  bytes: Uint8Array
  /** real text embedded in a PDF (e-Aadhaar, e-PAN ...). Far more accurate than OCR when present. */
  textLayer: string
  needsPassword?: 'need' | 'wrong'
}

export async function loadFile(file: File, password?: string): Promise<Loaded> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  const isPdf = file.type === 'application/pdf' || /\.pdf$/i.test(file.name)
  if (!isPdf) {
    const bmp = await createImageBitmap(file)
    const maxW = 2600
    const s = Math.min(1, maxW / bmp.width)
    const c = document.createElement('canvas')
    c.width = Math.round(bmp.width * s)
    c.height = Math.round(bmp.height * s)
    c.getContext('2d')!.drawImage(bmp, 0, 0, c.width, c.height)
    return { pages: [c], isPdf: false, isJpeg: /jpe?g/i.test(file.type) || /\.jpe?g$/i.test(file.name), bytes, textLayer: '' }
  }
  const pdfjs = await getPdfJs()
  let doc: any
  try {
    doc = await pdfjs.getDocument({ data: bytes.slice(), password }).promise
  } catch (e: any) {
    if (e?.name === 'PasswordException') return { pages: [], isPdf: true, isJpeg: false, bytes, textLayer: '', needsPassword: e.code === 2 ? 'wrong' : 'need' }
    throw e
  }
  const pages: HTMLCanvasElement[] = []
  let textLayer = ''
  const n = Math.min(doc.numPages, 4)
  for (let i = 1; i <= n; i++) {
    const page = await doc.getPage(i)
    try {
      textLayer += '\n' + pageText(await page.getTextContent())
    } catch {
      /* scanned PDF: no text layer, OCR will be used */
    }
    const base = page.getViewport({ scale: 1 })
    const scale = Math.max(1.5, Math.min(4, 2600 / base.width))
    const vp = page.getViewport({ scale })
    const c = document.createElement('canvas')
    c.width = Math.floor(vp.width)
    c.height = Math.floor(vp.height)
    await page.render({ canvasContext: c.getContext('2d')!, viewport: vp }).promise
    pages.push(c)
  }
  return { pages, isPdf: true, isJpeg: false, bytes, textLayer: textLayer.trim() }
}

/** Rebuild reading-order lines from pdf.js text items (group by baseline, sort by x). */
function pageText(tc: any): string {
  const rows = new Map<number, { x: number; t: string }[]>()
  for (const it of tc.items ?? []) {
    const t = String(it.str ?? '')
    if (!t.trim()) continue
    const y = Math.round((it.transform?.[5] ?? 0) / 3)
    const arr = rows.get(y) ?? []
    arr.push({ x: it.transform?.[4] ?? 0, t })
    rows.set(y, arr)
  }
  return [...rows.entries()]
    .sort((a, b) => b[0] - a[0])
    .map(([, v]) => v.sort((a, b) => a.x - b.x).map((q) => q.t).join(' ').replace(/\s+/g, ' ').trim())
    .join('\n')
}

/* ============================================================
 * 2. REAL ELA (JPEG q=90 re-save, 8x8 grid, edge-normalised)
 * ============================================================ */
export type ElaReport = {
  blocks: number[]
  rowVariance: number[]
  mean: number
  variance: number
  peak: number
  anomalousBlocks: number
  anomaly: boolean
  reliable: boolean
  note: string
}

function median(a: number[]) {
  const s = [...a].sort((x, y) => x - y)
  return s.length ? s[Math.floor(s.length / 2)] : 0
}

export async function computeEla(src: HTMLCanvasElement, reliable: boolean): Promise<ElaReport> {
  const W = Math.min(1600, src.width)
  const H = Math.round((src.height * W) / src.width)
  const a = document.createElement('canvas')
  a.width = W
  a.height = H
  const actx = a.getContext('2d', { willReadFrequently: true })!
  actx.fillStyle = '#fff'
  actx.fillRect(0, 0, W, H)
  actx.drawImage(src, 0, 0, W, H)
  const blob: Blob = await new Promise((res, rej) => a.toBlob((b) => (b ? res(b) : rej(new Error('toBlob'))), 'image/jpeg', 0.9))
  const bmp = await createImageBitmap(blob)
  const b = document.createElement('canvas')
  b.width = W
  b.height = H
  const bctx = b.getContext('2d', { willReadFrequently: true })!
  bctx.drawImage(bmp, 0, 0)
  const d1 = actx.getImageData(0, 0, W, H).data
  const d2 = bctx.getImageData(0, 0, W, H).data

  const err = new Array(64).fill(0)
  const edge = new Array(64).fill(0)
  const cnt = new Array(64).fill(0)
  for (let y = 1; y < H - 1; y++) {
    const by = Math.min(7, Math.floor((y / H) * 8))
    for (let x = 1; x < W - 1; x++) {
      const bx = Math.min(7, Math.floor((x / W) * 8))
      const i = (y * W + x) * 4
      const e = (Math.abs(d1[i] - d2[i]) + Math.abs(d1[i + 1] - d2[i + 1]) + Math.abs(d1[i + 2] - d2[i + 2])) / 3
      const g = Math.abs(d1[i] - d1[i + 4]) + Math.abs(d1[i] - d1[i + W * 4])
      const k = by * 8 + bx
      err[k] += e
      edge[k] += g
      cnt[k]++
    }
  }
  const raw64 = err.map((v, k) => v / Math.max(1, cnt[k]))
  const edge64 = edge.map((v, k) => v / Math.max(1, cnt[k]))
  const blocks = raw64.map((v) => Number(Math.min(1, v / 8).toFixed(3)))
  // edge-normalised ratio: text-heavy areas are naturally "noisy"; compare error *relative to* content
  const ratio = raw64.map((v, k) => v / (edge64[k] + 6))
  const med = median(ratio)
  const mad = median(ratio.map((r) => Math.abs(r - med))) * 1.4826 + 0.004
  const z = ratio.map((r) => (r - med) / mad)
  const hot = z.map((v, k) => v > 4.5 && raw64[k] > 0.6)
  const anomalousBlocks = hot.filter(Boolean).length
  const mean = blocks.reduce((s, v) => s + v, 0) / 64
  const variance = blocks.reduce((s, v) => s + (v - mean) ** 2, 0) / 64
  const rowVariance = Array.from({ length: 8 }, (_, r) => {
    const row = blocks.slice(r * 8, r * 8 + 8)
    const m = row.reduce((s, v) => s + v, 0) / 8
    return row.reduce((s, v) => s + (v - m) ** 2, 0) / 8
  })
  const anomaly = anomalousBlocks >= 3
  // mark hot blocks for the heatmap
  hot.forEach((h, k) => {
    if (h) blocks[k] = Math.max(blocks[k], 0.75)
  })
  return {
    blocks,
    rowVariance,
    mean,
    variance,
    peak: Math.max(...blocks),
    anomalousBlocks,
    anomaly,
    reliable,
    note: reliable
      ? ''
      : 'Source is a PDF raster (not an original JPEG): ELA is advisory only and does not drive the risk score.',
  }
}

/* ============================================================
 * 3. QR DETECTION  (native BarcodeDetector -> jsQR multi-scale/threshold -> ZXing)
 * ============================================================ */
export type QrHit = { text: string; bytes: Uint8Array; page: number; engine: string }

type Prep = 'raw' | 'contrast' | 'binary'

function prepared(c: HTMLCanvasElement, sx: number, sy: number, sw: number, sh: number, up: number, prep: Prep): ImageData {
  const t = document.createElement('canvas')
  t.width = Math.max(8, Math.round(sw * up))
  t.height = Math.max(8, Math.round(sh * up))
  const ctx = t.getContext('2d', { willReadFrequently: true })!
  ctx.imageSmoothingEnabled = up > 1 // smooth upscaling keeps the QR modules readable
  ctx.imageSmoothingQuality = 'high'
  ctx.fillStyle = '#fff'
  ctx.fillRect(0, 0, t.width, t.height)
  ctx.drawImage(c, sx, sy, sw, sh, 0, 0, t.width, t.height)
  const img = ctx.getImageData(0, 0, t.width, t.height)
  if (prep === 'raw') return img
  const d = img.data
  const n = t.width * t.height
  const g = new Uint8ClampedArray(n)
  const hist = new Array(256).fill(0)
  for (let i = 0; i < n; i++) {
    g[i] = (d[i * 4] * 299 + d[i * 4 + 1] * 587 + d[i * 4 + 2] * 114) / 1000
    hist[g[i]]++
  }
  if (prep === 'contrast') {
    let lo = 0
    let hi = 255
    let acc = 0
    for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc > n * 0.02) { lo = v; break } }
    acc = 0
    for (let v = 255; v >= 0; v--) { acc += hist[v]; if (acc > n * 0.02) { hi = v; break } }
    const span = Math.max(30, hi - lo)
    for (let i = 0; i < n; i++) {
      const v = Math.max(0, Math.min(255, ((g[i] - lo) * 255) / span))
      d[i * 4] = d[i * 4 + 1] = d[i * 4 + 2] = v
    }
    return img
  }
  // Otsu binarisation
  let sum = 0
  for (let v = 0; v < 256; v++) sum += v * hist[v]
  let sumB = 0
  let wB = 0
  let best = 0
  let thr = 128
  for (let v = 0; v < 256; v++) {
    wB += hist[v]
    if (!wB) continue
    const wF = n - wB
    if (!wF) break
    sumB += v * hist[v]
    const mB = sumB / wB
    const mF = (sum - sumB) / wF
    const between = wB * wF * (mB - mF) ** 2
    if (between > best) { best = between; thr = v }
  }
  for (let i = 0; i < n; i++) {
    const v = g[i] > thr ? 255 : 0
    d[i * 4] = d[i * 4 + 1] = d[i * 4 + 2] = v
  }
  return img
}

function zxingDecode(Z: any, img: ImageData): string | null {
  try {
    const n = img.width * img.height
    const lum = new Uint8ClampedArray(n)
    for (let i = 0; i < n; i++) lum[i] = (img.data[i * 4] * 299 + img.data[i * 4 + 1] * 587 + img.data[i * 4 + 2] * 114) / 1000
    const bmp = new Z.BinaryBitmap(new Z.HybridBinarizer(new Z.RGBLuminanceSource(lum, img.width, img.height)))
    const hints = new Map()
    hints.set(Z.DecodeHintType.TRY_HARDER, true)
    hints.set(Z.DecodeHintType.POSSIBLE_FORMATS, [Z.BarcodeFormat.QR_CODE])
    return new Z.QRCodeReader().decode(bmp, hints).getText() as string
  } catch {
    return null
  }
}

export async function scanQr(pages: HTMLCanvasElement[], onProgress?: (s: string) => void): Promise<QrHit | null> {
  const enc = new TextEncoder()
  // 1) native detector (fast + robust on Chrome/Edge/Android when available)
  try {
    const BD = (window as any).BarcodeDetector
    if (BD) {
      const det = new BD({ formats: ['qr_code'] })
      for (let p = 0; p < pages.length; p++) {
        const r = await det.detect(pages[p])
        if (r?.[0]?.rawValue && r[0].rawValue.length > 8) return { text: r[0].rawValue, bytes: enc.encode(r[0].rawValue), page: p, engine: 'BarcodeDetector' }
      }
    }
  } catch {
    /* fall through */
  }

  let jsQR: ((d: Uint8ClampedArray, w: number, h: number, o?: any) => any) | null = null
  try {
    jsQR = await getJsQR()
  } catch {
    jsQR = null // offline: ZXing / native detector only
  }
  let Z: any = null
  try {
    Z = await getZXing()
  } catch {
    Z = null
  }

  const t0 = performance.now()
  const deadline = t0 + 10000
  const tileDeadline = t0 + 6000 // tiles may use 6s at most, the rest is kept for rotated attempts
  for (let p = 0; p < pages.length; p++) {
    const c = pages[p]
    // upscale small photos: a QR printed on a 600px card is only ~60px wide
    const base = c.width < 1400 ? Math.min(4, 1800 / c.width) : 1
    const cand: [number, number, number, number, number][] = []
    cand.push([0, 0, c.width, c.height, base])
    if (base > 1.5) cand.push([0, 0, c.width, c.height, base * 1.5 > 5 ? 5 : base * 1.5])
    for (const f of [0.6, 0.4, 0.25]) {
      const tw = Math.round(c.width * f)
      const th = Math.round(c.height * f)
      const sx = Math.max(1, Math.round(tw * 0.5))
      const sy = Math.max(1, Math.round(th * 0.5))
      for (let y = 0; y + th <= c.height + 1; y += sy)
        for (let x = 0; x + tw <= c.width + 1; x += sx) {
          const w = Math.min(tw, c.width - x)
          const h = Math.min(th, c.height - y)
          const up = Math.max(1, Math.min(5, 900 / Math.max(w, h)))
          cand.push([x, y, w, h, up])
        }
    }
    let n = 0
    for (const [x, y, w, h, up] of cand) {
      if (performance.now() > tileDeadline) break // keep the 15 s triage budget
      const preps: Prep[] = n < 2 ? ['raw', 'contrast', 'binary'] : ['raw', 'binary']
      if (n++ % 10 === 0) {
        onProgress?.(`QR scan ${Math.min(99, Math.round((n / cand.length) * 100))}%`)
        await new Promise((r) => setTimeout(r, 0))
      }
      for (const prep of preps) {
        const img = prepared(c, x, y, w, h, up, prep)
        const hit = jsQR ? jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' }) : null
        if (hit?.data && hit.data.length > 8) return { text: hit.data as string, bytes: Uint8Array.from(hit.binaryData as number[]), page: p, engine: `jsQR/${prep}` }
        if (Z && prep !== 'binary') {
          const t = zxingDecode(Z, img)
          if (t && t.length > 8) return { text: t, bytes: enc.encode(t), page: p, engine: `ZXing/${prep}` }
        }
      }
    }
    // photo of a screen / tilted card: try small rotations of the whole page
    for (const deg of [-12, 12, -24, 24, -6, 6]) {
      if (performance.now() > deadline) return null
      onProgress?.(`QR scan (rotated ${deg}°)`)
      await new Promise((r) => setTimeout(r, 0))
      const rc = rotateCanvas(c, deg)
      const up = rc.width < 1400 ? Math.min(3, 1800 / rc.width) : 1
      for (const prep of ['raw', 'contrast', 'binary'] as Prep[]) {
        const img = prepared(rc, 0, 0, rc.width, rc.height, up, prep)
        const hit = jsQR ? jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' }) : null
        if (hit?.data && hit.data.length > 8) return { text: hit.data as string, bytes: Uint8Array.from(hit.binaryData as number[]), page: p, engine: `jsQR/rot${deg}` }
        if (Z && prep !== 'binary') {
          const t = zxingDecode(Z, img)
          if (t && t.length > 8) return { text: t, bytes: enc.encode(t), page: p, engine: `ZXing/rot${deg}` }
        }
      }
    }
  }
  return null
}

function rotateCanvas(src: HTMLCanvasElement, deg: number): HTMLCanvasElement {
  const rad = (deg * Math.PI) / 180
  const w = src.width
  const h = src.height
  const nw = Math.ceil(Math.abs(w * Math.cos(rad)) + Math.abs(h * Math.sin(rad)))
  const nh = Math.ceil(Math.abs(w * Math.sin(rad)) + Math.abs(h * Math.cos(rad)))
  const c = document.createElement('canvas')
  c.width = nw
  c.height = nh
  const ctx = c.getContext('2d')!
  ctx.fillStyle = '#fff'
  ctx.fillRect(0, 0, nw, nh)
  ctx.translate(nw / 2, nh / 2)
  ctx.rotate(rad)
  ctx.drawImage(src, -w / 2, -h / 2)
  return c
}

/* ============================================================
 * 4. AADHAAR: Verhoeff + Secure-QR decode + signature verify
 * ============================================================ */
const VD = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
const VP = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
export function verhoeffValid(num: string): boolean {
  if (!/^\d{12}$/.test(num) || num[0] === '0' || num[0] === '1') return false
  let c = 0
  const rev = num.split('').reverse().map(Number)
  for (let i = 0; i < rev.length; i++) c = VD[c][VP[i % 8][rev[i]]]
  return c === 0
}

export type AadhaarQr = {
  kind: 'secure' | 'legacy-xml'
  version: string
  fields: Record<string, string>
  refLast4: string
  signedData: Uint8Array | null
  signature: Uint8Array | null
  photoBytes: Uint8Array | null
  rawBytes: number
}

async function gunzip(b: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('gzip')
  const stream = new Blob([buf(b) as unknown as BlobPart]).stream().pipeThrough(ds)
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

function bigDecimalToBytes(dec: string): Uint8Array {
  let hex = BigInt(dec).toString(16)
  if (hex.length % 2) hex = '0' + hex
  return fromHex(hex)
}

const SECURE_FIELDS = ['referenceId', 'name', 'dob', 'gender', 'careOf', 'district', 'landmark', 'house', 'location', 'pincode', 'postOffice', 'state', 'street', 'subDistrict', 'vtc']

export async function decodeAadhaarQr(text: string): Promise<AadhaarQr | null> {
  const t = text.trim()
  if (/^\d{200,}$/.test(t)) {
    const packed = bigDecimalToBytes(t)
    const data = await gunzip(packed)
    const u8 = new TextDecoder('utf-8')
    const toks: string[] = []
    let p = 0
    while (p < data.length) {
      let q = p
      while (q < data.length && data[q] !== 255) q++
      toks.push(u8.decode(data.slice(p, q)))
      p = q + 1
      if (toks[0] === 'V2' ? toks.length === 17 : toks.length === 16) break
    }
    const isV2 = toks[0] === 'V2'
    // Some issuers emit an extra token (index / combine code) before referenceId, which shifts every field.
    // referenceId is the ONLY long pure-number token (14+ digits) at the start of the field list, so anchor on it.
    const bodyStart = toks.findIndex((s, i) => (isV2 ? i >= 2 : i >= 1) && /^\d{14,}$/.test(s))
    const ind = bodyStart > 0 ? toks[bodyStart - 1] : isV2 ? toks[1] : toks[0]
    const f = bodyStart >= 0 ? toks.slice(bodyStart) : isV2 ? toks.slice(2) : toks.slice(1)
    const fields: Record<string, string> = {}
    SECURE_FIELDS.forEach((k, i) => (fields[k] = (f[i] ?? '').trim()))
    const sig = data.slice(data.length - 256)
    const signedData = data.slice(0, data.length - 256)
    // photo (JPEG2000) starts at JP2 signature or codestream marker
    let ps = -1
    for (let i = p - 1; i < data.length - 12; i++) {
      if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 0 && data[i + 3] === 0x0c && data[i + 4] === 0x6a && data[i + 5] === 0x50) {
        ps = i
        break
      }
      if (data[i] === 0xff && data[i + 1] === 0x4f && data[i + 2] === 0xff && data[i + 3] === 0x51) {
        ps = i
        break
      }
    }
    const hashes = (ind === '1' || ind === '2' ? 32 : ind === '3' ? 64 : 0)
    const photo = ps >= 0 ? data.slice(ps, data.length - 256 - hashes) : null
    return {
      kind: 'secure',
      version: isV2 ? 'V2' : 'V1',
      fields,
      refLast4: (fields.referenceId || '').slice(0, 4),
      signedData,
      signature: sig,
      photoBytes: photo,
      rawBytes: packed.length,
    }
  }
  if (/<\?xml|<PrintLetterBarcodeData/i.test(t)) {
    const doc = new DOMParser().parseFromString(t, 'text/xml')
    const el = doc.getElementsByTagName('PrintLetterBarcodeData')[0] ?? doc.documentElement
    const fields: Record<string, string> = {}
    for (const a of Array.from(el.attributes)) fields[a.name] = a.value
    if (fields.uid) fields.referenceId = fields.uid
    if (fields.dob === undefined && fields.yob) fields.dob = fields.yob
    if (fields.gender) fields.gender = fields.gender.toUpperCase().startsWith('M') ? 'M' : fields.gender.toUpperCase().startsWith('F') ? 'F' : 'T'
    return { kind: 'legacy-xml', version: 'XML', fields, refLast4: (fields.uid || '').slice(-4), signedData: null, signature: null, photoBytes: null, rawBytes: t.length }
  }
  return null
}

export type SigCheck =
  /** RSA signature is valid AND the certificate is on the UIDAI trust list and currently valid: the only state that may be shown as "UIDAI verified" */
  | { state: 'verified'; certSubject: string; certNotAfter: string; certFp: string }
  /** RSA signature matches the loaded certificate, but that certificate is NOT authenticated as UIDAI's */
  | { state: 'valid-untrusted'; certSubject: string; certNotAfter: string; certFp: string; why: string }
  | { state: 'invalid'; reason: string; certTrusted: boolean }
  | { state: 'no-cert' }
  | { state: 'unsigned' }

export async function loadCertFile(file: File): Promise<{ info: CertInfo; der: Uint8Array }> {
  const der = certToDer(new Uint8Array(await file.arrayBuffer()))
  const info = parseCert(der)
  info.sha256 = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', buf(info.spki))))
  info.derSha256 = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', buf(der))))
  return { info, der }
}

export async function verifyAadhaarSignature(q: AadhaarQr, cert: CertInfo | null): Promise<SigCheck> {
  if (!q.signature || !q.signedData) return { state: 'unsigned' }
  if (!cert) return { state: 'no-cert' }
  const trust = assessCert(cert)
  try {
    const key = await crypto.subtle.importKey('spki', buf(cert.spki), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, buf(q.signature), buf(q.signedData))
    if (!ok)
      return { state: 'invalid', certTrusted: trust.state === 'trusted', reason: trust.state === 'trusted' ? 'RSA signature does not match the trusted UIDAI certificate: the QR data was altered or is not UIDAI-signed.' : `RSA signature does not match the loaded certificate. ${trust.reason} It may simply be the wrong certificate.` }
    return trust.state === 'trusted'
      ? { state: 'verified', certSubject: cert.subjectCN, certNotAfter: cert.notAfter, certFp: cert.sha256 ?? '' }
      : { state: 'valid-untrusted', certSubject: cert.subjectCN, certNotAfter: cert.notAfter, certFp: cert.sha256 ?? '', why: trust.reason }
  } catch (e: any) {
    return { state: 'invalid', certTrusted: false, reason: `Verification error: ${e?.message ?? e}` }
  }
}

/* ============================================================
 * 5. PDF EMBEDDED DIGITAL SIGNATURE (integrity check)
 * ============================================================ */
export type PdfSig = {
  present: boolean
  count: number
  digestOk: boolean | null // signed bytes hash == CMS messageDigest
  sigOk: boolean | null // RSA over signedAttrs verifies with embedded signer cert
  coversWholeFile: boolean | null
  signer: string
  issuer: string
  validTo: string
  detail: string
  /** certificate chain of the signer up to a pinned trusted root (revocation is NOT checked) */
  chain: ChainResult
}

const HASH_OIDS: Record<string, string> = {
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
}

export async function checkPdfSignature(bytes: Uint8Array, options: { aadhaarDocument?: boolean } = {}): Promise<PdfSig> {
  const empty: PdfSig = { present: false, count: 0, digestOk: null, sigOk: null, coversWholeFile: null, signer: '', issuer: '', validTo: '', detail: 'No embedded digital signature found.', chain: { state: 'none', detail: '', chain: [] } }
  const txt = new TextDecoder('latin1').decode(bytes)
  const re = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g
  const ranges: number[][] = []
  let m: RegExpExecArray | null
  while ((m = re.exec(txt))) ranges.push([+m[1], +m[2], +m[3], +m[4]])
  if (!ranges.length) return empty
  const [a, b, c, d] = ranges[ranges.length - 1]
  const out: PdfSig = { ...empty, present: true, count: ranges.length, detail: '' }
  try {
    const signed = new Uint8Array(b + d)
    signed.set(bytes.slice(a, a + b), 0)
    signed.set(bytes.slice(c, c + d), b)
    out.coversWholeFile = c + d === bytes.length || txt.slice(c + d).trim().length === 0
    const between = txt.slice(a + b, c)
    const hex = between.replace(/[<>\s]/g, '')
    const cms = fromHex(hex)
    const root = parseDer(cms, 0, cms.length)
    // ContentInfo -> [0] -> SignedData
    const sd = root.kids![1].kids![0]
    const kids = sd.kids!
    const certsNode = kids.find((k) => k.cls === 2 && k.tag === 0)
    const signerInfos = kids[kids.length - 1]
    const si = signerInfos.kids![0].kids!
    // si: version, sid, digestAlg, [0] signedAttrs, sigAlg, signature
    const digestAlgOid = oidOf(cms, si[2].kids![0])
    const hashName = HASH_OIDS[digestAlgOid]
    const attrsNode = si.find((k) => k.cls === 2 && k.tag === 0)
    const sigNode = si[si.length - 1]
    const signature = content(cms, sigNode)
    if (!hashName) {
      out.detail = `Unsupported digest algorithm ${digestAlgOid}.`
      return out
    }
    const docHash = new Uint8Array(await crypto.subtle.digest(hashName, buf(signed)))
    // messageDigest attribute
    let md: Uint8Array | null = null
    if (attrsNode) {
      for (const attr of attrsNode.kids!) {
        if (oidOf(cms, attr.kids![0]) === '1.2.840.113549.1.9.4') md = content(cms, attr.kids![1].kids![0])
      }
    }
    out.digestOk = md ? toHex(md) === toHex(docHash) : null
    // signer certificate(s)
    const certs: Uint8Array[] = (certsNode?.kids ?? []).map((n) => raw(cms, n))
    if (certs.length && attrsNode) {
      const attrsDer = raw(cms, attrsNode)
      const toBeSigned = attrsDer.slice()
      toBeSigned[0] = 0x31 // [0] IMPLICIT -> SET OF for hashing
      let verified = false
      for (const der of certs) {
        try {
          const info = parseCert(der)
          const key = await crypto.subtle.importKey('spki', buf(info.spki), { name: 'RSASSA-PKCS1-v1_5', hash: hashName }, false, ['verify'])
          if (await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, buf(signature), buf(toBeSigned))) {
            verified = true
            out.signer = info.subjectCN
            out.issuer = info.issuerCN
            out.validTo = info.notAfter
            break
          }
        } catch {
          /* try next cert */
        }
      }
      out.sigOk = verified
      if (!verified && certs[0]) {
        const info = parseCert(certs[0])
        out.signer = info.subjectCN
        out.issuer = info.issuerCN
        out.validTo = info.notAfter
      }
    }
    try {
      const signerPins = options.aadhaarDocument ? AADHAAR_PDF_SIGNER_PINS : []
      out.chain = await verifyChain(certs, undefined, out.signer, signerPins)
    } catch (e: any) {
      out.chain = { state: 'incomplete', detail: `Chain check failed: ${e?.message ?? e}`, chain: [] }
    }
    out.detail = [
      out.digestOk === false ? 'Document content changed after signing (hash mismatch).' : '',
      out.sigOk === false ? 'Signer RSA signature invalid.' : '',
      out.coversWholeFile === false ? 'Extra data appended after signature (incremental update).' : '',
      out.digestOk && out.sigOk && out.coversWholeFile ? `Content hash and signer signature verify. Chain: ${out.chain.detail} Revocation (CRL/OCSP) is not checked offline.` : '',
    ].filter(Boolean).join(' ')
  } catch (e: any) {
    out.detail = `Signature container could not be parsed: ${e?.message ?? e}`
  }
  return out
}

/* ============================================================
 * 6. OCR + FIELD EXTRACTION
 *    Order of trust:  PDF text layer  >  line-level OCR re-read  >  page OCR
 * ============================================================ */
export type Printed = {
  rawText: string
  aadhaarNo: string
  aadhaarCandidates: string[] // every 12-digit number the OCR passes produced
  name: string
  fatherName: string
  dob: string // DD-MM-YYYY or YYYY
  gender: string // M/F/T
  pincode: string
  pan: string
  panKeyword: boolean // the card says "Income Tax / Permanent Account" even if no valid PAN could be read
  dl: string
  dlKeyword: boolean
  epic: string
  epicKeyword: boolean
  aadhaarKeyword: boolean // text says Aadhaar / UIDAI even if the 12-digit number itself could not be read
  mrz: { line1: string; line2: string; line3?: string; kind: 'TD3' | 'TD1' } | null
  words: OcrWord[] // normalised boxes on page 1 (used to name the edited field)
  confidence: number // mean OCR confidence 0..100
  source: 'text-layer' | 'ocr' | 'text-layer+ocr'
}

function cropCanvas(c: HTMLCanvasElement, y0: number, y1: number): HTMLCanvasElement {
  const t = document.createElement('canvas')
  const h = Math.max(8, Math.round(c.height * (y1 - y0)))
  t.width = c.width
  t.height = h
  t.getContext('2d')!.drawImage(c, 0, Math.round(c.height * y0), c.width, h, 0, 0, c.width, h)
  return t
}

/** Upscale (small phone photos / webp cards), grayscale and stretch contrast: OCR needs ~30px tall glyphs. */
function prepForOcr(c: HTMLCanvasElement): HTMLCanvasElement {
  const target = Math.max(2200, Math.min(3200, c.width * 3))
  const s = c.width < target ? target / c.width : 1
  const t = document.createElement('canvas')
  t.width = Math.round(c.width * s)
  t.height = Math.round(c.height * s)
  const ctx = t.getContext('2d', { willReadFrequently: true })!
  ctx.imageSmoothingEnabled = true
  ctx.imageSmoothingQuality = 'high'
  ctx.fillStyle = '#fff'
  ctx.fillRect(0, 0, t.width, t.height)
  ctx.drawImage(c, 0, 0, t.width, t.height)
  const img = ctx.getImageData(0, 0, t.width, t.height)
  const d = img.data
  const n = t.width * t.height
  const hist = new Array(256).fill(0)
  const g = new Uint8ClampedArray(n)
  for (let i = 0; i < n; i++) {
    g[i] = (d[i * 4] * 299 + d[i * 4 + 1] * 587 + d[i * 4 + 2] * 114) / 1000
    hist[g[i]]++
  }
  let lo = 0
  let hi = 255
  let acc = 0
  for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc > n * 0.01) { lo = v; break } }
  acc = 0
  for (let v = 255; v >= 0; v--) { acc += hist[v]; if (acc > n * 0.01) { hi = v; break } }
  const span = Math.max(40, hi - lo)
  for (let i = 0; i < n; i++) {
    const v = Math.max(0, Math.min(255, ((g[i] - lo) * 255) / span))
    d[i * 4] = d[i * 4 + 1] = d[i * 4 + 2] = v
  }
  ctx.putImageData(img, 0, 0)
  return t
}

function cleanMrzLine(s: string) {
  return s.toUpperCase().replace(/[\s]/g, '').replace(/[«‹〈]/g, '<').replace(/[^A-Z0-9<]/g, '')
}

/** OCR repair: inside a numeric MRZ slot, letters that look like digits are turned into digits. */
const MRZ_D: Record<string, string> = { O: '0', Q: '0', D: '0', I: '1', L: '1', S: '5', B: '8', Z: '2', G: '6' }
const mrzDigits = (s: string) => s.replace(/[A-Z]/g, (c) => MRZ_D[c] ?? c)

/**
 * STRICT structure test. Plain text (an address, a paragraph) never passes: a real MRZ has fixed
 * length lines, digits only at fixed positions and a lot of '<' filler. Earlier versions accepted any
 * 30+ character line containing '<', so address text read through a letters-only OCR whitelist became
 * a fake "MRZ" and produced "MRZ checksum FAILED" on genuine Aadhaar cards.
 */
function td3Line2(l: string): string | null {
  if (l.length < 42 || l.length > 46) return null
  const x = l.padEnd(44, '<').slice(0, 44)
  const fixed = x.slice(0, 9) + mrzDigits(x.slice(9, 10)) + x.slice(10, 13) + mrzDigits(x.slice(13, 20)) + x.slice(20, 21) + mrzDigits(x.slice(21, 28)) + x.slice(28, 42) + mrzDigits(x.slice(42, 44))
  return /^[A-Z0-9<]{9}\d[A-Z<]{3}\d{7}[MF<]\d{7}[A-Z0-9<]{14}\d{2}$/.test(fixed) ? fixed : null
}
function td1Line2(l: string): string | null {
  if (l.length < 28 || l.length > 32) return null
  const x = l.padEnd(30, '<').slice(0, 30)
  const fixed = mrzDigits(x.slice(0, 7)) + x.slice(7, 8) + mrzDigits(x.slice(8, 15)) + x.slice(15, 18) + x.slice(18, 29) + mrzDigits(x.slice(29, 30))
  return /^\d{7}[MF<]\d{7}[A-Z<]{3}[A-Z0-9<]{11}\d$/.test(fixed) ? fixed : null
}
const fillerRatio = (l: string) => (l.match(/</g) ?? []).length / Math.max(1, l.length)

export function findMrz(text: string): Printed['mrz'] {
  const lines = text.split('\n').map(cleanMrzLine).filter((l) => l.length >= 28 && l.includes('<'))
  for (let i = 0; i < lines.length - 1; i++) {
    const a = lines[i]
    const b = lines[i + 1]
    if (/^P[A-Z<][A-Z<]{3}/.test(a) && a.length >= 40 && a.length <= 46 && a.includes('<<') && fillerRatio(a) >= 0.12) {
      const l2 = td3Line2(b)
      if (l2) return { kind: 'TD3', line1: a.padEnd(44, '<').slice(0, 44), line2: l2 }
    }
  }
  for (let i = 0; i < lines.length - 2; i++) {
    const a = lines[i]
    const l2 = td1Line2(lines[i + 1])
    const c = lines[i + 2]
    if (l2 && /^[ACI][A-Z<][A-Z<]{3}/.test(a) && a.length >= 28 && a.length <= 32 && c.length >= 28 && c.length <= 32 && c.includes('<<'))
      return { kind: 'TD1', line1: a.padEnd(30, '<').slice(0, 30), line2: l2, line3: c.padEnd(30, '<').slice(0, 30) }
  }
  return null
}

/** Obvious dummy numbers (sequential / repeated) can never be issued as real Aadhaar numbers by UIDAI. */
export function dummyAadhaarPattern(n: string): string | null {
  if (!/^\d{12}$/.test(n)) return null
  let run = 1
  let best = 1
  for (let i = 1; i < n.length; i++) {
    const up = (+n[i] - +n[i - 1] + 10) % 10 === 1
    const down = (+n[i - 1] - +n[i] + 10) % 10 === 1
    run = up || down ? run + 1 : 1
    best = Math.max(best, run)
  }
  if (best >= 7) return `sequential digits (${best} in a row)`
  if (/(\d)\1{5,}/.test(n)) return 'one digit repeated 6+ times'
  if (new Set(n.split('')).size <= 3) return 'only 3 distinct digits'
  return null
}

const NOT_NAME = /(government|govt|india|unique|identification|authority|aadhaar|aadhar|enrolment|enrollment|address|s\/o|d\/o|w\/o|c\/o|male|female|transgender|dob|birth|download|issue|vid|help|uidai|www|gov\.in|colony|road|street|nagar|district|state|pin|proof|citizenship|authentication|verification|scanning|offline|online|income|tax|department|permanent|account|number|signature|father|mother|card|licence|license|driving|election|commission|elector|photo|identity|valid|date|issued|space|mera|meri|pehchan)/i

const DATE_RE = /\b(\d{2})[\/\-.](\d{2})[\/\-.]((?:19|20)\d{2})\b/g
const DOB_LABEL = /(DOB|D\.O\.B|Date of Birth|Year of Birth|जन्म)/i
const GENDER_LINE = /^\W*(?:[^A-Za-z]*\/\s*)?(male|female|transgender)\W*$/i

/** Parse a block of text (PDF text layer OR OCR output) into fields. */
export function extractPrinted(text: string): Omit<Printed, 'mrz' | 'words' | 'confidence' | 'aadhaarCandidates' | 'source' | 'aadhaarKeyword'> {
  const flat = text.replace(/[|]/g, ' ')
  const nums = flat.match(/\b\d{4}\s?\d{4}\s?\d{4}\b/g) ?? []
  const candidates = nums.map((n) => n.replace(/\s/g, ''))
  const aadhaarNo = candidates.find(verhoeffValid) ?? candidates[0] ?? ''

  /* ----- DOB: labelled first, then unlabelled dates that are NOT issue / download dates ----- */
  let dob = ''
  const d1 = flat.match(/(?:DOB|D\.O\.B|Date of Birth|जन्म[^\n]{0,12}?)[^0-9\n]{0,20}(\d{2})[\/\-.](\d{2})[\/\-.](\d{4})/i)
  if (d1) dob = `${d1[1]}-${d1[2]}-${d1[3]}`
  else {
    for (const m of flat.matchAll(DATE_RE)) {
      const before = flat.slice(Math.max(0, m.index! - 24), m.index!)
      if (/(issued|issue|download|generated|date\s*:|valid|expiry|expires|from)/i.test(before)) continue
      dob = `${m[1]}-${m[2]}-${m[3]}`
      break
    }
    if (!dob) {
      const y = flat.match(/Year of Birth[^0-9]{0,10}(\d{4})/i)
      if (y) dob = y[1]
    }
  }

  let gender = ''
  if (/\bFEMALE\b/i.test(flat)) gender = 'F'
  else if (/\bMALE\b/i.test(flat)) gender = 'M'
  else if (/TRANSGENDER/i.test(flat)) gender = 'T'

  const pin = flat.match(/(?:PIN\s*Code|Pincode|PIN)[^0-9]{0,6}(\d{6})/i) ?? flat.match(/\b([1-9]\d{5})\b/)

  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean)
  const latinCount = (l: string) => (l.match(/[A-Za-z]/g) ?? []).length
  const nameOk = (raw: string, single: boolean) => {
    if (NOT_NAME.test(raw)) return ''
    return plausibleName(raw, single)
  }

  let name = ''
  let fatherName = ''

  // 1) explicit "Name: X" label (PAN, DL, voter ID)
  for (let i = 0; i < lines.length && !name; i++) {
    const m = lines[i].match(/^(?:.*\/\s*)?Name\s*[:\-]?\s*(.*)$/i)
    if (m && !/father|mother|husband|spouse/i.test(lines[i])) {
      const same = m[1] ? nameOk(m[1], true) : ''
      const next = !same && lines[i + 1] ? nameOk(lines[i + 1], true) : ''
      name = same || next
    }
  }
  const fm = flat.match(/Father'?s?\s*Name\s*[:\-]?\s*\n?\s*([A-Za-z .]{3,40})/i)
  if (fm) fatherName = plausibleName(fm[1].split('\n')[0], true)

  // 2) e-Aadhaar letter: "To,\nName\nS/O ..."
  if (!name) {
    const to = lines.findIndex((l) => /^to\W*$/i.test(l))
    if (to >= 0) for (let i = to + 1; i <= to + 3 && i < lines.length && !name; i++) name = nameOk(lines[i], true)
  }

  // 3) the line(s) right above DOB / gender (card layout). Single-word names (e.g. "Sumit") are allowed here.
  if (!name) {
    const anchor = lines.findIndex((l) => DOB_LABEL.test(l) || GENDER_LINE.test(l) || (l.match(DATE_RE) && latinCount(l) < 4))
    if (anchor > 0)
      for (let i = anchor - 1; i >= 0 && i >= anchor - 4 && !name; i--) {
        if (latinCount(lines[i]) < 3) continue // Hindi twin of the name
        name = nameOk(lines[i], true)
      }
  }
  // 4) last resort: first multi-word plausible line anywhere (single words are too risky here)
  if (!name) for (const l of lines) { name = nameOk(l, false); if (name) break }

  const pan = findPan(flat)
  const dl = findDl(flat)
  const epic = findEpic(flat)
  return {
    rawText: text,
    aadhaarNo,
    name,
    fatherName,
    dob,
    gender,
    pincode: pin?.[1] ?? '',
    pan,
    panKeyword: hasPanKeywords(flat),
    dl,
    dlKeyword: hasDlKeywords(flat),
    epic,
    epicKeyword: hasEpicKeywords(flat),
  }
}

function wordsOf(data: any, W: number, H: number): OcrWord[] {
  let raw: any[] = data?.words ?? []
  if (!raw.length && data?.blocks) {
    for (const b of data.blocks) for (const p of b.paragraphs ?? []) for (const l of p.lines ?? []) for (const w of l.words ?? []) raw.push(w)
  }
  return raw
    .filter((w) => w?.text && w?.bbox)
    .map((w) => ({ text: String(w.text).trim(), x0: w.bbox.x0 / W, y0: w.bbox.y0 / H, x1: w.bbox.x1 / W, y1: w.bbox.y1 / H, conf: w.confidence ?? 0 }))
    .filter((w) => w.text)
}

type WLine = { text: string; x0: number; y0: number; x1: number; y1: number; conf: number }
function linesFromWords(words: OcrWord[]): WLine[] {
  const sorted = [...words].sort((a, b) => (a.y0 + a.y1) / 2 - (b.y0 + b.y1) / 2)
  const out: { ws: OcrWord[]; yc: number; h: number }[] = []
  for (const w of sorted) {
    const yc = (w.y0 + w.y1) / 2
    const h = w.y1 - w.y0
    const line = out.find((l) => Math.abs(l.yc - yc) < Math.max(l.h, h) * 0.55)
    if (line) {
      line.ws.push(w)
      line.yc = (line.yc * (line.ws.length - 1) + yc) / line.ws.length
      line.h = Math.max(line.h, h)
    } else out.push({ ws: [w], yc, h })
  }
  return out
    .map((l) => {
      const ws = l.ws.sort((a, b) => a.x0 - b.x0)
      return {
        text: ws.map((w) => w.text).join(' '),
        x0: Math.min(...ws.map((w) => w.x0)),
        y0: Math.min(...ws.map((w) => w.y0)),
        x1: Math.max(...ws.map((w) => w.x1)),
        y1: Math.max(...ws.map((w) => w.y1)),
        conf: ws.reduce((s, w) => s + w.conf, 0) / ws.length,
      }
    })
    .sort((a, b) => a.y0 - b.y0)
}

/** Re-read ONE text line on its own (tight crop, letters-only, single-line mode). Fixes garbage names from page-level OCR. */
async function reReadNameLine(worker: any, page: HTMLCanvasElement, words: OcrWord[]): Promise<string> {
  const lines = linesFromWords(words)
  const anchor = lines.findIndex((l) => DOB_LABEL.test(l.text) || GENDER_LINE.test(l.text) || (l.text.match(DATE_RE) && (l.text.match(/[A-Za-z]/g) ?? []).length < 8))
  const pool: WLine[] = []
  if (anchor > 0) for (let i = anchor - 1; i >= 0 && i >= anchor - 4; i--) pool.push(lines[i])
  const labelled = lines.findIndex((l) => /^\W*(name|to)\W*$/i.test(l.text))
  if (labelled >= 0 && lines[labelled + 1]) pool.push(lines[labelled + 1])
  for (const l of pool) {
    if ((l.text.match(/[A-Za-z]/g) ?? []).length < 3 || NOT_NAME.test(l.text)) continue
    const padY = (l.y1 - l.y0) * 0.35
    const sx = Math.max(0, Math.floor((l.x0 - 0.01) * page.width))
    const sy = Math.max(0, Math.floor((l.y0 - padY) * page.height))
    const sw = Math.min(page.width - sx, Math.ceil((l.x1 - l.x0 + 0.02) * page.width))
    const sh = Math.min(page.height - sy, Math.ceil((l.y1 - l.y0 + 2 * padY) * page.height))
    if (sw < 20 || sh < 10) continue
    const up = sh < 70 ? 2 : 1
    const t = document.createElement('canvas')
    t.width = sw * up
    t.height = sh * up
    const ctx = t.getContext('2d')!
    ctx.fillStyle = '#fff'
    ctx.fillRect(0, 0, t.width, t.height)
    ctx.drawImage(page, sx, sy, sw, sh, 0, 0, t.width, t.height)
    await worker.setParameters({ tessedit_char_whitelist: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz .', tessedit_pageseg_mode: '7' })
    const { data } = await worker.recognize(t)
    const n = plausibleName(String(data.text ?? '').trim(), true)
    if (n && (data.confidence ?? 0) >= 45) return n
  }
  return ''
}

const mergeField = (a: string, b: string) => a || b

export async function ocrDocument(pages: HTMLCanvasElement[], onProgress?: (s: string) => void, textLayer = ''): Promise<Printed> {
  const worker = await getOcr()
  const haveText = textLayer.replace(/\s/g, '').length >= 60
  let all = ''
  let words: OcrWord[] = []
  let confSum = 0
  let confN = 0
  const prepped: HTMLCanvasElement[] = []
  // PDF with a real text layer: the text is EXACT (no OCR guessing). One light OCR pass on page 1 only,
  // just to place words / confidence — the slow extra passes (sparse, digit-only, MRZ zone) are skipped.
  const textOnly = haveText && pages.length > 0
  for (let i = 0; i < Math.min(textOnly ? 1 : haveText ? 1 : 2, pages.length); i++) {
    onProgress?.(`OCR page ${i + 1} (upscaled)`)
    const pc = prepForOcr(pages[i])
    prepped.push(pc)
    await worker.setParameters({ tessedit_char_whitelist: '', tessedit_pageseg_mode: textOnly ? '6' : '3' })
    const { data } = await worker.recognize(pc)
    all += '\n' + data.text
    if (i === 0) words = wordsOf(data, pc.width, pc.height)
    if (typeof data.confidence === 'number') { confSum += data.confidence; confN++ }
  }
  // second layout pass (sparse text) finds small isolated fields that block layout misses (skipped when the PDF already has real text)
  if (prepped[0] && !haveText) {
    onProgress?.('OCR sparse-text pass')
    await worker.setParameters({ tessedit_char_whitelist: '', tessedit_pageseg_mode: '11' })
    const { data } = await worker.recognize(prepped[0])
    all += '\n' + data.text
    const extra = wordsOf(data, prepped[0].width, prepped[0].height)
    const have = new Set(words.map((w) => `${w.text}@${Math.round(w.x0 * 50)},${Math.round(w.y0 * 50)}`))
    for (const w of extra) if (!have.has(`${w.text}@${Math.round(w.x0 * 50)},${Math.round(w.y0 * 50)}`)) words.push(w)
  }

  const fromText = haveText ? extractPrinted(textLayer) : null
  const fromOcr = extractPrinted(all)
  const base = fromText
    ? {
        ...fromOcr,
        aadhaarNo: fromText.aadhaarNo || fromOcr.aadhaarNo,
        name: mergeField(fromText.name, fromOcr.name),
        fatherName: mergeField(fromText.fatherName, fromOcr.fatherName),
        dob: mergeField(fromText.dob, fromOcr.dob),
        gender: mergeField(fromText.gender, fromOcr.gender),
        pincode: mergeField(fromText.pincode, fromOcr.pincode),
        pan: mergeField(fromText.pan, fromOcr.pan),
        panKeyword: fromText.panKeyword || fromOcr.panKeyword,
        dl: mergeField(fromText.dl, fromOcr.dl),
        dlKeyword: fromText.dlKeyword || fromOcr.dlKeyword,
        epic: mergeField(fromText.epic, fromOcr.epic),
        epicKeyword: fromText.epicKeyword || fromOcr.epicKeyword,
        rawText: textLayer + '\n' + all,
      }
    : fromOcr

  // OCR-only name: verify it with a tight single-line re-read. Reject it if neither reading is plausible (never show garbage).
  // Skipped for PDFs with a text layer: the text there is exact, re-reading cannot improve it.
  if (!fromText?.name && !textOnly) {
    onProgress?.('Re-reading name line')
    let nm = ''
    try {
      if (prepped[0]) nm = await reReadNameLine(worker, prepped[0], words)
    } catch {
      nm = ''
    }
    if (nm) base.name = nm
    else if (base.name) {
      // page OCR gave something: keep it only if its own words were read confidently
      const toks = base.name.toLowerCase().split(' ')
      const hit = words.filter((w) => toks.includes(w.text.toLowerCase().replace(/[^a-z]/g, '')))
      const conf = hit.length ? hit.reduce((a, w) => a + w.conf, 0) / hit.length : 0
      if (conf < 60) base.name = ''
    }
  }

  const cands = new Set<string>((base.rawText.replace(/[|]/g, ' ').match(/\b\d{4}\s?\d{4}\s?\d{4}\b/g) ?? []).map((n) => n.replace(/\s/g, '')))

  // digit-only pass on the lower half: Aadhaar number lives there. Several candidates protect against single-digit misreads.
  // Skipped when the exact text layer already provided the number (PDF input).
  if (prepped[0] && !textOnly && !base.pan && !base.dl && !base.epic && ![...cands].some(verhoeffValid)) {
    onProgress?.('Digit-only OCR pass')
    await worker.setParameters({ tessedit_char_whitelist: '0123456789 ', tessedit_pageseg_mode: '6' })
    for (const crop of [cropCanvas(prepped[0], 0.45, 1), cropCanvas(prepped[0], 0.6, 0.95), prepped[0]]) {
      const { data } = await worker.recognize(crop)
      for (const m of data.text.match(/\b\d{4}\s?\d{4}\s?\d{4}\b/g) ?? []) cands.add(m.replace(/\s/g, ''))
    }
  }
  const aadhaarCandidates = [...cands]
  const aadhaarNo = aadhaarCandidates.find(verhoeffValid) ?? (base.aadhaarNo || aadhaarCandidates[0] || '')

  const aadhaarKeyword = /(aadhaar|aadhar|uidai|unique\s+identification|enrol?ment\s+no|आधार|भारतीय\s+विशिष्ट)/i.test(base.rawText)
  // an Indian ID is never a passport: do not even look for an MRZ on it
  const indianId = aadhaarKeyword || !!aadhaarNo || !!base.pan || base.panKeyword || !!base.dl || base.dlKeyword || !!base.epic || base.epicKeyword
  let mrz = indianId ? null : findMrz(base.rawText)
  if (!mrz && !indianId && !textOnly) {
    onProgress?.('MRZ zone OCR')
    await worker.setParameters({ tessedit_char_whitelist: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<', tessedit_pageseg_mode: '6' })
    for (const p of pages.slice(0, 2)) {
      const { data } = await worker.recognize(cropCanvas(p, 0.62, 1))
      mrz = findMrz(data.text)
      if (mrz) break
    }
  }
  await worker.setParameters({ tessedit_char_whitelist: '', tessedit_pageseg_mode: '3' })
  return { ...base, aadhaarNo, aadhaarKeyword, aadhaarCandidates, mrz, words, confidence: confN ? confSum / confN : 0, source: haveText ? (all.trim() ? 'text-layer+ocr' : 'text-layer') : 'ocr' }
}

export function mrzFor(mrz: NonNullable<Printed['mrz']>): MrzField[] {
  return mrz.kind === 'TD3' ? validateTD3(mrz.line2) : validateTD1(mrz.line1, mrz.line2)
}

/* ============================================================
 * 7. TEXT COMPARISON
 * ============================================================ */
export function lev(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)])
  for (let j = 1; j <= b.length; j++) dp[0][j] = j
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
  return dp[a.length][b.length]
}
export type Cmp = 'match' | 'fuzzy' | 'mismatch' | 'unread'
export function cmpText(qr: string, printed: string): Cmp {
  const A = qr.toUpperCase().replace(/[^A-Z0-9]/g, '')
  const B = printed.toUpperCase().replace(/[^A-Z0-9]/g, '')
  if (!B) return 'unread'
  if (A === B) return 'match'
  const sim = 1 - lev(A, B) / Math.max(A.length, B.length, 1)
  return sim >= 0.82 ? 'fuzzy' : 'mismatch'
}

/* ============================================================
 * 8. QR <-> PRINTED CROSS-CHECK (shared by Triage and QR tab)
 * ============================================================ */
export type Row = { label: string; qr: string; printed: string; res: Cmp }

const digitsOnly = (s: string) => s.replace(/\D/g, '')
function cmpDob(qr: string, printed: string): Cmp {
  const a = digitsOnly(qr)
  const b = digitsOnly(printed)
  if (!b) return 'unread'
  if (b.length === 4) return a.endsWith(b) || a.startsWith(b) ? 'match' : 'mismatch'
  // QR may be DD-MM-YYYY or YYYY-MM-DD: compare as sets of the same digits in either order
  const flip = (x: string) => (x.length === 8 ? x.slice(4) + x.slice(2, 4) + x.slice(0, 2) : x)
  if (a === b || flip(a) === b) return 'match'
  return a.length === b.length && a.split('').filter((c, i) => c !== b[i]).length <= 1 ? 'fuzzy' : 'mismatch'
}

export function buildQrRows(aadhaar: AadhaarQr, printed: Printed | null | undefined): Row[] {
  const f = aadhaar.fields
  const pinInText = f.pincode && printed ? printed.rawText.replace(/\s/g, '').includes(f.pincode) : false
  return [
    { label: 'Name', qr: f.name || '—', printed: printed?.name || '', res: cmpText(f.name || '', printed?.name || '') },
    { label: 'Date of Birth', qr: f.dob || '—', printed: printed?.dob || '', res: cmpDob(f.dob || '', printed?.dob || '') },
    { label: 'Gender', qr: f.gender || '—', printed: printed?.gender || '', res: printed?.gender ? (f.gender?.toUpperCase().startsWith(printed.gender) ? 'match' : 'mismatch') : 'unread' },
    {
      label: 'Aadhaar last 4',
      qr: aadhaar.refLast4 || '—',
      printed: printed?.aadhaarNo ? printed.aadhaarNo.slice(-4) : '',
      res: printed?.aadhaarNo ? (printed.aadhaarNo.slice(-4) === aadhaar.refLast4 ? 'match' : 'mismatch') : 'unread',
    },
    { label: 'PIN code', qr: f.pincode || '—', printed: pinInText ? f.pincode : printed?.pincode || '', res: !printed ? 'unread' : pinInText ? 'match' : printed.pincode ? 'mismatch' : 'unread' },
  ]
}

export const CERT_KEY = 'verisight.uidai.cert'
export async function getStoredCert(): Promise<CertInfo | null> {
  try {
    const b64 = localStorage.getItem(CERT_KEY)
    if (!b64) return null
    const info = parseCert(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)))
    info.sha256 = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', buf(info.spki))))
    return info
  } catch {
    return null
  }
}
