/* ============================================================
 * METADATA / SOURCE ANALYSIS
 *  - What produced this file?  camera photo | scanner | screenshot | PDF | unknown
 *  - Is there a declared AI-generation marker (C2PA, IPTC DigitalSourceType, SD/Midjourney text chunks...)?
 *  - Was an image/PDF editor named in the metadata FIELDS (not just anywhere in the bytes)?
 *  - PDF: producer, creator, creation vs modification date, incremental updates after signing.
 *
 * Honest limits: absence of metadata proves nothing (WhatsApp / screenshots strip it). Only a
 * POSITIVE marker (AI tag, editor name, modified-after-created) is used as evidence.
 * ============================================================ */

export type SourceKind = 'camera-photo' | 'screenshot-or-export' | 'pdf' | 'unknown-image'

export type Meta = {
  format: 'jpeg' | 'png' | 'webp' | 'pdf' | 'tiff' | 'other'
  source: SourceKind
  /** pixel forensics (ELA / noise) are only trustworthy on an untouched camera / scanner JPEG */
  pixelForensicsReliable: boolean
  camera: string
  software: string
  exifDate: string
  hasExif: boolean
  aiMarkers: string[]
  c2pa: boolean
  editorTags: string[]
  pdfProducer: string
  pdfCreator: string
  pdfCreated: string
  pdfModified: string
  pdfRevisions: number
  pdfModifiedAfterCreation: boolean
  notes: string[]
}

const EDITOR_NAMES = [
  'Photoshop', 'GIMP', 'Canva', 'Picsart', 'PicsArt', 'Snapseed', 'Lightroom', 'Paint.NET', 'PhotoScape', 'Pixlr', 'Fotor',
  'Affinity', 'Illustrator', 'CorelDRAW', 'Inkscape', 'Krita', 'Figma', 'iLovePDF', 'Smallpdf', 'Sejda', 'PDFescape',
  'PDF-XChange Editor', 'Foxit PhantomPDF', 'Nitro Pro', 'Adobe Acrobat Pro', 'Microsoft Word', 'LibreOffice', 'WPS', 'Pixelmator', 'Remove.bg', 'PhotoRoom',
]

const AI_PATTERNS: [RegExp, string][] = [
  [/trainedAlgorithmicMedia/i, 'IPTC DigitalSourceType = AI generated'],
  [/compositeWithTrainedAlgorithmicMedia/i, 'IPTC DigitalSourceType = AI composite'],
  [/Stable\s?Diffusion/i, 'Stable Diffusion'],
  [/Midjourney/i, 'Midjourney'],
  [/DALL[\s\-·.]?E/i, 'DALL·E'],
  [/Adobe\s+Firefly/i, 'Adobe Firefly'],
  [/ComfyUI|Automatic1111|InvokeAI/i, 'Stable Diffusion UI'],
  [/Gemini|NovelAI|Leonardo\.?Ai|Ideogram|ImageFX|Imagen\s?\d?|Nano\s?Banana/i, 'AI image tool'],
  [/Steps:\s?\d+,\s?Sampler:/i, 'Stable Diffusion generation parameters'],
  [/\bOpenAI\b|ChatGPT|GPT-?4o/i, 'OpenAI generation tag'],
  [/Made with Google AI|Generated with Google AI|SynthID/i, 'Google AI / SynthID tag'],
]

const u16 = (b: Uint8Array, o: number, le: boolean) => (le ? b[o] | (b[o + 1] << 8) : (b[o] << 8) | b[o + 1])
const u32 = (b: Uint8Array, o: number, le: boolean) => (le ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0)

type Exif = { make: string; model: string; software: string; date: string }

/** Minimal EXIF reader (IFD0 + Exif IFD). Returns null when the JPEG has no EXIF. */
function readExif(b: Uint8Array): Exif | null {
  if (b[0] !== 0xff || b[1] !== 0xd8) return null
  let p = 2
  while (p + 4 < b.length && p < 200_000) {
    if (b[p] !== 0xff) break
    const m = b[p + 1]
    const len = (b[p + 2] << 8) | b[p + 3]
    if (m === 0xe1 && b[p + 4] === 0x45 && b[p + 5] === 0x78 && b[p + 6] === 0x69 && b[p + 7] === 0x66) {
      const t = p + 10 // TIFF header
      const le = b[t] === 0x49
      const ifd0 = t + u32(b, t + 4, le)
      const out: Exif = { make: '', model: '', software: '', date: '' }
      const str = (o: number, n: number, cnt: number) => {
        const at = cnt <= 4 ? o : t + u32(b, o, le)
        return new TextDecoder('latin1').decode(b.slice(at, at + Math.min(n, 120))).replace(/\0[\s\S]*$/, '').trim()
      }
      const walk = (ifd: number, depth: number) => {
        if (ifd + 2 > b.length || depth > 2) return
        const n = u16(b, ifd, le)
        for (let i = 0; i < Math.min(n, 60); i++) {
          const e = ifd + 2 + i * 12
          const tag = u16(b, e, le)
          const cnt = u32(b, e + 4, le)
          const valOff = e + 8
          if (tag === 0x010f) out.make = str(valOff, cnt, cnt)
          else if (tag === 0x0110) out.model = str(valOff, cnt, cnt)
          else if (tag === 0x0131) out.software = str(valOff, cnt, cnt)
          else if (tag === 0x9003 || (tag === 0x0132 && !out.date)) out.date = str(valOff, cnt, cnt)
          else if (tag === 0x8769) walk(t + u32(b, valOff, le), depth + 1)
        }
      }
      try {
        walk(ifd0, 0)
      } catch {
        /* truncated EXIF */
      }
      return out
    }
    if (m === 0xda) break
    p += 2 + len
  }
  return null
}

function pdfDate(s: string): string {
  const m = s.match(/D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?/)
  return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4] ?? '00'}:${m[5] ?? '00'}:${m[6] ?? '00'}` : ''
}

export function analyzeMetadata(bytes: Uint8Array, mime: string, name: string): Meta {
  const isPdf = bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46
  const isJpeg = bytes[0] === 0xff && bytes[1] === 0xd8
  const isPng = bytes[0] === 0x89 && bytes[1] === 0x50
  const isWebp = bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[8] === 0x57
  const isTiff = (bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2a) || (bytes[0] === 0x4d && bytes[1] === 0x4d && bytes[3] === 0x2a)
  const format: Meta['format'] = isPdf ? 'pdf' : isJpeg ? 'jpeg' : isPng ? 'png' : isWebp ? 'webp' : isTiff ? 'tiff' : /pdf/i.test(mime + name) ? 'pdf' : 'other'

  const meta: Meta = {
    format, source: isPdf ? 'pdf' : 'unknown-image', pixelForensicsReliable: false, camera: '', software: '', exifDate: '', hasExif: false,
    aiMarkers: [], c2pa: false, editorTags: [], pdfProducer: '', pdfCreator: '', pdfCreated: '', pdfModified: '', pdfRevisions: 0, pdfModifiedAfterCreation: false, notes: [],
  }

  // text view of the file (metadata lives at the start / end; a full scan of 25 MB is still fast)
  const dec = new TextDecoder('latin1')
  const txt = bytes.length > 6_000_000 ? dec.decode(bytes.slice(0, 3_000_000)) + dec.decode(bytes.slice(-3_000_000)) : dec.decode(bytes)

  /* ---- AI markers ---- */
  const ai = new Set<string>()
  for (const [re, label] of AI_PATTERNS) if (re.test(txt)) ai.add(label)
  if (/c2pa|jumbf|contentauth|cai:/i.test(txt) && /(jumb|c2pa)/i.test(txt)) {
    meta.c2pa = true
    const gen = txt.match(/OpenAI|ChatGPT|Google|Gemini|Adobe|Microsoft|Leica|Nikon|Canon|Sony|Samsung|Apple/i)
    if (gen) meta.notes.push(`Content Credentials signed by: ${gen[0]}. An AI flag is only raised when the manifest itself declares AI-generated media.`)
    meta.notes.push('Content Credentials (C2PA) manifest present: it records which tool created / edited the file.')
  }
  meta.aiMarkers = [...ai]

  if (isPdf) {
    const g = (key: string) => txt.match(new RegExp(`/${key}\\s*\\(([^)]{0,200})\\)`))?.[1]?.trim() ?? ''
    meta.pdfProducer = g('Producer')
    meta.pdfCreator = g('Creator')
    meta.pdfCreated = pdfDate(g('CreationDate'))
    meta.pdfModified = pdfDate(g('ModDate'))
    meta.pdfRevisions = (txt.match(/%%EOF/g) ?? []).length
    if (meta.pdfCreated && meta.pdfModified) {
      const d = Date.parse(meta.pdfModified) - Date.parse(meta.pdfCreated)
      meta.pdfModifiedAfterCreation = d > 120_000 // > 2 minutes apart
    }
    const fields = `${meta.pdfProducer} ${meta.pdfCreator}`
    meta.editorTags = EDITOR_NAMES.filter((e) => fields.includes(e))
    return meta
  }

  /* ---- images ---- */
  const ex = isJpeg ? readExif(bytes) : null
  if (ex) {
    meta.hasExif = true
    meta.camera = [ex.make, ex.model].filter(Boolean).join(' ')
    meta.software = ex.software
    meta.exifDate = ex.date
  }
  // XMP CreatorTool / PNG Software are also "named fields"
  const xmpTool = txt.match(/CreatorTool[>="'\s]+([^<"']{2,80})/)?.[1] ?? ''
  const pngSoft = isPng ? txt.match(/Software\0([^\0]{2,80})/)?.[1] ?? '' : ''
  const toolText = `${meta.software} ${xmpTool} ${pngSoft}`
  meta.editorTags = EDITOR_NAMES.filter((e) => toolText.includes(e))
  if (!meta.software && (xmpTool || pngSoft)) meta.software = (xmpTool || pngSoft).trim()

  if (isJpeg && meta.camera && meta.editorTags.length === 0 && meta.aiMarkers.length === 0) {
    meta.source = 'camera-photo'
    meta.pixelForensicsReliable = true
  } else if (!meta.camera) {
    meta.source = 'screenshot-or-export'
    meta.notes.push('No camera make/model in the file: this is a screenshot, an export, or metadata was stripped (WhatsApp, editors). Pixel forensics (ELA / noise) are advisory only on such files.')
  }
  return meta
}
