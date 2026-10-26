import type { VerdictInput } from '../lib/verdict'
import type { Meta } from '../lib/metadata'

export const camera: Meta = { format: 'jpeg', source: 'camera-photo', pixelForensicsReliable: true, camera: 'Canon EOS', software: '', exifDate: '', hasExif: true, aiMarkers: [], c2pa: false, editorTags: [], pdfProducer: '', pdfCreator: '', pdfCreated: '', pdfModified: '', pdfRevisions: 0, pdfModifiedAfterCreation: false, notes: [] }
export const screenshot: Meta = { ...camera, source: 'screenshot-or-export', pixelForensicsReliable: false, camera: '', hasExif: false }
export const pdfMeta: Meta = { ...camera, format: 'pdf', source: 'pdf', pixelForensicsReliable: false, camera: '' }

export const printed = { rawText: '', aadhaarNo: '', aadhaarCandidates: [], name: 'TEST USER', fatherName: '', dob: '01-01-1990', gender: 'M', pincode: '', pan: '', panKeyword: false, dl: '', dlKeyword: false, epic: '', epicKeyword: false, aadhaarKeyword: true, mrz: null, words: [], confidence: 90, source: 'ocr' as const }
export const noChain = { state: 'none' as const, detail: '', chain: [] }
export const noPdfSig = { present: false, count: 0, digestOk: null, sigOk: null, coversWholeFile: null, signer: '', issuer: '', validTo: '', detail: '', chain: noChain }
export const cleanTamper = { cols: 1, rows: 1, heat: [], regions: [], copyMoveBlocks: 0, editorTags: [], elaReliable: true, width: 1, height: 1 }
export const cleanEla = { blocks: [], rowVariance: [], mean: 0, variance: 0, peak: 0, anomalousBlocks: 0, anomaly: false, reliable: true, note: '' }
export const region = (id: number, fields: string[] = []) => ({ id, x: 0.1, y: 0.1, w: 0.1, h: 0.1, score: 1, kinds: ['ELA', 'NOISE'] as ('ELA' | 'NOISE')[], fields, note: '' })

const aadhaarQr = { kind: 'secure' as const, version: 'V2', fields: { name: 'TEST USER', dob: '01-01-1990', gender: 'M' }, refLast4: '1234', signedData: new Uint8Array(1), signature: new Uint8Array(256), photoBytes: null, rawBytes: 1 }
const qrHit = { text: '1'.repeat(300), bytes: new Uint8Array(1), page: 0, engine: 'test' }

/** A clean, valid Aadhaar PDF with a decoded QR: the baseline every test then breaks in ONE way. */
export function base(over: Partial<VerdictInput> = {}): VerdictInput {
  return {
    kind: 'aadhaar', printed: { ...printed, aadhaarNo: '999941057058' }, aadhaarValid: true, mrz: [], ela: cleanEla, tamper: cleanTamper, pdfSig: noPdfSig,
    qr: qrHit, qrPattern: null, qrAadhaar: aadhaarQr, qrRows: [{ label: 'Name', qr: 'TEST USER', printed: 'TEST USER', res: 'match' }], qrSig: { state: 'no-cert' },
    isPdf: true, meta: pdfMeta, ...over,
  }
}
export { aadhaarQr, qrHit }
