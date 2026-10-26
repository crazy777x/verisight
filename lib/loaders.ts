/* Runtime CDN loaders: no npm install needed, nothing to bundle. */
const cache = new Map<string, Promise<void>>()

export function loadScript(src: string): Promise<void> {
  const hit = cache.get(src)
  if (hit) return hit
  const p = new Promise<void>((resolve, reject) => {
    const s = document.createElement('script')
    s.src = src
    s.async = true
    s.onload = () => resolve()
    s.onerror = () => {
      cache.delete(src)
      reject(new Error(`Could not load ${src}. Check internet connection (needed once for OCR / face models).`))
    }
    document.head.appendChild(s)
  })
  cache.set(src, p)
  return p
}

const PDFJS = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174'
export async function getPdfJs(): Promise<any> {
  await loadScript(`${PDFJS}/pdf.min.js`)
  const lib = (window as any).pdfjsLib
  lib.GlobalWorkerOptions.workerSrc = `${PDFJS}/pdf.worker.min.js`
  return lib
}

export async function getJsQR(): Promise<(d: Uint8ClampedArray, w: number, h: number, o?: any) => any> {
  await loadScript('https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js')
  return (window as any).jsQR
}

export async function getZXing(): Promise<any> {
  await loadScript('https://cdn.jsdelivr.net/npm/@zxing/library@0.21.3/umd/index.min.js')
  return (window as any).ZXing
}

let tessWorker: Promise<any> | null = null
export async function getOcr(): Promise<any> {
  if (!tessWorker) {
    tessWorker = (async () => {
      await loadScript('https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js')
      return (window as any).Tesseract.createWorker('eng+hin') // Aadhaar prints the name in Hindi and English
    })().catch((e) => {
      tessWorker = null
      throw e
    })
  }
  return tessWorker
}

export const HUMAN_BASE = 'https://cdn.jsdelivr.net/npm/@vladmandic/human@3'
let humanInst: Promise<any> | null = null
export async function getHuman(): Promise<any> {
  if (!humanInst) {
    humanInst = (async () => {
      await loadScript(`${HUMAN_BASE}/dist/human.js`)
      const H = (window as any).Human
      const Ctor = H.Human ?? H
      const human = new Ctor({
        modelBasePath: `${HUMAN_BASE}/models/`,
        backend: 'webgl',
        debug: false,
        filter: { enabled: true, equalization: false },
        face: {
          enabled: true,
          detector: { rotation: false, maxDetected: 6, minConfidence: 0.25 },
          mesh: { enabled: true },
          iris: { enabled: false },
          description: { enabled: true },
          antispoof: { enabled: true },
          liveness: { enabled: true },
          emotion: { enabled: false },
          attention: { enabled: false },
        },
        body: { enabled: false },
        hand: { enabled: false },
        object: { enabled: false },
        segmentation: { enabled: false },
        gesture: { enabled: false },
      })
      await human.load()
      return human
    })().catch((e) => {
      humanInst = null
      throw e
    })
  }
  return humanInst
}
