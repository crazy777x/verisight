/* Multi-QR scan (browser only). The existing scanner stops at the first code; this adds the others where the browser can find them. */
import { scanQr } from './analysis'

export type MultiQr = {
  payloads: string[]
  /** true when the browser's BarcodeDetector exists, i.e. several codes on one page CAN be told apart */
  multiSupported: boolean
}

export async function scanQrMulti(pages: HTMLCanvasElement[], onProgress?: (s: string) => void): Promise<MultiQr> {
  const found: string[] = []
  const add = (t: string | undefined) => {
    const v = (t ?? '').trim()
    if (v && !found.includes(v)) found.push(v)
  }
  let multiSupported = false
  try {
    const BD = (window as any).BarcodeDetector
    if (BD) {
      multiSupported = true
      const det = new BD({ formats: ['qr_code', 'data_matrix', 'pdf417', 'code_128'] })
      for (const pg of pages) for (const r of (await det.detect(pg)) ?? []) add(r.rawValue)
    }
  } catch {
    /* native detector failed: fall back to the single-code scanner */
  }
  if (!found.length) {
    const one = await scanQr(pages, onProgress).catch(() => null)
    add(one?.text)
  }
  return { payloads: found, multiSupported }
}
