/* Multi-QR scan (browser only). The existing scanner stops at the first code; this adds the others where the browser can find them. */
import { scanQr } from './analysis'
import { getZXing } from './loaders'

export type MultiQr = {
  payloads: string[]
  /** true when the browser's BarcodeDetector exists, i.e. several codes on one page CAN be told apart */
  multiSupported: boolean
  warnings: string[]
}

async function scanOtherBarcodes(pages: HTMLCanvasElement[]): Promise<string[]> {
  const Z = await getZXing()
  const formats = [
    Z.BarcodeFormat.PDF_417,
    Z.BarcodeFormat.CODE_128,
    Z.BarcodeFormat.CODE_39,
    Z.BarcodeFormat.EAN_13,
    Z.BarcodeFormat.EAN_8,
    Z.BarcodeFormat.UPC_A,
    Z.BarcodeFormat.UPC_E,
    Z.BarcodeFormat.ITF,
  ].filter(Boolean)
  const hints = new Map()
  hints.set(Z.DecodeHintType.TRY_HARDER, true)
  hints.set(Z.DecodeHintType.POSSIBLE_FORMATS, formats)
  const values: string[] = []

  for (const page of pages) {
    const scale = Math.min(1, 1800 / Math.max(page.width, page.height))
    const canvas = document.createElement('canvas')
    canvas.width = Math.max(1, Math.round(page.width * scale))
    canvas.height = Math.max(1, Math.round(page.height * scale))
    canvas.getContext('2d', { willReadFrequently: true })!.drawImage(page, 0, 0, canvas.width, canvas.height)
    const pixels = canvas.getContext('2d', { willReadFrequently: true })!.getImageData(0, 0, canvas.width, canvas.height)
    const luminance = new Uint8ClampedArray(canvas.width * canvas.height)
    for (let i = 0; i < luminance.length; i++) {
      const p = i * 4
      luminance[i] = (pixels.data[p] * 299 + pixels.data[p + 1] * 587 + pixels.data[p + 2] * 114) / 1000
    }
    const source = new Z.RGBLuminanceSource(luminance, canvas.width, canvas.height)
    const bitmap = new Z.BinaryBitmap(new Z.HybridBinarizer(source))
    const reader = new Z.MultiFormatReader()
    reader.setHints(hints)
    try {
      const multiple = new Z.GenericMultipleBarcodeReader(reader)
      for (const result of multiple.decodeMultiple(bitmap) ?? []) {
        const text = result.getText()?.trim()
        if (text && !values.includes(text)) values.push(text)
      }
    } catch {
      reader.reset()
      try {
        const text = reader.decode(bitmap).getText()?.trim()
        if (text && !values.includes(text)) values.push(text)
      } catch {
        reader.reset()
      }
    }
  }
  return values
}

export async function scanQrMulti(pages: HTMLCanvasElement[], onProgress?: (s: string) => void): Promise<MultiQr> {
  const found: string[] = []
  const warnings: string[] = []
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
    try {
      const one = await scanQr(pages, onProgress)
      add(one?.text)
    } catch (error) {
      warnings.push(`QR fallback scan could not complete: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  if (!multiSupported) {
    try {
      for (const value of await scanOtherBarcodes(pages)) add(value)
    } catch (error) {
      warnings.push(`PDF417 / linear barcode fallback could not complete: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  return { payloads: found, multiSupported, warnings }
}
