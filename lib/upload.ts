/* Upload validation: size, type AND content (magic bytes). A renamed or corrupted file is refused with a clear message. */
export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024

export type UploadCheck = { ok: true; kind: 'pdf' | 'jpeg' | 'png' | 'webp' | 'tiff' } | { ok: false; error: string }

export function sniff(head: Uint8Array): 'pdf' | 'jpeg' | 'png' | 'webp' | 'tiff' | null {
  const at = (i: number, s: string) => [...s].every((c, k) => head[i + k] === c.charCodeAt(0))
  // %PDF may be preceded by a few junk bytes in real files; the spec allows it within the first 1024 bytes
  const txt = Array.from(head.slice(0, 1024), (b) => String.fromCharCode(b)).join('')
  if (txt.includes('%PDF-')) return 'pdf'
  if (head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return 'jpeg'
  if (head[0] === 0x89 && at(1, 'PNG') && head[4] === 0x0d) return 'png'
  if (at(0, 'RIFF') && at(8, 'WEBP')) return 'webp'
  if ((at(0, 'II') && head[2] === 42 && head[3] === 0) || (at(0, 'MM') && head[2] === 0 && head[3] === 42)) return 'tiff'
  return null
}

export function validateUpload(name: string, mime: string, size: number, head: Uint8Array): UploadCheck {
  if (size <= 0) return { ok: false, error: 'The file is empty.' }
  if (size > MAX_UPLOAD_BYTES) return { ok: false, error: 'File exceeds the 25 MB limit.' }
  const claimed = mime === 'application/pdf' || mime.startsWith('image/') || /\.(pdf|jpe?g|png|webp|tiff?)$/i.test(name)
  if (!claimed) return { ok: false, error: 'Unsupported format. Use PDF, JPG, PNG, WEBP or TIFF.' }
  const kind = sniff(head)
  if (!kind) return { ok: false, error: 'The file content is not a PDF or a supported image. It may be corrupted or renamed.' }
  const wantsPdf = mime === 'application/pdf' || /\.pdf$/i.test(name)
  if (wantsPdf !== (kind === 'pdf')) return { ok: false, error: 'The file extension does not match its content.' }
  return { ok: true, kind }
}

export async function validateFile(f: File): Promise<UploadCheck> {
  const head = new Uint8Array(await f.slice(0, 1536).arrayBuffer())
  return validateUpload(f.name, f.type, f.size, head)
}
