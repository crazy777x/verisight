import { json, requireRole, sameOrigin } from '@/lib/server/auth'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const MAX_UPLOAD_BYTES = 25 * 1024 * 1024

export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: 'Bad origin' }, 403)
  const g = requireRole(req, ['officer', 'investigator', 'admin'])
  if ('res' in g) return g.res

  let form: FormData
  try {
    form = await req.formData()
  } catch {
    return json({ error: 'Invalid multipart upload' }, 400)
  }

  const file = form.get('file')
  if (!(file instanceof File) || file.size === 0) return json({ error: 'No file uploaded' }, 400)
  if (file.size > MAX_UPLOAD_BYTES) return json({ error: 'File exceeds the 25 MB limit' }, 413)

  const filename = file.name.split(/[\\/]/).pop() || 'upload'
  const upload = new FormData()
  upload.append('file', file, filename)
  const backendUrl = process.env.VERISIGHT_BACKEND_URL ?? 'http://127.0.0.1:5000'

  let response: Response
  try {
    response = await fetch(new URL('/api/verify-document', backendUrl), {
      method: 'POST',
      body: upload,
      cache: 'no-store',
    })
  } catch (error) {
    console.error('Document processing backend request failed', error)
    return json({ error: 'Document processing service is unavailable. Start the Python backend and try again.' }, 503)
  }

  const result = await response.json().catch(() => null)
  if (!result || typeof result !== 'object') {
    return json({ error: 'Document processing service returned an invalid response' }, 502)
  }
  return json(result, response.status)
}
