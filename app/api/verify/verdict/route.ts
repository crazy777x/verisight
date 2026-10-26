import { json, requireRole, sameOrigin } from '@/lib/server/auth'
import { buildVerdict, type VerdictInput } from '@/lib/verdict'
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/** SERVER-SIDE scoring. The browser extracts the facts from the document; the risk rules and verdict logic live here. */
export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: 'Bad origin' }, 403)
  const g = requireRole(req, ['officer', 'investigator', 'admin'])
  if ('res' in g) return g.res
  const body = await req.json().catch(() => null)
  if (!body || typeof body !== 'object' || typeof (body as any).kind !== 'string') return json({ error: 'Invalid request' }, 400)
  try {
    const verdict = buildVerdict(body as VerdictInput)
    return json({ verdict })
  } catch {
    return json({ error: 'Verdict could not be computed' }, 422)
  }
}
