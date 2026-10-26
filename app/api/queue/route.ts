import { json, requireRole, sameOrigin } from '@/lib/server/auth'
import { addFlag, listQueue } from '@/lib/server/queue'
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: Request) {
  const g = requireRole(req, ['investigator', 'admin'])
  if ('res' in g) return g.res
  return json({ rows: await listQueue() })
}

export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: 'Bad origin' }, 403)
  const g = requireRole(req, ['officer', 'investigator', 'admin'])
  if ('res' in g) return g.res
  const b = await req.json().catch(() => null)
  if (!b || typeof b !== 'object') return json({ error: 'Invalid request' }, 400)
  const row = await addFlag(b, g.s.sub)
  return json({ id: row.id, locked: row.locked })
}
