import { json, requireRole, sameOrigin } from '@/lib/server/auth'
import { resolveEntry } from '@/lib/server/queue'
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: 'Bad origin' }, 403)
  const g = requireRole(req, ['investigator', 'admin'])
  if ('res' in g) return g.res
  const b = await req.json().catch(() => null)
  const status = b?.status === 'approved' || b?.status === 'detained' ? b.status : null
  if (!status || typeof b?.id !== 'string') return json({ error: 'Invalid request' }, 400)
  const r = await resolveEntry({ id: b.id, status, note: String(b.note ?? ''), pin: b.pin ? String(b.pin) : undefined, actor: g.s.sub, role: g.s.role })
  return r.ok ? json({ ok: true, row: r.row }) : json({ ok: false, error: r.error }, r.status)
}
