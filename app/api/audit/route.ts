import { json, requireRole, sameOrigin } from '@/lib/server/auth'
import { appendAudit, listAudit, verifyAuditChain } from '@/lib/server/audit'
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: Request) {
  const g = requireRole(req, ['investigator', 'admin'])
  if ('res' in g) return g.res
  const [rows, chain] = await Promise.all([listAudit(200), verifyAuditChain()])
  return json({ rows, chain })
}

/** Any signed-in operator may write an event; the actor and the time are set by the server, never by the client. */
export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: 'Bad origin' }, 403)
  const g = requireRole(req, ['officer', 'investigator', 'admin'])
  if ('res' in g) return g.res
  const b = await req.json().catch(() => null)
  const action = String(b?.action ?? '')
  if (!/^[A-Z0-9_]{3,40}$/.test(action)) return json({ error: 'Invalid action' }, 400)
  const row = await appendAudit(g.s.sub, action, String(b?.target ?? '').slice(0, 240))
  return json({ id: row.id })
}
