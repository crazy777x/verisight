import { currentSession, json, sameOrigin } from '@/lib/server/auth'
import { appendAudit } from '@/lib/server/audit'
import { cookieHeader } from '@/lib/server/core'
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: 'Bad origin' }, 403)
  const s = currentSession(req)
  if (s) await appendAudit(s.sub, 'SESSION_CLOSE', s.role)
  return json({ ok: true }, 200, { 'set-cookie': cookieHeader('', 0) })
}
