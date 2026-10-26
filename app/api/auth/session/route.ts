import { currentSession, json } from '@/lib/server/auth'
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: Request) {
  const s = currentSession(req)
  return s ? json({ operatorId: s.sub, role: s.role, startedAt: s.iat, expiresAt: s.exp }) : json({ error: 'Not authenticated' }, 401)
}
