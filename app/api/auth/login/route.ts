import { authenticate, clearFails, json, sameOrigin, noteFail, throttled } from '@/lib/server/auth'
import { appendAudit } from '@/lib/server/audit'
import { cookieHeader, signSession } from '@/lib/server/core'
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: 'Bad origin' }, 403)
  const ip = (req.headers.get('x-forwarded-for') ?? 'local').split(',')[0].trim()
  if (throttled(`ip:${ip}`)) return json({ error: 'Too many attempts. Try again later.' }, 429)
  let body: any
  try {
    body = await req.json()
  } catch {
    return json({ error: 'Invalid request' }, 400)
  }
  const operatorId = String(body?.operatorId ?? '').trim().toUpperCase().slice(0, 24)
  const passphrase = String(body?.passphrase ?? '').slice(0, 200)
  if (!operatorId || !passphrase) return json({ error: 'Operator ID and passphrase are required' }, 400)
  const r = await authenticate(operatorId, passphrase)
  if (!r.ok) {
    noteFail(`ip:${ip}`)
    await appendAudit(operatorId, r.reason === 'locked' ? 'LOGIN_BLOCKED' : 'LOGIN_FAILED', `ip ${ip}`)
    return json({ error: r.reason === 'locked' ? `Account locked. Try again in ${Math.ceil((r.retryAfter ?? 900) / 60)} min.` : 'Invalid operator ID or passphrase' }, r.reason === 'locked' ? 429 : 401)
  }
  const token = signSession({ sub: r.user.operatorId, role: r.user.role })
  clearFails(`ip:${ip}`)
  await appendAudit(r.user.operatorId, 'SESSION_OPEN', r.user.role)
  return json({ operatorId: r.user.operatorId, role: r.user.role, startedAt: Date.now() }, 200, { 'set-cookie': cookieHeader(token) })
}
