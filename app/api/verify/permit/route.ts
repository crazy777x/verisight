import { json, requireRole, sameOrigin } from '@/lib/server/auth'
import { runPermitChecks, type PermitInput } from '@/lib/permit'
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/** SERVER-SIDE permit / pass checks: validity, movement, signature rules and overall verdict. */
export async function POST(req: Request) {
  if (!sameOrigin(req)) return json({ error: 'Bad origin' }, 403)
  const g = requireRole(req, ['officer', 'investigator', 'admin'])
  if ('res' in g) return g.res
  const b = await req.json().catch(() => null)
  if (!b || typeof b !== 'object' || typeof (b as any).purpose !== 'string' || typeof (b as any).fields !== 'object') {
    return json({ error: 'Invalid request' }, 400)
  }
  // an issuer-status provider is a live function and cannot come from the browser; the server uses its own (default: not verified)
  const { provider: _ignored, ...input } = b as PermitInput & { provider?: unknown }
  try {
    const report = await runPermitChecks(input as PermitInput)
    return json({ report })
  } catch {
    return json({ error: 'Checks could not be computed' }, 422)
  }
}
