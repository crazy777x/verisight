import { DEMO_MODE, demoRole } from './demo-users'
import { checkSecret, exclusive, hashSecret, readCookie, readJson, verifySession, writeJson, type Role, type SessionPayload } from './core'

export type UserRecord = { operatorId: string; role: Role; salt: string; hash: string; pinSalt?: string; pinHash?: string; createdAt: number }

const USERS = 'users.json'
/** Real users (users.json today; replace this one function with a database / SSO lookup). */
export const loadUsers = () => readJson<UserRecord[]>(USERS, [])

export async function createUser(operatorId: string, role: Role, passphrase: string, pin?: string) {
  if (!/^[A-Z0-9-]{4,24}$/.test(operatorId)) throw new Error('Operator ID must be 4-24 chars A-Z 0-9 -')
  if (passphrase.length < 12) throw new Error('Passphrase must be at least 12 characters')
  if (role !== 'officer' && !(pin && /^\d{6,10}$/.test(pin))) throw new Error('Investigator / admin need an override PIN of 6-10 digits')
  await exclusive('users', async () => {
    const users = await loadUsers()
    if (users.some((u) => u.operatorId === operatorId)) throw new Error('Operator already exists')
    const p = hashSecret(passphrase)
    const q = pin ? hashSecret(pin) : null
    users.push({ operatorId, role, salt: p.salt, hash: p.hash, pinSalt: q?.salt, pinHash: q?.hash, createdAt: Date.now() })
    await writeJson(USERS, users)
  })
}

/* ---------- brute-force protection (per operator + per client), in memory ---------- */
type Bucket = { fails: number; until: number }
const buckets = new Map<string, Bucket>()
const MAX_FAILS = 5
const LOCK_MS = 15 * 60 * 1000
export function throttled(key: string, now = Date.now()): number {
  const b = buckets.get(key)
  return b && b.until > now ? Math.ceil((b.until - now) / 1000) : 0
}
export function noteFail(key: string, now = Date.now()) {
  const b = buckets.get(key) ?? { fails: 0, until: 0 }
  b.fails = b.until && b.until <= now ? 1 : b.fails + 1
  if (b.fails >= MAX_FAILS) b.until = now + LOCK_MS
  buckets.set(key, b)
}
export const clearFails = (key: string) => buckets.delete(key)

/** Verifies credentials. The role ALWAYS comes from the stored user record, never from the client. */
export async function authenticate(operatorId: string, passphrase: string): Promise<{ ok: true; user: UserRecord } | { ok: false; reason: 'bad' | 'locked'; retryAfter?: number }> {
  const id = operatorId.trim().toUpperCase()
  if (DEMO_MODE) return { ok: true, user: { operatorId: id, role: demoRole(id), salt: '', hash: '', createdAt: 0 } } // DEMO ONLY: open login
  const wait = throttled(`u:${id}`)
  if (wait) return { ok: false, reason: 'locked', retryAfter: wait }
  const user = (await loadUsers()).find((u) => u.operatorId === id)
  // always run one scrypt so the response time does not reveal whether the operator exists
  const ok = user ? checkSecret(passphrase, user.salt, user.hash) : (checkSecret(passphrase, '00', '00'.repeat(64)), false)
  if (!ok || !user) {
    noteFail(`u:${id}`)
    return { ok: false, reason: 'bad' }
  }
  clearFails(`u:${id}`)
  return { ok: true, user }
}

/** PIN check for overrides: personal PIN of the approving supervisor, 3 wrong tries lock it for 15 minutes. */
export async function checkPin(operatorId: string, pin: string): Promise<'ok' | 'bad' | 'locked' | 'no-pin'> {
  if (DEMO_MODE) return pin.length >= 4 ? 'ok' : 'bad' // DEMO ONLY
  const wait = throttled(`p:${operatorId}`)
  if (wait) return 'locked'
  const user = (await loadUsers()).find((u) => u.operatorId === operatorId)
  if (!user?.pinHash || !user.pinSalt) return 'no-pin'
  if (checkSecret(pin, user.pinSalt, user.pinHash)) {
    clearFails(`p:${operatorId}`)
    return 'ok'
  }
  noteFail(`p:${operatorId}`)
  const b = buckets.get(`p:${operatorId}`)
  if (b && b.fails >= 3) b.until = Date.now() + LOCK_MS
  return 'bad'
}

/* ---------- request guards ---------- */
export function currentSession(req: Request): SessionPayload | null {
  return verifySession(readCookie(req))
}
/** CSRF defence in depth (cookie is SameSite=Strict): state-changing requests must come from our own origin and be JSON. */
export function sameOrigin(req: Request): boolean {
  const origin = req.headers.get('origin')
  const host = req.headers.get('host')
  if (!origin) return req.method === 'GET'
  try {
    return new URL(origin).host === host
  } catch {
    return false
  }
}
export const json = (data: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } })

export function requireRole(req: Request, roles: Role[]): { s: SessionPayload } | { res: Response } {
  const s = currentSession(req)
  if (!s) return { res: json({ error: 'Not authenticated' }, 401) }
  if (!roles.includes(s.role)) return { res: json({ error: 'Your role is not allowed to do this' }, 403) }
  return { s }
}
