/* Server-only helpers: data directory, serialised file writes, password hashing, signed session tokens. */
import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { promises as fs } from 'node:fs'
import path from 'node:path'

export const DATA_DIR = process.env.VERISIGHT_DATA_DIR || path.join(process.cwd(), 'data')
export const IS_PROD = process.env.NODE_ENV === 'production'

let devSecret: string | null = null
export function sessionSecret(): string {
  const s = process.env.SESSION_SECRET
  if (s && s.length >= 32) return s
  if (IS_PROD) throw new Error('SESSION_SECRET (>= 32 chars) must be set in production')
  // development only: random per process, sessions end when the server restarts
  return (devSecret ??= randomBytes(32).toString('hex'))
}

/* ---------- serialised JSON file access (single-node demo database; swap for Postgres in real deployment) ---------- */
/** One queue per resource key ('audit', 'queue', 'users'). A task may take a DIFFERENT key inside itself, never the same one (that would deadlock). */
const chains = new Map<string, Promise<unknown>>()
export function exclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = chains.get(key) ?? Promise.resolve()
  const run = prev.then(fn, fn)
  chains.set(key, run.catch(() => undefined))
  return run
}
export async function readJson<T>(file: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await fs.readFile(path.join(DATA_DIR, file), 'utf8')) as T
  } catch {
    return fallback
  }
}
export async function writeJson(file: string, data: unknown) {
  await fs.mkdir(DATA_DIR, { recursive: true })
  const tmp = path.join(DATA_DIR, `${file}.${process.pid}.tmp`)
  await fs.writeFile(tmp, JSON.stringify(data, null, 1), { mode: 0o600 })
  await fs.rename(tmp, path.join(DATA_DIR, file))
}
export async function appendLine(file: string, line: string) {
  await fs.mkdir(DATA_DIR, { recursive: true })
  await fs.appendFile(path.join(DATA_DIR, file), line + '\n', { mode: 0o600 })
}
export async function readLines(file: string): Promise<string[]> {
  try {
    return (await fs.readFile(path.join(DATA_DIR, file), 'utf8')).split('\n').filter(Boolean)
  } catch {
    return []
  }
}

/* ---------- passwords (scrypt, per-user salt, constant-time compare) ---------- */
export function hashSecret(secret: string, salt = randomBytes(16).toString('hex')) {
  return { salt, hash: scryptSync(secret, salt, 64).toString('hex') }
}
export function checkSecret(secret: string, salt: string, hash: string): boolean {
  const a = Buffer.from(scryptSync(secret, salt, 64).toString('hex'))
  const b = Buffer.from(hash)
  return a.length === b.length && timingSafeEqual(a, b)
}

/* ---------- signed session token: base64url(payload).HMAC-SHA256 ---------- */
export type Role = 'officer' | 'investigator' | 'admin'
export type SessionPayload = { sub: string; role: Role; iat: number; exp: number; sid: string }
const b64 = (s: string | Buffer) => Buffer.from(s).toString('base64url')
export const SESSION_TTL_MS = 8 * 60 * 60 * 1000

export function signSession(p: Omit<SessionPayload, 'iat' | 'exp' | 'sid'>, now = Date.now()): string {
  const body: SessionPayload = { ...p, iat: now, exp: now + SESSION_TTL_MS, sid: randomBytes(8).toString('hex') }
  const payload = b64(JSON.stringify(body))
  const mac = createHmac('sha256', sessionSecret()).update(payload).digest('base64url')
  return `${payload}.${mac}`
}
export function verifySession(token: string | undefined | null, now = Date.now()): SessionPayload | null {
  if (!token) return null
  const [payload, mac] = token.split('.')
  if (!payload || !mac) return null
  const good = createHmac('sha256', sessionSecret()).update(payload).digest('base64url')
  const a = Buffer.from(mac)
  const b = Buffer.from(good)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  try {
    const p = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as SessionPayload
    if (!p.exp || p.exp < now || !['officer', 'investigator', 'admin'].includes(p.role)) return null
    return p
  } catch {
    return null
  }
}

export const COOKIE = 'vs_session'
export function cookieHeader(token: string, maxAgeSec = SESSION_TTL_MS / 1000) {
  return `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${IS_PROD ? '; Secure' : ''}`
}
export function readCookie(req: Request, name = COOKIE): string | null {
  const raw = req.headers.get('cookie') ?? ''
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return null
}
export const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')
