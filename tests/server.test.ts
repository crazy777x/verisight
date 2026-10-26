import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

process.env.VERISIGHT_DATA_DIR = mkdtempSync(path.join(tmpdir(), 'vs-'))
process.env.SESSION_SECRET = 'x'.repeat(48)

// loaded with require AFTER the env is set (the modules read it at import time)
/* eslint-disable @typescript-eslint/no-require-imports */
const core: typeof import('../lib/server/core') = require('../lib/server/core')
const auth: typeof import('../lib/server/auth') = require('../lib/server/auth')
const audit: typeof import('../lib/server/audit') = require('../lib/server/audit')
const queue: typeof import('../lib/server/queue') = require('../lib/server/queue')

const req = (token?: string) => new Request('http://localhost/x', { headers: token ? { cookie: `${core.COOKIE}=${token}` } : {} })

test('users: weak passphrase / missing PIN rejected, good user created', async () => {
  await assert.rejects(auth.createUser('OFF-0001', 'officer', 'short'))
  await assert.rejects(auth.createUser('INV-0001', 'investigator', 'long-enough-pass-1'))
  await auth.createUser('OFF-0001', 'officer', 'officer-pass-12345')
  await auth.createUser('INV-0001', 'investigator', 'investigator-pass-1', '123456')
  await auth.createUser('INV-0002', 'investigator', 'investigator-pass-2', '654321')
  await auth.createUser('ADM-0001', 'admin', 'admin-pass-123456', '111222')
  const users = JSON.parse(readFileSync(path.join(process.env.VERISIGHT_DATA_DIR!, 'users.json'), 'utf8'))
  assert.ok(!JSON.stringify(users).includes('officer-pass'), 'passphrase must never be stored in clear')
})

test('login: any well-formed ID + 8 chars is NO LONGER enough', async () => {
  assert.equal((await auth.authenticate('ANYONE-1', 'password123')).ok, false)
  assert.equal((await auth.authenticate('OFF-0001', 'wrong-pass-123456')).ok, false)
  const ok = await auth.authenticate('off-0001', 'officer-pass-12345')
  assert.ok(ok.ok && ok.user.role === 'officer')
})

test('login: account locks after 5 wrong passphrases (brute force), even with the right one afterwards', async () => {
  for (let i = 0; i < 5; i++) await auth.authenticate('ADM-0001', 'nope-nope-nope-1')
  const r = await auth.authenticate('ADM-0001', 'admin-pass-123456')
  assert.equal(r.ok, false)
  assert.equal((r as any).reason, 'locked')
})

test('session: signed cookie, tamper / expiry / role forgery all rejected', () => {
  const t = core.signSession({ sub: 'OFF-0001', role: 'officer' })
  assert.equal(core.verifySession(t)?.role, 'officer')
  const [payload, mac] = t.split('.')
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(payload, 'base64url').toString()), role: 'admin' })).toString('base64url')
  assert.equal(core.verifySession(`${forged}.${mac}`), null, 'role changed by the client')
  assert.equal(core.verifySession(`${payload}.${mac.slice(0, -2)}AA`), null)
  assert.equal(core.verifySession(t, Date.now() + core.SESSION_TTL_MS + 1000), null, 'expired')
  assert.equal(core.verifySession('garbage'), null)
  assert.equal(core.verifySession(null), null)
})

test('server-side role enforcement: officer cannot read audit / queue', () => {
  const off = core.signSession({ sub: 'OFF-0001', role: 'officer' })
  const inv = core.signSession({ sub: 'INV-0001', role: 'investigator' })
  assert.ok('res' in auth.requireRole(req(), ['investigator', 'admin']) && (auth.requireRole(req(), ['investigator']) as any).res.status === 401)
  assert.equal((auth.requireRole(req(off), ['investigator', 'admin']) as any).res.status, 403)
  assert.ok('s' in auth.requireRole(req(inv), ['investigator', 'admin']))
})

test('CSRF: cross-origin POST refused', () => {
  const bad = new Request('http://localhost/x', { method: 'POST', headers: { origin: 'https://evil.example', host: 'localhost' } })
  const good = new Request('http://localhost/x', { method: 'POST', headers: { origin: 'http://localhost', host: 'localhost' } })
  assert.equal(auth.sameOrigin(bad), false)
  assert.equal(auth.sameOrigin(good), true)
})

test('audit: hash chain verifies, and any edit of the file is detected', async () => {
  await audit.appendAudit('A', 'ONE', 't1')
  await audit.appendAudit('B', 'TWO', 't2')
  assert.equal((await audit.verifyAuditChain()).ok, true)
  const f = path.join(process.env.VERISIGHT_DATA_DIR!, 'audit.jsonl')
  const lines = readFileSync(f, 'utf8').split('\n').filter(Boolean)
  const row = JSON.parse(lines[0])
  row.actor = 'SOMEONE-ELSE'
  lines[0] = JSON.stringify(row)
  writeFileSync(f, lines.join('\n') + '\n')
  const r = await audit.verifyAuditChain()
  assert.equal(r.ok, false)
  assert.equal(r.brokenAt, row.id)
})

test('queue: SAFE-LOCK is decided by the server and nobody can release it', async () => {
  const hi = await queue.addFlag({ subject: 'X', docType: 'Aadhaar', docNo: '1', risk: 85, lane: 'L3', reasons: [] }, 'OFF-0001')
  assert.equal(hi.locked, true)
  for (const [who, role] of [['INV-0001', 'investigator'], ['ADM-0001', 'admin']] as const) {
    const r = await queue.resolveEntry({ id: hi.id, status: 'approved', note: 'a long enough written reason', pin: '123456', actor: who, role })
    assert.equal(r.ok, false)
    assert.equal((r as any).status, 403)
  }
})

test('queue: override rules (role, reason, PIN, self-approval, one-time)', async () => {
  const mid = await queue.addFlag({ subject: 'Y', docType: 'Aadhaar', docNo: '2', risk: 55, lane: 'L2', reasons: [] }, 'OFF-0001')
  assert.equal(mid.locked, false)
  const base = { id: mid.id, status: 'approved' as const }
  assert.equal((await queue.resolveEntry({ ...base, note: 'long enough reason here', pin: '123456', actor: 'OFF-0001', role: 'officer' })).ok, false, 'officer')
  assert.equal((await queue.resolveEntry({ ...base, note: 'short', pin: '123456', actor: 'INV-0001', role: 'investigator' })).ok, false, 'no justification')
  assert.equal((await queue.resolveEntry({ ...base, note: 'long enough reason here', actor: 'INV-0001', role: 'investigator' })).ok, false, 'no pin')
  assert.equal((await queue.resolveEntry({ ...base, note: 'long enough reason here', pin: '000000', actor: 'INV-0001', role: 'investigator' })).ok, false, 'wrong pin')
  assert.equal((await queue.resolveEntry({ ...base, note: 'long enough reason here', pin: '654321', actor: 'INV-0001', role: 'investigator' })).ok, false, "someone else's pin")
  const ok = await queue.resolveEntry({ ...base, note: 'long enough reason here', pin: '123456', actor: 'INV-0001', role: 'investigator' })
  assert.equal(ok.ok, true)
  assert.equal((await queue.resolveEntry({ ...base, note: 'long enough reason here', pin: '123456', actor: 'INV-0001', role: 'investigator' })).ok, false, 'already resolved')
})

test('queue: PIN is locked after 3 wrong tries', async () => {
  const e = await queue.addFlag({ subject: 'Z', docType: 'Aadhaar', docNo: '3', risk: 50, lane: 'L2', reasons: [] }, 'OFF-0001')
  const go = (pin: string) => queue.resolveEntry({ id: e.id, status: 'approved', note: 'long enough reason here', pin, actor: 'INV-0002', role: 'investigator' })
  for (let i = 0; i < 3; i++) await go('000000')
  const r = await go('654321') // the correct PIN is now refused too
  assert.equal(r.ok, false)
  assert.equal((r as any).status, 429)
})

test('queue: a person cannot approve their own flag', async () => {
  const e = await queue.addFlag({ subject: 'S', docType: 'Aadhaar', docNo: '4', risk: 50, lane: 'L2', reasons: [] }, 'ADM-0001')
  const r = await queue.resolveEntry({ id: e.id, status: 'approved', note: 'long enough reason here', pin: '111222', actor: 'ADM-0001', role: 'admin' })
  assert.equal(r.ok, false)
})

test('every refusal is written to the audit log', async () => {
  const rows = await audit.listAudit(500)
  assert.ok(rows.some((r) => r.action === 'OVERRIDE_DENIED_SAFE_LOCK'))
  assert.ok(rows.some((r) => r.action === 'OVERRIDE_PIN_FAILED'))
})
