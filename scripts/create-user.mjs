// usage: node scripts/create-user.mjs OPERATOR-ID role "passphrase (12+ chars)" [override-pin 6-10 digits]
// role: officer | investigator | admin.  investigator / admin MUST have a PIN (their personal override PIN).
import { randomBytes, scryptSync } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
const [id, role, pass, pin] = process.argv.slice(2)
const dir = process.env.VERISIGHT_DATA_DIR || path.join(process.cwd(), 'data')
const file = path.join(dir, 'users.json')
const fail = (m) => { console.error('Error:', m); process.exit(1) }
if (!id || !role || !pass) fail('usage: node scripts/create-user.mjs OPERATOR-ID officer|investigator|admin "passphrase" [pin]')
const ID = id.toUpperCase()
if (!/^[A-Z0-9-]{4,24}$/.test(ID)) fail('Operator ID: 4-24 chars A-Z 0-9 -')
if (!['officer', 'investigator', 'admin'].includes(role)) fail('role must be officer, investigator or admin')
if (pass.length < 12) fail('passphrase must be at least 12 characters')
if (role !== 'officer' && !/^\d{6,10}$/.test(pin ?? '')) fail('investigator / admin need an override PIN of 6-10 digits')
const h = (s) => { const salt = randomBytes(16).toString('hex'); return { salt, hash: scryptSync(s, salt, 64).toString('hex') } }
mkdirSync(dir, { recursive: true })
const users = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : []
if (users.some((u) => u.operatorId === ID)) fail('operator already exists')
const p = h(pass), q = pin ? h(pin) : null
users.push({ operatorId: ID, role, salt: p.salt, hash: p.hash, pinSalt: q?.salt, pinHash: q?.hash, createdAt: Date.now() })
writeFileSync(file, JSON.stringify(users, null, 1), { mode: 0o600 })
console.log(`Created ${role} ${ID} in ${file}`)
