import { appendLine, exclusive, readLines, sha256 } from './core'

export type AuditRow = { id: string; at: number; actor: string; action: string; target: string; prev: string; hash: string }
const FILE = 'audit.jsonl'
const GENESIS = '0'.repeat(64)

const hashOf = (r: Omit<AuditRow, 'hash'>) => sha256(`${r.prev}|${r.id}|${r.at}|${r.actor}|${r.action}|${r.target}`)

/** Append-only, SHA-256 hash-chained, SERVER timestamp (the client cannot choose time or actor). */
export function appendAudit(actor: string, action: string, target: string): Promise<AuditRow> {
  return exclusive('audit', async () => {
    const lines = await readLines(FILE)
    const last = lines.length ? (JSON.parse(lines[lines.length - 1]) as AuditRow) : null
    const base = { id: `A${String(lines.length + 1).padStart(6, '0')}`, at: Date.now(), actor: actor.slice(0, 40), action: action.slice(0, 48), target: target.slice(0, 240), prev: last?.hash ?? GENESIS }
    const row: AuditRow = { ...base, hash: hashOf(base) }
    await appendLine(FILE, JSON.stringify(row))
    return row
  })
}

export async function listAudit(limit = 200): Promise<AuditRow[]> {
  const rows = (await readLines(FILE)).map((l) => JSON.parse(l) as AuditRow)
  return rows.slice(-limit).reverse() // newest first
}

/** Re-computes the whole chain. Any edit, deletion or re-ordering of the file is detected. */
export async function verifyAuditChain(): Promise<{ ok: boolean; count: number; brokenAt?: string }> {
  const rows = (await readLines(FILE)).map((l) => JSON.parse(l) as AuditRow)
  let prev = GENESIS
  for (const r of rows) {
    if (r.prev !== prev || r.hash !== hashOf({ id: r.id, at: r.at, actor: r.actor, action: r.action, target: r.target, prev: r.prev })) return { ok: false, count: rows.length, brokenAt: r.id }
    prev = r.hash
  }
  return { ok: true, count: rows.length }
}
