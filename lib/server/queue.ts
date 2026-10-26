import { exclusive, readJson, writeJson, type Role } from './core'
import { appendAudit } from './audit'
import { checkPin } from './auth'
import { HARD_LOCK_RISK, REVIEW_RISK } from '../policy'

export type Reason = { code: string; detail: string }
export type QueueRow = {
  id: string; subject: string; docType: string; docNo: string; risk: number; lane: string; flaggedAt: number; reasons: Reason[]
  status: 'pending' | 'approved' | 'detained'; locked: boolean; flaggedBy: string; resolvedBy?: string; resolvedAt?: number; note?: string; caseId?: string
}
const FILE = 'queue.json'
const clip = (s: unknown, n: number) => String(s ?? '').slice(0, n)

export function addFlag(input: { subject: string; docType: string; docNo: string; risk: number; lane: string; reasons: Reason[]; caseId?: string }, actor: string): Promise<QueueRow> {
  return exclusive('queue', async () => {
    const list = await readJson<QueueRow[]>(FILE, [])
    const risk = Math.max(0, Math.min(100, Math.round(Number(input.risk) || 0)))
    const row: QueueRow = {
      id: `VS-${(Date.now().toString(36) + Math.random().toString(36).slice(2, 4)).toUpperCase().slice(-7)}`,
      subject: clip(input.subject, 80), docType: clip(input.docType, 30), docNo: clip(input.docNo, 40), risk, lane: clip(input.lane, 40), flaggedAt: Date.now(),
      reasons: (Array.isArray(input.reasons) ? input.reasons : []).slice(0, 20).map((r) => ({ code: clip(r.code, 30), detail: clip(r.detail, 400) })),
      status: 'pending',
      locked: risk >= HARD_LOCK_RISK, // decided HERE, by the server, from the risk score
      flaggedBy: actor, caseId: input.caseId ? clip(input.caseId, 40) : undefined,
    }
    list.unshift(row)
    await writeJson(FILE, list.slice(0, 2000))
    await appendAudit('SYSTEM', row.locked ? 'AUTO_FLAG_SAFE_LOCK' : 'AUTO_FLAG_REVIEW', `${row.id} · risk ${risk} · by ${actor}`)
    return row
  })
}

export const listQueue = () => readJson<QueueRow[]>(FILE, [])

export type ResolveResult = { ok: true; row: QueueRow } | { ok: false; status: number; error: string }

/** Every rule is enforced here, on the server. The browser only asks. */
export function resolveEntry(a: { id: string; status: 'approved' | 'detained'; note: string; pin?: string; actor: string; role: Role }): Promise<ResolveResult> {
  return exclusive('queue', async () => {
    const list = await readJson<QueueRow[]>(FILE, [])
    const row = list.find((x) => x.id === a.id)
    if (!row) return { ok: false, status: 404, error: 'Entry not found' }
    const deny = async (action: string, status: number, error: string): Promise<ResolveResult> => {
      await appendAudit(a.actor, action, `${a.id} · ${error}`)
      return { ok: false, status, error }
    }
    if (a.role === 'officer') return deny('DECISION_DENIED_CLEARANCE', 403, 'Officers cannot resolve queue entries')
    if (row.status !== 'pending') return deny('DECISION_CHANGE_DENIED', 409, `Already ${row.status}`)
    if (a.status === 'approved') {
      if (row.locked || row.risk >= HARD_LOCK_RISK) return deny('OVERRIDE_DENIED_SAFE_LOCK', 403, `Risk ${row.risk} >= ${HARD_LOCK_RISK}: SAFE-LOCK, nobody can release it`)
      if (row.risk < REVIEW_RISK) return deny('OVERRIDE_DENIED_NOT_NEEDED', 400, 'Entry does not need an override')
      if (clip(a.note, 200).trim().length < 10) return deny('OVERRIDE_DENIED_NO_REASON', 400, 'A written justification (10+ chars) is required')
      if (row.flaggedBy === a.actor) return deny('OVERRIDE_DENIED_SELF_APPROVAL', 403, 'You cannot approve a case you flagged yourself')
      if (!a.pin) return deny('OVERRIDE_DENIED_NO_PIN', 400, 'The supervisor PIN is required')
      const pin = await checkPin(a.actor, String(a.pin ?? ''))
      if (pin === 'locked') return deny('OVERRIDE_PIN_LOCKED', 429, 'PIN locked for 15 minutes after repeated failures')
      if (pin !== 'ok') return deny('OVERRIDE_PIN_FAILED', 403, pin === 'no-pin' ? 'No PIN is set for this operator' : 'Invalid PIN')
    }
    row.status = a.status
    row.resolvedBy = a.actor
    row.resolvedAt = Date.now()
    row.note = clip(a.note, 200)
    await writeJson(FILE, list)
    await appendAudit(a.actor, a.status === 'approved' ? 'OVERRIDE_APPROVED' : 'LOCK_AND_DETAIN', `${row.id}${row.note ? ` · ${row.note}` : ''}`)
    return { ok: true, row }
  })
}
