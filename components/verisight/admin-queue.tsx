'use client'

import { useEffect, useRef, useState } from 'react'
import {
  Ban,
  ChevronRight,
  ClipboardList,
  KeyRound,
  ListChecks,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useStore, type FlagReason, type QueueEntry } from './store'
import { HARD_LOCK_RISK } from '@/lib/verdict'
import { ActionButton, Panel, RiskGauge, Spinner, StatusBadge } from './primitives'

const REASON_META: Record<FlagReason['code'], string> = {
  ELA_ANOMALY: 'ELA anomaly',
  MRZ_CHECKSUM: 'MRZ checksum',
  SIG_INVALID: 'Signature invalid',
  QR_MISMATCH: 'QR mismatch',
  SIGNED_DATA_MISMATCH: 'Signed data differs from print',
  FACE_MISMATCH: 'Face mismatch',
  LIVENESS_FAIL: 'Liveness fail',
  AADHAAR_CHECKSUM: 'Aadhaar number invalid',
  DOC_SIG_BROKEN: 'Document signature broken',
  UNREADABLE: 'Unreadable / unidentified',
  AI_GENERATED: 'AI-generated marker',
  META_SUSPECT: 'Metadata suspicious',
  SOURCE_NOTE: 'Source note',
  UNVERIFIED: 'Not issuer-verified',
}


function ago(ts: number) {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

export function AdminQueue() {
  const { queue, audit, session } = useStore()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [filter, setFilter] = useState<'pending' | 'all'>('pending')
  const selected = queue.find((q) => q.id === selectedId) ?? null
  const rows = filter === 'pending' ? queue.filter((q) => q.status === 'pending') : queue

  const pending = queue.filter((q) => q.status === 'pending')
  const stats = [
    { label: 'Awaiting clearance', value: pending.length, tone: 'text-destructive' },
    { label: 'Overrides approved', value: queue.filter((q) => q.status === 'approved').length, tone: 'text-success' },
    { label: 'Locked & detained', value: queue.filter((q) => q.status === 'detained').length, tone: 'text-warning' },
    {
      label: 'Mean risk (pending)',
      value: pending.length ? Math.round(pending.reduce((a, b) => a + b.risk, 0) / pending.length) : 0,
      tone: 'text-foreground',
    },
  ]

  return (
    <div className="flex flex-col gap-5">
      <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {stats.map((s) => (
          <div key={s.label} className="rounded-lg border border-border bg-card p-4 backdrop-blur-xl">
            <dt className="text-[11px] uppercase tracking-wider text-muted-foreground">{s.label}</dt>
            <dd className={cn('mt-1 font-mono text-3xl font-semibold tabular-nums', s.tone)}>{s.value}</dd>
          </div>
        ))}
      </dl>

      <div className="grid gap-5 2xl:grid-cols-[1fr_420px]">
        <Panel
          title="Command Center Queue"
          icon={ListChecks}
          bodyClassName="p-0"
          actions={
            <div className="flex rounded-md border border-border p-0.5" role="group" aria-label="Filter queue">
              {(['pending', 'all'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  aria-pressed={filter === f}
                  onClick={() => setFilter(f)}
                  className={cn(
                    'rounded px-2.5 py-1 font-mono text-[11px] uppercase',
                    filter === f ? 'bg-secondary text-foreground' : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="border-b border-border text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Entry</th>
                  <th className="px-4 py-2.5 font-medium">Subject</th>
                  <th className="px-4 py-2.5 font-medium">Flags</th>
                  <th className="px-4 py-2.5 font-medium">Risk</th>
                  <th className="px-4 py-2.5 font-medium">Status</th>
                  <th className="px-4 py-2.5 font-medium">
                    <span className="sr-only">Inspect</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-10 text-center text-sm text-muted-foreground">
                      Queue clear. No entries awaiting manual clearance.
                    </td>
                  </tr>
                )}
                {rows.map((q) => (
                  <tr
                    key={q.id}
                    className={cn(
                      'cursor-pointer border-b border-border/60 transition-colors hover:bg-secondary/40',
                      selectedId === q.id && 'bg-secondary/50',
                    )}
                    onClick={() => setSelectedId(q.id)}
                  >
                    <td className="px-4 py-3">
                      <p className="font-mono text-xs text-foreground">{q.id}</p>
                      <p className="font-mono text-[11px] text-muted-foreground">
                        {q.lane} · {ago(q.flaggedAt)}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-sm text-foreground">{q.subject}</p>
                      <p className="font-mono text-[11px] text-muted-foreground">
                        {q.docType} · {q.docNo}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {q.reasons.map((r) => (
                          <StatusBadge key={r.code} tone="danger" className="text-[10px]">
                            {REASON_META[r.code]}
                          </StatusBadge>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'font-mono text-lg font-semibold tabular-nums',
                          q.risk >= 70 ? 'text-destructive' : q.risk >= 40 ? 'text-warning' : 'text-success',
                        )}
                      >
                        {q.risk}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge
                        tone={q.status === 'pending' ? 'warning' : q.status === 'approved' ? 'success' : 'danger'}
                        pulse={q.status === 'pending'}
                      >
                        {q.status}
                      </StatusBadge>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedId(q.id)
                        }}
                        className="inline-flex size-9 items-center justify-center rounded-md text-muted-foreground hover:bg-secondary hover:text-foreground"
                      >
                        <ChevronRight className="size-4" aria-hidden="true" />
                        <span className="sr-only">Inspect {q.id}</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Audit Trail" icon={ScrollText} bodyClassName="max-h-[520px] overflow-y-auto p-0">
          {audit.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No events recorded this session.</p>
          ) : (
            <ol className="divide-y divide-border/60 font-mono text-[11px]">
              {audit.map((a) => (
                <li key={a.id} className="flex flex-col gap-0.5 px-4 py-2.5">
                  <div className="flex items-center justify-between gap-3">
                    <span
                      className={cn(
                        'font-semibold',
                        /DENIED|DETAIN|LOCK|FLAG|SEAL|TAMPER/.test(a.action)
                          ? 'text-destructive'
                          : /APPROVED|VERIFIED|CLEARED/.test(a.action)
                            ? 'text-success'
                            : 'text-foreground',
                      )}
                    >
                      {a.action}
                    </span>
                    <span className="text-muted-foreground">{new Date(a.at).toISOString().slice(11, 19)}Z</span>
                  </div>
                  <span className="truncate text-muted-foreground">
                    {a.actor} → {a.target}
                  </span>
                  <span className="text-muted-foreground/60">chain#{a.hash}</span>
                </li>
              ))}
            </ol>
          )}
        </Panel>
      </div>

      {selected && (
        <InspectionDrawer entry={selected} canOverride={!!session && session.role !== 'officer'} onClose={() => setSelectedId(null)} />
      )}
    </div>
  )
}

function InspectionDrawer({
  entry,
  canOverride,
  onClose,
}: {
  entry: QueueEntry
  canOverride: boolean
  onClose: () => void
}) {
  const { resolve } = useStore()
  const [mode, setMode] = useState<'view' | 'pin' | 'detain'>('view')
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    closeRef.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const resolved = entry.status !== 'pending'
  // anti-bribery: the system decides this from the risk score, never the operator. Also forced if the seal does not match.
  const hardLocked = entry.locked || entry.risk >= HARD_LOCK_RISK

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button type="button" aria-label="Close inspection drawer" className="absolute inset-0 bg-background/70 backdrop-blur-sm" onClick={onClose} />
      <aside
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
        className="relative flex h-full w-full max-w-lg flex-col border-l border-border bg-popover shadow-2xl animate-in slide-in-from-right duration-200"
      >
        <header className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div>
            <p className="font-mono text-xs text-muted-foreground">
              {entry.id} · {entry.lane}
            </p>
            <h2 id="drawer-title" className="mt-1 text-lg font-semibold text-foreground">
              {entry.subject}
            </h2>
            <p className="font-mono text-xs text-muted-foreground">
              {entry.docType} · {entry.docNo}
            </p>
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            className="flex size-10 items-center justify-center rounded-md border border-border text-muted-foreground hover:text-foreground"
          >
            <X className="size-4" aria-hidden="true" />
            <span className="sr-only">Close</span>
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-5 py-5">
          <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-background/50 p-4">
            <RiskGauge score={entry.risk} size={140} />
            <div className="flex flex-col items-end gap-2">
              <StatusBadge
                tone={entry.status === 'pending' ? 'warning' : entry.status === 'approved' ? 'success' : 'danger'}
                pulse={entry.status === 'pending'}
              >
                {entry.status}
              </StatusBadge>
              <p className="font-mono text-[11px] text-muted-foreground">Gate: {entry.status === 'approved' ? 'RELEASED' : hardLocked ? 'SAFE-LOCKED (permanent)' : 'HELD FOR REVIEW'}</p>
            </div>
          </div>

          {hardLocked && !resolved && (
            <div role="alert" className="glow-danger mt-4 rounded-lg border-2 border-destructive bg-destructive/10 p-4">
              <p className="flex items-center gap-2 font-mono text-sm font-bold text-destructive">
                <Ban className="size-4" aria-hidden="true" /> ANTI-BRIBERY SAFE-LOCK ACTIVE
              </p>
              <p className="mt-1 text-sm text-foreground">
                Risk {entry.risk}/100 is at or above {HARD_LOCK_RISK}. The system locked this decision. No officer, investigator or admin can release it, whatever the justification or PIN.
                {entry.locked && ' (Record integrity seal did not match: lock was forced.)'}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">The only available action is escalation: Permanent Lock &amp; Detain. A fresh, genuine document must be submitted as a new case.</p>
            </div>
          )}
          {!hardLocked && !resolved && (
            <div className="mt-4 rounded-lg border border-warning/50 bg-warning/10 p-3 text-xs text-foreground">
              Risk {entry.risk}/100 is below the lock limit ({HARD_LOCK_RISK}). A supervisor may override with PIN + written justification. The override is permanently logged.
            </div>
          )}

          <h3 className="mb-3 mt-6 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            <ClipboardList className="size-3.5 text-primary" aria-hidden="true" />
            Why this entry was flagged
          </h3>
          <ul className="flex flex-col gap-2">
            {entry.reasons.map((r) => (
              <li key={r.code} className="rounded-md border border-destructive/30 bg-destructive/5 p-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="size-4 text-destructive" aria-hidden="true" />
                  <span className="text-sm font-medium text-foreground">{REASON_META[r.code]}</span>
                  <span className="ml-auto font-mono text-[10px] text-muted-foreground">{r.code}</span>
                </div>
                <p className="mt-1.5 font-mono text-xs leading-relaxed text-muted-foreground">{r.detail}</p>
              </li>
            ))}
          </ul>

          {mode === 'pin' && (
            <PinForm
              onCancel={() => setMode('view')}
              onConfirm={async (note, pin) => {
                const r = await resolve(entry.id, 'approved', note, pin)
                setMode('view')
                return r
              }}
            />
          )}
          {mode === 'detain' && (
            <div className="mt-6 rounded-lg border border-destructive/50 bg-destructive/10 p-4" role="alertdialog" aria-labelledby="detain-title">
              <p id="detain-title" className="font-mono text-sm font-semibold text-destructive">
                CONFIRM PERMANENT LOCK & DETAIN
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                Gate {entry.lane} stays sealed and the subject is referred to custody. This action is irreversible and
                will be signed into the audit chain.
              </p>
              <div className="mt-4 flex gap-2">
                <ActionButton variant="outline" onClick={() => setMode('view')}>
                  Cancel
                </ActionButton>
                <ActionButton
                  variant="danger"
                  className="flex-1"
                  onClick={async () => {
                    const r = await resolve(entry.id, 'detained', 'referred to custody')
                    if (!r.ok) window.alert(`Refused by the server: ${r.error}`)
                    setMode('view')
                  }}
                >
                  <Ban className="size-4" aria-hidden="true" />
                  Confirm detain
                </ActionButton>
              </div>
            </div>
          )}
        </div>

        <footer className="border-t border-border px-5 py-4">
          {resolved ? (
            <p className="text-center font-mono text-xs text-muted-foreground">
              Entry resolved as <span className="text-foreground">{entry.status.toUpperCase()}</span>. Logged to audit chain.
            </p>
          ) : (
            <div className="flex flex-col gap-2 sm:flex-row">
              <ActionButton
                className="flex-1"
                aria-label="Approve override (requires PIN)"
                onClick={() => setMode('pin')}
                disabled={!canOverride || hardLocked || mode !== 'view'}
                title={hardLocked ? 'Disabled by Safe-Lock: risk too high' : canOverride ? undefined : 'Investigator / Admin clearance required'}
              >
                {hardLocked ? <Ban className="size-4" aria-hidden="true" /> : <KeyRound className="size-4" aria-hidden="true" />}
                <span className="whitespace-nowrap">{hardLocked ? 'Override disabled' : 'Approve Override'}</span>
                {!hardLocked && <span className="font-mono text-[10px] opacity-70">PIN</span>}
              </ActionButton>
              <ActionButton variant="danger" className="flex-1" onClick={() => setMode('detain')} disabled={mode !== 'view'}>
                <Ban className="size-4" aria-hidden="true" />
                Permanent Lock & Detain
              </ActionButton>
            </div>
          )}
          {!canOverride && !resolved && !hardLocked && (
            <p className="mt-2 text-center text-[11px] text-muted-foreground">Override requires L3 Investigator or L5 Admin clearance.</p>
          )}
        </footer>
      </aside>
    </div>
  )
}

function PinForm({ onCancel, onConfirm }: { onCancel: () => void; onConfirm: (note: string, pin: string) => Promise<{ ok: boolean; error?: string }> }) {
  const [pin, setPin] = useState('')
  const [justification, setJustification] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [attempts, setAttempts] = useState(0)
  const [busy, setBusy] = useState(false)
  const locked = false // PIN lockout is enforced by the server (3 wrong PINs = 15 minutes)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (justification.trim().length < 10) {
      setError('Provide a justification of at least 10 characters.')
      return
    }
    setBusy(true)
    const r = await onConfirm(justification.trim().slice(0, 200), pin)
    setBusy(false)
    if (!r.ok) {
      setPin('')
      setAttempts((n) => n + 1)
      setError(r.error ?? 'Refused by the server')
    }
  }

  return (
    <form onSubmit={submit} className="mt-6 rounded-lg border border-primary/40 bg-primary/5 p-4" noValidate>
      <p className="flex items-center gap-2 font-mono text-sm font-semibold text-primary">
        <ShieldCheck className="size-4" aria-hidden="true" />
        SUPERVISOR OVERRIDE AUTHORIZATION
      </p>
      <label className="mt-4 flex flex-col gap-1.5">
        <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Justification</span>
        <textarea
          value={justification}
          onChange={(e) => setJustification(e.target.value)}
          rows={2}
          disabled={locked || busy}
          placeholder="e.g. Verified with issuing consulate via secure line"
          className="resize-none rounded-md border border-input bg-background/60 p-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
        />
      </label>
      <label className="mt-3 flex flex-col gap-1.5">
        <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Admin PIN</span>
        <input
          type="password"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          value={pin}
          onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))}
          disabled={locked || busy}
          className="h-11 rounded-md border border-input bg-background/60 px-3 text-center font-mono text-lg tracking-[0.6em] text-foreground focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
          aria-describedby="pin-hint"
        />
        <span id="pin-hint" className="font-mono text-[10px] text-muted-foreground">
          Every override is written to the tamper-evident audit chain with your operator ID.
        </span>
      </label>
      {error && (
        <p role="alert" className="mt-2 text-xs text-destructive">
          {error}
        </p>
      )}
      <div className="mt-4 flex gap-2">
        <ActionButton variant="outline" onClick={onCancel}>
          Cancel
        </ActionButton>
        <ActionButton type="submit" className="flex-1" disabled={locked || busy || pin.length < 4}>
          {busy ? <Spinner label="Verifying PIN" /> : <KeyRound className="size-4" aria-hidden="true" />}
          Authorize override
        </ActionButton>
      </div>
    </form>
  )
}
