'use client'

import { AlertOctagon, AlertTriangle, ShieldQuestion } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Verdict } from '@/lib/verdict'
import { actionFor, isTamperEvidence } from '@/lib/policy'

const SEV = {
  critical: { label: 'CRITICAL', cls: 'border-destructive/60 bg-destructive/10 text-destructive' },
  high: { label: 'HIGH', cls: 'border-warning/60 bg-warning/10 text-warning' },
  medium: { label: 'MEDIUM', cls: 'border-border bg-secondary/50 text-foreground' },
  info: { label: 'INFO', cls: 'border-border bg-secondary/40 text-muted-foreground' },
} as const

export function VerdictCard({ verdict, elapsedMs, queueId }: { verdict: Verdict; elapsedMs: number; queueId?: string }) {
  const bad = verdict.level === 'LIKELY_FORGED'
  const mid = verdict.level === 'SUSPICIOUS'
  const Icon = bad ? AlertOctagon : mid ? AlertTriangle : ShieldQuestion
  return (
    <section
      role={bad ? 'alert' : 'status'}
      className={cn('rounded-lg border-2 p-5', bad ? 'glow-danger border-destructive bg-destructive/10' : mid ? 'border-warning bg-warning/10' : 'border-success/50 bg-success/10')}
    >
      <div className="flex items-start gap-3">
        <Icon className={cn('mt-1 size-8 shrink-0', bad ? 'text-destructive' : mid ? 'text-warning' : 'text-success')} aria-hidden="true" />
        <div className="min-w-0">
          <h2 className={cn('text-xl font-bold leading-tight tracking-wide sm:text-3xl', bad ? 'text-destructive' : mid ? 'text-warning' : 'text-success')}>{verdict.headline}</h2>
          <p className="mt-1 text-sm text-foreground sm:text-base">{verdict.sub}</p>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground">
            Risk {verdict.risk}/100 · {(elapsedMs / 1000).toFixed(2)}s{queueId ? ` · queued as ${queueId}` : ''}
          </p>
        </div>
      </div>

      {verdict.findings.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-2 text-xs font-bold tracking-wider text-foreground">
            {bad ? 'FAIL REASONS' : mid ? 'REVIEW REASONS' : 'CHECK FINDINGS'}
          </h3>
          <ul className="flex flex-col gap-2">
            {verdict.findings.map((f, i) => {
              const action = actionFor(f.code, f.severity)
              const label = action === 'LOCK' ? 'FAIL SIGNAL' : action === 'REVIEW' ? 'REVIEW REASON' : 'SUPPORTING SIGNAL'
              return (
                <li key={i} className={cn('rounded-md border px-3 py-2.5', isTamperEvidence(f.code, f.severity) ? SEV[f.severity].cls : 'border-warning/50 bg-warning/5 text-warning')}>
                  <p className="flex flex-wrap items-center gap-2 text-base font-semibold sm:text-lg">
                    <span className="rounded bg-background/60 px-1.5 py-0.5 font-mono text-[10px] tracking-wider">{label}</span>
                    {f.title}
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-foreground/80 sm:text-sm">{f.detail}</p>
                  {f.regionIds && f.regionIds.length > 0 && <p className="mt-1 font-mono text-[11px]">See highlighted area {f.regionIds.map((r) => `#${r}`).join(', ')} on the document below</p>}
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </section>
  )
}
