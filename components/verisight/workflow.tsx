'use client'

import { ArrowRight, Check } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useStore, type TabId, type WorkflowStep } from './store'

const FLOW: { id: WorkflowStep; tab: TabId; label: string }[] = [
  { id: 'triage', tab: 'triage', label: '1 · Document Triage' },
  { id: 'qr', tab: 'qr', label: '2 · QR & Signature' },
  { id: 'biometric', tab: 'biometric', label: '3 · Biometric Match' },
]

/** Slim progress bar under the tabs: shows which verification steps are finished and lets the officer jump. */
export function WorkflowStepper() {
  const { steps, tab, goTo } = useStore()
  return (
    <ol aria-label="Verification workflow" className="mx-auto flex max-w-[1600px] items-center gap-2 overflow-x-auto px-3 py-2 text-xs sm:px-6">
      {FLOW.map((f, i) => {
        const done = steps[f.id]
        const active = tab === f.tab
        return (
          <li key={f.id} className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={() => goTo(f.tab)}
              className={cn(
                'flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono transition-colors',
                done ? 'border-success/50 bg-success/10 text-success' : active ? 'border-primary/60 bg-primary/10 text-foreground' : 'border-border text-muted-foreground hover:text-foreground',
              )}
            >
              {done && <Check className="size-3" aria-hidden="true" />}
              {f.label}
            </button>
            {i < FLOW.length - 1 && <ArrowRight className="size-3 text-muted-foreground" aria-hidden="true" />}
          </li>
        )
      })}
    </ol>
  )
}

/**
 * "Next step" prompt. It NEVER changes the tab by itself: the officer stays on the page as long as needed
 * and presses the button when ready. (The earlier auto-countdown jumped away while people were still reading.)
 */
export function AutoAdvance({ enabled, from, to, label }: { enabled: boolean; from: TabId; to: TabId; label: string; seconds?: number; resetKey?: string }) {
  const { goTo, tab } = useStore()
  if (!enabled || tab !== from) return null
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-xl border border-primary/30 bg-primary/5 px-4 py-3" role="status">
      <p className="text-sm text-foreground">
        Step complete. Review everything on this page, then continue when you are ready.
      </p>
      <div className="ml-auto">
        <button type="button" onClick={() => goTo(to)} className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground shadow-sm transition hover:brightness-110">
          Next: {label} <ArrowRight className="size-3.5" aria-hidden="true" />
        </button>
      </div>
    </div>
  )
}
