import { Loader2, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

export type Tone = 'success' | 'danger' | 'warning' | 'neutral'

export function Panel({
  title,
  icon: Icon,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: string
  icon?: LucideIcon
  actions?: React.ReactNode
  children: React.ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section
      className={cn(
        'rounded-2xl border border-border bg-card shadow-[0_8px_30px_-12px_rgb(0_0_0/0.6),inset_0_1px_0_0_rgb(255_255_255/0.05)] backdrop-blur-xl',
        className,
      )}
    >
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold tracking-tight text-foreground">
            {Icon && <Icon className="size-4 text-primary" aria-hidden="true" />}
            {title}
          </h2>
          {actions}
        </header>
      )}
      <div className={cn('p-4', bodyClassName)}>{children}</div>
    </section>
  )
}

const toneClasses: Record<Tone, string> = {
  success: 'border-success/40 bg-success/10 text-success',
  danger: 'border-destructive/50 bg-destructive/10 text-destructive',
  warning: 'border-warning/40 bg-warning/10 text-warning',
  neutral: 'border-border bg-secondary/60 text-muted-foreground',
}

export function StatusBadge({
  tone,
  children,
  pulse,
  className,
}: {
  tone: Tone
  children: React.ReactNode
  pulse?: boolean
  className?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wide',
        toneClasses[tone],
        className,
      )}
    >
      <span
        className={cn(
          'size-1.5 rounded-full',
          tone === 'success' && 'bg-success',
          tone === 'danger' && 'bg-destructive',
          tone === 'warning' && 'bg-warning',
          tone === 'neutral' && 'bg-muted-foreground',
          pulse && 'animate-pulse',
        )}
        aria-hidden="true"
      />
      {children}
    </span>
  )
}

export function Spinner({ className, label = 'Loading' }: { className?: string; label?: string }) {
  return (
    <>
      <Loader2 className={cn('size-4 animate-spin', className)} aria-hidden="true" />
      <span className="sr-only">{label}</span>
    </>
  )
}

export function ActionButton({
  variant = 'primary',
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'danger' | 'ghost' | 'outline'
}) {
  return (
    <button
      type="button"
      {...props}
      className={cn(
        'inline-flex min-h-10 items-center justify-center gap-2 rounded-lg px-4 text-sm font-semibold transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring disabled:pointer-events-none disabled:opacity-40',
        variant === 'primary' && 'bg-primary text-primary-foreground hover:bg-primary/90',
        variant === 'danger' && 'bg-destructive text-white hover:bg-destructive/90',
        variant === 'outline' && 'border border-border bg-secondary/40 text-foreground hover:bg-secondary',
        variant === 'ghost' && 'text-muted-foreground hover:bg-secondary hover:text-foreground',
        className,
      )}
    />
  )
}

export function RiskGauge({ score, size = 168 }: { score: number; size?: number }) {
  const clamped = Math.max(0, Math.min(100, score))
  const r = 64
  const circumference = Math.PI * r
  const offset = circumference * (1 - clamped / 100)
  const color = clamped >= 70 ? 'var(--destructive)' : clamped >= 40 ? 'var(--warning)' : 'var(--success)'
  const label = clamped >= 70 ? 'HIGH RISK' : clamped >= 40 ? 'ELEVATED' : 'LOW RISK'
  return (
    <div className="relative flex flex-col items-center" style={{ width: size }}>
      <svg viewBox="0 0 160 92" className="w-full" role="img" aria-label={`Risk score ${clamped} of 100, ${label}`}>
        <path d="M 16 84 A 64 64 0 0 1 144 84" fill="none" stroke="rgb(148 163 184 / 0.15)" strokeWidth="10" strokeLinecap="round" />
        <path
          d="M 16 84 A 64 64 0 0 1 144 84"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 900ms cubic-bezier(.2,.8,.2,1), stroke 300ms', filter: `drop-shadow(0 0 6px ${color})` }}
        />
      </svg>
      <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
        <span className="font-mono text-4xl font-semibold tabular-nums" style={{ color }}>
          {clamped}
        </span>
        <span className="font-mono text-[10px] tracking-[0.2em] text-muted-foreground">{label}</span>
      </div>
    </div>
  )
}

export function StepList({
  steps,
  current,
  done,
}: {
  steps: { label: string; detail?: string }[]
  current: number
  done: boolean
}) {
  return (
    <ol className="flex flex-col gap-2">
      {steps.map((s, i) => {
        const state = done || i < current ? 'done' : i === current ? 'active' : 'pending'
        return (
          <li
            key={s.label}
            className={cn(
              'flex items-start gap-3 rounded-md border px-3 py-2 transition-colors',
              state === 'done' && 'border-success/25 bg-success/5',
              state === 'active' && 'border-primary/40 bg-primary/10',
              state === 'pending' && 'border-border bg-transparent opacity-60',
            )}
          >
            <span
              className={cn(
                'mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border font-mono text-[10px]',
                state === 'done' && 'border-success bg-success text-primary-foreground',
                state === 'active' && 'border-primary text-primary',
                state === 'pending' && 'border-border text-muted-foreground',
              )}
            >
              {state === 'active' ? <Spinner className="size-3" label={`Running ${s.label}`} /> : i + 1}
            </span>
            <div className="min-w-0">
              <p className="text-sm font-medium text-foreground">{s.label}</p>
              {s.detail && <p className="font-mono text-[11px] text-muted-foreground">{s.detail}</p>}
            </div>
          </li>
        )
      })}
    </ol>
  )
}

export function ProgressBar({ value, tone = 'success' }: { value: number; tone?: Tone }) {
  return (
    <div
      className="h-1.5 w-full overflow-hidden rounded-full bg-secondary"
      role="progressbar"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className={cn(
          'h-full rounded-full transition-[width] duration-300',
          tone === 'success' && 'bg-success',
          tone === 'danger' && 'bg-destructive',
          tone === 'warning' && 'bg-warning',
          tone === 'neutral' && 'bg-muted-foreground',
        )}
        style={{ width: `${value}%` }}
      />
    </div>
  )
}

export function AlertBanner({
  tone,
  title,
  children,
  icon: Icon,
}: {
  tone: 'success' | 'danger' | 'warning'
  title: string
  children?: React.ReactNode
  icon: LucideIcon
}) {
  return (
    <div
      role={tone === 'danger' ? 'alert' : 'status'}
      className={cn(
        'flex items-start gap-3 rounded-lg border px-4 py-3',
        tone === 'success' && 'glow-success border-success/40 bg-success/10',
        tone === 'danger' && 'glow-danger border-destructive/50 bg-destructive/10',
        tone === 'warning' && 'border-warning/40 bg-warning/10',
      )}
    >
      <Icon
        className={cn(
          'mt-0.5 size-5 shrink-0',
          tone === 'success' && 'text-success',
          tone === 'danger' && 'text-destructive',
          tone === 'warning' && 'text-warning',
        )}
        aria-hidden="true"
      />
      <div className="min-w-0">
        <p
          className={cn(
            'font-mono text-sm font-semibold tracking-wide',
            tone === 'success' && 'text-success',
            tone === 'danger' && 'text-destructive',
            tone === 'warning' && 'text-warning',
          )}
        >
          {title}
        </p>
        {children && <div className="mt-0.5 text-sm text-muted-foreground">{children}</div>}
      </div>
    </div>
  )
}

export function KeyValue({ label, value, mono = true, tone }: { label: string; value: React.ReactNode; mono?: boolean; tone?: Tone }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-border/60 py-1.5 last:border-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd
        className={cn(
          'truncate text-right text-xs',
          mono && 'font-mono',
          tone === 'success' && 'text-success',
          tone === 'danger' && 'text-destructive',
          tone === 'warning' && 'text-warning',
          !tone && 'text-foreground',
        )}
      >
        {value}
      </dd>
    </div>
  )
}
