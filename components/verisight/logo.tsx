import { ScanEye } from 'lucide-react'

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className="flex size-8 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
        <ScanEye className="size-4.5" aria-hidden="true" />
      </span>
      {!compact && (
        <span className="flex flex-col leading-none">
          <span className="text-sm font-semibold tracking-wide text-foreground">VeriSight</span>
          <span className="mt-1 text-[11px] tracking-wide text-muted-foreground">
            Border identity engine
          </span>
        </span>
      )}
    </div>
  )
}
