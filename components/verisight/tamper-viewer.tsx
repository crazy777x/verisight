'use client'

import { useEffect, useRef, useState } from 'react'
import { Crosshair } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { OcrWord, TamperReport } from '@/lib/tamper'
import { Panel, StatusBadge } from './primitives'

/** Shows the document itself with every suspected edit boxed and numbered. */
export function TamperViewer({ page, report, words }: { page: HTMLCanvasElement; report: TamperReport; words: OcrWord[] }) {
  const ref = useRef<HTMLCanvasElement>(null)
  const [showRegions, setShowRegions] = useState(true)
  const [showHeat, setShowHeat] = useState(false)
  const [showText, setShowText] = useState(false)
  const [sel, setSel] = useState<number | null>(null)

  useEffect(() => {
    const cv = ref.current
    if (!cv) return
    const W = Math.min(1200, page.width)
    const H = Math.round((page.height * W) / page.width)
    cv.width = W
    cv.height = H
    const ctx = cv.getContext('2d')!
    ctx.drawImage(page, 0, 0, W, H)

    if (showHeat) {
      const cw = W / report.cols
      const ch = H / report.rows
      report.heat.forEach((v, k) => {
        if (v <= 0) return
        ctx.fillStyle = `rgba(255, 45, 85, ${0.18 + v * 0.5})`
        ctx.fillRect((k % report.cols) * cw, Math.floor(k / report.cols) * ch, cw, ch)
      })
    }
    if (showText) {
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.9)'
      ctx.lineWidth = 1
      for (const w of words) ctx.strokeRect(w.x0 * W, w.y0 * H, (w.x1 - w.x0) * W, (w.y1 - w.y0) * H)
    }
    if (showRegions) {
      const fs = Math.max(13, Math.round(W / 55))
      ctx.font = `700 ${fs}px ui-monospace, monospace`
      for (const r of report.regions) {
        const x = r.x * W
        const y = r.y * H
        const w = Math.max(10, r.w * W)
        const h = Math.max(10, r.h * H)
        const active = sel === r.id
        ctx.fillStyle = active ? 'rgba(255,45,85,0.28)' : 'rgba(255,45,85,0.14)'
        ctx.fillRect(x, y, w, h)
        ctx.strokeStyle = '#ff2d55'
        ctx.lineWidth = active ? 5 : 3
        ctx.strokeRect(x, y, w, h)
        const tag = `#${r.id} ${Math.round(r.score * 100)}%`
        const tw = ctx.measureText(tag).width + 10
        const ty = y - fs - 6 < 0 ? y + h : y - fs - 6
        ctx.fillStyle = '#ff2d55'
        ctx.fillRect(x, ty, tw, fs + 6)
        ctx.fillStyle = '#fff'
        ctx.textBaseline = 'top'
        ctx.fillText(tag, x + 5, ty + 3)
      }
    }
  }, [page, report, words, showRegions, showHeat, showText, sel])

  const toggle = (label: string, on: boolean, set: (v: boolean) => void) => (
    <button
      type="button"
      onClick={() => set(!on)}
      aria-pressed={on}
      className={cn('min-h-9 rounded-md border px-3 text-xs font-medium transition-colors', on ? 'border-primary bg-primary/15 text-foreground' : 'border-border text-muted-foreground hover:text-foreground')}
    >
      {label}
    </button>
  )

  return (
    <Panel
      title="Where was it edited?"
      icon={Crosshair}
      actions={<StatusBadge tone={report.regions.length ? 'danger' : 'success'}>{report.regions.length ? `${report.regions.length} suspect area${report.regions.length > 1 ? 's' : ''}` : 'No edited area'}</StatusBadge>}
    >
      <div className="mb-3 flex flex-wrap gap-2">
        {toggle('Boxes', showRegions, setShowRegions)}
        {toggle('Heatmap', showHeat, setShowHeat)}
        {toggle('OCR text boxes', showText, setShowText)}
      </div>
      <div className="overflow-hidden rounded-md border border-border bg-background/70">
        <canvas ref={ref} className="h-auto w-full" role="img" aria-label="Document with suspected edited regions highlighted" />
      </div>

      {report.regions.length > 0 ? (
        <ol className="mt-4 flex flex-col gap-2">
          {report.regions.map((r) => (
            <li key={r.id}>
              <button
                type="button"
                onClick={() => setSel(sel === r.id ? null : r.id)}
                className={cn('w-full rounded-md border px-3 py-2.5 text-left transition-colors', sel === r.id ? 'border-destructive bg-destructive/15' : 'border-destructive/40 bg-destructive/[0.06] hover:bg-destructive/10')}
              >
                <p className="text-base font-semibold text-destructive">
                  #{r.id} · {r.kinds.join(' + ')} · {Math.round(r.score * 100)}%
                </p>
                {r.fields.length > 0 && <p className="mt-0.5 text-sm font-medium text-foreground">Edited text near: “{r.fields.join(' ')}”</p>}
                <p className="mt-0.5 text-xs text-muted-foreground">{r.note}</p>
              </button>
            </li>
          ))}
        </ol>
      ) : (
        <p className="mt-3 text-xs text-muted-foreground">No region stood out from its surroundings. This does not prove the document is original: a clean re-photograph or a high-quality edit can leave no pixel trace.</p>
      )}
      <p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">
        {report.elaReliable ? 'Source is an untouched camera or scanner JPEG: compression analysis is reliable.' : 'Source is a screenshot, export or PDF render: compression traces are weak, so these boxes are advisory only and never decide the verdict.'}
      </p>
    </Panel>
  )
}
