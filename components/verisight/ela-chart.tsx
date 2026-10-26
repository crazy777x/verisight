import type { ElaReport } from '@/lib/analysis'
import { KeyValue } from './primitives'

export function ElaChart({ report }: { report: ElaReport }) {
  const maxRow = Math.max(...report.rowVariance, 0.01)
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 sm:grid-cols-[auto_1fr]">
        <div>
          <p className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Block error heatmap (8×8)</p>
          <div
            className="grid w-40 grid-cols-8 gap-0.5 rounded border border-border bg-background/70 p-1"
            role="img"
            aria-label={`ELA heatmap with ${report.anomalousBlocks} anomalous blocks`}
          >
            {report.blocks.map((v, i) => (
              <span
                key={i}
                className="aspect-square rounded-[2px]"
                style={{
                  backgroundColor: v > 0.6 ? `rgb(255 99 120 / ${0.35 + v * 0.6})` : `rgb(62 207 142 / ${0.12 + v * 0.9})`,
                }}
              />
            ))}
          </div>
        </div>
        <div className="min-w-0">
          <p className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">Row variance σ²</p>
          <svg viewBox="0 0 200 110" className="h-40 w-full" role="img" aria-label="Per-row noise variance bar chart">
            {[0, 0.5, 1].map((t) => (
              <line key={t} x1="0" x2="200" y1={100 - t * 90} y2={100 - t * 90} stroke="rgb(148 163 184 / 0.12)" strokeDasharray="2 3" />
            ))}
            {report.rowVariance.map((v, i) => {
              const h = (v / maxRow) * 90
              const hot = v > 0.01
              return (
                <rect
                  key={i}
                  x={i * 25 + 4}
                  y={100 - h}
                  width="17"
                  height={Math.max(h, 1)}
                  rx="2"
                  fill={hot ? 'var(--destructive)' : 'var(--success)'}
                  opacity={hot ? 0.9 : 0.7}
                />
              )
            })}
            {report.rowVariance.map((_, i) => (
              <text key={i} x={i * 25 + 12.5} y="109" textAnchor="middle" fontSize="7" fill="rgb(139 155 180)" fontFamily="var(--font-mono)">
                R{i}
              </text>
            ))}
          </svg>
        </div>
      </div>
      <dl className="grid gap-x-6 sm:grid-cols-2">
        <KeyValue label="Mean error level" value={report.mean.toFixed(4)} />
        <KeyValue label="Global variance σ²" value={report.variance.toFixed(4)} tone={report.anomaly ? 'danger' : 'success'} />
        <KeyValue label="Peak block" value={report.peak.toFixed(3)} tone={report.peak > 0.6 ? 'danger' : undefined} />
        <KeyValue label="Anomalous blocks" value={`${report.anomalousBlocks} / 64`} tone={report.anomaly ? 'danger' : 'success'} />
      </dl>
      <p className="font-mono text-[11px] leading-relaxed text-muted-foreground">
        {!report.reliable
          ? `> ${report.note}`
          : report.anomaly
          ? '> Localized compression discontinuity detected. Region exhibits re-save signature inconsistent with surrounding substrate — probable splice or photo substitution.'
          : '> Error levels uniformly distributed across substrate. No re-compression boundaries detected.'}
      </p>
    </div>
  )
}
