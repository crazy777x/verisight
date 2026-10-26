'use client'

import { Database, Download, Trash2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useStore, type CaseRecord } from './store'
import { ActionButton, Panel, StatusBadge } from './primitives'

function save(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
const csvCell = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`

export function RecordsPanel() {
  const { cases, deleteCase, clearCases } = useStore()

  const exportJson = () => save(`verisight-cases-${Date.now()}.json`, JSON.stringify(cases.map(({ thumb, ...c }) => c), null, 2), 'application/json')
  const exportCsv = () => {
    const head = ['id', 'time', 'operator', 'file', 'sha256', 'docType', 'subject', 'docNo', 'risk', 'verdict', 'findings', 'editedRegions']
    const rows = cases.map((c) => [c.id, new Date(c.at).toISOString(), c.operator, c.fileName, c.fileDigest, c.docType, c.subject, c.docNo, c.risk, c.headline, c.findings.map((f) => f.title).join(' | '), c.regions.length])
    save(`verisight-cases-${Date.now()}.csv`, [head, ...rows].map((r) => r.map(csvCell).join(',')).join('\n'), 'text/csv')
  }
  const one = (c: CaseRecord) => {
    const { thumb, ...rest } = c
    save(`${c.id}.json`, JSON.stringify(rest, null, 2), 'application/json')
  }

  return (
    <div className="flex flex-col gap-5">
      <Panel
        title="Saved Case Records"
        icon={Database}
        actions={<StatusBadge tone="neutral">{cases.length} saved</StatusBadge>}
      >
        <p className="mb-4 text-xs leading-relaxed text-muted-foreground">
          Every triage is saved automatically in <span className="font-mono text-foreground">this browser (localStorage)</span>. Nothing is uploaded to a server. Aadhaar numbers are stored masked (last 4 digits only). Clearing browser data deletes the records, so export regularly.
        </p>
        <div className="flex flex-wrap gap-2">
          <ActionButton variant="outline" onClick={exportJson} disabled={!cases.length}>
            <Download className="size-4" aria-hidden="true" /> Export JSON
          </ActionButton>
          <ActionButton variant="outline" onClick={exportCsv} disabled={!cases.length}>
            <Download className="size-4" aria-hidden="true" /> Export CSV
          </ActionButton>
          <ActionButton
            variant="ghost"
            onClick={() => {
              if (window.confirm('Delete ALL saved case records from this browser?')) clearCases()
            }}
            disabled={!cases.length}
          >
            <Trash2 className="size-4" aria-hidden="true" /> Clear all
          </ActionButton>
        </div>
      </Panel>

      {cases.length === 0 ? (
        <Panel className="flex min-h-48 items-center justify-center" bodyClassName="text-center text-sm text-muted-foreground">
          No cases yet. Run a triage and it will appear here.
        </Panel>
      ) : (
        <ul className="grid gap-4 lg:grid-cols-2">
          {cases.map((c) => (
            <li key={c.id}>
              <Panel
                title={c.id}
                actions={<StatusBadge tone={c.risk >= 70 ? 'danger' : c.risk >= 40 ? 'warning' : 'success'}>Risk {c.risk}</StatusBadge>}
              >
                <div className="flex gap-3">
                  {c.thumb ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img src={c.thumb} alt="" className="h-24 w-auto max-w-[40%] rounded border border-border object-contain" />
                  ) : (
                    <div className="h-24 w-32 rounded border border-dashed border-border" aria-hidden="true" />
                  )}
                  <div className="min-w-0 flex-1">
                    <p className={cn('text-sm font-bold', c.risk >= 70 ? 'text-destructive' : c.risk >= 40 ? 'text-warning' : 'text-success')}>{c.headline}</p>
                    <p className="truncate font-mono text-[11px] text-muted-foreground">{c.fileName}</p>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      {c.docType} · {c.docNo} · {new Date(c.at).toLocaleString()}
                    </p>
                    <p className="mt-1 text-xs text-foreground">{c.regions.length} edited area(s) · QR {c.qr.found ? c.qr.kind : 'not found'}</p>
                  </div>
                </div>
                {c.findings.length > 0 && (
                  <ul className="mt-3 list-disc pl-5 text-xs text-muted-foreground">
                    {c.findings.slice(0, 4).map((f, i) => (
                      <li key={i}>{f.title}</li>
                    ))}
                  </ul>
                )}
                <div className="mt-3 flex gap-2">
                  <ActionButton variant="outline" className="min-h-9 text-xs" onClick={() => one(c)}>
                    <Download className="size-3.5" aria-hidden="true" /> Report
                  </ActionButton>
                  <ActionButton variant="ghost" className="min-h-9 text-xs" onClick={() => deleteCase(c.id)}>
                    <Trash2 className="size-3.5" aria-hidden="true" /> Delete
                  </ActionButton>
                </div>
              </Panel>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
