'use client'

import { Compass } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ALL_CHECKS, CATEGORY_LABEL, CHECK_LABEL, PURPOSES, docTypeById, docTypesForPurpose, evaluateSelection, purposeById, type DocTypeId, type PurposeId } from '@/lib/purposes'
import { useStore } from './store'
import { Panel, StatusBadge } from './primitives'

const selectCls =
  'h-11 w-full rounded-md border border-input bg-background/60 px-3 text-sm text-foreground focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30'

/**
 * STEP 1 (verification purpose) + STEP 2 (document type).
 * Changing either never clears an uploaded file: the file lives in the panel that owns it.
 * A purpose or a type is only a RULE SELECTOR. It never establishes that a document is genuine.
 */
export function SelectionPanel({ disabled }: { disabled?: boolean }) {
  const { selection, setSelection, suggestion, setSuggestion } = useStore()
  const purpose = purposeById(selection.purpose)
  const { primary, other } = docTypesForPurpose(selection.purpose)
  const sel = evaluateSelection(selection.purpose, selection.docType)
  const grouped = (list: typeof primary) => {
    const cats = [...new Set(list.map((d) => d.category))]
    return cats.map((c) => (
      <optgroup key={c} label={CATEGORY_LABEL[c]}>
        {list.filter((d) => d.category === c).map((d) => (
          <option key={d.id} value={d.id}>
            {d.label}
          </option>
        ))}
      </optgroup>
    ))
  }
  const suggested = suggestion?.id ? docTypeById(suggestion.id) : null

  return (
    <Panel title="Select verification purpose and document type" icon={Compass}>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="flex flex-col gap-1.5">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Step 1 · Verification purpose</span>
          <select value={selection.purpose} disabled={disabled} onChange={(e) => setSelection({ purpose: e.target.value as PurposeId })} className={selectCls} aria-label="Verification purpose">
            {PURPOSES.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
          <span className="text-xs text-muted-foreground">{purpose.hint}</span>
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Step 2 · Document type</span>
          <select value={selection.docType} disabled={disabled} onChange={(e) => setSelection({ docType: e.target.value as DocTypeId })} className={selectCls} aria-label="Document type">
            <option value="auto">Auto-detect Document Type (suggests, you confirm)</option>
            {grouped(primary)}
            {other.length > 0 && <optgroup label="Other document types">{other.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}</optgroup>}
            <option value="other">Other / Unknown Document</option>
          </select>
          <span className="text-xs text-muted-foreground">Usual documents for this purpose are listed first. All other types stay available.</span>
        </label>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
        <StatusBadge tone="neutral">Purpose: {purpose.label}</StatusBadge>
        <StatusBadge tone="neutral">Type: {docTypeById(selection.docType).label}</StatusBadge>
        {sel.fit === 'limited' && <StatusBadge tone="warning">Limited applicability</StatusBadge>}
      </div>

      {suggestion && suggestion.confidence !== 'none' && (
        <div className="mt-3 flex flex-wrap items-center gap-3 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2 text-xs" role="status">
          <span className="text-foreground">
            {suggested ? `Suggested type: ${suggested.label}` : 'Auto-detect is not sure.'} <span className="text-muted-foreground">({suggestion.reason})</span>
          </span>
          {suggested && selection.docType !== suggested.id && (
            <button type="button" className="rounded-md border border-border px-2 py-1 font-semibold hover:bg-secondary" onClick={() => setSelection({ docType: suggested.id })}>
              Use this type
            </button>
          )}
          <button type="button" className="text-muted-foreground underline" onClick={() => setSuggestion(null)}>
            Dismiss
          </button>
        </div>
      )}

      {sel.warnings.map((w) => (
        <p key={w} className="mt-3 rounded-lg border border-warning/40 bg-warning/10 px-3 py-2 text-xs text-warning">
          {w}
        </p>
      ))}

      <details className="mt-3 text-xs">
        <summary className="cursor-pointer select-none text-muted-foreground">Checks for this selection ({ALL_CHECKS.filter((c) => sel.checks[c] === 'applicable').length} applicable)</summary>
        <ul className="mt-2 grid gap-1 sm:grid-cols-2">
          {ALL_CHECKS.map((c) => (
            <li key={c} className="flex items-center justify-between gap-2 rounded border border-border/60 px-2 py-1">
              <span className="text-foreground">{CHECK_LABEL[c]}</span>
              <span className={cn('font-mono text-[11px]', sel.checks[c] === 'applicable' ? 'text-success' : sel.checks[c] === 'unavailable' ? 'text-warning' : 'text-muted-foreground')}>
                {sel.checks[c] === 'applicable' ? 'applies' : sel.checks[c] === 'unavailable' ? 'not available here' : 'not applicable'}
              </span>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-muted-foreground">{sel.limits}</p>
        <p className="mt-1 text-muted-foreground">Choosing a purpose or type does not make a document genuine. It only decides which rules are shown.</p>
      </details>
    </Panel>
  )
}
