'use client'

import { useEffect, useRef, useState } from 'react'
import { PlayCircle, RotateCcw, ShieldAlert, ShieldCheck, Upload } from 'lucide-react'
import { cn } from '@/lib/utils'
import { checkPdfSignature, loadFile, ocrDocument } from '@/lib/analysis'
import { analyzeMetadata } from '@/lib/metadata'
import { analyzeTamper } from '@/lib/tamper'
import { detectQrPattern } from '@/lib/qrpattern'
import { scanQrMulti } from '@/lib/qrmulti'
import { validateFile } from '@/lib/upload'
import { docTypeById, purposeById, suggestDocType } from '@/lib/purposes'
import {
  DUP_SCOPE, FIELD_KEYS, FIELD_LABEL, extractPermitFields, emptyFields, sha256hex, REQUIRED,
  type ForensicIndicator, type MovementEvent, type Overall, type PermitFields, type PermitReport, type RegistryEntry, type RowState,
} from '@/lib/permit'
import { useStore } from './store'
import { SelectionPanel } from './selection-panel'
import { ActionButton, AlertBanner, KeyValue, Panel, Spinner, StatusBadge } from './primitives'

const LS_RECORDS = 'verisight.permit.records.v1'
/** Pinned SHA-256 fingerprints (hex, comma separated) of signing keys you trust. Empty = every issuer is "unknown". */
const TRUSTED_KEYS = (process.env.NEXT_PUBLIC_PERMIT_TRUSTED_KEYS_SHA256 ?? '').split(',').map((s) => s.trim()).filter(Boolean)

type LocalRecord = RegistryEntry & { id: string; checkpoint: string; direction: 'entry' | 'exit'; overall: Overall; note: string; operator: string }

const CORE: (keyof PermitFields)[] = ['permitNo', 'holderName', 'category', 'issuingAuthority', 'jurisdiction', 'idRef', 'issueDate', 'validFrom', 'validTo']
const MORE: (keyof PermitFields)[] = [
  'dailyFrom', 'dailyTo', 'allowedDays', 'entries', 'entryPoints', 'exitPoints', 'area', 'movementPurpose', 'vehicleNo', 'chassisNo', 'engineNo',
  'cargo', 'hsnCode', 'quantity', 'goodsValue', 'departure', 'destination', 'organisation', 'employeeId', 'documentNo', 'certificateId', 'mrzText',
]

const ROW_STYLE: Record<RowState, string> = {
  pass: 'text-success border-success/40 bg-success/10',
  fail: 'text-destructive border-destructive/50 bg-destructive/10',
  warn: 'text-warning border-warning/40 bg-warning/10',
  info: 'text-muted-foreground border-border bg-secondary/50',
  na: 'text-muted-foreground border-border bg-transparent',
  unavailable: 'text-warning border-warning/30 bg-transparent',
}
const ROW_WORD: Record<RowState, string> = { pass: 'PASSED', fail: 'FAILED', warn: 'ATTENTION', info: 'INFO', na: 'NOT APPLICABLE', unavailable: 'NOT AVAILABLE' }

const input = 'h-10 w-full rounded-md border border-input bg-background/60 px-3 text-sm text-foreground focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30'

function readRecords(): LocalRecord[] {
  try {
    return JSON.parse(localStorage.getItem(LS_RECORDS) ?? '[]') as LocalRecord[]
  } catch {
    return []
  }
}

export function PermitPanel() {
  const { selection, setSuggestion, session, log } = useStore()
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState('')
  const [needPw, setNeedPw] = useState(false)
  const [thumb, setThumb] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<PermitFields>(emptyFields())
  const [extraction, setExtraction] = useState<{ ran: boolean; ambiguous: (keyof PermitFields)[]; missing: (keyof PermitFields)[]; note: string }>({ ran: false, ambiguous: [], missing: [], note: '' })
  const [scanned, setScanned] = useState<{ payloads: string[]; multiSupported: boolean; drawn: boolean; done: boolean; warnings: string[] }>({ payloads: [], multiSupported: false, drawn: false, done: false, warnings: [] })
  const [pasted, setPasted] = useState('')
  const [forensics, setForensics] = useState<{ ran: boolean; indicators: ForensicIndicator[]; notes: string[] }>({ ran: false, indicators: [], notes: [] })
  const [digest, setDigest] = useState('')
  const [reviewed, setReviewed] = useState(false)
  const [checkpoint, setCheckpoint] = useState('')
  const [direction, setDirection] = useState<'entry' | 'exit'>('entry')
  const [tz, setTz] = useState('')
  const [report, setReport] = useState<PermitReport | null>(null)
  const [note, setNote] = useState('')
  const [saved, setSaved] = useState(false)
  const [records, setRecords] = useState<LocalRecord[]>([])
  const reportRef = useRef<HTMLDivElement>(null)

  useEffect(() => setRecords(readRecords()), [])

  const set = (k: keyof PermitFields, v: string) => {
    setFields((f) => ({ ...f, [k]: v }))
    setReviewed(false)
    setReport(null)
  }

  async function accept(f: File) {
    setError(null)
    const v = await validateFile(f)
    if (!v.ok) return setError(v.error)
    setFile(f)
    setNeedPw(false)
    setReport(null)
    setSaved(false)
    setScanned({ payloads: [], multiSupported: false, drawn: false, done: false, warnings: [] })
    setForensics({ ran: false, indicators: [], notes: [] })
    setExtraction({ ran: false, ambiguous: [], missing: [], note: '' })
  }

  /** Step 3: read the document. Nothing is uploaded: OCR, QR and forensics run in this browser. */
  async function readDocument() {
    if (!file) return
    setError(null)
    setReport(null)
    try {
      setBusy('Loading file')
      const loaded = await loadFile(file, password || undefined)
      if (loaded.needsPassword) {
        setNeedPw(true)
        setError(loaded.needsPassword === 'wrong' ? 'Wrong PDF password.' : 'This PDF is password protected. Enter the password and read again.')
        return
      }
      setThumb(loaded.pages[0].toDataURL('image/jpeg', 0.6))
      const digestHex = await sha256hex(loaded.bytes)
      setDigest(digestHex)

      setBusy('OCR')
      let text = loaded.textLayer
      let ran = false
      let ocrNote = ''
      try {
        const printed = await ocrDocument(loaded.pages, setBusy, loaded.textLayer)
        text = printed.rawText || loaded.textLayer
        ran = true
        ocrNote = `Source: ${printed.source}, mean confidence ${Math.round(printed.confidence)}%. Raw text is kept only in this session.`
      } catch (e) {
        ocrNote = `OCR could not run (${(e as Error).message}). Enter the fields by hand.`
      }
      const ex = extractPermitFields(text, REQUIRED)
      setFields({ ...emptyFields(), ...ex.fields })
      setExtraction({ ran, ambiguous: ex.ambiguous, missing: ex.missing, note: ocrNote })
      setReviewed(false)
      setSuggestion(suggestDocType(text))

      setBusy('Scanning QR / barcodes')
      const multi = await scanQrMulti(loaded.pages, setBusy)
      const pattern = multi.payloads.length ? null : detectQrPattern(loaded.pages)
      setScanned({ payloads: multi.payloads, multiSupported: multi.multiSupported, drawn: !!pattern?.present, done: true, warnings: multi.warnings })

      setBusy('Forensics')
      const meta = analyzeMetadata(loaded.bytes, file.type, file.name)
      const tamper = await analyzeTamper(loaded.pages[0], loaded.bytes, meta.pixelForensicsReliable)
      const ind: ForensicIndicator[] = []
      if (meta.aiMarkers.length) ind.push({ title: 'Declared AI-generation marker', detail: meta.aiMarkers.join(', '), strength: 'review' })
      if (meta.editorTags.length) ind.push({ title: 'Editor named in metadata', detail: meta.editorTags.join(', '), strength: 'supporting' })
      if (meta.pdfModifiedAfterCreation) ind.push({ title: 'PDF modified after creation', detail: `${meta.pdfRevisions} revision(s)`, strength: 'supporting' })
      if (tamper.regions.length) ind.push({ title: 'Compression / noise differences', detail: `${tamper.regions.length} region(s). Common in genuine scans, screenshots and recompressed files.`, strength: 'supporting' })
      if (tamper.copyMoveBlocks > 0) ind.push({ title: 'Repeated image blocks', detail: `${tamper.copyMoveBlocks} block(s). Can be a repeated seal or logo.`, strength: 'supporting' })
      if (loaded.isPdf) {
        const sig = await checkPdfSignature(loaded.bytes)
        if (sig.present && (sig.digestOk === false || sig.sigOk === false)) ind.push({ title: 'PDF signature does not verify', detail: sig.detail, strength: 'review' })
      }
      setForensics({ ran: true, indicators: ind, notes: meta.notes })
    } catch (e) {
      setError(`Could not read this document: ${(e as Error).message}`)
    } finally {
      setBusy(null)
    }
  }

  /** Step 5: run every applicable check. Needs the operator to have confirmed the fields (step 4). */
  async function runChecks() {
    setError(null)
    setSaved(false)
    try {
      setBusy('Running checks')
      const payloads = [...scanned.payloads, ...pasted.split(/\n{2,}|\n---+\n/).map((s) => s.trim()).filter(Boolean)]
      const qrPayloads = scanned.done || payloads.length ? payloads : null
      const now = Date.now()
      const recs = readRecords()
      const tzNum = tz.trim() === '' ? undefined : Number(tz)
      const prior: MovementEvent[] = recs.map((r) => ({ permitNo: r.permitNo, checkpoint: r.checkpoint, direction: r.direction, atMs: r.at }))
      const event: MovementEvent | null = checkpoint.trim() ? { permitNo: fields.permitNo, checkpoint: checkpoint.trim(), direction, atMs: now } : null
      // checks run on the SERVER (app/api/verify/permit); the browser only sends the form data
      const pr = await fetch('/api/verify/permit', {
        method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({
        purpose: selection.purpose,
        docType: selection.docType,
        fields,
        reviewed,
        extraction: { ran: extraction.ran, ambiguous: extraction.ambiguous, missing: extraction.missing },
        qrPayloads,
        qrDrawnButUnreadable: scanned.drawn,
        nowMs: now,
        tzMin: tzNum !== undefined && Number.isFinite(tzNum) ? Math.round(tzNum * 60) : undefined,
        tzGiven: tzNum !== undefined && Number.isFinite(tzNum),
        trustedKeys: TRUSTED_KEYS,
        registry: recs,
        fileDigest: digest,
        forensics: forensics.ran ? { ran: true, indicators: forensics.indicators } : undefined,
        movement: { event, prior },
        }),
      })
      if (!pr.ok) throw new Error(((await pr.json().catch(() => ({}))).error) ?? 'Server could not run the checks')
      const r: PermitReport = (await pr.json()).report
      setReport(r)
      log('PERMIT_CHECK', `${r.overall} ${selection.purpose}/${selection.docType} ${fields.permitNo ? fields.permitNo.slice(0, 4) + '…' : 'no-number'}`)
      setTimeout(() => reportRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
    } catch (e) {
      setError(`Checks could not complete: ${(e as Error).message}`)
    } finally {
      setBusy(null)
    }
  }

  /** Local PROTOTYPE record: used for the duplicate / single-entry indicators. Not an official checkpoint record. */
  function saveRecord() {
    if (!report) return
    const rec: LocalRecord = {
      id: crypto.randomUUID(), at: Date.now(), permitNo: fields.permitNo, holder: fields.holderName, qrHash: report.qrHash, fileDigest: digest,
      checkpoint: checkpoint.trim(), direction, overall: report.overall, note: note.trim().slice(0, 300), operator: session?.operatorId ?? '',
    }
    const next = [rec, ...readRecords()].slice(0, 200)
    try {
      localStorage.setItem(LS_RECORDS, JSON.stringify(next))
      setRecords(next)
      setSaved(true)
      log('PERMIT_RECORD', `${report.overall} ${checkpoint.trim() || 'no-checkpoint'} ${direction}`)
    } catch {
      setError('Could not save the local record (browser storage is full or blocked).')
    }
  }

  const missing = REQUIRED.filter((k) => !fields[k].trim())
  const canRun = !busy && (!!file || FIELD_KEYS.some((k) => fields[k].trim()))
  const tone = report?.overall === 'VERIFIED' ? 'success' : report && ['INVALID', 'EXPIRED', 'REVOKED', 'SUSPENDED'].includes(report.overall) ? 'danger' : 'warning'

  return (
    <div className="flex flex-col gap-5">
      <div id="permit-selection">
        <SelectionPanel disabled={!!busy} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[380px_1fr]">
        <Panel title="Step 3 · Upload or scan the pass" icon={Upload}>
          <div className="flex flex-col gap-3">
            <p className="text-xs text-muted-foreground">PDF, JPG, PNG, WEBP or TIFF, up to 25 MB. The file never leaves this browser. You can change the purpose or type above without losing this file.</p>
            {thumb && (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={thumb} alt="Original document preview" className="max-h-48 rounded border border-border object-contain" />
            )}
            <input
              type="file"
              accept="application/pdf,image/*"
              aria-label="Choose document file"
              disabled={!!busy}
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) void accept(f)
                e.target.value = ''
              }}
              className="text-xs"
            />
            {file && <p className="truncate font-mono text-xs text-foreground">{file.name} · {(file.size / 1024 / 1024).toFixed(2)} MB</p>}
            {needPw && <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="PDF password" className={input} aria-label="PDF password" />}
            <ActionButton onClick={readDocument} disabled={!file || !!busy}>
              {busy && busy !== 'Running checks' ? <Spinner label="Reading" /> : <PlayCircle className="size-4" aria-hidden="true" />}
              {busy && busy !== 'Running checks' ? busy : 'Read document (OCR · QR · forensics)'}
            </ActionButton>
            <label className="flex flex-col gap-1 text-xs">
              <span className="font-medium uppercase tracking-wider text-muted-foreground">Or paste QR payload(s) (separate several with a blank line)</span>
              <textarea value={pasted} onChange={(e) => { setPasted(e.target.value); setReport(null) }} rows={3} className="rounded-md border border-input bg-background/60 p-2 font-mono text-xs" placeholder="VSP1.…  or  {&quot;permitNo&quot;:…}" />
            </label>
            {scanned.done && (
              <>
                <dl>
                  <KeyValue label="QR / barcodes decoded" value={scanned.payloads.length} tone={scanned.payloads.length ? undefined : 'warning'} />
                  <KeyValue label="Several codes detectable" value={scanned.multiSupported ? 'yes (browser BarcodeDetector)' : 'no: only the first QR may be read'} tone={scanned.multiSupported ? undefined : 'warning'} />
                </dl>
                {scanned.warnings.map((warning) => <p key={warning} className="text-xs text-warning">{warning}</p>)}
              </>
            )}
            {extraction.note && <p className="text-xs text-muted-foreground">{extraction.note}</p>}
            {error && <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">{error}</p>}
          </div>
        </Panel>

        <Panel title="Step 4 · Review the extracted fields" icon={ShieldCheck} actions={<StatusBadge tone={reviewed ? 'success' : 'warning'}>{reviewed ? 'Fields confirmed' : 'Not confirmed'}</StatusBadge>}>
          <p className="mb-3 text-xs text-muted-foreground">Nothing is guessed. Empty means &quot;not read&quot;. Correct anything OCR got wrong, then confirm. Reading a date or number wrongly here changes the verdict.</p>
          <div className="grid gap-3 sm:grid-cols-2">
            {CORE.map((k) => (
              <label key={k} className="flex flex-col gap-1">
                <span className="text-xs text-muted-foreground">
                  {FIELD_LABEL[k]}
                  {REQUIRED.includes(k) && ' *'}
                  {extraction.ambiguous.includes(k) && <span className="ml-1 text-warning">(read two different ways)</span>}
                </span>
                <input value={fields[k]} onChange={(e) => set(k, e.target.value)} className={cn(input, !fields[k].trim() && REQUIRED.includes(k) && 'border-warning/60')} />
              </label>
            ))}
          </div>
          <details className="mt-3">
            <summary className="cursor-pointer select-none text-xs text-muted-foreground">Movement, vehicle, cargo and document fields (optional)</summary>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              {MORE.map((k) => (
                <label key={k} className="flex flex-col gap-1">
                  <span className="text-xs text-muted-foreground">{FIELD_LABEL[k]}</span>
                  {k === 'mrzText'
                    ? <textarea value={fields[k]} onChange={(e) => set(k, e.target.value)} className={cn(input, 'min-h-20 py-2 font-mono text-xs')} />
                    : <input value={fields[k]} onChange={(e) => set(k, e.target.value)} className={input} />}
                </label>
              ))}
            </div>
          </details>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <label className="flex flex-col gap-1">
              <span className="text-xs text-muted-foreground">Checkpoint (optional)</span>
              <input value={checkpoint} onChange={(e) => { setCheckpoint(e.target.value); setReport(null) }} className={input} placeholder="e.g. Gate A" />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-muted-foreground">Event</span>
              <select value={direction} onChange={(e) => { setDirection(e.target.value as 'entry' | 'exit'); setReport(null) }} className={input}>
                <option value="entry">Entry</option>
                <option value="exit">Exit</option>
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-muted-foreground">Permit time zone (hours from UTC)</span>
              <input value={tz} onChange={(e) => { setTz(e.target.value); setReport(null) }} className={input} placeholder="blank = +5.5 assumed" inputMode="decimal" />
            </label>
          </div>
          <label className="mt-4 flex items-start gap-2 text-sm">
            <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} className="mt-1" />
            <span>I compared these values with the original document and confirm they are correct.</span>
          </label>
          {missing.length > 0 && <p className="mt-2 text-xs text-warning">Missing required field(s): {missing.map((k) => FIELD_LABEL[k]).join(', ')}. The result cannot be VERIFIED without them.</p>}
          <div className="mt-4 flex flex-wrap gap-2">
            <ActionButton onClick={runChecks} disabled={!canRun}>
              {busy === 'Running checks' ? <Spinner label="Running" /> : <PlayCircle className="size-4" aria-hidden="true" />}
              Step 5 · Run applicable checks
            </ActionButton>
            {report && (
              <ActionButton variant="outline" onClick={() => document.getElementById('permit-selection')?.scrollIntoView({ behavior: 'smooth' })}>
                <RotateCcw className="size-4" aria-hidden="true" /> Change purpose / type
              </ActionButton>
            )}
          </div>
        </Panel>
      </div>

      <div ref={reportRef} />
      {report && (
        <Panel title="Step 6 · Verification report" icon={ShieldAlert}>
          <div className="flex flex-col gap-4">
            <AlertBanner tone={tone} title={report.overall.replace('_', ' ')} icon={report.overall === 'VERIFIED' ? ShieldCheck : ShieldAlert}>
              {report.headline}
            </AlertBanner>
            {report.liveLabel && <p className="rounded-lg border border-warning/40 bg-warning/10 px-3 py-2 font-mono text-xs font-semibold text-warning">{report.liveLabel}</p>}
            <p className="rounded-lg border border-border bg-secondary/40 px-3 py-2 text-xs text-muted-foreground">
              This is a prototype assessment, not an official clearance or an immigration decision. A person must decide.
            </p>

            <dl className="grid gap-x-6 sm:grid-cols-2">
              <KeyValue label="Verification purpose" value={purposeById(report.purpose).label} />
              <KeyValue label="Selected document type" value={docTypeById(report.docType).label} />
              <KeyValue label="Checked at" value={new Date(report.at).toLocaleString()} />
              <KeyValue label="Input" value={file ? file.name : 'fields typed / QR pasted'} />
            </dl>

            {report.warnings.map((w) => <p key={w} className="text-xs text-warning">{w}</p>)}

            <div>
              <h3 className="mb-2 text-sm font-semibold">Why</h3>
              <ul className="list-disc pl-5 text-sm text-muted-foreground">
                {report.reasons.map((r) => <li key={r}>{r}</li>)}
              </ul>
            </div>

            <div>
              <h3 className="mb-2 text-sm font-semibold">Independent checks</h3>
              <ul className="grid gap-2">
                {report.rows.map((r) => (
                  <li key={r.key} className={cn('rounded-lg border px-3 py-2', ROW_STYLE[r.state])}>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm font-medium text-foreground">{r.label}</span>
                      <span className="font-mono text-[11px]">{ROW_WORD[r.state]}</span>
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">{r.text}</p>
                  </li>
                ))}
              </ul>
            </div>

            {report.compare.length > 0 && (
              <div className="overflow-x-auto">
                <h3 className="mb-2 text-sm font-semibold">QR ↔ printed data</h3>
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-muted-foreground"><th className="py-1 pr-3">Field</th><th className="pr-3">QR</th><th className="pr-3">Printed</th><th>Result</th></tr></thead>
                  <tbody>
                    {report.compare.map((c) => (
                      <tr key={c.field} className="border-t border-border/60">
                        <td className="py-1 pr-3">{c.label}</td>
                        <td className="pr-3 font-mono">{c.qr || '—'}</td>
                        <td className="pr-3 font-mono">{c.printed || '—'}</td>
                        <td className={cn('font-mono', c.res === 'mismatch' ? 'text-destructive' : c.res === 'match' ? 'text-success' : 'text-warning')}>{c.res.toUpperCase()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="text-xs text-muted-foreground">
              <p className="font-semibold text-foreground">Limits for this document type</p>
              <p>{report.limits}</p>
              <p className="mt-1">Duplicate scope: {DUP_SCOPE}</p>
              {forensics.notes.map((n) => <p key={n} className="mt-1">{n}</p>)}
            </div>

            <div className="rounded-lg border border-border p-3">
              <h3 className="text-sm font-semibold">Local movement record (prototype)</h3>
              <p className="mb-2 text-xs text-muted-foreground">Saved only in this browser. It is NOT an official checkpoint record and is not tamper-proof. The audit action is also written to the server log.</p>
              <label className="flex flex-col gap-1 text-xs">
                <span className="text-muted-foreground">Manual review outcome / justification (optional)</span>
                <input value={note} onChange={(e) => setNote(e.target.value)} maxLength={300} className={input} />
              </label>
              <div className="mt-2 flex items-center gap-3">
                <ActionButton variant="outline" onClick={saveRecord} disabled={saved}>{saved ? 'Saved locally' : 'Save local record'}</ActionButton>
                <span className="text-xs text-muted-foreground">{records.length} local record(s)</span>
                {records.length > 0 && (
                  <button type="button" className="text-xs text-muted-foreground underline" onClick={() => { localStorage.removeItem(LS_RECORDS); setRecords([]) }}>
                    Clear local records
                  </button>
                )}
              </div>
            </div>
          </div>
        </Panel>
      )}
    </div>
  )
}
