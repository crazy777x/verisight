'use client'

import { useState } from 'react'
import { FileKey2, ShieldAlert, ShieldCheck, Upload } from 'lucide-react'
import {
  buildQrRows,
  checkPdfSignature,
  computeEla,
  decodeAadhaarQr,
  loadFile,
  ocrDocument,
  scanQr,
  verhoeffValid,
  verifyAadhaarSignature,
  type AadhaarQr,
  type PdfSig,
  type Printed,
  type Row,
  type SigCheck,
} from '@/lib/analysis'
import { compareIdentityFields, type IdentityComparison, type IdentityFields } from '@/lib/cross-document'
import { analyzeMetadata } from '@/lib/metadata'
import { analyzeTamper, labelRegions, type TamperReport } from '@/lib/tamper'
import { type Verdict, type VerdictInput } from '@/lib/verdict'
import { detectQrPattern, type QrPattern } from '@/lib/qrpattern'
import { validateFile } from '@/lib/upload'
import { useStore } from './store'
import { ActionButton, Panel, Spinner, StatusBadge } from './primitives'

type AadhaarCheck = {
  verdict: Verdict
  printed: Printed
  qrAadhaar: AadhaarQr | null
  qrRows: Row[]
  qrSig: SigCheck | null
  comparisons: IdentityComparison[]
  trustedSource: boolean
}

function comparisonSummary(rows: IdentityComparison[]) {
  const available = rows.filter((row) => row.result !== 'unavailable')
  if (!available.length) return 'No common fields could be compared.'
  if (available.some((row) => row.result === 'mismatch')) return 'One or more common fields differ. Manual review required.'
  if (available.some((row) => row.result === 'partial')) return 'Only a partial date match was possible. Manual review required.'
  return 'All available common fields match.'
}

export function AadhaarCrossCheck({ documentType, documentFields }: { documentType: string; documentFields: IdentityFields }) {
  const { cert } = useStore()
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [check, setCheck] = useState<AadhaarCheck | null>(null)

  async function runCheck() {
    if (!file) return
    setBusy(true)
    setError(null)
    setCheck(null)
    try {
      setProgress('Loading Aadhaar document')
      const loaded = await loadFile(file, password || undefined)
      if (loaded.needsPassword) {
        setError(loaded.needsPassword === 'wrong' ? 'Wrong Aadhaar PDF password.' : 'Enter the Aadhaar PDF password and try again.')
        return
      }

      setProgress('Checking Aadhaar text')
      const printed = await ocrDocument(loaded.pages, setProgress, loaded.textLayer)
      const aadhaarValid = printed.aadhaarNo ? verhoeffValid(printed.aadhaarNo) : null
      const meta = analyzeMetadata(loaded.bytes, file.type, file.name)
      const ela = loaded.isPdf
        ? { blocks: [], rowVariance: [], mean: 0, variance: 0, peak: 0, anomalousBlocks: 0, anomaly: false, reliable: true, note: 'PDF render: pixel forensics not applicable.' }
        : await computeEla(loaded.pages[0], meta.pixelForensicsReliable)
      const tamper: TamperReport = loaded.isPdf
        ? { cols: 1, rows: 1, heat: [], regions: [], copyMoveBlocks: 0, editorTags: [], elaReliable: false, width: 1, height: 1 }
        : await analyzeTamper(loaded.pages[0], loaded.bytes, meta.pixelForensicsReliable)
      labelRegions(tamper.regions, printed.words)

      setProgress('Checking Aadhaar signature and QR')
      const pdfSig: PdfSig = loaded.isPdf
        ? await checkPdfSignature(loaded.bytes, { aadhaarDocument: true })
        : { present: false, count: 0, digestOk: null, sigOk: null, coversWholeFile: null, signer: '', issuer: '', validTo: '', detail: 'Image input: no embedded signature container.', chain: { state: 'none', detail: '', chain: [] } }
      const qr = await scanQr(loaded.pages, setProgress).catch(() => null)
      const qrPattern: QrPattern | null = !qr ? detectQrPattern(loaded.pages) : null
      let qrAadhaar: AadhaarQr | null = null
      let qrRows: Row[] = []
      let qrSig: SigCheck | null = null
      if (qr) {
        try {
          qrAadhaar = await decodeAadhaarQr(qr.text)
        } catch {
          qrAadhaar = null
        }
        if (qrAadhaar) {
          qrRows = buildQrRows(qrAadhaar, printed)
          if (qrAadhaar.kind === 'secure') qrSig = await verifyAadhaarSignature(qrAadhaar, cert)
        }
      }

      const input: VerdictInput = {
        kind: 'aadhaar',
        printed,
        aadhaarValid,
        mrz: [],
        ela,
        tamper,
        pdfSig,
        qr,
        qrPattern,
        qrAadhaar,
        qrRows,
        qrSig,
        isPdf: loaded.isPdf,
        meta,
        qrPx: qrPattern?.box ? qrPattern.box.w * (loaded.pages[qrPattern.page]?.width ?? 0) : 0,
      }
      setProgress('Running existing Aadhaar verdict checks')
      const response = await fetch('/api/verify/verdict', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(input),
      })
      const payload = await response.json().catch(() => null)
      if (!response.ok || !payload?.verdict) throw new Error(payload?.error ?? 'Aadhaar verdict could not be computed.')

      const verdict = payload.verdict as Verdict
      const comparisons = qrAadhaar
        ? compareIdentityFields(
            { name: qrAadhaar.fields.name, dob: qrAadhaar.fields.dob, gender: qrAadhaar.fields.gender, pincode: qrAadhaar.fields.pincode },
            documentFields,
          )
        : compareIdentityFields({}, documentFields)
      setCheck({
        verdict,
        printed,
        qrAadhaar,
        qrRows,
        qrSig,
        comparisons,
        trustedSource: verdict.headline === 'AUTHENTIC · UIDAI SIGNATURE VERIFIED' && qrSig?.state === 'verified',
      })
    } catch (e) {
      setError(`Aadhaar cross-check could not complete: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setBusy(false)
      setProgress('')
    }
  }

  const compareRows = check?.comparisons.filter((row) => row.result !== 'unavailable') ?? []
  const mismatch = compareRows.some((row) => row.result === 'mismatch' || row.result === 'partial')
  const allMatch = !!compareRows.length && !mismatch
  const finalTone = !check?.trustedSource ? 'warning' : mismatch ? 'warning' : allMatch ? 'success' : 'warning'
  const finalLabel = !check?.trustedSource ? 'AADHAAR NOT TRUSTED' : mismatch ? 'REVIEW · FIELD DIFFERENCE' : allMatch ? 'FIELDS MATCH' : 'NO COMMON FIELDS'

  return (
    <Panel title={`Optional Aadhaar cross-check · ${documentType}`} icon={FileKey2}>
      <div className="flex flex-col gap-3">
        <p className="text-xs leading-relaxed text-muted-foreground">
          The {documentType} checks run first. Aadhaar is optional and checked only when you choose a file here. The existing Aadhaar checks run on the selected file in this browser; extracted verification data is sent to this app&apos;s verdict endpoint. The document file itself is not uploaded or saved.
        </p>
        <label className="flex flex-col gap-1.5 text-xs">
          <span className="font-medium uppercase tracking-wider text-muted-foreground">Optional Aadhaar PDF or image</span>
          <input
            type="file"
            accept="application/pdf,image/*"
            disabled={busy}
            onChange={async (event) => {
              const selected = event.target.files?.[0] ?? null
              event.target.value = ''
              setCheck(null)
              setError(null)
              setFile(null)
              if (!selected) return
              const validation = await validateFile(selected)
              if (!validation.ok) {
                setError(validation.error)
                return
              }
              setFile(selected)
            }}
            className="text-xs"
          />
        </label>
        {file && <p className="truncate font-mono text-[11px] text-muted-foreground">{file.name}</p>}
        {file && (/pdf/i.test(file.type) || /\.pdf$/i.test(file.name)) && (
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">Aadhaar PDF password (if protected)</span>
            <input
              type="password"
              autoComplete="off"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="h-10 rounded-md border border-input bg-background/60 px-3 font-mono text-xs text-foreground"
            />
          </label>
        )}
        <div>
          <ActionButton variant="outline" onClick={runCheck} disabled={!file || busy}>
            {busy ? <Spinner label={progress || 'Checking Aadhaar'} /> : <Upload className="size-4" aria-hidden="true" />}
            {busy ? progress || 'Checking Aadhaar…' : check ? 'Run Aadhaar cross-check again' : 'Check Aadhaar and compare'}
          </ActionButton>
        </div>
        {error && <p role="alert" className="text-xs text-destructive">{error}</p>}

        {check && (
          <div className="mt-2 flex flex-col gap-3 border-t border-border pt-4">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge tone={check.trustedSource ? 'success' : 'warning'}>{check.verdict.headline}</StatusBadge>
              <StatusBadge tone={finalTone}>{finalLabel}</StatusBadge>
              <StatusBadge tone={check.verdict.risk >= 70 ? 'danger' : check.verdict.risk >= 40 ? 'warning' : 'neutral'}>Aadhaar risk {check.verdict.risk}</StatusBadge>
            </div>
            <p className="text-xs text-muted-foreground">{check.verdict.sub}</p>
            {!check.trustedSource && (
              <p role="status" className="rounded-md border border-warning/40 bg-warning/10 p-2 text-xs text-warning">
                Aadhaar cannot be used as a trusted comparison source unless the existing UIDAI signature verification returns verified and the existing Aadhaar verdict passes.
              </p>
            )}
            {check.qrRows.length > 0 && (
              <div>
                <h3 className="mb-2 text-xs font-semibold">Aadhaar QR ↔ its printed text</h3>
                <ul className="grid gap-1">
                  {check.qrRows.map((row) => (
                    <li key={row.label} className="flex items-center justify-between gap-2 text-xs">
                      <span className="text-muted-foreground">{row.label}</span>
                      <StatusBadge tone={row.res === 'match' ? 'success' : row.res === 'unread' ? 'neutral' : 'warning'}>{row.res}</StatusBadge>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div>
              <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold">
                {allMatch && check.trustedSource ? <ShieldCheck className="size-4 text-success" aria-hidden="true" /> : <ShieldAlert className="size-4 text-warning" aria-hidden="true" />}
                Aadhaar QR ↔ {documentType} text
              </h3>
              {compareRows.length ? (
                <ul className="grid gap-1">
                  {compareRows.map((row) => (
                    <li key={row.field} className="flex items-center justify-between gap-2 text-xs">
                      <span className="text-muted-foreground">{row.label}</span>
                      <span className="min-w-0 flex-1 truncate text-right font-mono">{row.aadhaar} ↔ {row.document}</span>
                      <StatusBadge tone={row.result === 'match' ? 'success' : 'warning'}>{row.result}</StatusBadge>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-muted-foreground">No common readable fields were available in both documents.</p>
              )}
              <p role="status" className="mt-2 text-xs text-muted-foreground">
                {!check.trustedSource ? 'Comparison is informational only because Aadhaar did not pass its trusted issuer check.' : comparisonSummary(check.comparisons)}
                {' '}A field match is a cross-check signal, not proof that the other document was issued by its authority.
              </p>
            </div>
            {check.verdict.findings.length > 0 && (
              <ul className="list-disc pl-5 text-xs text-muted-foreground">
                {check.verdict.findings.map((finding, index) => <li key={`${finding.code}-${index}`}>{finding.title}: {finding.detail}</li>)}
              </ul>
            )}
          </div>
        )}
      </div>
    </Panel>
  )
}
