'use client'

import { useEffect, useRef, useState } from 'react'
import { Activity, BadgeCheck, Binary, Camera, FileKey2, FileText, KeyRound, Lock, LockOpen, PlayCircle, RotateCcw, ShieldAlert, Timer, Upload } from 'lucide-react'
import { cn } from '@/lib/utils'
import { type MrzField } from '@/lib/forensics'
import {
  buildQrRows,
  checkPdfSignature,
  computeEla,
  decodeAadhaarQr,
  loadFile,
  mrzFor,
  ocrDocument,
  scanQr,
  verhoeffValid,
  verifyAadhaarSignature,
  type AadhaarQr,
  type ElaReport,
  type PdfSig,
  type Printed,
  type Row,
  type SigCheck,
} from '@/lib/analysis'
import { analyzeMetadata, type Meta } from '@/lib/metadata'
import { analyzeTamper, labelRegions, type TamperReport } from '@/lib/tamper'
import { HARD_LOCK_RISK, REVIEW_RISK, type Verdict } from '@/lib/verdict'
import { detectQrPattern, type QrPattern } from '@/lib/qrpattern'
import { validateDl, validateEpic, validatePan, type IdKind } from '@/lib/docs'
import { SelectionPanel } from './selection-panel'
import { suggestDocType, docTypeById, type DocTypeId } from '@/lib/purposes'
import { validateFile } from '@/lib/upload'
import { AutoAdvance } from './workflow'
import { CameraCapture } from './camera-capture'
import { TamperViewer } from './tamper-viewer'
import { VerdictCard } from './verdict-card'
import { useStore, type FlagReason } from './store'
import { ActionButton, KeyValue, Panel, ProgressBar, RiskGauge, StatusBadge, StepList } from './primitives'
import { ScanTheatre } from './scan-theatre'
import { ElaChart } from './ela-chart'

const DOC_TYPES = ['Auto-detect', 'Aadhaar (UIDAI)', 'PAN card', 'Passport (TD3)', 'National ID (TD1)', "Driving licence", 'Voter ID (EPIC)'] as const
type DocType = (typeof DOC_TYPES)[number]

/** The triage engine understands these identity documents. Every other selected type is analysed in the Border Pass & Permit tab. */
const ENGINE_FOR: Partial<Record<DocTypeId, DocType>> = {
  auto: 'Auto-detect',
  aadhaar: 'Aadhaar (UIDAI)',
  pan: 'PAN card',
  passport: 'Passport (TD3)',
  'driving-licence': 'Driving licence',
  'voter-id': 'Voter ID (EPIC)',
}

const STAGES = [
  { label: 'Ingest & normalize', detail: 'PDF/image → canvas · password · page raster' },
  { label: 'OCR + identity checksum', detail: 'Tesseract · ICAO 9303 mod-10 / Aadhaar Verhoeff' },
  { label: 'Tamper localisation', detail: 'ELA · noise · copy-move · editor metadata' },
  { label: 'Digital signature + QR scan', detail: 'PDF CMS · native / jsQR / ZXing · UIDAI RSA · QR↔print match' },
  { label: 'Verdict & gate decision', detail: 'evidence-based (hard evidence cannot be averaged away)' },
]

type Result = {
  kind: IdKind
  meta: Meta
  qrPattern: QrPattern | null
  mrzLines: { line1: string; line2: string; line3?: string } | null
  mrz: MrzField[]
  printed: Printed
  aadhaarValid: boolean | null
  ela: ElaReport
  pdfSig: PdfSig
  fileDigest: string
  qrFound: boolean
  qrEngine: string
  qrRows: Row[]
  qrAadhaar: AadhaarQr | null
  qrSig: SigCheck | null
  tamper: TamperReport
  verdict: Verdict
  page: HTMLCanvasElement
  risk: number
  reasons: FlagReason[]
  elapsedMs: number
  queueId?: string
  caseId?: string
}

function makeThumb(c: HTMLCanvasElement) {
  const w = Math.min(360, c.width)
  const t = document.createElement('canvas')
  t.width = w
  t.height = Math.round((c.height * w) / c.width)
  t.getContext('2d')!.drawImage(c, 0, 0, t.width, t.height)
  return t.toDataURL('image/jpeg', 0.6)
}

const maskAadhaar = (n: string) => (n.length === 12 ? `XXXX XXXX ${n.slice(8)}` : n || '—')


function IdentityPanel({ result }: { result: Result }) {
  const p = result.printed
  const k = result.kind
  const title = k === 'aadhaar' ? 'Aadhaar Identity Checks' : k === 'pan' ? 'PAN Card Checks' : k === 'dl' ? 'Driving Licence Checks' : k === 'epic' ? 'Voter ID (EPIC) Checks' : 'Identity Checks'
  const idChecks = k === 'pan' ? (p.pan ? validatePan(p.pan, p.name, p.fatherName) : []) : k === 'dl' ? (p.dl ? validateDl(p.dl) : []) : k === 'epic' ? (p.epic ? validateEpic(p.epic) : []) : []
  const numberRead = k === 'pan' ? p.pan : k === 'dl' ? p.dl : k === 'epic' ? p.epic : p.aadhaarNo
  const formatOk = k === 'aadhaar' ? !!result.aadhaarValid : !!numberRead && idChecks.length === 0
  const badge =
    k === 'none' ? <StatusBadge tone="warning">Not identified</StatusBadge>
    : k === 'aadhaar' ? <StatusBadge tone={result.aadhaarValid ? 'success' : 'danger'}>{result.aadhaarValid ? 'Verhoeff valid' : 'Verhoeff failed'}</StatusBadge>
    : <StatusBadge tone={formatOk ? 'success' : 'danger'}>{formatOk ? 'Format valid' : numberRead ? 'Format problem' : 'Number not read'}</StatusBadge>
  const src = p.source === 'ocr' ? 'OCR' : p.source === 'text-layer' ? 'PDF text layer (exact)' : 'PDF text layer + OCR'
  return (
    <Panel title={title} icon={Binary} actions={badge}>
      {k === 'none' ? (
        <p className="text-sm text-muted-foreground">
          Neither an MRZ nor a recognisable Aadhaar / PAN / Licence / Voter ID number could be read. Try a sharper, straight, full-page scan (min 150 dpi), or pick the document type manually.
        </p>
      ) : (
        <>
          <p className="mb-3 text-xs text-muted-foreground">
            {k === 'aadhaar'
              ? 'Aadhaar has no MRZ. Its 12-digit number carries a Verhoeff check digit, which is validated here.'
              : 'PAN / Licence / EPIC numbers have no public checksum, so only the official structure rules can be checked (a pass is NOT proof of genuineness).'}{' '}
            Fields read from: <span className="font-mono text-foreground">{src}</span>.
          </p>
          <dl>
            {k === 'aadhaar' && (
              <>
                <KeyValue label="Aadhaar No." value={maskAadhaar(p.aadhaarNo)} tone={result.aadhaarValid ? 'success' : 'danger'} />
                <KeyValue label="Verhoeff check digit" value={result.aadhaarValid ? 'PASS' : 'FAIL'} tone={result.aadhaarValid ? 'success' : 'danger'} />
                {p.aadhaarCandidates.length > 1 && <KeyValue label="OCR readings tried" value={p.aadhaarCandidates.map(maskAadhaar).join(' · ')} />}
              </>
            )}
            {k === 'pan' && (
              <>
                <KeyValue label="PAN" value={p.pan ? `${p.pan.slice(0, 2)}XXXXX${p.pan.slice(7)}` : 'not read'} tone={formatOk ? 'success' : 'danger'} />
                <KeyValue label="Holder type (4th char)" value={p.pan ? p.pan[3] : '—'} />
              </>
            )}
            {k === 'dl' && <KeyValue label="Licence No." value={p.dl ? `${p.dl.slice(0, 4)}XXXXXXXX${p.dl.slice(-3)}` : 'not read'} tone={formatOk ? 'success' : 'danger'} />}
            {k === 'epic' && <KeyValue label="EPIC No." value={p.epic ? `${p.epic.slice(0, 3)}XXXX${p.epic.slice(-3)}` : 'not read'} tone={formatOk ? 'success' : 'danger'} />}
            <KeyValue label="Name" value={p.name || 'not read (rejected if unclear)'} />
            {p.fatherName && <KeyValue label="Father's name" value={p.fatherName} />}
            <KeyValue label="Date of birth" value={p.dob || 'not read'} />
            {k !== 'pan' && <KeyValue label="Gender" value={p.gender || 'not read'} />}
            {k === 'aadhaar' && <KeyValue label="PIN" value={p.pincode || 'not read'} />}
          </dl>
          {idChecks.length > 0 && (
            <ul className="mt-3 flex flex-col gap-1.5">
              {idChecks.map((c, i) => (
                <li key={i} className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs">
                  <span className="font-semibold text-destructive">{c.title}</span>
                  <span className="mt-0.5 block text-muted-foreground">{c.detail}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Panel>
  )
}

export function TriageBay() {
  const { addFlag, addCase, log, setCaseDoc, cert, certError, loadCert, markStep, resetSteps, selection, setSuggestion, goTo } = useStore()
  const certRef = useRef<HTMLInputElement>(null)
  const docType: DocType = ENGINE_FOR[selection.docType] ?? 'Auto-detect'
  const notIdentity = !(selection.docType in ENGINE_FOR)
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState('')
  const [pwState, setPwState] = useState<'need' | 'wrong' | null>(null)
  const [dragging, setDragging] = useState(false)
  const [stage, setStage] = useState(-1)
  const [stageNote, setStageNote] = useState('')
  const [elapsed, setElapsed] = useState(0)
  const [result, setResult] = useState<Result | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const [cameraOpen, setCameraOpen] = useState(false)
  const autoRunRef = useRef(false)
  const previewRef = useRef<string | null>(null)

  useEffect(
    () => () => {
      if (previewRef.current) URL.revokeObjectURL(previewRef.current)
    },
    [],
  )

  const running = stage >= 0 && !result

  // a camera capture is verified straight away: runTriage runs once the captured file is in state
  useEffect(() => {
    if (autoRunRef.current && file) {
      autoRunRef.current = false
      runTriage()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file])

  async function acceptFile(f: File, autoRun = false) {
    const v = await validateFile(f) // size, type AND content (magic bytes): a renamed or corrupted file is refused
    if (!v.ok) return setFileError(v.error)
    setFileError(null)
    if (previewRef.current) URL.revokeObjectURL(previewRef.current)
    const url = f.type.startsWith('image/') ? URL.createObjectURL(f) : null
    previewRef.current = url
    setPreviewUrl(url)
    autoRunRef.current = autoRun // only a valid camera capture is verified automatically
    setFile(f)
    setPwState(null)
    setPassword('')
    setResult(null)
    setStage(-1)
    setCaseDoc(null)
    resetSteps()
  }

  async function runTriage() {
    if (!file) return
    setResult(null)
    resetSteps()
    setFileError(null)
    const started = performance.now()
    const tick = setInterval(() => setElapsed(performance.now() - started), 80)
    try {
      setStage(0)
      const loaded = await loadFile(file, password || undefined)
      if (loaded.needsPassword) {
        setPwState(loaded.needsPassword)
        setStage(-1)
        setFileError(loaded.needsPassword === 'wrong' ? 'Wrong PDF password.' : 'This PDF is password protected. Enter the password and run again. (e-Aadhaar: first 4 letters of name in CAPITALS + birth year, e.g. SUMI1999)')
        return
      }

      setStage(1)
      const printed = await ocrDocument(loaded.pages, setStageNote, loaded.textLayer)
      const forced: IdKind | null =
        docType === 'Aadhaar (UIDAI)' ? 'aadhaar' : docType === 'PAN card' ? 'pan' : docType === 'Driving licence' ? 'dl' : docType === 'Voter ID (EPIC)' ? 'epic' : docType === 'Passport (TD3)' || docType === 'National ID (TD1)' ? 'mrz' : null
      let kind: IdKind
      if (forced === 'mrz') kind = printed.mrz ? 'mrz' : 'none'
      else if (forced) kind = forced
      else if (printed.mrz) kind = 'mrz'
      else if (printed.pan || printed.panKeyword) kind = 'pan'
      else if (printed.aadhaarNo || printed.aadhaarKeyword) kind = 'aadhaar'
      else if (printed.dl || printed.dlKeyword) kind = 'dl'
      else if (printed.epic || printed.epicKeyword) kind = 'epic'
      else kind = 'none'
      setSuggestion(suggestDocType(printed.rawText || loaded.textLayer))
      const mrz = kind === 'mrz' && printed.mrz ? mrzFor(printed.mrz) : []
      const aadhaarValid = kind === 'aadhaar' && printed.aadhaarNo ? verhoeffValid(printed.aadhaarNo) : null

      setStage(2)
      const meta = analyzeMetadata(loaded.bytes, file.type, file.name)
      // PDF renders are a digital page: pixel forensics never affect a PDF verdict, so do not spend time computing them.
      const ela = loaded.isPdf
        ? { blocks: [], rowVariance: [], mean: 0, variance: 0, peak: 0, anomalousBlocks: 0, anomaly: false, reliable: true, note: 'PDF render: pixel forensics not applicable.' }
        : await computeEla(loaded.pages[0], meta.pixelForensicsReliable)
      const tamper = loaded.isPdf
        ? { cols: 1, rows: 1, heat: [], regions: [], copyMoveBlocks: 0, editorTags: [], elaReliable: false, width: 1, height: 1 }
        : await analyzeTamper(loaded.pages[0], loaded.bytes, meta.pixelForensicsReliable)
      labelRegions(tamper.regions, printed.words)

      setStage(3)
      setStageNote('Scanning for signature & QR')
      const pdfSig = loaded.isPdf
        ? await checkPdfSignature(loaded.bytes, { aadhaarDocument: kind === 'aadhaar' })
        : { present: false, count: 0, digestOk: null, sigOk: null, coversWholeFile: null, signer: '', issuer: '', validTo: '', detail: 'Image input: no embedded signature container.', chain: { state: 'none' as const, detail: '', chain: [] } }
      const qr = kind === 'mrz' ? null : await scanQr(loaded.pages, setStageNote).catch(() => null)
      const qrPattern = !qr && kind !== 'mrz' ? detectQrPattern(loaded.pages) : null
      let qrAadhaar: AadhaarQr | null = null
      let qrRows: Row[] = []
      let qrSig: SigCheck | null = null
      if (qr && kind === 'aadhaar') {
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
      const digestBuf = await crypto.subtle.digest('SHA-256', loaded.bytes as unknown as BufferSource)
      const fileDigest = Array.from(new Uint8Array(digestBuf)).map((b) => b.toString(16).padStart(2, '0')).join('')

      setStage(4)
      const qrPx = qrPattern?.box ? qrPattern.box.w * (loaded.pages[qrPattern.page]?.width ?? 0) : 0
      // scoring runs on the SERVER (app/api/verify/verdict); the browser only sends the extracted facts
      const vr = await fetch('/api/verify/verdict', {
        method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({ kind, printed, aadhaarValid, mrz, ela, tamper, pdfSig, qr, qrPattern, qrAadhaar, qrRows, qrSig, isPdf: loaded.isPdf, meta, qrPx }),
      })
      if (!vr.ok) throw new Error('Server could not compute the verdict')
      const verdict: Verdict = (await vr.json()).verdict
      const risk = verdict.risk
      const reasons: FlagReason[] = verdict.findings.map((f) => ({ code: f.code, detail: `${f.title}. ${f.detail}` }))

      clearInterval(tick)
      const elapsedMs = performance.now() - started
      setElapsed(elapsedMs)

      const subject = (kind === 'mrz' && printed.mrz ? printed.mrz.line1.slice(5).replace(/<<+/g, ', ').replace(/</g, ' ').trim() : printed.name) || file.name
      const docNo =
        kind === 'mrz' && printed.mrz
          ? printed.mrz.kind === 'TD3' ? printed.mrz.line2.slice(0, 9) : printed.mrz.line1.slice(5, 14)
          : kind === 'pan' ? printed.pan ? `${printed.pan.slice(0, 2)}XXXXX${printed.pan.slice(7)}` : '—'
          : kind === 'dl' ? printed.dl ? `${printed.dl.slice(0, 4)}XXXXXXXX${printed.dl.slice(-3)}` : '—'
          : kind === 'epic' ? printed.epic ? `${printed.epic.slice(0, 3)}XXXX${printed.epic.slice(-3)}` : '—'
          : maskAadhaar(printed.aadhaarNo)
      const docLabel = kind === 'mrz' ? (printed.mrz?.kind === 'TD1' ? 'National ID' : 'Passport') : kind === 'aadhaar' ? 'Aadhaar' : kind === 'pan' ? 'PAN card' : kind === 'dl' ? 'Driving licence' : kind === 'epic' ? 'Voter ID' : 'Unknown'

      setCaseDoc({ fileName: file.name, pages: loaded.pages, isPdf: loaded.isPdf, printed, qr, qrPattern, subject, docNo, docType: docLabel, risk })

      let queueId: string | undefined
      if (risk >= REVIEW_RISK) {
        queueId = await addFlag({ subject, docType: docLabel, docNo, risk, lane: risk >= HARD_LOCK_RISK ? 'Lane 03 · SAFE-LOCK' : 'Lane 02 · REVIEW', reasons })
        log(risk >= HARD_LOCK_RISK ? 'SAFE_LOCK_ENGAGED' : 'TRIAGE_REVIEW', `${queueId} · risk ${risk}`)
      } else {
        log('TRIAGE_CLEARED', `${file.name} · risk ${risk}`)
      }

      const caseId = addCase({
        fileName: file.name,
        fileDigest,
        docType: docLabel,
        subject,
        docNo,
        risk,
        level: verdict.level,
        headline: verdict.headline,
        findings: verdict.findings.map((f) => ({ severity: f.severity, title: f.title, detail: f.detail })),
        regions: tamper.regions.map((r) => ({ id: r.id, x: r.x, y: r.y, w: r.w, h: r.h, score: r.score, kinds: r.kinds, fields: r.fields })),
        fields: { name: printed.name, dob: printed.dob, gender: printed.gender, pincode: printed.pincode },
        qr: { found: !!qr, kind: qrAadhaar ? qrAadhaar.kind : qr ? 'non-aadhaar' : qrPattern?.present ? 'pattern-only (undecodable)' : '', signature: qrSig?.state ?? 'n/a', mismatches: qrRows.filter((r) => r.res === 'mismatch').map((r) => r.label) },
        thumb: makeThumb(loaded.pages[0]),
      })

      markStep('triage', true)
      setResult({
        kind,
        qrPattern,
        mrzLines: kind === 'mrz' && printed.mrz ? printed.mrz : null,
        mrz,
        printed,
        aadhaarValid,
        ela,
        pdfSig,
        fileDigest,
        qrFound: !!qr,
        qrEngine: qr?.engine ?? '',
        qrRows,
        qrAadhaar,
        qrSig,
        tamper,
        verdict,
        meta,
        page: loaded.pages[0],
        risk,
        reasons,
        elapsedMs,
        queueId,
        caseId,
      })
    } catch (e: any) {
      setStage(-1)
      setFileError(`Triage failed: ${e?.message ?? e}`)
    } finally {
      clearInterval(tick)
      setStageNote('')
    }
  }

  function reset() {
    setResult(null)
    setStage(-1)
    setElapsed(0)
    setFile(null)
    setPreviewUrl(null)
    setPwState(null)
    setPassword('')
    setFileError(null)
    setCaseDoc(null)
  }

  const locked = result ? result.risk >= HARD_LOCK_RISK : false
  const review = result ? result.risk >= REVIEW_RISK && !locked : false

  return (
    <div className="flex flex-col gap-5">
    <SelectionPanel disabled={running} />
    <div className="grid gap-5 xl:grid-cols-[380px_1fr]">
      <div className="flex flex-col gap-5">
        <Panel title="Document Capture" icon={Upload}>
          <div className="flex flex-col gap-4">
            {notIdentity && (
              <p className="rounded-lg border border-warning/40 bg-warning/10 px-3 py-2 text-xs text-warning" role="status">
                &quot;{docTypeById(selection.docType).label}&quot; is analysed in the Border Pass &amp; Permit tab. Triage only runs identity-document checks (Aadhaar, PAN, passport, licence, voter ID) and will treat this file generically.{' '}
                <button type="button" className="font-semibold underline" onClick={() => goTo('permit')}>Open that tab</button>
              </p>
            )}

            <div
              onDragOver={(e) => {
                e.preventDefault()
                setDragging(true)
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault()
                setDragging(false)
                const f = e.dataTransfer.files?.[0]
                if (f) acceptFile(f)
              }}
              className={cn(
                'relative flex min-h-44 flex-col items-center justify-center gap-3 overflow-hidden rounded-lg border-2 border-dashed px-4 py-6 text-center transition-colors',
                dragging ? 'border-primary bg-primary/10' : 'border-border bg-background/40',
              )}
            >
              {previewUrl ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img src={previewUrl} alt="Captured document preview" className="max-h-32 rounded border border-border object-contain" />
              ) : (
                <span className="flex size-12 items-center justify-center rounded-full border border-border bg-secondary/50">
                  <FileText className="size-5 text-muted-foreground" aria-hidden="true" />
                </span>
              )}
              {running && <div className="scan-line pointer-events-none absolute inset-x-0 top-0 h-1/4" aria-hidden="true" />}
              {file ? (
                <div>
                  <p className="max-w-[260px] truncate font-mono text-xs text-foreground">{file.name}</p>
                  <p className="font-mono text-[11px] text-muted-foreground">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
              ) : (
                <div>
                  <p className="text-sm font-medium text-foreground">Drop passport, Aadhaar or ID scan</p>
                  <p className="text-xs text-muted-foreground">PDF, JPG, PNG · max 25 MB</p>
                </div>
              )}
              <div className="flex flex-wrap justify-center gap-2">
                <ActionButton variant="outline" onClick={() => fileRef.current?.click()} disabled={running} className="min-h-9 text-xs">
                  Browse files
                </ActionButton>
                <ActionButton variant="outline" onClick={() => setCameraOpen((o) => !o)} disabled={running} className="min-h-9 text-xs">
                  <Camera className="size-3.5" aria-hidden="true" />
                  {cameraOpen ? 'Close camera' : 'Use camera'}
                </ActionButton>
              </div>
              {cameraOpen && (
                <div className="w-full text-left">
                  <CameraCapture
                    onCapture={(f) => {
                      setCameraOpen(false)
                      acceptFile(f, true)
                    }}
                    onClose={() => setCameraOpen(false)}
                  />
                </div>
              )}
              <input
                ref={fileRef}
                type="file"
                accept="application/pdf,image/*"
                className="sr-only"
                tabIndex={-1}
                aria-label="Upload document"
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  if (f) acceptFile(f)
                  e.target.value = ''
                }}
              />
            </div>

            <div className="flex items-center gap-3 rounded-md border border-border bg-background/50 px-3 py-2.5">
              <FileKey2 className={cn('size-4 shrink-0', cert ? 'text-success' : 'text-warning')} aria-hidden="true" />
              <div className="min-w-0 flex-1">
                <p className="text-[11px] uppercase tracking-wider text-muted-foreground">UIDAI certificate</p>
                <p className="truncate font-mono text-xs text-foreground">{cert ? cert.subjectCN || 'loaded' : 'not loaded: Aadhaar QR signature cannot be proven'}</p>
              </div>
              <ActionButton variant="outline" className="min-h-8 px-2.5 text-xs" onClick={() => certRef.current?.click()} disabled={running}>
                {cert ? 'Replace' : 'Load'}
              </ActionButton>
              <input ref={certRef} type="file" accept=".cer,.crt,.pem,.der" className="sr-only" tabIndex={-1} aria-label="Load UIDAI certificate" onChange={(e) => { const f = e.target.files?.[0]; if (f) loadCert(f); e.target.value = '' }} />
            </div>
            {certError && <p role="alert" className="text-xs text-destructive">{certError}</p>}

            {(pwState || (file && /pdf/i.test(file.type))) && (
              <label className="flex flex-col gap-1.5">
                <span className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  <KeyRound className="size-3.5" aria-hidden="true" /> PDF password (only if protected)
                </span>
                <input
                  type="text"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="e-Aadhaar: SUMI1999"
                  className="h-10 rounded-md border border-input bg-background/60 px-3 font-mono text-xs text-foreground focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
                />
              </label>
            )}

            {fileError && (
              <p role="alert" className="text-xs text-destructive">
                {fileError}
              </p>
            )}

            <div className="flex gap-2">
              <ActionButton className="flex-1" onClick={runTriage} disabled={!file || running}>
                <PlayCircle className="size-4" aria-hidden="true" />
                {running ? 'Triage running…' : 'Run fast triage'}
              </ActionButton>
              <ActionButton variant="outline" onClick={reset} disabled={running} aria-label="Reset triage">
                <RotateCcw className="size-4" aria-hidden="true" />
              </ActionButton>
            </div>
          </div>
        </Panel>

        <Panel
          title="Triage Pipeline"
          icon={Timer}
          actions={
            <span className={cn('font-mono text-xs tabular-nums', elapsed > 15000 ? 'text-warning' : result ? 'text-success' : 'text-muted-foreground')}>
              {(elapsed / 1000).toFixed(2)}s / 15.00s
            </span>
          }
        >
          <div className="flex flex-col gap-3">
            <ProgressBar value={result ? 100 : stage < 0 ? 0 : (stage / STAGES.length) * 100 + 8} tone={locked ? 'danger' : 'success'} />
            <StepList steps={STAGES} current={stage} done={!!result} />
            <ScanTheatre stage={stage} running={running} done={!!result} />
            {stageNote && <p className="font-mono text-[11px] text-muted-foreground">{stageNote}…</p>}
            <p className="text-[11px] text-muted-foreground">First run downloads OCR language data, so it is slower than later runs.</p>
          </div>
        </Panel>
      </div>

      <div className="flex flex-col gap-5">
        {!result ? (
          <Panel className="flex min-h-80 items-center justify-center" bodyClassName="flex w-full max-w-md flex-col items-center gap-3 text-center">
            <ScanTheatre stage={stage} running={running} done={false} />
            <p className="text-sm font-medium text-foreground">{running ? `Processing: ${STAGES[stage]?.label}` : 'Awaiting document capture'}</p>
            <p className="max-w-sm text-sm text-muted-foreground">
              Real forensic results (OCR, checksums, ELA, signature) will appear here once triage completes.
            </p>
          </Panel>
        ) : (
          <>
            <VerdictCard verdict={result.verdict} elapsedMs={result.elapsedMs} queueId={result.queueId} />
            <AutoAdvance enabled from="triage" to={result.kind === 'mrz' ? 'biometric' : 'qr'} label={result.kind === 'mrz' ? 'Biometric Match' : 'QR & Signature check'} resetKey={result.caseId} />
            {result.caseId && <p className="font-mono text-[11px] text-muted-foreground">Saved as {result.caseId} · see the Case Records tab</p>}

            <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
              <Panel title="Risk Score" icon={Activity} bodyClassName="flex flex-col items-center gap-4">
                <RiskGauge score={result.risk} />
                <div
                  className={cn(
                    'flex w-full items-center gap-3 rounded-md border px-3 py-2.5',
                    locked ? 'glow-danger border-destructive/50 bg-destructive/10' : review ? 'border-warning/50 bg-warning/10' : 'border-success/30 bg-success/5',
                  )}
                >
                  {locked ? <Lock className="size-5 shrink-0 text-destructive" aria-hidden="true" /> : review ? <ShieldAlert className="size-5 shrink-0 text-warning" aria-hidden="true" /> : <LockOpen className="size-5 shrink-0 text-success" aria-hidden="true" />}
                  <div>
                    <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Safe-Lock</p>
                    <p className={cn('font-mono text-sm font-semibold', locked ? 'text-destructive' : review ? 'text-warning' : 'text-success')}>{locked ? 'LOCKED' : review ? 'REVIEW' : 'DISENGAGED'}</p>
                    <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
                      {locked
                        ? 'Decision frozen by the system. No officer or admin can release it.'
                        : review
                          ? 'Supervisor may override with PIN + written reason.'
                          : 'No block. Normal processing.'}
                    </p>
                  </div>
                </div>
                <dl className="w-full">
                  <KeyValue label="Elapsed" value={`${(result.elapsedMs / 1000).toFixed(2)} s`} tone="success" />
                  <KeyValue label="Signals flagged" value={result.reasons.length} tone={result.reasons.length ? 'danger' : 'success'} />
                  <KeyValue label="QR on document" value={result.qrFound ? `Decoded · ${result.qrEngine}` : result.qrPattern?.present ? 'Drawn but UNREADABLE' : result.kind === 'mrz' ? 'n/a (passport)' : 'Not found'} tone={result.qrFound ? 'success' : result.kind === 'mrz' ? undefined : 'warning'} />
                  <KeyValue label="Lock / Review at" value={`${HARD_LOCK_RISK} / ${REVIEW_RISK}`} />
                </dl>
              </Panel>

              {result.kind === 'mrz' && result.mrzLines ? (
                <Panel
                  title="ICAO 9303 MRZ Checksum"
                  icon={Binary}
                  actions={
                    <StatusBadge tone={result.mrz.every((f) => f.valid) ? 'success' : 'danger'}>
                      {result.mrz.every((f) => f.valid) ? 'All valid' : `${result.mrz.filter((f) => !f.valid).length} failed`}
                    </StatusBadge>
                  }
                >
                  <div className="mb-4 overflow-x-auto rounded-md border border-border bg-background/70 p-3 font-mono text-[11px] leading-relaxed tracking-[0.12em] text-foreground sm:text-xs">
                    <p className="whitespace-pre">{result.mrzLines.line1}</p>
                    <p className="whitespace-pre">{result.mrzLines.line2}</p>
                    {result.mrzLines.line3 && <p className="whitespace-pre">{result.mrzLines.line3}</p>}
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[520px] text-left text-xs">
                      <thead className="text-[11px] uppercase tracking-wider text-muted-foreground">
                        <tr>
                          <th className="pb-2 font-medium">Field</th>
                          <th className="pb-2 font-medium">Value</th>
                          <th className="pb-2 font-medium">{'Σ(v·w) mod 10'}</th>
                          <th className="pb-2 text-center font-medium">Stated</th>
                          <th className="pb-2 text-right font-medium">Status</th>
                        </tr>
                      </thead>
                      <tbody className="font-mono">
                        {result.mrz.map((f) => (
                          <tr key={f.label} className="border-t border-border/60">
                            <td className="py-2 font-sans text-foreground">{f.label}</td>
                            <td className="max-w-[160px] truncate py-2 text-muted-foreground">{f.value}</td>
                            <td className="py-2 text-muted-foreground">
                              {f.sum} mod 10 = <span className="text-foreground">{f.computed}</span>
                            </td>
                            <td className={cn('py-2 text-center', f.valid ? 'text-success' : 'text-destructive')}>{f.stated}</td>
                            <td className="py-2 text-right">
                              <StatusBadge tone={f.valid ? 'success' : 'danger'}>{f.valid ? 'Pass' : 'Fail'}</StatusBadge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <p className="mt-3 text-[11px] text-muted-foreground">MRZ is read by OCR. A single misread character fails a check digit, so confirm visually before acting.</p>
                </Panel>
              ) : (
                <IdentityPanel result={result} />
              )}
            </div>

            <MetaPanel meta={result.meta} />

            <TamperViewer page={result.page} report={result.tamper} words={result.printed.words} />

            <div className="grid gap-5 lg:grid-cols-2">
              <Panel
                title="Error Level Analysis · Pixel Noise"
                icon={Activity}
                actions={
                  <StatusBadge tone={result.ela.anomaly ? (result.ela.reliable ? 'danger' : 'warning') : 'success'}>
                    {result.ela.anomaly ? (result.ela.reliable ? 'Anomaly' : 'Advisory') : 'Uniform'}
                  </StatusBadge>
                }
              >
                <ElaChart report={result.ela} />
              </Panel>

              <Panel
                title="Digital Signature Verification"
                icon={BadgeCheck}
                actions={
                  !result.pdfSig.present ? (
                    <StatusBadge tone="neutral">{result.meta.format === 'pdf' ? 'No signature' : 'Image: n/a'}</StatusBadge>
                  ) : result.pdfSig.digestOk === false || result.pdfSig.sigOk === false ? (
                    <StatusBadge tone="danger">Signature broken</StatusBadge>
                  ) : (
                    <StatusBadge tone={result.pdfSig.digestOk && result.pdfSig.sigOk ? 'success' : 'warning'}>
                      {result.pdfSig.digestOk && result.pdfSig.sigOk ? 'Signature valid' : 'Unverified'}
                    </StatusBadge>
                  )
                }
              >
                <dl>
                  <KeyValue label="Embedded signatures" value={result.pdfSig.count} />
                  <KeyValue label="Signer" value={result.pdfSig.signer || '—'} />
                  <KeyValue label="Issuer" value={result.pdfSig.issuer || '—'} />
                  <KeyValue label="Content hash" value={result.pdfSig.digestOk === null ? '—' : result.pdfSig.digestOk ? 'MATCH' : 'MISMATCH'} tone={result.pdfSig.digestOk === null ? undefined : result.pdfSig.digestOk ? 'success' : 'danger'} />
                  <KeyValue label="Signer RSA" value={result.pdfSig.sigOk === null ? '—' : result.pdfSig.sigOk ? 'VALID' : 'INVALID'} tone={result.pdfSig.sigOk === null ? undefined : result.pdfSig.sigOk ? 'success' : 'danger'} />
                  <KeyValue label="Covers whole file" value={result.pdfSig.coversWholeFile === null ? '—' : result.pdfSig.coversWholeFile ? 'YES' : 'NO · data appended'} tone={result.pdfSig.coversWholeFile === false ? 'danger' : undefined} />
                  <KeyValue label="Trust chain to root CA" value="Not checked (offline)" />
                </dl>
                <p className="mt-2 text-[11px] text-muted-foreground">{result.pdfSig.detail}</p>
                {result.meta.format !== 'pdf' && (
                  <p className="mt-2 rounded-md border border-border bg-background/60 p-2 text-[11px] leading-relaxed text-muted-foreground">
                    A JPG / PNG can never carry the PDF signature. To prove an Aadhaar is genuine, upload the original e-Aadhaar PDF (digital signature) or open the QR &amp; Signature tab and load the UIDAI certificate.
                  </p>
                )}
                <div className="mt-3 rounded-md border border-border bg-background/70 p-3">
                  <p className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">File digest (SHA-256)</p>
                  <p className="break-all font-mono text-xs text-foreground">{result.fileDigest}</p>
                </div>
              </Panel>
            </div>
          </>
        )}
      </div>
    </div>
    </div>
  )
}


function MetaPanel({ meta }: { meta: Meta }) {
  const srcLabel = meta.source === 'camera-photo' ? 'Camera / scanner photo' : meta.source === 'pdf' ? 'PDF document' : meta.source === 'screenshot-or-export' ? 'Screenshot / export (no camera data)' : 'Unknown image'
  const bad = meta.aiMarkers.length > 0 || meta.editorTags.length > 0 || meta.pdfModifiedAfterCreation
  return (
    <Panel
      title="Metadata · Source · AI-generation check"
      icon={FileKey2}
      actions={<StatusBadge tone={meta.aiMarkers.length ? 'danger' : bad ? 'warning' : 'success'}>{meta.aiMarkers.length ? 'AI marker found' : bad ? 'Review' : 'No bad marker'}</StatusBadge>}
    >
      <dl>
        <KeyValue label="File type" value={meta.format.toUpperCase()} />
        <KeyValue label="Source" value={srcLabel} tone={meta.source === 'screenshot-or-export' ? 'warning' : undefined} />
        {meta.format !== 'pdf' && <KeyValue label="Camera" value={meta.camera || 'none in file'} />}
        <KeyValue label="Software tag" value={meta.software || '—'} tone={meta.editorTags.length ? 'danger' : undefined} />
        {meta.format === 'pdf' && (
          <>
            <KeyValue label="PDF producer" value={meta.pdfProducer || '—'} tone={meta.editorTags.length ? 'danger' : undefined} />
            <KeyValue label="Created / modified" value={`${meta.pdfCreated || '—'} / ${meta.pdfModified || '—'}`} tone={meta.pdfModifiedAfterCreation ? 'warning' : undefined} />
            <KeyValue label="Revisions saved" value={meta.pdfRevisions || '—'} />
          </>
        )}
        <KeyValue label="AI-generation marker" value={meta.aiMarkers.length ? meta.aiMarkers.join(', ') : 'none declared'} tone={meta.aiMarkers.length ? 'danger' : 'success'} />
        <KeyValue label="Content Credentials (C2PA)" value={meta.c2pa ? 'present' : 'none'} />
      </dl>
      <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
        Only positive markers count as evidence. Missing metadata proves nothing, because screenshots and WhatsApp strip it. {meta.notes.join(' ')}
      </p>
    </Panel>
  )
}
