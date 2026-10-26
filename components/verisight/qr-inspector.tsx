'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { ArrowLeftRight, CheckCircle2, CircleDashed, FileKey2, QrCode, ScanLine, ShieldAlert, ShieldCheck, ShieldQuestion, Upload, XCircle, AlertTriangle } from 'lucide-react'
import { cn } from '@/lib/utils'
import { buildQrRows, decodeAadhaarQr, loadFile, scanQr, verifyAadhaarSignature, type AadhaarQr, type Cmp, type Row, type SigCheck } from '@/lib/analysis'
import { detectQrPattern } from '@/lib/qrpattern'
import { classifyQrPayload } from '@/lib/qrformat'
import { useStore } from './store'
import { AutoAdvance } from './workflow'
import { assessCert } from '@/lib/trust'
import { ActionButton, AlertBanner, KeyValue, Panel, Spinner, StatusBadge } from './primitives'

type Found = 'decoded' | 'pattern-only' | 'none'
type View = {
  source: string
  found: Found
  aadhaar: AadhaarQr | null
  generic: Record<string, string> | null
  rawText: string
  sig: SigCheck
  rows: Row[]
}
type CheckState = 'pass' | 'fail' | 'warn' | 'skip'
type Check = { label: string; state: CheckState; detail: string }

const certExpired = (notAfter: string) => {
  const t = Date.parse(notAfter)
  return Number.isFinite(t) && t < Date.now()
}

export function QrInspector() {
  const { log, addFlag, caseDoc, cert, certError, loadCert, clearCert, markStep } = useStore()
  const [view, setView] = useState<View | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [manual, setManual] = useState('')
  const [showManual, setShowManual] = useState(false)
  const lastText = useRef('')
  const lastSource = useRef('')
  const lastAuto = useRef(false)
  const flagged = useRef('')
  const certInput = useRef<HTMLInputElement>(null)
  const qrInput = useRef<HTMLInputElement>(null)

  /** ONE pipeline for every input (triage QR, uploaded QR image/PDF, pasted payload, certificate change). */
  const verify = useCallback(
    async (text: string, source: string, auto: boolean) => {
      setBusy(true)
      setError(null)
      lastText.current = text
      lastSource.current = source
      lastAuto.current = auto
      try {
        const printed = caseDoc?.printed
        const aadhaar = await decodeAadhaarQr(text)
        let rows: Row[] = []
        let sig: SigCheck = { state: 'unsigned' }
        let generic: Record<string, string> | null = null
        if (aadhaar) {
          rows = buildQrRows(aadhaar, printed)
          sig = aadhaar.kind === 'secure' ? await verifyAadhaarSignature(aadhaar, cert) : { state: 'unsigned' }
        } else {
          try {
            const j = JSON.parse(text)
            if (j && typeof j === 'object' && !Array.isArray(j)) {
              generic = Object.fromEntries(Object.entries(j).map(([k, v]) => [k, String(v)]))
              sig = { state: 'no-cert' }
            }
          } catch {
            /* not JSON */
          }
        }
        setView({ source, found: 'decoded', aadhaar, generic, rawText: text, sig, rows })
        markStep('qr', true)
        log('QR_VERIFY', `${source} · ${aadhaar ? aadhaar.kind : generic ? 'json' : 'unknown'} · sig ${sig.state}`)

        const mism = rows.filter((r) => r.res === 'mismatch')
        const bad = sig.state === 'invalid'
        const trustedBad = sig.state === 'invalid' && sig.certTrusted
        const key = `${text.slice(0, 40)}:${text.length}:${sig.state}:${mism.length}`
        // Triage already queued its own document: only flag manually supplied QRs here
        if (!auto && (bad || mism.length) && flagged.current !== key) {
          flagged.current = key
          addFlag({
            subject: aadhaar?.fields.name || caseDoc?.subject || 'UNKNOWN',
            docType: aadhaar ? 'Aadhaar' : 'Unknown QR',
            docNo: caseDoc?.docNo ?? '—',
            risk: Math.min(97, 40 + (trustedBad ? 40 : bad ? 10 : 0) + mism.length * 12),
            lane: 'Lane 03 · QR',
            reasons: [
              ...(bad ? [{ code: 'SIG_INVALID' as const, detail: sig.state === 'invalid' ? sig.reason : 'Signature invalid' }] : []),
              ...(mism.length ? [{ code: 'QR_MISMATCH' as const, detail: `QR ≠ printed: ${mism.map((r) => `${r.label} (${r.qr} vs ${r.printed})`).join(', ')}` }] : []),
            ],
          })
        }
      } catch (e: any) {
        setError(`Decode failed: ${e?.message ?? e}`)
        setView(null)
      } finally {
        setBusy(false)
      }
    },
    [addFlag, caseDoc, cert, log, markStep],
  )

  // AUTO 1: a document was triaged -> verify its QR immediately
  useEffect(() => {
    setView(null)
    setError(null)
    if (!caseDoc) return
    if (caseDoc.qr) verify(caseDoc.qr.text, `${caseDoc.fileName} · page ${caseDoc.qr.page + 1}`, true)
    else {
      setView({ source: caseDoc.fileName, found: caseDoc.qrPattern?.present ? 'pattern-only' : 'none', aadhaar: null, generic: null, rawText: '', sig: { state: 'unsigned' }, rows: [] })
      markStep('qr', false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseDoc])

  // AUTO 2: certificate loaded / replaced -> re-verify the same payload straight away (no extra click)
  const certKey = cert?.sha256 ?? ''
  useEffect(() => {
    if (certKey && lastText.current) verify(lastText.current, lastSource.current || 'payload', lastAuto.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [certKey])

  async function onQrFile(f: File) {
    setBusy(true)
    setError(null)
    try {
      const loaded = await loadFile(f)
      if (loaded.needsPassword) throw new Error('PDF is password protected: use the Document Triage tab.')
      const hit = await scanQr(loaded.pages)
      if (!hit) {
        const pat = detectQrPattern(loaded.pages)
        setView({ source: f.name, found: pat.present ? 'pattern-only' : 'none', aadhaar: null, generic: null, rawText: '', sig: { state: 'unsigned' }, rows: [] })
        markStep('qr', false)
      } else await verify(hit.text, f.name, false)
    } catch (e: any) {
      setError(e?.message ?? String(e))
    } finally {
      setBusy(false)
    }
  }

  /* ---------------- derived report ---------------- */
  const sig = view?.sig
  const certTrust = cert ? assessCert(cert) : null
  const mism = view ? view.rows.filter((r) => r.res === 'mismatch').length : 0
  const unread = view ? view.rows.filter((r) => r.res === 'unread').length : 0
  const matched = view ? view.rows.filter((r) => r.res === 'match').length : 0
  const resTone = (r: Cmp) => (r === 'match' ? 'success' : r === 'fuzzy' ? 'warning' : r === 'unread' ? 'neutral' : 'danger')
  const resLabel = (r: Cmp) => (r === 'match' ? 'Match' : r === 'fuzzy' ? 'Close' : r === 'unread' ? 'Not read' : 'Mismatch')

  const checks: Check[] = []
  if (view) {
    checks.push({
      label: 'QR code located & decoded',
      state: view.found === 'decoded' ? 'pass' : 'warn',
      detail:
        view.found === 'decoded' ? 'Decoded successfully.' : view.found === 'pattern-only' ? 'A QR picture is printed but could not be decoded. In a screenshot or small photo the QR is usually too small, so this is NOT proof of forgery. Upload the original e-Aadhaar PDF (use "Upload a QR image / PDF") or a flat 300 dpi scan to verify it.' : 'No QR found. Not applicable for passports. For Aadhaar upload the original e-Aadhaar PDF or a sharper scan: screenshots lose the QR.',
    })
    if (view.found === 'decoded') {
      checks.push({
        label: 'QR format',
        state: view.aadhaar ? 'pass' : view.generic ? 'warn' : 'fail',
        detail: view.aadhaar
          ? view.aadhaar.kind === 'secure' ? `Aadhaar Secure QR ${view.aadhaar.version}` : 'Aadhaar legacy XML (unsigned)'
          : `${classifyQrPayload(view.rawText).label}. This is not recognized as Aadhaar Secure QR; it may belong to another issuer. QR shape alone cannot identify a government issuer or prove a signature.`,
      })
      if (view.aadhaar?.kind === 'secure') {
        checks.push({
          label: 'UIDAI certificate',
          state: !cert ? 'warn' : certTrust?.state === 'trusted' ? 'pass' : 'warn',
          detail: !cert ? 'Not loaded: signature cannot be checked.' : certTrust?.state === 'trusted' ? `${cert.subjectCN || 'Loaded'} · on the UIDAI trust list · valid until ${cert.notAfter}` : `${cert.subjectCN || 'Loaded'} · NOT TRUSTED. ${certTrust?.reason ?? ''} Fingerprint: ${cert.derSha256 ?? ''}`,
        })
        checks.push({
          label: 'RSA digital signature',
          state: sig?.state === 'verified' ? 'pass' : sig?.state === 'invalid' && sig.certTrusted ? 'fail' : 'warn',
          detail: sig?.state === 'verified' ? 'Signature matches the trusted UIDAI certificate: data is untouched.' : sig?.state === 'invalid' ? sig.reason : sig?.state === 'valid-untrusted' ? `Signature is mathematically valid for the loaded certificate, but that certificate is not authenticated as UIDAI's. NOT UIDAI VERIFIED. ${sig.why}` : 'Cannot be verified until the UIDAI certificate is loaded.',
        })
      }
      if (view.rows.length) {
        checks.push({
          label: 'QR data = printed data',
          state: mism ? 'fail' : unread === view.rows.length ? 'warn' : unread ? 'warn' : 'pass',
          detail: mism ? `${mism} field(s) differ.` : `${matched} of ${view.rows.length} fields match${unread ? `, ${unread} not read by OCR` : ''}.`,
        })
      } else if (view.aadhaar) {
        checks.push({ label: 'QR data = printed data', state: 'skip', detail: 'No printed document loaded to compare with. Run Document Triage first.' })
      }
    }
  }
  const overall: 'bad' | 'ok' | 'warn' | 'none' = !view ? 'none' : checks.some((c) => c.state === 'fail') ? 'bad' : sig?.state === 'verified' && !mism ? 'ok' : 'warn'
  const complete = !!view && !busy
  const stateIcon = (s: CheckState) =>
    s === 'pass' ? <CheckCircle2 className="size-4 text-success" aria-hidden="true" /> : s === 'fail' ? <XCircle className="size-4 text-destructive" aria-hidden="true" /> : s === 'warn' ? <AlertTriangle className="size-4 text-warning" aria-hidden="true" /> : <CircleDashed className="size-4 text-muted-foreground" aria-hidden="true" />

  return (
    <div className="grid gap-5 xl:grid-cols-[420px_1fr]">
      {/* ================= ONE input panel: QR + certificate + raw payload ================= */}
      <Panel title="Verification Inputs" icon={QrCode} actions={<StatusBadge tone={cert ? 'success' : 'warning'}>{cert ? 'Cert loaded' : 'Cert needed'}</StatusBadge>}>
        <div className="flex flex-col gap-5 text-sm">
          <section>
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">1 · QR source</p>
            <div className="rounded-md border border-border bg-background/50 p-3">
              {caseDoc ? (
                <p className="break-all font-mono text-xs text-foreground">
                  {caseDoc.fileName} · {caseDoc.qr ? 'QR decoded in triage' : caseDoc.qrPattern?.present ? 'QR drawn, not readable' : 'no QR found'}
                </p>
              ) : (
                <p className="text-xs text-muted-foreground">No document yet. Run Document Triage: its QR is verified here automatically.</p>
              )}
            </div>
            <ActionButton variant="outline" className="mt-2 w-full" onClick={() => qrInput.current?.click()} disabled={busy}>
              <Upload className="size-4" aria-hidden="true" /> Upload a QR image / PDF
            </ActionButton>
            <input ref={qrInput} type="file" accept="application/pdf,image/*" className="sr-only" tabIndex={-1} onChange={(e) => { const f = e.target.files?.[0]; if (f) onQrFile(f); e.target.value = '' }} />
          </section>

          <section>
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">2 · UIDAI signing certificate</p>
            <p className="mb-2 text-xs leading-relaxed text-muted-foreground">Download the official public certificate (.cer / .pem) from uidai.gov.in once. It is saved in this browser and used for every check, also in Document Triage.</p>
            {cert && (
              <dl className="mb-2">
                <KeyValue label="Subject" value={cert.subjectCN || '—'} />
                <KeyValue label="Valid until" value={cert.notAfter} tone={certExpired(cert.notAfter) ? 'warning' : undefined} />
                <KeyValue label="Key SHA-256" value={(cert.sha256 ?? '').slice(0, 24) + '…'} />
              </dl>
            )}
            <div className="flex gap-2">
              <ActionButton variant="outline" className="flex-1" onClick={() => certInput.current?.click()}>
                <FileKey2 className="size-4" aria-hidden="true" /> {cert ? 'Replace certificate' : 'Load UIDAI certificate'}
              </ActionButton>
              {cert && (
                <ActionButton variant="ghost" onClick={clearCert} aria-label="Remove certificate">
                  Remove
                </ActionButton>
              )}
            </div>
            <input ref={certInput} type="file" accept=".cer,.crt,.pem,.der" className="sr-only" tabIndex={-1} onChange={(e) => { const f = e.target.files?.[0]; if (f) loadCert(f); e.target.value = '' }} />
            {certError && <p role="alert" className="mt-2 text-xs text-destructive">{certError}</p>}
          </section>

          <section>
            <button type="button" onClick={() => setShowManual((v) => !v)} className="mb-2 flex w-full items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground" aria-expanded={showManual}>
              <span>3 · Paste raw payload (advanced)</span>
              <span className="font-mono">{showManual ? '−' : '+'}</span>
            </button>
            {showManual && (
              <>
                <textarea
                  value={manual}
                  onChange={(e) => setManual(e.target.value)}
                  spellCheck={false}
                  rows={5}
                  placeholder="Paste decoded QR text (Aadhaar numeric string, XML or JSON)"
                  className="w-full resize-y rounded-md border border-input bg-background/70 p-3 font-mono text-xs text-foreground focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
                />
              </>
            )}
          </section>

          <ActionButton
            className="w-full"
            onClick={() => {
              if (manual.trim()) verify(manual.trim(), 'pasted payload', false)
              else if (lastText.current) verify(lastText.current, lastSource.current, lastAuto.current)
              else if (caseDoc?.qr) verify(caseDoc.qr.text, caseDoc.fileName, true)
            }}
            disabled={busy || (!manual.trim() && !lastText.current && !caseDoc?.qr)}
          >
            {busy ? <Spinner label="Verifying" /> : <ScanLine className="size-4" aria-hidden="true" />}
            Verify everything
          </ActionButton>
          {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
        </div>
      </Panel>

      {/* ================= ONE report ================= */}
      <div className="flex flex-col gap-5">
        {!view ? (
          <Panel className="flex min-h-80 items-center justify-center" bodyClassName="flex flex-col items-center gap-3 text-center">
            {busy ? <Spinner className="size-8 text-primary" label="Verifying" /> : <QrCode className="size-8 text-muted-foreground" aria-hidden="true" />}
            <p className="text-sm font-medium text-foreground">{busy ? 'Verifying…' : 'Nothing verified yet'}</p>
            <p className="max-w-sm text-sm text-muted-foreground">Run Document Triage (QR is checked automatically), upload a QR image, or paste a payload. Certificate, QR and printed text are all checked together in one report.</p>
          </Panel>
        ) : (
          <>
            {overall === 'bad' ? (
              <AlertBanner tone="danger" icon={ShieldAlert} title={sig?.state === 'invalid' && sig.certTrusted ? 'QR SIGNATURE REJECTED' : view.found === 'pattern-only' ? 'FAKE QR: NOTHING TO DECODE' : mism ? 'QR ≠ PRINTED DOCUMENT' : 'QR CHECK FAILED'}>
                {checks.filter((c) => c.state === 'fail').map((c) => c.detail).join(' ')}
              </AlertBanner>
            ) : overall === 'ok' ? (
              <AlertBanner tone="success" icon={ShieldCheck} title="UIDAI SIGNATURE VERIFIED">
                QR data is authentic and untouched.{unread ? ` ${unread} printed field(s) could not be read by OCR, so they were not compared.` : ' All compared fields match the printed document.'}
              </AlertBanner>
            ) : (
              <AlertBanner tone="warning" icon={ShieldQuestion} title="NOT FULLY VERIFIED">
                {view.found === 'none' ? 'No QR available to verify.' : sig?.state === 'no-cert' ? 'Load the UIDAI certificate (left) to complete the signature check.' : 'This QR type carries no digital signature, so authenticity cannot be proven.'}
              </AlertBanner>
            )}

            <Panel title="Verification Checklist" icon={ShieldCheck} actions={<span className="font-mono text-[11px] text-muted-foreground">{view.source}</span>}>
              <ul className="flex flex-col divide-y divide-border/60">
                {checks.map((c) => (
                  <li key={c.label} className="flex items-start gap-3 py-2.5">
                    <span className="mt-0.5">{stateIcon(c.state)}</span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-foreground">{c.label}</p>
                      <p className="text-xs leading-relaxed text-muted-foreground">{c.detail}</p>
                    </div>
                  </li>
                ))}
              </ul>
              {view.aadhaar && (
                <dl className="mt-3 grid gap-x-8 border-t border-border pt-3 md:grid-cols-2">
                  <KeyValue label="Scheme" value={view.aadhaar.kind === 'secure' ? 'RSA-2048 · SHA-256 · PKCS#1 v1.5' : '—'} />
                  <KeyValue label="Payload size" value={`${view.aadhaar.rawBytes} bytes`} />
                  {sig?.state === 'verified' && <KeyValue label="Verified with" value={sig.certSubject || 'UIDAI cert'} tone="success" />}
                </dl>
              )}
            </Panel>

            {view.aadhaar && (
              <Panel title="Decoded QR Fields" icon={QrCode}>
                <dl className="grid gap-x-8 md:grid-cols-2">
                  {Object.entries(view.aadhaar.fields as Record<string, string>).filter(([, v]) => v).map(([k, v]) => (
                    <KeyValue key={k} label={k} value={k === 'uid' || k === 'referenceId' ? `${k === 'uid' ? 'XXXX XXXX ' : 'ref …'}${v.slice(k === 'uid' ? -4 : 0, k === 'uid' ? undefined : 4)}` : v} />
                  ))}
                </dl>
              </Panel>
            )}

            {view.generic && (
              <Panel title="Decoded JSON Fields" icon={QrCode}>
                <dl className="grid gap-x-8 md:grid-cols-2">
                  {Object.entries(view.generic).map(([k, v]) => (
                    <KeyValue key={k} label={k} value={v} />
                  ))}
                </dl>
              </Panel>
            )}

            {view.rows.length > 0 && (
              <Panel title="Payload Cross-Verification" icon={ArrowLeftRight} actions={<StatusBadge tone={mism ? 'danger' : unread ? 'warning' : 'success'}>{mism ? `${mism} mismatch` : unread ? `${unread} not read` : 'All match'}</StatusBadge>}>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[520px] text-left text-xs">
                    <thead className="text-[11px] uppercase tracking-wider text-muted-foreground">
                      <tr>
                        <th className="pb-2 font-medium">Field</th>
                        <th className="pb-2 font-medium">QR payload</th>
                        <th className="pb-2 font-medium">Printed text</th>
                        <th className="pb-2 text-right font-medium">Result</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono">
                      {view.rows.map((r) => (
                        <tr key={r.label} className={cn('border-t border-border/60', r.res === 'mismatch' && 'bg-destructive/[0.07]')}>
                          <td className="py-2.5 pl-1 font-sans text-foreground">{r.label}</td>
                          <td className="py-2.5 text-muted-foreground">{r.qr}</td>
                          <td className="py-2.5 text-muted-foreground">{r.printed || '—'}</td>
                          <td className="py-2.5 pr-1 text-right"><StatusBadge tone={resTone(r.res)}>{resLabel(r.res)}</StatusBadge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
            )}

            <AutoAdvance enabled={complete && overall !== 'bad'} from="qr" to="biometric" label="Biometric Match" seconds={5} resetKey={view.source + (sig?.state ?? '')} />
            {complete && overall === 'bad' && (
              <p className="text-xs text-muted-foreground">This QR check failed. Review the evidence above before moving on.</p>
            )}
          </>
        )}
      </div>
    </div>
  )
}
