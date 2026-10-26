import type { AadhaarQr, ElaReport, PdfSig, Printed, QrHit, Row, SigCheck } from './analysis'
import { dummyAadhaarPattern } from './analysis'
import type { MrzField } from './forensics'
import type { TamperReport } from './tamper'
import type { QrPattern } from './qrpattern'
import type { Meta } from './metadata'
import { floorFor, HARD_LOCK_RISK, REVIEW_RISK, type FlagCode, type Severity } from './policy'
import { dobSanity, validateDl, validateEpic, validatePan, type IdKind } from './docs'
import { classifyQrPayload } from './qrformat'

/* ============================================================
 * EVIDENCE-BASED VERDICT
 * Every finding carries a severity; hard evidence (checksum, signature,
 * QR mismatch, dummy number) can never be averaged away (lib/policy.ts).
 * ============================================================ */

export { HARD_LOCK_RISK, REVIEW_RISK } from './policy'
export type { Severity, FlagCode } from './policy'

export type Finding = {
  severity: Severity
  code: FlagCode
  title: string
  detail: string
  points: number
  regionIds?: number[]
}

export type Level = 'LIKELY_FORGED' | 'SUSPICIOUS' | 'NO_SIGNAL'

export type Verdict = {
  level: Level
  risk: number
  headline: string
  sub: string
  findings: Finding[]
  canOverride: boolean
}

export type VerdictInput = {
  kind: IdKind
  printed: Printed
  aadhaarValid: boolean | null
  mrz: MrzField[]
  ela: ElaReport
  tamper: TamperReport
  pdfSig: PdfSig
  qr: QrHit | null
  qrPattern?: QrPattern | null
  qrAadhaar: AadhaarQr | null
  qrRows: Row[]
  qrSig: SigCheck | null
  isPdf: boolean
  meta: Meta
  /** approximate width in pixels of the printed QR (0 = unknown). Dense Aadhaar QRs need roughly 300 px to be decodable. */
  qrPx?: number
}

const mask = (n: string) => (n.length === 12 ? `XXXX XXXX ${n.slice(8)}` : n || '—')

/** a PDF whose embedded signature verifies AND whose signer chains to a pinned trusted root */
const pdfFullyTrusted = (p: PdfSig) =>
  p.present && p.digestOk === true && p.sigOk === true && p.coversWholeFile !== false && p.chain.state === 'trusted'

export function buildVerdict(i: VerdictInput): Verdict {
  // 🛡️ PDF GUARD: a PDF render is a digital page, not a photo — tamper regions (red boxes)
  // are never rendered for PDFs; the PDF signature / QR signature is the real evidence.
  if (i.isPdf && i.tamper) {
    i.tamper.regions = []
    i.tamper.copyMoveBlocks = 0
  }

  const f: Finding[] = []
  const add = (x: Finding) => f.push(x)

  const pdfTrusted = pdfFullyTrusted(i.pdfSig)
  const aadhaarQrTrusted = i.kind === 'aadhaar' && i.qrSig?.state === 'verified'
  const aadhaarQrMatches =
    i.kind === 'aadhaar' &&
    !!i.qrAadhaar &&
    i.qrRows.some((row) => row.res === 'match') &&
    i.qrRows.every((row) => row.res !== 'mismatch')
  const aadhaarTrusted = aadhaarQrMatches && aadhaarQrTrusted

  /* ---------- identity checksums ---------- */
  const fails = i.kind === 'mrz' ? i.mrz.filter((m) => !m.valid) : []
  if (fails.length)
    add({
      severity: 'critical',
      code: 'MRZ_CHECKSUM',
      title: `MRZ checksum FAILED (${fails.length} field${fails.length > 1 ? 's' : ''})`,
      detail: fails.map((m) => `${m.label}: printed ${m.stated}, should be ${m.computed}`).join('; ') + '. A single OCR misread can cause this, confirm visually.',
      points: 45,
    })

  if (i.kind === 'aadhaar' && !i.printed.aadhaarNo && !aadhaarTrusted)
    add({ severity: 'high', code: 'UNREADABLE', title: 'Aadhaar number could not be read', detail: 'No 12-digit number was found by OCR, so the Verhoeff checksum could not run. Use a sharper, straight photo.', points: 15 })

  if (i.kind === 'aadhaar' && i.printed.aadhaarNo && i.aadhaarValid === false && !aadhaarTrusted) {
    const n = i.printed.aadhaarNo
    const cands = i.printed.aadhaarCandidates.length
    add({
      severity: 'critical',
      code: 'AADHAAR_CHECKSUM',
      title: `Aadhaar number ${mask(n)} is NOT a valid number`,
      detail: `The last digit of every real Aadhaar is a Verhoeff check digit. This number fails it${cands > 1 ? ` (${cands} OCR readings, none valid)` : ''}. A genuine card cannot have this number.`,
      points: 60,
    })
    const dummy = dummyAadhaarPattern(n)
    if (dummy)
      add({
        severity: 'critical',
        code: 'AADHAAR_CHECKSUM',
        title: 'Dummy / sample number pattern',
        detail: `The Aadhaar number looks made-up: ${dummy}. UIDAI does not issue numbers like this.`,
        points: 40,
      })
  }

  /* ---------- QR ---------- */
  if (i.kind === 'aadhaar') {
    const fromPicture = !i.isPdf && !i.meta.pixelForensicsReliable // screenshot / export / stripped image
    const tiny = (i.qrPx ?? 0) > 0 && (i.qrPx ?? 0) < 300
    if (!i.qr && i.qrPattern?.present) {
      if (fromPicture || tiny)
        add({
          severity: 'medium',
          code: 'QR_MISMATCH',
          title: 'QR is present but too small / blurry to decode',
          detail: `A QR is printed on the card but this ${fromPicture ? 'screenshot / image export' : 'photo'} does not hold enough pixels to read it${i.qrPx ? ` (about ${Math.round(i.qrPx)} px wide, a dense Aadhaar QR needs ~300 px)` : ''}. This is NOT evidence of forgery. For proof upload the original e-Aadhaar PDF, or re-scan the card flat at 300 dpi or more.`,
          points: 8,
        })
      else
        add({
          severity: 'critical',
          code: 'QR_MISMATCH',
          title: 'QR-shaped picture present but it contains NO readable data',
          detail: 'QR finder squares were found and the picture is large enough, yet no decoder (native / jsQR / ZXing, multi-scale, rotated) could read it. Fake and AI-generated cards often print a QR that looks real but is only artwork.',
          points: 45,
        })
    } else if (!i.qr)
      add({
        severity: i.isPdf ? 'high' : 'medium',
        code: 'QR_MISMATCH',
        title: i.isPdf ? 'No readable Secure QR in this PDF' : 'No readable Secure QR in this image',
        detail: i.isPdf
          ? 'A genuine e-Aadhaar PDF always carries a UIDAI-signed Secure QR and it renders at high resolution. None could be decoded.'
          : 'Screenshots and low-resolution photos usually lose the QR. This alone does not prove forgery, but the card cannot be proven genuine. Upload the original e-Aadhaar PDF (best) or a flat 300 dpi scan.',
        points: i.isPdf ? 20 : 10,
      })
    else if (i.qr && !i.qrAadhaar)
      add({
        severity: 'high',
        code: 'QR_MISMATCH',
        title: 'QR is not an Aadhaar Secure QR',
        detail: 'A QR was decoded but its content is not in UIDAI format (numeric Secure QR / XML). It may be a decorative or fake QR.',
        points: 25,
      })
    else if (i.qr && i.qrAadhaar) {
      // a trusted PDF signature already proves the document; QR-vs-printed mismatch is then not an accusation
      const mism = i.qrRows.filter((r) => r.res === 'mismatch')
      if (mism.length) {
        const signedMismatch = aadhaarQrTrusted && i.printed.confidence >= 80
        add({
          severity: signedMismatch ? 'critical' : 'high',
          code: signedMismatch ? 'SIGNED_DATA_MISMATCH' : 'QR_MISMATCH',
          title: `QR data ≠ printed data (${mism.map((r) => r.label).join(', ')})`,
          detail: `${mism.map((r) => `${r.label}: QR "${r.qr}" vs printed "${r.printed}"`).join('; ')}${signedMismatch ? ' The UIDAI signature is trusted and OCR confidence is high: the printed document content conflicts with the signed QR.' : ' The signed QR and extracted print differ; OCR may be wrong, so confirm the fields before deciding.'}`,
          points: signedMismatch ? 70 : Math.min(30, 15 * mism.length),
        })
      }
      if (i.qrSig?.state === 'invalid')
        add(
          i.qrSig.certTrusted
            ? { severity: 'critical', code: 'SIG_INVALID', title: 'UIDAI signature on QR is INVALID', detail: i.qrSig.reason, points: 60 }
            : { severity: 'high', code: 'SIG_INVALID', title: 'QR signature does not match the loaded certificate', detail: i.qrSig.reason, points: 25 },
        )
      else if (i.qrSig?.state === 'valid-untrusted')
        add({ severity: 'medium', code: 'META_SUSPECT', title: 'QR signature is valid, but the certificate is not authenticated as UIDAI', detail: i.qrSig.why + ' The card is therefore NOT shown as UIDAI verified.', points: 5 })
    }
  }

  /* ---------- digital signature in PDF ---------- */
  if (i.pdfSig.present && (i.pdfSig.digestOk === false || i.pdfSig.sigOk === false))
    add({ severity: 'critical', code: 'DOC_SIG_BROKEN', title: 'PDF signature BROKEN: file changed after signing', detail: i.pdfSig.detail, points: 50 })
  else if (i.pdfSig.present && i.pdfSig.chain.state === 'broken')
    add({ severity: 'high', code: 'DOC_SIG_BROKEN', title: 'PDF signer certificate chain is broken', detail: i.pdfSig.chain.detail, points: 40 })
  else if (i.pdfSig.present && i.pdfSig.digestOk && i.pdfSig.sigOk && !pdfTrusted) {
    const trustSetup = i.kind === 'aadhaar'
      ? 'Configure NEXT_PUBLIC_PDF_TRUSTED_ROOTS_SHA256 with a verified CA fingerprint, or NEXT_PUBLIC_AADHAAR_PDF_SIGNER_SHA256 with a verified Aadhaar signer fingerprint.'
      : 'Configure NEXT_PUBLIC_PDF_TRUSTED_ROOTS_SHA256 with a verified CA fingerprint.'
    add({ severity: 'medium', code: 'META_SUSPECT', title: 'PDF signature is valid but the signer is not trusted', detail: `Anyone can sign a PDF with their own certificate. ${i.pdfSig.chain.detail} ${trustSetup}`, points: 5 })
  }
  else if (i.pdfSig.present && i.pdfSig.coversWholeFile === false)
    add({ severity: 'high', code: 'DOC_SIG_BROKEN', title: 'Data appended after the PDF signature', detail: i.pdfSig.detail, points: 20 })

  /* ---------- localised tampering ----------
   * Pixel forensics are only trusted on an untouched camera / scanner JPEG. On screenshots, PDF renders and re-saved images,
   * logos, text and photos legitimately differ in compression and noise, so they are advisory and can never lock a document alone. */
  const t = i.tamper
  const reliable = i.meta.pixelForensicsReliable && !i.isPdf
  const pixelFindings: Finding[] = []
  const addPx = (x: Finding) => pixelFindings.push(x)
  const cm = t.regions.filter((r) => r.kinds.includes('COPY-MOVE'))
  if (cm.length)
    addPx({
      severity: reliable ? 'critical' : 'medium',
      code: 'ELA_ANOMALY',
      title: 'Repeated (cloned) image area found',
      detail: `${t.copyMoveBlocks} image blocks repeat exactly elsewhere on the document. ${reliable ? 'A camera photo cannot repeat pixels exactly, so this is a copy-paste.' : 'On a digital page (screenshot / PDF render) repeated logos and identical digits repeat naturally, so this is advisory only.'}`,
      points: reliable ? 35 : 6,
      regionIds: cm.map((r) => r.id),
    })
  const strong = t.regions.filter((r) => !r.kinds.includes('COPY-MOVE') && r.score >= 0.55)
  if (strong.length) {
    const onText = strong.filter((r) => r.fields.length)
    addPx({
      severity: reliable ? 'high' : 'medium',
      code: 'ELA_ANOMALY',
      title: `${strong.length} edited area${strong.length > 1 ? 's' : ''} ${reliable ? 'detected' : 'to double-check'}${onText.length ? ' near printed text' : ''}`,
      detail:
        (onText.length ? `Near text: ${onText.map((r) => `"${r.fields.join(' ')}"`).join(', ')}. ` : '') +
        (reliable ? 'Compression / noise differs from the rest of the page.' : 'This file is a screenshot, export or re-saved image, so compression traces are unreliable. Advisory only: it does not lock the decision. Check the QR signature instead.'),
      points: reliable ? (onText.length ? 30 : 22) : 4,
      regionIds: strong.map((r) => r.id),
    })
  } else if (i.ela.anomaly && !t.regions.length) {
    addPx({ severity: 'medium', code: 'ELA_ANOMALY', title: 'Uneven compression across page', detail: `${i.ela.anomalousBlocks} blocks deviate (advisory).`, points: reliable ? 10 : 2 })
  }
  // all pixel evidence together can reach REVIEW only on a reliable source, and never LOCK without hard evidence elsewhere
  const pxCap = reliable ? 35 : 8
  let pxLeft = pxCap
  for (const x of pixelFindings) {
    const pts = Math.min(x.points, pxLeft)
    pxLeft -= pts
    add({ ...x, points: pts })
  }

  /* ---------- document NOT verified by its issuer's signature ----------
   * A QR or PDF signature only proves anything when we hold the ISSUER's public key and know its format.
   * Wired for: Aadhaar Secure QR (UIDAI certificate) and PDF signatures (pinned roots). Every other
   * document (PAN, DL, voter ID, passport MRZ) cannot be verified offline, so it goes to human review,
   * never shown as low risk. */
  const issuerVerified = i.kind === 'aadhaar' ? aadhaarTrusted : pdfTrusted
  if (i.kind !== 'none' && !issuerVerified) {
    const docName: Record<string, string> = { aadhaar: 'Aadhaar', pan: 'PAN card', dl: 'Driving licence', epic: 'Voter ID', mrz: 'Passport / national ID' }
    const name = docName[i.kind] ?? 'Document'
    const editNear = pixelFindings.filter((x) => x.code === 'ELA_ANOMALY' && x.title.includes('edited'))
    const cloned = pixelFindings.some((x) => x.code === 'ELA_ANOMALY' && x.title.includes('cloned'))
    let why: string
    if (i.kind === 'aadhaar') {
      why = !i.qr
        ? 'No readable Secure QR was decoded, so the printed name, DOB and number could not be compared with the signed data.'
        : !i.qrAadhaar
          ? 'The QR could not be read as a UIDAI Secure QR.'
          : i.qrSig
            ? `The QR signature state is "${i.qrSig.state}" (load the UIDAI certificate in the QR tab).`
            : 'The UIDAI certificate is not loaded, so the QR signature was not checked.'
    } else if (i.kind === 'mrz') {
      why = 'A passport / MRZ check only validates checksums. Nothing here proves the issuer signed this document.'
    } else {
      why = i.qr
        ? (() => {
            const shape = classifyQrPayload(i.qr.text)
            return `A QR was decoded (${i.qr.bytes.length} bytes; payload shape: ${shape.label}), but no issuer-specific signature rule or trusted public key is configured for ${name}. ${shape.detail}`
          })()
        : `No QR was decoded from this ${name}, and no issuer signature is available to check.`
    }
    add({
      severity: 'medium',
      code: 'UNVERIFIED',
      title: `${name} NOT verified by issuer signature`,
      detail: `${why} ${editNear.length || cloned ? `Pixel checks also flagged ${cloned ? 'cloned image area' : ''}${cloned && editNear.length ? ' and ' : ''}${editNear.length ? `${editNear.length} edited area(s)` : ''}. ` : ''}A low score does NOT mean genuine. Manual review required.`,
      points: 0, // no extra points: UNVERIFIED sets a REVIEW floor only, so it cannot push a case to LOCK by itself
    })
  }

  /* ---------- metadata: only POSITIVE markers count ---------- */
  const m = i.meta
  if (m.aiMarkers.length && !i.isPdf)
    add({
      severity: 'high',
      code: 'AI_GENERATED',
      title: `AI-generation marker in file metadata: ${m.aiMarkers.slice(0, 3).join(', ')}`,
      detail: 'The file contains metadata associated with an AI image tool. Metadata can be edited or copied, so this is a strong review indicator, not cryptographic proof of AI generation.',
      points: 25,
    })
  if (m.editorTags.length)
    add({
      severity: 'high',
      code: 'META_SUSPECT',
      title: `Editing software named in metadata: ${m.editorTags.slice(0, 3).join(', ')}`,
      detail: m.format === 'pdf' ? `PDF Producer / Creator fields name an editor (Producer: ${m.pdfProducer || '-'}, Creator: ${m.pdfCreator || '-'}). Government-issued PDFs are normally not produced by an editor.` : 'The image metadata names an image editor. Scans and camera photos normally do not.',
      points: 25,
    })
  if (m.format === 'pdf' && m.pdfModifiedAfterCreation)
    add({ severity: 'medium', code: 'META_SUSPECT', title: 'PDF was modified after it was created', detail: `Created ${m.pdfCreated}, last modified ${m.pdfModified}. Genuine e-documents are usually never re-saved.`, points: 10 })
  if (m.source === 'screenshot-or-export' && !i.isPdf)
    add({ severity: 'info', code: 'SOURCE_NOTE', title: 'Source is a screenshot / export, not a camera photo or original PDF', detail: 'Pixel checks are advisory on this file. The strongest proof is the original e-Aadhaar PDF (digital signature) or the UIDAI-signed QR with the certificate loaded.', points: 0 })

  /* ---------- other Indian IDs: PAN / Driving Licence / Voter ID ---------- */
  const addId = (c: ReturnType<typeof validatePan>[number], code: FlagCode = 'AADHAAR_CHECKSUM') => add({ severity: c.severity, code, title: c.title, detail: c.detail, points: c.points })
  if (i.kind === 'pan') {
    if (i.printed.pan) validatePan(i.printed.pan, i.printed.name, i.printed.fatherName).forEach((c) => addId(c))
    else add({ severity: 'high', code: 'UNREADABLE', title: 'PAN number could not be read', detail: 'The card looks like a PAN card but no AAAAA9999A number was found. Use a sharper photo.', points: 20 })
  }
  if (i.kind === 'dl') {
    if (i.printed.dl) validateDl(i.printed.dl).forEach((c) => addId(c))
    else add({ severity: 'high', code: 'UNREADABLE', title: 'Driving licence number could not be read', detail: 'No SS-RR-YYYY-NNNNNNN number was found.', points: 15 })
  }
  if (i.kind === 'epic') {
    if (i.printed.epic) validateEpic(i.printed.epic).forEach((c) => addId(c))
    else add({ severity: 'high', code: 'UNREADABLE', title: 'Voter ID (EPIC) number could not be read', detail: 'No 3-letter + 7-digit EPIC was found.', points: 15 })
  }
  // PAN-specific: a name that was read must also look like a name (garbage names are dropped upstream)
  if (i.kind !== 'none' && i.kind !== 'mrz' && i.printed.dob) {
    const d = dobSanity(i.printed.dob)
    if (!d.ok) add({ severity: 'critical', code: 'UNREADABLE', title: 'Date of birth is impossible', detail: d.reason + '. A genuine document cannot carry this date.', points: 45 })
  }

  /* ---------- quality / unreadable ---------- */
  if (i.kind === 'none')
    add({ severity: 'high', code: 'UNREADABLE', title: 'Document type could not be identified', detail: 'No MRZ and no 12-digit Aadhaar number could be read. Poor scan or unsupported document.', points: 20 })
  else if (i.kind === 'aadhaar' && !aadhaarTrusted) {
    const missing = [!i.printed.name && 'name', !i.printed.dob && 'DOB', !i.printed.gender && 'gender'].filter(Boolean) as string[]
    if (missing.length >= 2)
      add({
        severity: 'medium',
        code: 'UNREADABLE',
        title: `OCR could not read: ${missing.join(', ')}`,
        detail: 'Printed fields were not extracted, so QR-vs-printed matching is incomplete. Use a sharper, straight, well-lit photo.',
        points: 8,
      })
  }

  /* ---------- fusion ---------- */
  const sum = f.reduce((s, x) => s + x.points, 0)
  // explicit policy (lib/policy.ts): each finding forces a minimum risk. Supporting evidence (ELA, metadata) forces nothing.
  const floor = f.reduce((mx, x) => Math.max(mx, floorFor(x.code, x.severity)), 0)
  let risk = Math.max(Math.min(99, sum), floor)
  const order: Severity[] = ['critical', 'high', 'medium', 'info']
  f.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || b.points - a.points)

  let level: Level = risk >= HARD_LOCK_RISK ? 'LIKELY_FORGED' : risk >= REVIEW_RISK ? 'SUSPICIOUS' : 'NO_SIGNAL'
  const verified = i.kind === 'aadhaar' ? aadhaarTrusted : pdfTrusted
  let headline: string
  let sub: string
  if (level === 'LIKELY_FORGED') {
    headline = 'FAIL · DOCUMENT LIKELY FORGED'
    sub = `${f.length} finding${f.length === 1 ? '' : 's'} recorded. See FAIL REASONS below. Decision is SAFE-LOCKED: no officer can release this document.`
  } else if (level === 'SUSPICIOUS') {
    headline = 'REVIEW · MANUAL CHECK REQUIRED'
    sub = !verified
      ? 'Not verified by the issuer and not proven genuine. See REVIEW REASONS below. Supervisor review required; override needs PIN + written justification.'
      : 'Evidence of a problem, but not conclusive. See REVIEW REASONS below. Supervisor review required; override needs PIN + written justification.'
  } else if (i.kind === 'aadhaar' && !verified) {
    headline = 'NOT PROVEN GENUINE · NO FORGERY EVIDENCE'
    sub = i.qr
      ? 'Load the UIDAI certificate in the QR tab (it must be on the trust list) to cryptographically verify this card.'
      : 'Nothing proves a forgery, but no readable UIDAI-signed QR was available. Upload the original e-Aadhaar PDF or a sharper scan to verify it.'
  } else if (verified) {
    headline = i.kind === 'aadhaar' ? 'AUTHENTIC · UIDAI SIGNATURE VERIFIED' : 'AUTHENTIC · TRUSTED PDF SIGNATURE'
    sub = i.kind === 'aadhaar'
      ? 'The Aadhaar Secure QR has a trusted UIDAI signature and its readable fields match the printed card. Pixel heuristics cannot override this.'
      : pdfTrusted
        ? 'The PDF signature verifies and its signer chains to a pinned trusted root. Pixel heuristics cannot override this.'
        : 'The Aadhaar Secure QR is signed with a certificate on the UIDAI trust list and its data matches the printed card. Pixel heuristics cannot override this.'
  } else {
    headline = 'NO FORGERY SIGNAL FOUND'
    sub = 'Passed all offline checks. This is not proof of authenticity.'
  }

  const canOverride = level !== 'LIKELY_FORGED'

  return { level, risk, headline, sub, findings: f, canOverride }
}
