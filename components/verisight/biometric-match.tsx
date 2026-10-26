'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Camera, CameraOff, Fingerprint, ImageUp, ScanFace, ShieldAlert, ShieldCheck, Video } from 'lucide-react'
import { cn } from '@/lib/utils'
import { getHuman } from '@/lib/loaders'
import { useStore } from './store'
import { AutoAdvance } from './workflow'
import { ActionButton, AlertBanner, KeyValue, Panel, ProgressBar, StatusBadge, StepList } from './primitives'

const STEPS = [
  { label: 'Step 1 · Face detection & embedding', detail: 'Human FaceRes · high-dim descriptor' },
  { label: 'Step 2 · Passive liveness & anti-spoofing', detail: 'antispoof + liveness models' },
  { label: 'Step 3 · Vector distance comparison', detail: 'similarity vs. face found on document' },
]

const THRESHOLD = 0.45

type Ref = { embedding: number[]; thumb: string; score: number }
type Outcome = {
  embedding: number[]
  real: number | null
  live: number | null
  livenessPass: boolean
  similarity: number
  verified: boolean
  probe: string
}

async function embedFromCanvas(human: any, src: HTMLCanvasElement, keepThumb = true): Promise<Ref | null> {
  const res = await human.detect(src)
  const faces = (res.face ?? []).filter((f: any) => f.embedding?.length)
  if (!faces.length) return null
  faces.sort((a: any, b: any) => b.box[2] * b.box[3] - a.box[2] * a.box[3])
  const f = faces[0]
  const [x, y, w, h] = f.box
  const m = 0.25
  const sx = Math.max(0, x - w * m)
  const sy = Math.max(0, y - h * m)
  const sw = Math.min(src.width - sx, w * (1 + 2 * m))
  const sh = Math.min(src.height - sy, h * (1 + 2 * m))
  const t = document.createElement('canvas')
  t.width = 200
  t.height = 200
  if (keepThumb) t.getContext('2d')!.drawImage(src, sx, sy, sw, sh, 0, 0, 200, 200)
  return { embedding: Array.from(f.embedding as number[]), thumb: t.toDataURL('image/jpeg', 0.85), score: f.score ?? f.faceScore ?? 0.5 }
}

/** Faces on a printed document are small: tile the page and upscale every tile before detecting. */
async function findDocumentFace(human: any, pages: HTMLCanvasElement[]): Promise<Ref | null> {
  let best: (Ref & { rank: number }) | null = null
  for (const page of pages.slice(0, 2)) {
    const regions: number[][] = [[0, 0, 1, 1]]
    for (const ry of [0, 0.25, 0.5]) for (const rx of [0, 0.25, 0.5]) regions.push([rx, ry, 0.5, 0.5])
    for (const [rx, ry, rw, rh] of regions) {
      const sx = Math.round(rx * page.width)
      const sy = Math.round(ry * page.height)
      const sw = Math.round(rw * page.width)
      const sh = Math.round(rh * page.height)
      const scale = 900 / Math.max(sw, sh)
      const t = document.createElement('canvas')
      t.width = Math.round(sw * scale)
      t.height = Math.round(sh * scale)
      const ctx = t.getContext('2d')!
      ctx.fillStyle = '#fff'
      ctx.fillRect(0, 0, t.width, t.height)
      ctx.drawImage(page, sx, sy, sw, sh, 0, 0, t.width, t.height)
      const res = await human.detect(t)
      for (const f of res.face ?? []) {
        if (!f.embedding?.length) continue
        const area = f.box[2] * f.box[3]
        const rank = (f.score ?? f.faceScore ?? 0.5) * Math.sqrt(area)
        if (!best || rank > best.rank) {
          const th = await embedFromCanvasBox(t, f)
          best = { embedding: Array.from(f.embedding as number[]), thumb: th, score: f.score ?? f.faceScore ?? 0.5, rank }
        }
      }
    }
  }
  return best
}

function embedFromCanvasBox(src: HTMLCanvasElement, f: any): Promise<string> {
  const [x, y, w, h] = f.box
  const m = 0.25
  const sx = Math.max(0, x - w * m)
  const sy = Math.max(0, y - h * m)
  const sw = Math.min(src.width - sx, w * (1 + 2 * m))
  const sh = Math.min(src.height - sy, h * (1 + 2 * m))
  const t = document.createElement('canvas')
  t.width = 200
  t.height = 200
  t.getContext('2d')!.drawImage(src, sx, sy, sw, sh, 0, 0, 200, 200)
  return Promise.resolve(t.toDataURL('image/jpeg', 0.85))
}

export function BiometricMatch({ active }: { active: boolean }) {
  const { addFlag, log, caseDoc, markStep } = useStore()
  const videoRef = useRef<HTMLVideoElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const probeInput = useRef<HTMLInputElement>(null)
  const refInput = useRef<HTMLInputElement>(null)
  const [streaming, setStreaming] = useState(false)
  const [camError, setCamError] = useState<string | null>(null)
  const [ref, setRef] = useState<Ref | null>(null)
  const [refState, setRefState] = useState<'idle' | 'loading' | 'ready' | 'none' | 'error'>('idle')
  const [refMsg, setRefMsg] = useState('')
  const [step, setStep] = useState(-1)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const [matchErr, setMatchErr] = useState<string | null>(null)

  const stopCamera = useCallback(() => {
    streamRef.current?.getTracks().forEach((t) => t.stop())
    streamRef.current = null
    if (videoRef.current) videoRef.current.srcObject = null
    setStreaming(false)
  }, [])

  useEffect(() => {
    if (!active) stopCamera()
  }, [active, stopCamera])
  useEffect(() => stopCamera, [stopCamera])

  // AUTO: reference portrait = the face printed on the uploaded document
  useEffect(() => {
    setOutcome(null)
    setRef(null)
    if (!caseDoc) {
      setRefState('idle')
      return
    }
    let dead = false
    ;(async () => {
      setRefState('loading')
      setRefMsg('Loading face models (first time ~10 MB download)…')
      try {
        const human = await getHuman()
        setRefMsg('Locating the portrait on the document…')
        const r = await findDocumentFace(human, caseDoc.pages)
        if (dead) return
        if (r) {
          setRef(r)
          setRefState('ready')
        } else {
          setRefState('none')
        }
      } catch (e: any) {
        if (!dead) {
          setRefState('error')
          setRefMsg(e?.message ?? String(e))
        }
      }
    })()
    return () => {
      dead = true
    }
  }, [caseDoc])

  async function startCamera() {
    setCamError(null)
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false })
      streamRef.current = stream
      setStreaming(true)
      requestAnimationFrame(async () => {
        if (videoRef.current) {
          videoRef.current.srcObject = stream
          await videoRef.current.play().catch(() => undefined)
        }
      })
    } catch (e) {
      const name = e instanceof DOMException ? e.name : ''
      setCamError(name === 'NotAllowedError' ? 'Camera permission denied. Allow camera access in the browser address bar.' : 'No camera available on this station. Upload a probe photo instead.')
    }
  }

  async function onRefUpload(f: File) {
    setRefState('loading')
    setRefMsg('Reading portrait…')
    try {
      const human = await getHuman()
      const bmp = await createImageBitmap(f)
      const c = document.createElement('canvas')
      c.width = bmp.width
      c.height = bmp.height
      c.getContext('2d')!.drawImage(bmp, 0, 0)
      const r = await embedFromCanvas(human, c)
      if (r) {
        setRef(r)
        setRefState('ready')
      } else setRefState('none')
    } catch (e: any) {
      setRefState('error')
      setRefMsg(e?.message ?? String(e))
    }
  }

  async function matchCanvas(probeCanvas: HTMLCanvasElement | HTMLVideoElement) {
    if (!ref) return
    setOutcome(null)
    setMatchErr(null)
    try {
      setStep(0)
      const human = await getHuman()
      const res = await human.detect(probeCanvas)
      const faces = (res.face ?? []).filter((f: any) => f.embedding?.length)
      if (!faces.length) {
        setStep(-1)
        setMatchErr('No face detected in the live frame. Face the camera, remove glasses/mask, improve lighting.')
        return
      }
      faces.sort((a: any, b: any) => b.box[2] * b.box[3] - a.box[2] * a.box[3])
      const f = faces[0]
      setStep(1)
      const real = typeof f.real === 'number' ? f.real : null
      const live = typeof f.live === 'number' ? f.live : null
      const livenessPass = (real === null || real >= 0.5) && (live === null || live >= 0.5)
      setStep(2)
      const similarity = human.match.similarity(ref.embedding, f.embedding)
      const verified = livenessPass && similarity >= THRESHOLD
      const probe = (() => {
        const c = document.createElement('canvas')
        c.width = 240
        c.height = 240
        const [x, y, w, h] = f.box
        const m = 0.3
        const src = probeCanvas as any
        const sw0 = (src.videoWidth ?? src.width) as number
        const sh0 = (src.videoHeight ?? src.height) as number
        const sx = Math.max(0, x - w * m)
        const sy = Math.max(0, y - h * m)
        c.getContext('2d')!.drawImage(src, sx, sy, Math.min(sw0 - sx, w * (1 + 2 * m)), Math.min(sh0 - sy, h * (1 + 2 * m)), 0, 0, 240, 240)
        return c.toDataURL('image/jpeg', 0.85)
      })()
      const out: Outcome = { embedding: Array.from(f.embedding as number[]), real, live, livenessPass, similarity, verified, probe }
      setOutcome(out)
      markStep('biometric', true)
      setStep(3)
      if (!verified) {
        const id = await addFlag({
          subject: caseDoc?.subject ?? 'UNKNOWN',
          docType: caseDoc?.docType ?? 'Unknown',
          docNo: caseDoc?.docNo ?? '—',
          risk: livenessPass ? 88 : 94,
          lane: 'Lane 03',
          reasons: [
            ...(similarity < THRESHOLD ? [{ code: 'FACE_MISMATCH' as const, detail: `Face similarity ${similarity.toFixed(3)} below ${THRESHOLD.toFixed(2)} threshold` }] : []),
            ...(!livenessPass ? [{ code: 'LIVENESS_FAIL' as const, detail: `Anti-spoof ${real === null ? 'n/a' : (real * 100).toFixed(0) + '%'} · liveness ${live === null ? 'n/a' : (live * 100).toFixed(0) + '%'}` }] : []),
          ],
        })
        log('BIOMETRIC_DENIED', id)
      } else {
        log('BIOMETRIC_VERIFIED', `sim ${similarity.toFixed(3)}`)
      }
    } catch (e: any) {
      setStep(-1)
      setMatchErr(`Match failed: ${e?.message ?? e}`)
    }
  }

  async function onProbeUpload(f: File) {
    const bmp = await createImageBitmap(f)
    const c = document.createElement('canvas')
    c.width = bmp.width
    c.height = bmp.height
    c.getContext('2d')!.drawImage(bmp, 0, 0)
    await matchCanvas(c)
  }

  const running = step >= 0 && step < 3 && !outcome
  const overall = outcome ? 100 : step < 0 ? 0 : (step / STEPS.length) * 100 + 10
  const canMatch = refState === 'ready' && streaming && !running

  return (
    <div className="grid gap-5 xl:grid-cols-[1fr_400px]">
      <div className="flex flex-col gap-5">
        <Panel title="1:1 Live Capture" icon={Video} actions={<StatusBadge tone={streaming ? 'success' : 'neutral'} pulse={streaming}>{streaming ? 'Live' : 'Idle'}</StatusBadge>}>
          <div className="grid gap-4 md:grid-cols-[1fr_220px]">
            <div className="relative aspect-video overflow-hidden rounded-lg border border-border bg-background">
              <video ref={videoRef} muted playsInline autoPlay className={cn('size-full -scale-x-100 object-cover', !streaming && 'invisible')} aria-label="Live webcam feed, mirrored" />
              {!streaming && (
                <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 p-6 text-center">
                  <CameraOff className="size-8 text-muted-foreground" aria-hidden="true" />
                  <p className="text-sm text-muted-foreground">Camera offline</p>
                  {camError && <p role="alert" className="max-w-sm text-xs text-warning">{camError}</p>}
                </div>
              )}
              {streaming && running && <div className="scan-line pointer-events-none absolute inset-x-0 top-0 h-1/4" aria-hidden="true" />}
            </div>

            <div className="flex flex-col gap-3">
              <div>
                <p className="mb-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">Portrait found on document</p>
                <div className="relative flex aspect-square items-center justify-center overflow-hidden rounded-lg border border-border bg-background/50 p-2 text-center">
                  {ref ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img src={ref.thumb} alt="Portrait extracted from the document" className="absolute inset-0 size-full object-cover" />
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      {refState === 'idle' && 'Run Document Triage first, or upload a portrait.'}
                      {refState === 'loading' && refMsg}
                      {refState === 'none' && 'No face found on the document. Upload a portrait manually.'}
                      {refState === 'error' && `Face engine error: ${refMsg}`}
                    </p>
                  )}
                </div>
              </div>
              {outcome?.probe && (
                <div>
                  <p className="mb-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">Live probe</p>
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={outcome.probe} alt="Captured probe frame" className="aspect-square w-full rounded-lg border border-border object-cover" />
                </div>
              )}
            </div>
          </div>

          {matchErr && <p role="alert" className="mt-3 text-xs text-destructive">{matchErr}</p>}

          <div className="mt-4 flex flex-wrap items-center gap-3">
            {streaming ? (
              <ActionButton variant="outline" onClick={stopCamera} disabled={running}><CameraOff className="size-4" aria-hidden="true" />Stop camera</ActionButton>
            ) : (
              <ActionButton variant="outline" onClick={startCamera}><Camera className="size-4" aria-hidden="true" />Start camera</ActionButton>
            )}
            <ActionButton variant="ghost" onClick={() => refInput.current?.click()} disabled={running}><ImageUp className="size-4" aria-hidden="true" />Upload portrait</ActionButton>
            <ActionButton variant="ghost" onClick={() => probeInput.current?.click()} disabled={running || refState !== 'ready'}><ImageUp className="size-4" aria-hidden="true" />Upload probe photo</ActionButton>
            <input ref={refInput} type="file" accept="image/*" className="sr-only" tabIndex={-1} onChange={(e) => { const f = e.target.files?.[0]; if (f) onRefUpload(f); e.target.value = '' }} />
            <input ref={probeInput} type="file" accept="image/*" className="sr-only" tabIndex={-1} onChange={(e) => { const f = e.target.files?.[0]; if (f) onProbeUpload(f); e.target.value = '' }} />
            <ActionButton className="ml-auto" onClick={() => videoRef.current && matchCanvas(videoRef.current)} disabled={!canMatch}>
              <ScanFace className="size-4" aria-hidden="true" />
              {running ? 'Matching…' : 'Capture & match'}
            </ActionButton>
          </div>
        </Panel>

        {outcome && (
          <Panel title={`Probe Embedding Vector (first 48 of ${outcome.embedding.length} dims)`} icon={Fingerprint}>
            <div className="flex h-20 items-center gap-px" role="img" aria-label="Embedding vector visualisation">
              {outcome.embedding.slice(0, 48).map((v, i) => {
                const mx = Math.max(...outcome.embedding.slice(0, 48).map(Math.abs), 1e-6)
                const h = Math.min(50, (Math.abs(v) / mx) * 50)
                return (
                  <span key={i} className="relative h-full flex-1">
                    <span className={cn('absolute inset-x-0 rounded-sm', v >= 0 ? 'bg-success/70' : 'bg-chart-4')} style={{ top: v >= 0 ? `${50 - h}%` : '50%', height: `${h}%` }} />
                  </span>
                )
              })}
            </div>
          </Panel>
        )}
      </div>

      <div className="flex flex-col gap-5">
        <Panel title="Forensic State Machine" icon={ScanFace}>
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between font-mono text-xs text-muted-foreground">
              <span>{outcome ? 'COMPLETE' : running ? `STATE ${step + 1}/3` : 'IDLE'}</span>
              <span className="tabular-nums">{Math.round(overall)}%</span>
            </div>
            <ProgressBar value={overall} tone={outcome && !outcome.verified ? 'danger' : 'success'} />
            <StepList steps={STEPS} current={step} done={!!outcome} />
          </div>
        </Panel>

        {outcome && (
          <>
            {outcome.verified ? (
              <AlertBanner tone="success" icon={ShieldCheck} title="FACE MATCHES DOCUMENT">Live subject matches the portrait on the document. Passive liveness passed.</AlertBanner>
            ) : (
              <AlertBanner tone="danger" icon={ShieldAlert} title="SECURITY ALERT: MISMATCH — ACCESS DENIED">
                {!outcome.livenessPass ? 'Possible presentation attack (photo / screen). ' : 'Face does not match the document portrait. '}
                Entry escalated to Override Gateway.
              </AlertBanner>
            )}
            <AutoAdvance enabled={!!outcome} from="biometric" to="records" label="Case Records" seconds={6} resetKey={String(outcome.similarity)} />
            <Panel title="Match Result" icon={Fingerprint}>
              <div className="mb-4 flex items-end justify-between">
                <div>
                  <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Similarity</p>
                  <p className={cn('font-mono text-5xl font-semibold tabular-nums', outcome.verified ? 'text-success' : 'text-destructive')}>
                    {(outcome.similarity * 100).toFixed(1)}
                    <span className="text-2xl">%</span>
                  </p>
                </div>
                <StatusBadge tone={outcome.verified ? 'success' : 'danger'}>{outcome.verified ? 'Match' : 'Denied'}</StatusBadge>
              </div>
              <dl>
                <KeyValue label="Similarity score" value={outcome.similarity.toFixed(4)} tone={outcome.similarity >= THRESHOLD ? 'success' : 'danger'} />
                <KeyValue label="Decision threshold" value={`≥ ${THRESHOLD.toFixed(2)}`} />
                <KeyValue label="Anti-spoof (real)" value={outcome.real === null ? 'n/a' : `${(outcome.real * 100).toFixed(1)}%`} tone={outcome.real === null ? undefined : outcome.real >= 0.5 ? 'success' : 'danger'} />
                <KeyValue label="Liveness" value={outcome.live === null ? 'n/a' : `${(outcome.live * 100).toFixed(1)}%`} tone={outcome.live === null ? undefined : outcome.live >= 0.5 ? 'success' : 'danger'} />
              </dl>
              <p className="mt-3 text-[11px] text-muted-foreground">Passive liveness is a screening aid, not proof. Printed ID photos are low quality, so the threshold should be calibrated on your own test set.</p>
            </Panel>
          </>
        )}
      </div>
    </div>
  )
}
