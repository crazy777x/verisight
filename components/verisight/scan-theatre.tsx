'use client'

import { useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'

/* ============================================================
 * FORENSIC SCAN THEATRE
 * Ek animated, stage-aware visual jo verification ke waqt chalta hai
 * taaki user ko wait bore na lage. Har stage ka apna animation:
 *   0 Ingest            -> document slide + corner brackets lock
 *   1 OCR + checksum    -> scanning line + characters decode hote hue
 *   2 Tamper            -> magnifier lens document ke upar ghumta hai
 *   3 Signature + QR    -> QR blocks pulse hote hain, RSA ring spin
 *   4 Verdict           -> needle wala dial sweep karta hai
 * Har stage ke "live log" lines bhi tick hote hain (activity feel).
 * ============================================================ */

const LOG_LINES: string[][] = [
  ['rasterize page → canvas', 'detecting encryption…', 'page geometry normalized', 'magic bytes verified'],
  ['loading tesseract model…', 'reading printed fields…', 'verhoeff checksum → running', 'ICAO 9303 mod-10 → running', 'field candidates locked'],
  ['error level analysis…', 'noise variance map…', 'copy-move block match…', 'editor metadata probe…'],
  ['PDF CMS digest…', 'native detector → jsQR → ZXing', 'UIDAI RSA verify (SHA-256)', 'QR ↔ printed comparison'],
  ['fusing evidence…', 'policy floor applied', 'gate decision computed'],
]

export function ScanTheatre({ stage, running, done }: { stage: number; running: boolean; done: boolean }) {
  const active = running && stage >= 0 && stage < 5
  const current = active ? stage : done ? 4 : -1
  const [logIdx, setLogIdx] = useState(0)
  const logRef = useRef(0)

  // har ~1.4 s me next log line (stage change par reset)
  useEffect(() => {
    logRef.current = 0
    setLogIdx(0)
  }, [stage])

  useEffect(() => {
    if (!active) return
    const t = setInterval(() => {
      logRef.current = (logRef.current + 1) % LOG_LINES[Math.max(0, Math.min(4, stage))].length
      setLogIdx(logRef.current)
    }, 1400)
    return () => clearInterval(t)
  }, [active, stage])

  const lines = LOG_LINES[Math.max(0, Math.min(4, current))] ?? LOG_LINES[0]
  const shown = active ? lines.slice(0, logIdx + 1) : done ? lines.slice(0, 2) : []

  return (
    <div className="relative overflow-hidden rounded-lg border border-border bg-[#0a0f1e]" aria-hidden="true">
      {/* subtle grid backdrop */}
      <div
        className="absolute inset-0 opacity-[0.15]"
        style={{
          backgroundImage: 'linear-gradient(rgba(120,160,255,.4) 1px, transparent 1px), linear-gradient(90deg, rgba(120,160,255,.4) 1px, transparent 1px)',
          backgroundSize: '26px 26px',
        }}
      />
      <div className="relative flex h-56 items-center justify-center">
        {current === 0 && <IngestAnim active={active} done={done} />}
        {current === 1 && <OcrAnim active={active} done={done} />}
        {current === 2 && <MagnifierAnim active={active} done={done} />}
        {current === 3 && <QrSigAnim active={active} done={done} />}
        {current === 4 && <VerdictDial active={active} done={done} />}
        {current < 0 && (
          <div className="flex flex-col items-center gap-2 text-slate-500">
            <div className="size-10 rounded-full border-2 border-dashed border-slate-600" />
            <p className="font-mono text-[11px]">standby</p>
          </div>
        )}
      </div>
      {/* live log ticker */}
      <div className="relative border-t border-white/10 bg-black/30 px-3 py-2 font-mono text-[10px] leading-4 text-emerald-300/80">
        {shown.length === 0 && <span className="text-slate-500">— idle —</span>}
        {shown.map((l, i) => (
          <p key={l} className={cn(i === shown.length - 1 && 'text-emerald-300')}>
            <span className="text-slate-500">$</span> {l}
            {i === shown.length - 1 && active && <span className="ml-1 inline-block h-3 w-1.5 animate-pulse bg-emerald-300 align-middle" />}
          </p>
        ))}
      </div>
    </div>
  )
}

/* ---------- 0: INGEST — document slides in, corner brackets lock ---------- */
function IngestAnim({ active, done }: { active: boolean; done: boolean }) {
  return (
    <div className="relative flex h-full w-full items-center justify-center">
      <div className="absolute inset-6">
        {[
          'left-0 top-0 border-l-2 border-t-2',
          'right-0 top-0 border-r-2 border-t-2',
          'bottom-0 left-0 border-b-2 border-l-2',
          'bottom-0 right-0 border-b-2 border-r-2',
        ].map((pos, i) => (
          <span
            key={pos}
            className={cn(
              'absolute size-7 border-cyan-400/80 transition-all duration-500',
              pos,
              (active || done) && 'scale-110 opacity-100',
              !active && !done && 'scale-90 opacity-30',
            )}
            style={{ transitionDelay: `${i * 120}ms` }}
          />
        ))}
      </div>
      <div
        className={cn(
          'flex h-28 w-20 flex-col gap-1 rounded-sm border border-slate-500/60 bg-slate-200/90 p-1.5 shadow-[0_0_30px_rgba(80,180,255,.25)] transition-transform duration-700',
          active ? 'translate-y-0 rotate-0' : 'translate-y-3 rotate-3',
        )}
      >
        <div className="h-2 w-3/4 rounded-sm bg-slate-500/50" />
        <div className="h-1.5 w-full rounded-sm bg-slate-400/40" />
        <div className="h-1.5 w-5/6 rounded-sm bg-slate-400/40" />
        <div className="mt-auto flex gap-1">
          <div className="size-4 rounded-full bg-slate-500/40" />
          <div className="h-1.5 flex-1 self-center rounded-sm bg-slate-400/40" />
        </div>
      </div>
    </div>
  )
}

/* ---------- 1: OCR — scan line chalti hai, characters decode hote hain ---------- */
function OcrAnim({ active, done }: { active: boolean; done: boolean }) {
  const chars = 'A6H4R 9021 VERHOEFF 7 3 1 MRZ<<'
  const [n, setN] = useState(0)
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => setN((v) => (v + 1) % (chars.length + 6)), 130)
    return () => clearInterval(t)
  }, [active, chars.length])
  return (
    <div className="relative flex h-full w-full flex-col items-center justify-center gap-4">
      <div className="relative h-24 w-72 overflow-hidden rounded-md border border-slate-600/60 bg-slate-900/60">
        {/* fake text lines */}
        <div className="flex h-full flex-col justify-center gap-2 px-4">
          {['####################', '######################', '##################', '###############'].map((w, i) => (
            <div key={i} className="h-2 rounded-sm bg-slate-700/70" style={{ width: `${70 - i * 8}%` }} />
          ))}
        </div>
        {/* decode hote hue characters */}
        <div className="absolute inset-0 flex items-center justify-center px-4 font-mono text-[11px] tracking-widest text-cyan-300/90">
          <span>{chars.slice(0, Math.min(n, chars.length))}</span>
          {active && n <= chars.length && <span className="ml-0.5 inline-block h-3.5 w-1.5 animate-pulse bg-cyan-300" />}
        </div>
        {/* scanning line */}
        {active && <div className="absolute left-0 h-0.5 w-full animate-[scanline_1.6s_linear_infinite] bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,.9)]" />}
      </div>
      <p className="font-mono text-[10px] text-slate-400">{done ? 'checksums verified ✓' : active ? 'tesseract · mod-10 · verhoeff' : ''}</p>
    </div>
  )
}

/* ---------- 2: TAMPER — magnifier lens document par ghumta hai ---------- */
function MagnifierAnim({ active, done }: { active: boolean; done: boolean }) {
  const t = useRef(0)
  const [pos, setPos] = useState({ x: 30, y: 40 })
  useEffect(() => {
    if (!active) return
    const iv = setInterval(() => {
      t.current += 0.09
      setPos({ x: 50 + Math.cos(t.current) * 26, y: 42 + Math.sin(t.current * 1.3) * 18 })
    }, 40)
    return () => clearInterval(iv)
  }, [active])
  const spots = [
    { x: 68, y: 30, s: 'ELA' },
    { x: 30, y: 62, s: 'NOISE' },
    { x: 74, y: 66, s: 'COPY' },
  ]
  return (
    <div className="relative h-full w-full overflow-hidden">
      {/* fake document */}
      <div className="absolute left-1/2 top-1/2 h-36 w-56 -translate-x-1/2 -translate-y-1/2 rounded-md border border-slate-600/60 bg-slate-200/90 p-3">
        <div className="flex h-full flex-col gap-1.5">
          <div className="h-2.5 w-2/3 rounded-sm bg-slate-500/50" />
          <div className="h-1.5 w-full rounded-sm bg-slate-400/40" />
          <div className="h-1.5 w-11/12 rounded-sm bg-slate-400/40" />
          <div className="mt-auto flex items-end justify-between">
            <div className="size-8 rounded-full bg-slate-500/40" />
            <div className="size-8 bg-slate-600/40" style={{ clipPath: 'polygon(0 0,1 0,1 1,0 1)' }} />
          </div>
        </div>
        {/* hotspots */}
        {!done && spots.map((s) => <span key={s.s} className="absolute size-2 animate-ping rounded-full bg-amber-400/80" style={{ left: `${s.x}%`, top: `${s.y}%` }} />)}
      </div>
      {/* magnifier lens */}
      <div
        className={cn('absolute z-10 flex size-20 items-center justify-center rounded-full border-2 transition-all', done ? 'border-emerald-400/80' : 'border-cyan-300/90')}
        style={{
          left: `${done ? 68 : pos.x}%`,
          top: `${done ? 30 : pos.y}%`,
          transform: 'translate(-50%,-50%)',
          boxShadow: done ? '0 0 24px rgba(52,211,153,.5)' : '0 0 24px rgba(34,211,238,.5), inset 0 0 18px rgba(34,211,238,.25)',
          backdropFilter: 'brightness(1.4) contrast(1.2)',
          transition: done ? 'all .6s' : 'left .04s linear, top .04s linear',
        }}
      >
        <span className={cn('font-mono text-[8px] font-bold', done ? 'text-emerald-300' : 'text-cyan-200')}>{done ? 'CLEAR' : 'ELA·SCAN'}</span>
      </div>
      <p className="absolute bottom-2 left-1/2 -translate-x-1/2 font-mono text-[10px] text-slate-400">{done ? 'no tamper localised ✓' : active ? 'ela · noise · copy-move' : ''}</p>
    </div>
  )
}

/* ---------- 3: SIGNATURE + QR — QR modules pulse, RSA ring ghoomta hai ---------- */
function QrSigAnim({ active, done }: { active: boolean; done: boolean }) {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => setTick((v) => v + 1), 260)
    return () => clearInterval(t)
  }, [active])
  const cells = 7
  return (
    <div className="flex h-full w-full items-center justify-center gap-10">
      {/* QR */}
      <div className="relative">
        <div className="grid gap-[2px] rounded-md border border-slate-600/60 bg-white/90 p-2" style={{ gridTemplateColumns: `repeat(${cells}, 10px)` }}>
          {Array.from({ length: cells * cells }).map((_, i) => {
            const r = Math.floor(i / cells)
            const c = i % cells
            const finder = (r < 3 && c < 3) || (r < 3 && c >= cells - 3) || (r >= cells - 3 && c < 3)
            const on = finder ? (r !== 1 || c !== 1) && (r !== 1 || c !== cells - 2) && (r !== cells - 2 || c !== 1) : (r * 7 + c * 13 + tick) % 3 !== 0
            return <span key={i} className={cn('size-2.5 rounded-[1px] transition-colors duration-200', on ? 'bg-slate-900' : 'bg-slate-300')} />
          })}
        </div>
        {active && <div className="absolute -inset-1 animate-pulse rounded-md border border-cyan-400/50" />}
      </div>
      {/* RSA ring */}
      <div className="relative flex size-24 items-center justify-center">
        <div className={cn('absolute inset-0 rounded-full border-2 border-dashed', done ? 'border-emerald-400/80' : 'animate-[spin_3s_linear_infinite] border-cyan-400/70')} style={{ animationDirection: 'reverse' }} />
        <div className={cn('absolute inset-3 rounded-full border', done ? 'border-emerald-300/60' : 'animate-pulse border-cyan-300/40')} />
        <span className={cn('font-mono text-[9px] font-bold', done ? 'text-emerald-300' : 'text-cyan-300')}>{done ? 'SIG ✓' : 'RSA-2048'}</span>
      </div>
      <div className="flex flex-col items-center gap-2">
        <span className={cn('font-mono text-2xl', done ? 'text-emerald-400' : active ? 'text-amber-300' : 'text-slate-600')}>{done ? '=' : active ? '⇄' : '?'}</span>
        <span className="font-mono text-[9px] text-slate-400">QR ↔ print</span>
      </div>
    </div>
  )
}

/* ---------- 4: VERDICT — dial sweep + evidence blocks fuse ---------- */
function VerdictDial({ active, done }: { active: boolean; done: boolean }) {
  const [ang, setAng] = useState(-120)
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => setAng((a) => (a >= 120 ? -120 : a + 8)), 40)
    return () => clearInterval(t)
  }, [active])
  const blocks = ['SIG', 'QR', 'OCR', 'ELA', 'META']
  return (
    <div className="flex h-full w-full flex-col items-center justify-center gap-3">
      <div className="flex gap-2">
        {blocks.map((b, i) => (
          <div
            key={b}
            className={cn(
              'flex size-11 items-center justify-center rounded-md border font-mono text-[9px] font-bold transition-all',
              done || active ? 'border-cyan-400/60 bg-cyan-400/10 text-cyan-200' : 'border-slate-700 text-slate-600',
            )}
            style={{ transitionDelay: `${i * 100}ms`, transform: done ? 'scale(1.05)' : undefined }}
          >
            {b}
          </div>
        ))}
      </div>
      <div className="relative h-16 w-40 overflow-hidden">
        {/* dial arc */}
        <svg viewBox="0 0 160 70" className="h-full w-full">
          <path d="M12 62 A 68 68 0 0 1 148 62" fill="none" stroke="rgba(148,163,184,.3)" strokeWidth="6" strokeLinecap="round" />
          <path d="M12 62 A 68 68 0 0 1 148 62" fill="none" stroke={done ? '#34d399' : '#22d3ee'} strokeWidth="6" strokeLinecap="round" strokeDasharray="214" strokeDashoffset={done ? 0 : 214 - ((ang + 120) / 240) * 214} className="transition-all duration-100" />
          <line
            x1="80" y1="62"
            x2={80 + 52 * Math.cos(((ang + 120) / 240 * Math.PI - Math.PI) * -1)}
            y2={62 + 52 * Math.sin(((ang + 120) / 240 * Math.PI - Math.PI) * -1)}
            stroke={done ? '#34d399' : '#22d3ee'} strokeWidth="2.5" strokeLinecap="round"
          />
          <circle cx="80" cy="62" r="4" fill={done ? '#34d399' : '#22d3ee'} />
        </svg>
      </div>
      <p className="font-mono text-[10px] text-slate-400">{done ? 'verdict issued ✓' : active ? 'fusing evidence · policy floor' : ''}</p>
    </div>
  )
}