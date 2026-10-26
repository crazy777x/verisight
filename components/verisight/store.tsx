'use client'

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { fnvHex } from '@/lib/forensics'
import { CERT_KEY, loadCertFile, type Printed, type QrHit } from '@/lib/analysis'
import { parseCert, toHex, type CertInfo } from '@/lib/asn1'
import type { QrPattern } from '@/lib/qrpattern'
import type { FlagCode } from '@/lib/policy'
import type { DocTypeId, PurposeId, Suggestion } from '@/lib/purposes'

export type Role = 'officer' | 'investigator' | 'admin'
export type TabId = 'triage' | 'permit' | 'qr' | 'biometric' | 'records' | 'queue'
export type Selection = { purpose: PurposeId; docType: DocTypeId }
export type WorkflowStep = 'triage' | 'qr' | 'biometric'

export const ROLE_META: Record<Role, { label: string; clearance: string }> = {
  officer: { label: 'Border Security Officer', clearance: 'L2' },
  investigator: { label: 'Forensic Investigator', clearance: 'L3' },
  admin: { label: 'Super Admin', clearance: 'L5' },
}

export type Session = {
  operatorId: string
  role: Role
  nodeId: string
  keyFingerprint: string
  startedAt: number
}

export type FlagReason = {
  code: FlagCode
  detail: string
}

export type QueueStatus = 'pending' | 'approved' | 'detained'

export type QueueEntry = {
  id: string
  subject: string
  docType: string
  docNo: string
  risk: number
  lane: string
  flaggedAt: number
  reasons: FlagReason[]
  status: QueueStatus
  /** Anti-bribery SAFE-LOCK: decided by the SERVER from the risk score. A locked entry can NEVER be approved by anyone. */
  locked: boolean
  flaggedBy?: string
  resolvedBy?: string
  resolvedAt?: number
  note?: string
  caseId?: string
}

export type AuditEntry = {
  id: string
  at: number
  actor: string
  action: string
  target: string
  hash: string
  prev?: string
}

export type CaseDoc = {
  fileName: string
  pages: HTMLCanvasElement[]
  isPdf: boolean
  printed: Printed | null
  qr: QrHit | null
  qrPattern?: QrPattern | null
  subject: string
  docNo: string
  docType: string
  risk?: number
}

/** One saved triage result. Persisted in this browser's localStorage. Aadhaar numbers are stored MASKED only. */
export type CaseRecord = {
  id: string
  at: number
  operator: string
  fileName: string
  fileDigest: string
  docType: string
  subject: string
  docNo: string
  risk: number
  level: string
  headline: string
  findings: { severity: string; title: string; detail: string }[]
  regions: { id: number; x: number; y: number; w: number; h: number; score: number; kinds: string[]; fields: string[] }[]
  fields: { name: string; dob: string; gender: string; pincode: string }
  qr: { found: boolean; kind: string; signature: string; mismatches: string[] }
  thumb: string // small jpeg data-URL
}

type Store = {
  sessionReady?: boolean
  cases: CaseRecord[]
  addCase: (c: Omit<CaseRecord, 'id' | 'at' | 'operator'>) => string
  deleteCase: (id: string) => void
  clearCases: () => void
  caseDoc: CaseDoc | null
  setCaseDoc: (c: CaseDoc | null) => void
  session: Session | null
  /** server-side authentication; the role is decided by the server from the user record */
  login: (operatorId: string, passphrase: string) => Promise<{ ok: boolean; error?: string }>
  logout: () => void
  queue: QueueEntry[]
  addFlag: (entry: Omit<QueueEntry, 'id' | 'flaggedAt' | 'status' | 'locked'>) => Promise<string>
  /** the SERVER applies every rule (role, SAFE-LOCK, PIN, justification). Returns the server's answer. */
  resolve: (id: string, status: Exclude<QueueStatus, 'pending'>, note: string, pin?: string) => Promise<{ ok: boolean; error?: string }>
  cert: CertInfo | null
  certError: string | null
  loadCert: (file: File) => Promise<boolean>
  clearCert: () => void
  /** Step 1 + 2 of the workflow: chosen purpose and document type. Shared by Triage and Border Pass tabs; never proves anything. */
  selection: Selection
  setSelection: (s: Partial<Selection>) => void
  /** auto-detect only ever SUGGESTS a type; the operator decides */
  suggestion: Suggestion | null
  setSuggestion: (s: Suggestion | null) => void
  tab: TabId
  goTo: (t: TabId) => void
  steps: Record<WorkflowStep, boolean>
  markStep: (s: WorkflowStep, done: boolean) => void
  resetSteps: () => void
  audit: AuditEntry[]
  auditChainOk: boolean | null
  log: (action: string, target: string) => void
  refreshServerData: () => Promise<void>
}

const StoreContext = createContext<Store | null>(null)

const LS = { cases: 'verisight.cases.v1' }

function readLS<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch {
    return fallback
  }
}

async function api<T = any>(url: string, init?: Omit<RequestInit, 'body'> & { body?: unknown }): Promise<{ ok: boolean; status: number; data: T }> {
  try {
    const r = await fetch(url, {
      ...init,
      headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
      body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
      credentials: 'same-origin',
    })
    const data = (await r.json().catch(() => ({}))) as T
    return { ok: r.ok, status: r.status, data }
  } catch {
    return { ok: false, status: 0, data: { error: 'Server not reachable' } as T }
  }
}

export function StoreProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [sessionReady, setSessionReady] = useState(false)
  const [queue, setQueue] = useState<QueueEntry[]>([])
  const [cases, setCases] = useState<CaseRecord[]>([])
  const [ready, setReady] = useState(false)
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [auditChainOk, setAuditChainOk] = useState<boolean | null>(null)
  const [caseDoc, setCaseDoc] = useState<CaseDoc | null>(null)
  const [cert, setCertState] = useState<CertInfo | null>(null)
  const [certError, setCertError] = useState<string | null>(null)
  const [tab, setTab] = useState<TabId>('triage')
  const [selection, setSel] = useState<Selection>({ purpose: 'general', docType: 'auto' })
  const [suggestion, setSuggestion] = useState<Suggestion | null>(null)
  const setSelection = useCallback((p: Partial<Selection>) => setSel((cur) => ({ ...cur, ...p })), [])
  const [steps, setSteps] = useState<Record<WorkflowStep, boolean>>({ triage: false, qr: false, biometric: false })

  const toSession = (u: { operatorId: string; role: Role; startedAt: number }): Session => {
    const seed = fnvHex(`${u.operatorId}${u.startedAt}`)
    return { operatorId: u.operatorId, role: u.role, nodeId: `AGN-${seed.slice(0, 4).toUpperCase()}-${seed.slice(4, 8).toUpperCase()}`, keyFingerprint: fnvHex(seed + 'k') + fnvHex(seed + 'e'), startedAt: u.startedAt }
  }

  // restore the server session (httpOnly cookie) after a page reload
  useEffect(() => {
    api('/api/auth/session').then((r) => {
      if (r.ok) setSession(toSession(r.data))
      setSessionReady(true)
    })
  }, [])

  // browser-local data: saved cases (a convenience list) and the stored certificate
  useEffect(() => {
    try {
      const b64 = localStorage.getItem(CERT_KEY)
      if (b64) {
        const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
        const info = parseCert(der)
        Promise.all([crypto.subtle.digest('SHA-256', info.spki as unknown as BufferSource), crypto.subtle.digest('SHA-256', der as unknown as BufferSource)]).then(([h, d]) => {
          info.sha256 = toHex(new Uint8Array(h))
          info.derSha256 = toHex(new Uint8Array(d))
          setCertState(info)
        })
      }
    } catch {
      /* ignore broken stored certificate */
    }
    setCases(readLS<CaseRecord[]>(LS.cases, []))
    setReady(true)
  }, [])

  useEffect(() => {
    if (!ready) return
    let list = cases
    for (let attempt = 0; attempt < 6; attempt++) {
      try {
        localStorage.setItem(LS.cases, JSON.stringify(list))
        return
      } catch {
        list = list.map((c, i) => (i >= Math.max(0, list.length - 5 * (attempt + 1)) ? { ...c, thumb: '' } : c)).slice(0, 200 - attempt * 30)
      }
    }
  }, [ready, cases])

  /** queue + audit trail live on the server; only investigators / admins may read them */
  const refreshServerData = useCallback(async () => {
    if (!session || session.role === 'officer') return
    const [q, a] = await Promise.all([api<{ rows: QueueEntry[] }>('/api/queue'), api<{ rows: AuditEntry[]; chain: { ok: boolean } }>('/api/audit')])
    if (q.ok) setQueue(q.data.rows)
    if (a.ok) {
      setAudit(a.data.rows)
      setAuditChainOk(a.data.chain.ok)
    }
    if (q.status === 401 || a.status === 401) setSession(null) // session expired
  }, [session])

  useEffect(() => {
    if (!session) return
    refreshServerData()
    const id = setInterval(refreshServerData, 8000)
    return () => clearInterval(id)
  }, [session, refreshServerData])

  const login = useCallback<Store['login']>(async (operatorId, passphrase) => {
    const r = await api<any>('/api/auth/login', { method: 'POST', body: { operatorId, passphrase } })
    if (!r.ok) return { ok: false, error: r.data?.error ?? 'Login failed' }
    setSession(toSession(r.data))
    setTab('triage')
    return { ok: true }
  }, [])

  const logout = useCallback(() => {
    api('/api/auth/logout', { method: 'POST', body: {} })
    setSession(null)
    setQueue([])
    setAudit([])
    setCaseDoc(null)
  }, [])

  const log = useCallback(
    (action: string, target: string) => {
      api('/api/audit', { method: 'POST', body: { action, target } }).then(() => {
        if (session && session.role !== 'officer') refreshServerData()
      })
    },
    [session, refreshServerData],
  )

  const addFlag = useCallback<Store['addFlag']>(
    async (entry) => {
      const r = await api<{ id: string }>('/api/queue', { method: 'POST', body: entry })
      if (session && session.role !== 'officer') refreshServerData()
      return r.ok ? r.data.id : 'NOT-SAVED'
    },
    [session, refreshServerData],
  )

  const resolve = useCallback<Store['resolve']>(
    async (id, status, note, pin) => {
      const r = await api<{ ok?: boolean; error?: string }>('/api/queue/resolve', { method: 'POST', body: { id, status, note, pin } })
      await refreshServerData()
      return r.ok ? { ok: true } : { ok: false, error: r.data?.error ?? 'Refused by the server' }
    },
    [refreshServerData],
  )

  const loadCert = useCallback<Store['loadCert']>(
    async (f) => {
      setCertError(null)
      try {
        const { info, der } = await loadCertFile(f)
        localStorage.setItem(CERT_KEY, btoa(String.fromCharCode(...der)))
        setCertState(info)
        log('UIDAI_CERT_LOADED', `${info.subjectCN || 'cert'} · ${(info.derSha256 ?? '').slice(0, 16)}`)
        return true
      } catch (e: any) {
        setCertError(`Not a valid X.509 certificate: ${e?.message ?? e}`)
        return false
      }
    },
    [log],
  )
  const clearCert = useCallback(() => {
    try {
      localStorage.removeItem(CERT_KEY)
    } catch {
      /* ignore */
    }
    setCertState(null)
  }, [])
  const goTo = useCallback((t: TabId) => setTab(t), [])
  const markStep = useCallback((s: WorkflowStep, done: boolean) => setSteps((p) => (p[s] === done ? p : { ...p, [s]: done })), [])
  const resetSteps = useCallback(() => setSteps({ triage: false, qr: false, biometric: false }), [])

  const addCase = useCallback<Store['addCase']>(
    (c) => {
      const at = Date.now()
      const id = `CASE-${new Date(at).toISOString().slice(2, 10).replace(/-/g, '')}-${fnvHex(`${at}${c.fileDigest}`).slice(0, 5).toUpperCase()}`
      const rec: CaseRecord = { ...c, id, at, operator: session?.operatorId ?? 'SYSTEM' }
      setCases((prev) => [rec, ...prev].slice(0, 200))
      log('CASE_SAVED', `${id} · risk ${c.risk}`)
      return id
    },
    [log, session],
  )
  const deleteCase = useCallback((id: string) => {
    setCases((prev) => prev.filter((c) => c.id !== id))
  }, [])
  const clearCases = useCallback(() => setCases([]), [])

  const value = useMemo(
    () => ({ cases, addCase, deleteCase, clearCases, caseDoc, setCaseDoc, session, login, logout, queue, addFlag, resolve, audit, auditChainOk, log, refreshServerData, cert, certError, loadCert, clearCert, tab, goTo, steps, markStep, resetSteps, sessionReady, selection, setSelection, suggestion, setSuggestion }),
    [cases, addCase, deleteCase, clearCases, caseDoc, session, login, logout, queue, addFlag, resolve, audit, auditChainOk, log, refreshServerData, cert, certError, loadCert, clearCert, tab, goTo, steps, markStep, resetSteps, sessionReady, selection, setSelection, suggestion],
  )

  return <StoreContext.Provider value={value as Store & { sessionReady: boolean }}>{children}</StoreContext.Provider>
}

export function useStore() {
  const ctx = useContext(StoreContext)
  if (!ctx) throw new Error('useStore must be used within StoreProvider')
  return ctx
}
