'use client'

import { useState } from 'react'
import { Fingerprint, Lock, ScanEye, ShieldCheck, WifiOff } from 'lucide-react'
import { useStore } from './store'
import { ActionButton, Spinner, StatusBadge } from './primitives'
import { Logo } from './logo'

const HANDSHAKE = ['Verifying credentials on the server']

export function LoginGateway() {
  const { login } = useStore()
  const [operatorId, setOperatorId] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [phase, setPhase] = useState<number | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!operatorId.trim() || !passphrase) {
      setError('Enter your operator ID and passphrase.')
      return
    }
    setError(null)
    setPhase(0)
    const r = await login(operatorId.trim(), passphrase)
    setPhase(null)
    if (!r.ok) {
      setPassphrase('')
      setError(r.error ?? 'Login failed')
    }
  }

  const busy = phase !== null

  return (
    <main className="flex min-h-dvh items-center justify-center px-4 py-10">
      <div className="grid w-full max-w-5xl overflow-hidden rounded-xl border border-border bg-card backdrop-blur-xl lg:grid-cols-[1fr_1.1fr]">
        <aside className="relative hidden flex-col justify-between border-r border-border bg-sidebar/80 p-8 lg:flex">
          <div>
            <Logo />
            <h1 className="mt-10 text-balance text-3xl font-semibold leading-tight text-foreground">
              Check an identity document before you trust it.
            </h1>
            <p className="mt-3 text-pretty text-sm leading-relaxed text-muted-foreground">
              VeriSight runs document forensics, QR and signature verification and face matching inside your browser.
              Documents are never uploaded. Logins, the review queue and the audit log are handled by the server.
            </p>
          </div>
          <dl className="mt-10 grid grid-cols-2 gap-3">
            {[
              { k: 'Network', v: 'LOCAL ONLY', icon: WifiOff },
              { k: 'Sessions', v: 'SERVER SIGNED', icon: Lock },
              { k: 'Audit log', v: 'HASH-CHAINED', icon: Fingerprint },
              { k: 'Documents', v: 'STAY IN BROWSER', icon: ScanEye },
            ].map(({ k, v, icon: Icon }) => (
              <div key={k} className="rounded-md border border-border bg-background/40 p-3">
                <dt className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">
                  <Icon className="size-3" aria-hidden="true" />
                  {k}
                </dt>
                <dd className="mt-1 font-mono text-sm text-foreground">{v}</dd>
              </div>
            ))}
          </dl>
        </aside>

        <form onSubmit={handleSubmit} className="flex flex-col gap-6 p-6 sm:p-8" noValidate>
          <div className="flex items-center justify-between lg:hidden">
            <Logo />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <StatusBadge tone="success" pulse>
                Gateway online
              </StatusBadge>
              <StatusBadge tone="neutral">Local analysis</StatusBadge>
            </div>
            <h2 className="mt-4 text-xl font-semibold text-foreground">Secure Login Gateway</h2>
            <p className="mt-1 text-sm text-muted-foreground">Sign in with the account issued to you.</p>
          </div>

          <div className="flex flex-col gap-4">
            <label className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-foreground">Operator ID</span>
              <input
                value={operatorId}
                onChange={(e) => setOperatorId(e.target.value)}
                autoComplete="username"
                placeholder="BSO-4471"
                disabled={busy}
                className="h-11 rounded-lg border border-input bg-background/60 px-3 font-mono text-sm uppercase text-foreground placeholder:text-muted-foreground/60 focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
              />
            </label>
            <label className="flex flex-col gap-1.5">
              <span className="text-sm font-medium text-foreground">Passphrase</span>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                autoComplete="current-password"
                placeholder="••••••••••"
                disabled={busy}
                className="h-11 rounded-md border border-input bg-background/60 px-3 font-mono text-sm text-foreground placeholder:text-muted-foreground/60 focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
              />
            </label>
          </div>

          <p className="rounded-xl border border-border bg-background/40 px-3 py-2.5 text-xs leading-relaxed text-muted-foreground">
            Your role (officer, investigator or admin) is assigned by the server from your account. It cannot be chosen here.
          </p>

          {error && (
            <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
          )}

          <ActionButton type="submit" disabled={busy} className="h-11">
            {busy ? (
              <>
                <Spinner label="Authenticating" />
                <span className="font-mono text-xs">{HANDSHAKE[phase ?? 0]}…</span>
              </>
            ) : (
              <>
                <ShieldCheck className="size-4" aria-hidden="true" />
                Authenticate
              </>
            )}
          </ActionButton>
          <p className="text-center font-mono text-[11px] text-muted-foreground">
            Every login and action is written to a server-side, hash-chained audit log.
          </p>
        </form>
      </div>
    </main>
  )
}
