'use client'

import { useEffect, useState } from 'react'
import { Cpu, KeyRound, LogOut, WifiOff } from 'lucide-react'
import { ROLE_META, useStore } from './store'
import { Logo } from './logo'
import { StatusBadge } from './primitives'

function useClock() {
  const [now, setNow] = useState<Date | null>(null)
  useEffect(() => {
    setNow(new Date())
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return now
}

export function TopBar() {
  const { session, logout } = useStore()
  const now = useClock()
  if (!session) return null
  const uptime = now ? Math.max(0, Math.floor((now.getTime() - session.startedAt) / 1000)) : 0
  const hh = String(Math.floor(uptime / 3600)).padStart(2, '0')
  const mm = String(Math.floor((uptime % 3600) / 60)).padStart(2, '0')
  const ss = String(uptime % 60).padStart(2, '0')

  return (
    <header className="border-b border-border bg-sidebar/80 backdrop-blur-xl">
      <div className="tricolor h-1 w-full" aria-hidden="true" />
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-6 gap-y-3 px-3 py-3 sm:px-6">
        <Logo />

        <dl className="order-3 flex w-full flex-wrap items-center gap-x-5 gap-y-2 font-mono text-[11px] md:order-none md:w-auto md:flex-1">
          <div className="flex items-center gap-1.5">
            <Cpu className="size-3.5 text-muted-foreground" aria-hidden="true" />
            <dt className="text-muted-foreground">NODE</dt>
            <dd className="text-foreground">{session.nodeId}</dd>
          </div>
          <div className="flex items-center gap-1.5">
            <WifiOff className="size-3.5 text-success" aria-hidden="true" />
            <dt className="sr-only">Network</dt>
            <dd className="text-success" title="Documents are analysed inside this browser tab and are never uploaded to any server.">LOCAL PROCESSING</dd>
          </div>
          <div className="flex items-center gap-1.5">
            <KeyRound className="size-3.5 text-success" aria-hidden="true" />
            <dt className="text-muted-foreground">SESSION ID</dt>
            <dd className="text-foreground" title="Identifier of this browser session">
              {session.keyFingerprint.slice(0, 4)}…{session.keyFingerprint.slice(-4)}
            </dd>
          </div>
          <div className="hidden items-center gap-1.5 lg:flex">
            <dt className="text-muted-foreground">SESSION</dt>
            <dd className="tabular-nums text-foreground">
              {hh}:{mm}:{ss}
            </dd>
          </div>
          <div className="hidden items-center gap-1.5 xl:flex">
            <dt className="text-muted-foreground">UTC</dt>
            <dd className="tabular-nums text-foreground">{now ? now.toISOString().slice(11, 19) : '--:--:--'}</dd>
          </div>
        </dl>

        <div className="ml-auto flex items-center gap-3">
          <div className="hidden text-right sm:block">
            <p className="font-mono text-xs text-foreground">{session.operatorId}</p>
            <p className="text-[11px] text-muted-foreground">{ROLE_META[session.role].label}</p>
          </div>
          <StatusBadge tone="success">{ROLE_META[session.role].clearance}</StatusBadge>
          <button
            type="button"
            onClick={logout}
            className="flex size-10 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:border-destructive/50 hover:text-destructive"
          >
            <LogOut className="size-4" aria-hidden="true" />
            <span className="sr-only">End session</span>
          </button>
        </div>
      </div>
    </header>
  )
}
