'use client'

import { StoreProvider, useStore } from './store'
import { LoginGateway } from './login-gateway'
import { CommandCenter } from './command-center'

function Gate() {
  const { session, sessionReady } = useStore()
  if (!sessionReady) return <main className="flex min-h-dvh items-center justify-center text-sm text-muted-foreground">Checking session…</main>
  return session ? <CommandCenter /> : <LoginGateway />
}

export function VeriSightApp() {
  return (
    <StoreProvider>
      <Gate />
    </StoreProvider>
  )
}
