'use client'

import { Database, FileSearch, Lock, QrCode, ScanFace, ShieldAlert, Stamp } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useStore, type Role, type TabId } from './store'
import { WorkflowStepper } from './workflow'
import { TopBar } from './top-bar'
import { TriageBay } from './triage-bay'
import { PermitPanel } from './permit-panel'
import { QrInspector } from './qr-inspector'
import { BiometricMatch } from './biometric-match'
import { AdminQueue } from './admin-queue'
import { RecordsPanel } from './records-panel'
import ForensicScannerLoader from '@/components/ForensicScannerLoader'

const TABS: { id: TabId; label: string; short: string; icon: typeof FileSearch; roles: Role[] }[] = [
  { id: 'triage', label: 'Document Triage', short: 'Triage', icon: FileSearch, roles: ['officer', 'investigator', 'admin'] },
  { id: 'permit', label: 'Border Pass & Permit', short: 'Permit', icon: Stamp, roles: ['officer', 'investigator', 'admin'] },
  { id: 'qr', label: 'QR & Crypto Inspector', short: 'QR', icon: QrCode, roles: ['officer', 'investigator', 'admin'] },
  { id: 'biometric', label: 'Biometric Match', short: 'Biometric', icon: ScanFace, roles: ['officer', 'investigator', 'admin'] },
  { id: 'records', label: 'Case Records', short: 'Records', icon: Database, roles: ['officer', 'investigator', 'admin'] },
  { id: 'queue', label: 'Override Gateway', short: 'Queue', icon: ShieldAlert, roles: ['investigator', 'admin'] },
]

export function CommandCenter() {
  const store = useStore() as any
  const { session, queue, tab, goTo: setTab, isAnalyzing, isProcessing } = store
  const role = session!.role
  const pending = queue.filter((q: any) => q.status === 'pending').length
  const analyzing = isAnalyzing || isProcessing || false

  return (
    <div className="flex min-h-dvh flex-col">
      <TopBar />
      <nav aria-label="Modules" className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] gap-1 overflow-x-auto px-3 sm:px-6" role="tablist">
          {TABS.map((t) => {
            const allowed = t.roles.includes(role)
            const active = tab === t.id
            return (
              <button
                key={t.id}
                type="button"
                role="tab"
                aria-selected={active}
                aria-controls={`panel-${t.id}`}
                id={`tab-${t.id}`}
                disabled={!allowed}
                onClick={() => setTab(t.id)}
                title={allowed ? undefined : 'Requires Investigator or Super Admin clearance'}
                className={cn(
                  'relative flex min-h-12 shrink-0 items-center gap-2 px-3 text-sm font-medium transition-colors sm:px-4',
                  active ? 'text-foreground' : 'text-muted-foreground hover:text-foreground',
                  !allowed && 'cursor-not-allowed opacity-40 hover:text-muted-foreground',
                )}
              >
                {allowed ? <t.icon className="size-4" aria-hidden="true" /> : <Lock className="size-4" aria-hidden="true" />}
                <span className="hidden sm:inline">{t.label}</span>
                <span className="sm:hidden">{t.short}</span>
                {t.id === 'queue' && allowed && pending > 0 && (
                  <span className="rounded bg-destructive px-1.5 py-0.5 font-mono text-[10px] font-semibold text-white">
                    {pending}
                  </span>
                )}
                {active && <span className="absolute inset-x-2 bottom-0 h-0.5 rounded-full bg-primary" aria-hidden="true" />}
              </button>
            )
          })}
        </div>
        <div className="border-t border-border/60">
          <WorkflowStepper />
        </div>
      </nav>

      <main className="mx-auto w-full max-w-[1600px] flex-1 px-3 py-5 sm:px-6 sm:py-6">
        <div role="tabpanel" id="panel-triage" aria-labelledby="tab-triage" hidden={tab !== 'triage'}>
          {analyzing ? (
            <div className="flex min-h-[450px] w-full items-center justify-center">
              <ForensicScannerLoader />
            </div>
          ) : (
            <TriageBay />
          )}
        </div>
        <div role="tabpanel" id="panel-permit" aria-labelledby="panel-permit" hidden={tab !== 'permit'}>
          <PermitPanel />
        </div>
        <div role="tabpanel" id="panel-qr" aria-labelledby="panel-qr" hidden={tab !== 'qr'}>
          <QrInspector />
        </div>
        <div role="tabpanel" id="panel-biometric" aria-labelledby="panel-biometric" hidden={tab !== 'biometric'}>
          <BiometricMatch active={tab === 'biometric'} />
        </div>
        <div role="tabpanel" id="panel-records" aria-labelledby="panel-records" hidden={tab !== 'records'}>
          <RecordsPanel />
        </div>
        {role !== 'officer' && (
          <div role="tabpanel" id="panel-queue" aria-labelledby="panel-queue" hidden={tab !== 'queue'}>
            <AdminQueue />
          </div>
        )}
      </main>
    </div>
  )
}