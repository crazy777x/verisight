'use client'

import { useState } from 'react'
import { ArrowRight, Fingerprint, LockKeyhole, ScanEye, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useStore } from './store'

export function LoginGateway() {
  const { login } = useStore()
  const [error, setError] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const submitCredentials = async (id: string, secret: string) => {
    setError('')
    setIsSubmitting(true)

    try {
      const result = await login(id.trim(), secret)
      if (!result.ok) setError(result.error ?? 'Unable to sign in. Check your details and try again.')
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Unable to reach the sign-in service. Try again.')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <main className="min-h-dvh bg-[#f3f2ed] text-[#17232d]">
      <div className="grid min-h-dvh lg:grid-cols-[minmax(0,1.1fr)_minmax(440px,0.9fr)]">
        <section className="relative flex min-h-[430px] flex-col overflow-hidden bg-[#172b39] px-6 py-7 text-[#f3f2ed] sm:px-10 lg:min-h-dvh lg:px-14 lg:py-10">
          <div className="absolute inset-y-0 right-0 hidden w-px bg-white/10 lg:block" aria-hidden="true" />
          <header className="flex items-center gap-3">
            <span className="flex size-10 items-center justify-center border border-white/20 text-[#d3e2d9]">
              <ScanEye className="size-5" aria-hidden="true" />
            </span>
            <span>
              <span className="block text-sm font-semibold tracking-[0.12em]">VERISIGHT</span>
              <span className="mt-1 block text-[10px] tracking-[0.16em] text-white/55">DOCUMENT REVIEW SYSTEM</span>
            </span>
          </header>

          <div className="my-auto max-w-xl py-14 lg:py-20">
            <p className="mb-5 flex items-center gap-2 text-[11px] font-medium tracking-[0.16em] text-[#c5d6cd]">
              <span className="size-1.5 rounded-full bg-[#9fbea9]" aria-hidden="true" />
              OPERATIONS ACCESS
            </p>
            <h1 className="max-w-lg text-4xl font-medium leading-[1.12] tracking-[-0.035em] sm:text-5xl">
              A clearer view of every document.
            </h1>
            <p className="mt-6 max-w-md text-sm leading-6 text-white/65">
              Sign in to review identity documents, inspect verification signals and keep case work in one place.
            </p>

            <div className="mt-12 border-t border-white/15 pt-5">
              <p className="mb-4 text-[10px] font-medium tracking-[0.16em] text-white/45">AVAILABLE WORK AREAS</p>
              <ul className="grid gap-3 text-sm text-white/80 sm:grid-cols-3 lg:grid-cols-1">
                <li className="flex items-center gap-3">
                  <Fingerprint className="size-4 text-[#c5d6cd]" aria-hidden="true" />
                  <span>Document triage &amp; biometrics</span>
                </li>
                <li className="flex items-center gap-3">
                  <ShieldCheck className="size-4 text-[#c5d6cd]" aria-hidden="true" />
                  <span>QR, permit &amp; signature checks</span>
                </li>
                <li className="flex items-center gap-3">
                  <LockKeyhole className="size-4 text-[#c5d6cd]" aria-hidden="true" />
                  <span>Role-based review and case records</span>
                </li>
              </ul>
            </div>
          </div>

          <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-white/15 pt-4 text-[10px] tracking-[0.08em] text-white/45">
            <span>VERISIGHT · SECURE OPERATIONS</span>
            <span>AUTHORIZED PERSONNEL ONLY</span>
          </footer>
        </section>

        <section className="flex items-center justify-center px-5 py-12 sm:px-10 lg:px-14">
          <div className="w-full max-w-[410px]">
            <div className="mb-9">
              <p className="text-[11px] font-medium tracking-[0.15em] text-[#64736d]">ONLY DEMO ACCESS</p>
              <h2 className="mt-3 text-2xl font-semibold tracking-[-0.025em]">For testing &amp; showing</h2>
              <p className="mt-2 text-sm leading-6 text-[#657078]">
                Continue with the temporary demo officer account.
              </p>
            </div>

            <div className="space-y-5">
              {error && (
                <p role="alert" className="border-l-2 border-[#a3423d] bg-[#a3423d]/5 px-3 py-2.5 text-sm text-[#8b302c]">
                  {error}
                </p>
              )}

              <Button
                type="button"
                onClick={() => submitCredentials('OFF1', 'officer2006')}
                disabled={isSubmitting}
                className="h-12 w-full justify-between rounded-none bg-[#315b52] px-4 text-sm font-medium text-white hover:bg-[#264b43] disabled:opacity-60"
              >
                <span>{isSubmitting ? 'Entering demo…' : 'Enter demo'}</span>
                <ArrowRight className="size-4" aria-hidden="true" />
              </Button>
            </div>

            <div className="mt-7 border-t border-[#d8dad5] pt-5">
              <p className="text-xs leading-5 text-[#657078]">
                Document analysis runs locally in your browser. Sign-in is verified by the VeriSight server.
              </p>
              <div className="mt-5 border border-[#cbd0cc] bg-[#fbfaf7] p-4">
                <div className="flex items-start gap-3">
                  <LockKeyhole className="mt-0.5 size-4 shrink-0 text-[#315b52]" aria-hidden="true" />
                  <div>
                    <h3 className="text-xs font-semibold text-[#35434a]">Demo account · testing and showing only</h3>
                    <p className="mt-1 text-[11px] leading-5 text-[#657078]">
                      The button signs in through the server using the temporary demo officer account.
                    </p>
                  </div>
                </div>
                <p className="mt-3 text-[10px] leading-4 text-[#7b8589]">
                  This shared demo account is public. Do not use it for real or sensitive data.
                </p>
              </div>
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}
