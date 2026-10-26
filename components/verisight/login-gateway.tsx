'use client'

import { useState, type FormEvent } from 'react'
import { ArrowRight, Eye, EyeOff, Fingerprint, LockKeyhole, ScanEye, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useStore } from './store'

export function LoginGateway() {
  const { login } = useStore()
  const [operatorId, setOperatorId] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [showPassphrase, setShowPassphrase] = useState(false)
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

  const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    await submitCredentials(operatorId, passphrase)
  }

  const fillDemoCredentials = () => {
    setOperatorId('OFF1')
    setPassphrase('officer2006')
    setError('')
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
              <p className="text-[11px] font-medium tracking-[0.15em] text-[#64736d]">OFFICER PORTAL</p>
              <h2 className="mt-3 text-2xl font-semibold tracking-[-0.025em]">Sign in to VeriSight</h2>
              <p className="mt-2 text-sm leading-6 text-[#657078]">
                Use the operator ID and passphrase assigned to your account.
              </p>
            </div>

            <form onSubmit={handleLogin} className="space-y-5">
              <div>
                <label htmlFor="operator-id" className="mb-2 block text-xs font-medium text-[#35434a]">
                  Operator ID
                </label>
                <input
                  id="operator-id"
                  name="username"
                  type="text"
                  value={operatorId}
                  onChange={(event) => setOperatorId(event.target.value)}
                  autoComplete="username"
                  required
                  maxLength={24}
                  className="h-12 w-full border border-[#cbd0cc] bg-[#fbfaf7] px-3.5 text-sm text-[#17232d] outline-none transition focus:border-[#315b52] focus:ring-2 focus:ring-[#315b52]/15"
                  placeholder="e.g. OFF-0001"
                />
              </div>

              <div>
                <label htmlFor="passphrase" className="mb-2 block text-xs font-medium text-[#35434a]">
                  Passphrase
                </label>
                <div className="relative">
                  <input
                    id="passphrase"
                    name="password"
                    type={showPassphrase ? 'text' : 'password'}
                    value={passphrase}
                    onChange={(event) => setPassphrase(event.target.value)}
                    autoComplete="current-password"
                    required
                    maxLength={200}
                    className="h-12 w-full border border-[#cbd0cc] bg-[#fbfaf7] px-3.5 pr-12 text-sm text-[#17232d] outline-none transition focus:border-[#315b52] focus:ring-2 focus:ring-[#315b52]/15"
                    placeholder="Enter your passphrase"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassphrase((visible) => !visible)}
                    className="absolute inset-y-0 right-0 flex w-12 items-center justify-center text-[#657078] hover:text-[#17232d] focus-visible:outline-2 focus-visible:outline-offset-[-4px] focus-visible:outline-[#315b52]"
                    aria-label={showPassphrase ? 'Hide passphrase' : 'Show passphrase'}
                  >
                    {showPassphrase ? <EyeOff className="size-4" aria-hidden="true" /> : <Eye className="size-4" aria-hidden="true" />}
                  </button>
                </div>
              </div>

              {error && (
                <p role="alert" className="border-l-2 border-[#a3423d] bg-[#a3423d]/5 px-3 py-2.5 text-sm text-[#8b302c]">
                  {error}
                </p>
              )}

              <Button
                type="submit"
                disabled={isSubmitting}
                className="h-12 w-full justify-between rounded-none bg-[#315b52] px-4 text-sm font-medium text-white hover:bg-[#264b43] disabled:opacity-60"
              >
                <span>{isSubmitting ? 'Signing in…' : 'Sign in securely'}</span>
                <ArrowRight className="size-4" aria-hidden="true" />
              </Button>
            </form>

            <div className="mt-7 border-t border-[#d8dad5] pt-5">
              <p className="text-xs leading-5 text-[#657078]">
                Document analysis runs locally in your browser. Sign-in is verified by the VeriSight server.
              </p>
              <div className="mt-5 border border-[#cbd0cc] bg-[#fbfaf7] p-4">
                <div className="flex items-start gap-3">
                  <LockKeyhole className="mt-0.5 size-4 shrink-0 text-[#315b52]" aria-hidden="true" />
                  <div>
                    <h3 className="text-xs font-semibold text-[#35434a]">Temporary demo login</h3>
                    <p className="mt-1 text-[11px] leading-5 text-[#657078]">
                      Enter these demo credentials manually, or fill them into the form and sign in.
                    </p>
                  </div>
                </div>
                <dl className="mt-3 grid grid-cols-[1fr_auto] gap-x-4 gap-y-2 border-t border-[#e1e3df] pt-3 text-xs">
                  <dt className="text-[#657078]">Temporary ID</dt>
                  <dd className="font-mono text-[#35434a]">OFF1</dd>
                  <dt className="text-[#657078]">Password</dt>
                  <dd className="font-mono text-[#35434a]">officer2006</dd>
                </dl>
                <p className="mt-3 text-[10px] leading-4 text-[#7b8589]">
                  This shared temporary account is for demonstrations only. Do not use it for real data.
                </p>
              </div>
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={fillDemoCredentials}
                  disabled={isSubmitting}
                  className="text-xs font-medium text-[#315b52] underline decoration-[#315b52]/35 underline-offset-4 hover:decoration-[#315b52] focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#315b52]"
                >
                  Fill demo credentials
                </button>
              </div>
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}
