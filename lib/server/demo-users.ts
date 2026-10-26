/* DEMO MODE (DEMO_MODE=true): ANY operator ID + ANY passphrase logs in, so the project can be shown to anyone.
 * Role comes from the ID prefix: OFF... = officer, INV... = investigator, anything else = admin.
 * In demo mode any PIN of 4+ characters is accepted for overrides.
 * This is completely open on purpose. It must NEVER be enabled in a real deployment: leave DEMO_MODE unset
 * and connect the real user store (database / SSO) in lib/server/auth.ts. */
import type { Role } from './core'

export const DEMO_MODE = process.env.DEMO_MODE === 'true'

export function demoRole(operatorId: string): Role {
  const id = operatorId.toUpperCase()
  if (id.startsWith('OFF')) return 'officer'
  if (id.startsWith('INV')) return 'investigator'
  return 'admin'
}
