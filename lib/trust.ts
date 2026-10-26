/* ============================================================
 * TRUST MODEL
 * A valid RSA signature only proves "signed by whoever owns this certificate".
 * It proves "UIDAI / a government CA" ONLY if that certificate is independently
 * known to be genuine. We therefore need a TRUST LIST of pinned SHA-256 fingerprints
 * that the deploying organisation obtained out-of-band (uidai.gov.in, CCA India,
 * a printed handover sheet ...).  Without pins nothing is ever called "UIDAI VERIFIED".
 *
 * Configure in .env.local (comma-separated SHA-256 hex fingerprints of the certificate DER or SPKI public key):
 *   NEXT_PUBLIC_UIDAI_TRUSTED_SHA256=...      UIDAI Secure-QR signing certificate(s)
 *   NEXT_PUBLIC_PDF_TRUSTED_ROOTS_SHA256=...  root / intermediate CAs allowed to sign e-Aadhaar PDFs
 *   NEXT_PUBLIC_AADHAAR_PDF_SIGNER_SHA256=... signer certificates / public keys for Aadhaar PDFs only
 * Print the fingerprint of a downloaded certificate with:  node scripts/fingerprint.mjs file.cer
 * ============================================================ */
import { parseAsn1Time, parseCertFull, type CertInfo } from './asn1'

const norm = (s: string) => s.toLowerCase().replace(/[^0-9a-f]/g, '')
const list = (v: string | undefined) => (v ?? '').split(',').map(norm).filter((x) => x.length === 64)

export const UIDAI_PINS = list(process.env.NEXT_PUBLIC_UIDAI_TRUSTED_SHA256)
export const PDF_ROOT_PINS = list(process.env.NEXT_PUBLIC_PDF_TRUSTED_ROOTS_SHA256)
export const AADHAAR_PDF_SIGNER_PINS = list(process.env.NEXT_PUBLIC_AADHAAR_PDF_SIGNER_SHA256)

export type CertTrust = { state: 'trusted' | 'untrusted' | 'expired' | 'not-yet-valid'; reason: string }

/** Is this loaded certificate on the UIDAI trust list AND currently valid? */
export function assessCert(info: CertInfo, pins: string[] = UIDAI_PINS, now: Date = new Date()): CertTrust {
  const nb = parseAsn1Time(info.notBefore)
  const na = parseAsn1Time(info.notAfter)
  if (na && na.getTime() < now.getTime()) return { state: 'expired', reason: `Certificate expired on ${na.toISOString().slice(0, 10)}. Load the current UIDAI certificate.` }
  if (nb && nb.getTime() > now.getTime()) return { state: 'not-yet-valid', reason: `Certificate is not valid before ${nb.toISOString().slice(0, 10)}.` }
  if (!pins.length) return { state: 'untrusted', reason: 'No UIDAI trust list is configured (NEXT_PUBLIC_UIDAI_TRUSTED_SHA256). The certificate cannot be authenticated, so a matching signature does NOT prove the card is from UIDAI.' }
  const ok = (info.derSha256 && pins.includes(info.derSha256)) || (info.sha256 && pins.includes(info.sha256))
  return ok ? { state: 'trusted', reason: 'Certificate fingerprint is on the configured UIDAI trust list.' } : { state: 'untrusted', reason: 'Certificate fingerprint is NOT on the UIDAI trust list. This is not the certificate UIDAI published: do not trust signatures made with it.' }
}

const SIG_HASH: Record<string, string> = {
  '1.2.840.113549.1.1.5': 'SHA-1', '1.2.840.113549.1.1.11': 'SHA-256', '1.2.840.113549.1.1.12': 'SHA-384', '1.2.840.113549.1.1.13': 'SHA-512',
}
const u8 = (b: Uint8Array) => b as unknown as BufferSource
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, '0')).join('')
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i])

export type ChainResult = { state: 'trusted' | 'untrusted-root' | 'incomplete' | 'broken' | 'none'; detail: string; chain: string[] }

/**
 * Walk signer -> issuer -> ... using the certificates embedded in the PDF, verifying every certificate's
 * signature with its issuer's key, until a CA or signer certificate DER / SPKI public-key fingerprint is pinned.
 * Revocation (CRL / OCSP) needs the network and is NOT checked.
 */
export async function verifyChain(
  certs: Uint8Array[],
  pins: string[] = PDF_ROOT_PINS,
  signerHint = '',
  signerPins: string[] = [],
): Promise<ChainResult> {
  if (!certs.length) return { state: 'none', detail: 'No certificate embedded in the signature.', chain: [] }
  const parsed = certs.map((der) => ({ der, c: parseCertFull(der) }))
  let cur = parsed.find((p) => p.c.subjectCN === signerHint) ?? parsed[0]
  const chain: string[] = []
  for (let depth = 0; depth < 8; depth++) {
    const fp = hex(await crypto.subtle.digest('SHA-256', u8(cur.der)))
    const publicKeyFp = hex(await crypto.subtle.digest('SHA-256', u8(cur.c.spki)))
    chain.push(cur.c.subjectCN || '(no CN)')
    const signerPinned = depth === 0 && (signerPins.includes(fp) || signerPins.includes(publicKeyFp))
    const caPinned = pins.includes(fp) || pins.includes(publicKeyFp)
    if (signerPinned || caPinned) {
      const nb = parseAsn1Time(cur.c.notBefore)
      const na = parseAsn1Time(cur.c.notAfter)
      if (nb && nb.getTime() > Date.now()) return { state: 'untrusted-root', detail: `Pinned certificate "${cur.c.subjectCN}" is not valid before ${nb.toISOString().slice(0, 10)}.`, chain }
      if (na && na.getTime() < Date.now()) return { state: 'untrusted-root', detail: `Pinned certificate "${cur.c.subjectCN}" expired on ${na.toISOString().slice(0, 10)}.`, chain }
      return {
        state: 'trusted',
        detail: signerPinned
          ? `PDF signer certificate or public key is pinned: ${cur.c.subjectCN}.`
          : `Chain reaches a pinned trusted CA certificate or public key: ${cur.c.subjectCN}.`,
        chain,
      }
    }
    const selfSigned = eq(cur.c.issuerDer, cur.c.subjectDer)
    const issuer = selfSigned ? cur : parsed.find((p) => eq(p.c.subjectDer, cur.c.issuerDer))
    if (!issuer) return { state: 'incomplete', detail: `Issuer "${cur.c.issuerCN}" is not embedded in the PDF, so the chain cannot be completed.${pins.length ? '' : ' No PDF trust roots are configured.'}`, chain }
    const hash = SIG_HASH[cur.c.sigAlgOid]
    if (!hash) return { state: 'incomplete', detail: `Unsupported certificate signature algorithm ${cur.c.sigAlgOid}.`, chain }
    try {
      const key = await crypto.subtle.importKey('spki', u8(issuer.c.spki), { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify'])
      const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, u8(cur.c.signature), u8(cur.c.tbs))
      if (!ok) return { state: 'broken', detail: `Certificate "${cur.c.subjectCN}" is NOT signed by "${issuer.c.subjectCN}": forged or corrupted chain.`, chain }
    } catch (e: any) {
      return { state: 'incomplete', detail: `Could not verify certificate signature: ${e?.message ?? e}`, chain }
    }
    if (selfSigned) return { state: 'untrusted-root', detail: `Chain ends at self-signed root "${cur.c.subjectCN}" which is not on the trust list${pins.length ? '' : ' (no PDF trust roots configured)'}.`, chain }
    cur = issuer
  }
  return { state: 'incomplete', detail: 'Certificate chain too long.', chain }
}
