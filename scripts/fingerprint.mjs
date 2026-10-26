// usage: node scripts/fingerprint.mjs certificate.cer [uidai|pdf-root|aadhaar-pdf-signer]   (PEM or DER)
// Confirm the certificate against a trusted source before adding its fingerprint to .env.local.
import { readFileSync } from 'node:fs'
import { createHash, X509Certificate } from 'node:crypto'
const file = process.argv[2]
const purpose = process.argv[3] ?? 'uidai'
const envName = {
  uidai: 'NEXT_PUBLIC_UIDAI_TRUSTED_SHA256',
  pdf: 'NEXT_PUBLIC_PDF_TRUSTED_ROOTS_SHA256',
  'pdf-root': 'NEXT_PUBLIC_PDF_TRUSTED_ROOTS_SHA256',
  'aadhaar-pdf-signer': 'NEXT_PUBLIC_AADHAAR_PDF_SIGNER_SHA256',
}[purpose]
if (!file || !envName || process.argv.length > 4) {
  console.error('usage: node scripts/fingerprint.mjs certificate.cer [uidai|pdf-root|aadhaar-pdf-signer]')
  process.exit(1)
}
const data = readFileSync(file)
const cert = new X509Certificate(data)
const certFingerprint = createHash('sha256').update(cert.raw).digest('hex')
const publicKeyFingerprint = createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('hex')
console.log('Subject :', cert.subject.replace(/\n/g, ', '))
console.log('Issuer  :', cert.issuer.replace(/\n/g, ', '))
console.log('Valid   :', cert.validFrom, '->', cert.validTo)
console.log('Certificate DER SHA-256 :', certFingerprint)
console.log('Public key SPKI SHA-256 :', publicKeyFingerprint)
console.log('\nAdd either SHA-256 fingerprint to .env.local:')
console.log(envName + '=' + certFingerprint)
if (purpose !== 'uidai') console.log(envName + '=' + publicKeyFingerprint + '  # SPKI public-key fingerprint')
