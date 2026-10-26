/* ============================================================
 * VERIFICATION PURPOSE + DOCUMENT TYPE CATALOGUE
 *
 * One shared engine, small per-document "adapters" that only say which checks apply.
 * Rules:
 *  - choosing a purpose or a type NEVER makes a document genuine;
 *  - a check that does not apply is NOT_APPLICABLE (never "failed");
 *  - a check that applies but has no real backend in this prototype is UNAVAILABLE
 *    (e.g. live issuer status), it is never simulated;
 *  - a custom / unknown purpose never switches security checks off.
 * ============================================================ */

export type PurposeId =
  | 'intl-border' | 'border-resident' | 'border-trade' | 'immigration' | 'airport' | 'police' | 'govt-office'
  | 'vehicle-gate' | 'industrial-gate' | 'port-cargo' | 'forestry' | 'visitor-access' | 'general' | 'custom'

export type AdapterId =
  | 'aadhaar' | 'pan' | 'voter' | 'passport' | 'driving-licence' | 'govt-id' | 'visa' | 'travel-permit'
  | 'border-pass' | 'vehicle-registration' | 'vehicle-permit' | 'cargo-trade' | 'org-access' | 'govt-certificate' | 'generic'

export type DocTypeId =
  | 'aadhaar' | 'pan' | 'voter-id' | 'passport' | 'driving-licence' | 'govt-id'
  | 'visa' | 'travel-permit'
  | 'border-resident-pass' | 'daily-movement-pass' | 'border-trade-pass' | 'local-movement-permit' | 'temporary-entry-pass' | 'visitor-pass' | 'other-border-permit'
  | 'vehicle-entry-permit' | 'vehicle-registration' | 'cargo-permit' | 'customs-declaration' | 'goods-transit-permit' | 'forestry-transit-permit'
  | 'employee-id' | 'contractor-pass' | 'industrial-access-permit' | 'port-access-permit' | 'govt-certificate'
  | 'auto' | 'other'

export type CheckId =
  | 'ocr' | 'qr' | 'qr-ocr-consistency' | 'signature' | 'issuer-trust' | 'mrz' | 'id-format'
  | 'date-validity' | 'live-status' | 'forensics' | 'photo-compare' | 'movement-rules' | 'duplicate'

export type Applicability = 'applicable' | 'not-applicable' | 'unavailable'

export const CHECK_LABEL: Record<CheckId, string> = {
  ocr: 'OCR field extraction',
  qr: 'QR / barcode',
  'qr-ocr-consistency': 'QR ↔ printed consistency',
  signature: 'Digital signature',
  'issuer-trust': 'Issuer trust',
  mrz: 'MRZ checksum',
  'id-format': 'Document-number format',
  'date-validity': 'Date / validity window',
  'live-status': 'Live issuer status',
  forensics: 'Image / PDF forensics',
  'photo-compare': 'Photograph comparison',
  'movement-rules': 'Location & movement rules',
  duplicate: 'Duplicate indicators (local)',
}

export const ALL_CHECKS = Object.keys(CHECK_LABEL) as CheckId[]

const A = 'applicable' as const
const N = 'not-applicable' as const
const U = 'unavailable' as const

type CheckMap = Record<CheckId, Applicability>
const base = (o: Partial<CheckMap>): CheckMap => ({
  ocr: A, qr: N, 'qr-ocr-consistency': N, signature: N, 'issuer-trust': N, mrz: N, 'id-format': N,
  'date-validity': A, 'live-status': U, forensics: A, 'photo-compare': N, 'movement-rules': N, duplicate: A,
  ...o,
})

/** What each adapter can really check. 'live-status' is UNAVAILABLE everywhere: no authorised issuer API is connected. */
export const ADAPTERS: Record<AdapterId, { label: string; checks: CheckMap; limits: string }> = {
  aadhaar: {
    label: 'Aadhaar',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: A, 'issuer-trust': A, 'id-format': A, 'date-validity': N, 'photo-compare': A }),
    limits: 'UIDAI authenticity needs the Secure QR signature checked against a pinned UIDAI certificate. A screenshot cannot prove it.',
  },
  pan: {
    label: 'PAN card',
    checks: base({ 'id-format': A, 'date-validity': N, qr: U, 'photo-compare': A }),
    limits: 'PAN has no public checksum or signature scheme here: a correct format only means "possible", never "genuine".',
  },
  voter: {
    label: 'Voter ID (EPIC)',
    checks: base({ 'id-format': A, 'date-validity': N, 'photo-compare': A }),
    limits: 'EPIC has no public checksum or signature scheme here. Format only.',
  },
  passport: {
    label: 'Passport',
    checks: base({ mrz: A, 'id-format': A, 'photo-compare': A, signature: U, 'issuer-trust': U }),
    limits: 'A valid MRZ checksum is not proof the passport is genuine. Chip (ePassport) verification is not implemented.',
  },
  'driving-licence': {
    label: 'Driving licence',
    checks: base({ 'id-format': A, 'photo-compare': A, qr: U }),
    limits: 'Format and dates only. No registry (Sarathi/VAHAN) lookup is connected.',
  },
  'govt-id': {
    label: 'Government identity card',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: U, 'issuer-trust': U, 'photo-compare': A }),
    limits: 'Rules are generic. Signature checks need a documented issuer format and a pinned key.',
  },
  visa: {
    label: 'Visa',
    checks: base({ mrz: A, 'id-format': A, qr: U, signature: U, 'issuer-trust': U }),
    limits: 'No e-visa registry is connected: dates and fields only.',
  },
  'travel-permit': {
    label: 'Travel permit',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: A, 'issuer-trust': A, 'movement-rules': A }),
    limits: 'Printed validity is not live status.',
  },
  'border-pass': {
    label: 'Border pass / permit',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: A, 'issuer-trust': A, 'movement-rules': A, 'photo-compare': A }),
    limits: 'No official border-pass QR specification is assumed. Only the documented VeriSight demo envelope can be signature-checked.',
  },
  'vehicle-registration': {
    label: 'Vehicle registration',
    checks: base({ 'id-format': A, 'date-validity': A, qr: U }),
    limits: 'No VAHAN lookup. Registration-number format and permit cross-checks only.',
  },
  'vehicle-permit': {
    label: 'Vehicle entry permit',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: A, 'issuer-trust': A, 'movement-rules': A }),
    limits: 'Printed validity is not live status.',
  },
  'cargo-trade': {
    label: 'Cargo / trade / transit permit',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: A, 'issuer-trust': A, 'movement-rules': A }),
    limits: 'No customs / forest registry is connected. Do not read a passed format check as registry verification.',
  },
  'org-access': {
    label: 'Organisation access pass',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: A, 'issuer-trust': A, 'movement-rules': A, 'photo-compare': A }),
    limits: 'Authorisation data of the organisation is not connected.',
  },
  'govt-certificate': {
    label: 'Government certificate',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: A, 'issuer-trust': A }),
    limits: 'Rules are generic. PDF signature trust needs a pinned root.',
  },
  generic: {
    label: 'Unknown / other document',
    checks: base({ qr: A, 'qr-ocr-consistency': A, signature: A, 'issuer-trust': A, 'photo-compare': A }),
    limits: 'Generic analysis only. No document-specific rules are applied.',
  },
}

export type DocCategory = 'identity' | 'travel' | 'border' | 'vehicle-trade' | 'organisation' | 'special'

export type DocTypeDef = { id: DocTypeId; label: string; category: DocCategory; adapter: AdapterId }

export const CATEGORY_LABEL: Record<DocCategory, string> = {
  identity: 'Identity documents',
  travel: 'Travel documents',
  border: 'Border passes',
  'vehicle-trade': 'Vehicle and trade documents',
  organisation: 'Organisation and access documents',
  special: 'Other',
}

export const DOC_TYPES: DocTypeDef[] = [
  { id: 'aadhaar', label: 'Aadhaar Card', category: 'identity', adapter: 'aadhaar' },
  { id: 'pan', label: 'PAN Card', category: 'identity', adapter: 'pan' },
  { id: 'voter-id', label: 'Voter ID', category: 'identity', adapter: 'voter' },
  { id: 'passport', label: 'Passport', category: 'identity', adapter: 'passport' },
  { id: 'driving-licence', label: 'Driving Licence', category: 'identity', adapter: 'driving-licence' },
  { id: 'govt-id', label: 'Government Identity Card', category: 'identity', adapter: 'govt-id' },
  { id: 'visa', label: 'Visa', category: 'travel', adapter: 'visa' },
  { id: 'travel-permit', label: 'Travel Permit', category: 'travel', adapter: 'travel-permit' },
  { id: 'border-resident-pass', label: 'Border Resident Pass', category: 'border', adapter: 'border-pass' },
  { id: 'daily-movement-pass', label: 'Daily Movement Pass', category: 'border', adapter: 'border-pass' },
  { id: 'border-trade-pass', label: 'Border Trade Pass', category: 'border', adapter: 'border-pass' },
  { id: 'local-movement-permit', label: 'Local Movement Permit', category: 'border', adapter: 'border-pass' },
  { id: 'temporary-entry-pass', label: 'Temporary Entry Pass', category: 'border', adapter: 'border-pass' },
  { id: 'visitor-pass', label: 'Visitor Pass', category: 'border', adapter: 'border-pass' },
  { id: 'other-border-permit', label: 'Other Border Permit', category: 'border', adapter: 'border-pass' },
  { id: 'vehicle-entry-permit', label: 'Vehicle Entry Permit', category: 'vehicle-trade', adapter: 'vehicle-permit' },
  { id: 'vehicle-registration', label: 'Vehicle Registration Document', category: 'vehicle-trade', adapter: 'vehicle-registration' },
  { id: 'cargo-permit', label: 'Cargo Permit', category: 'vehicle-trade', adapter: 'cargo-trade' },
  { id: 'customs-declaration', label: 'Customs Declaration', category: 'vehicle-trade', adapter: 'cargo-trade' },
  { id: 'goods-transit-permit', label: 'Goods Transit Permit', category: 'vehicle-trade', adapter: 'cargo-trade' },
  { id: 'forestry-transit-permit', label: 'Forestry Transit Permit', category: 'vehicle-trade', adapter: 'cargo-trade' },
  { id: 'employee-id', label: 'Employee ID', category: 'organisation', adapter: 'org-access' },
  { id: 'contractor-pass', label: 'Contractor Pass', category: 'organisation', adapter: 'org-access' },
  { id: 'industrial-access-permit', label: 'Industrial Access Permit', category: 'organisation', adapter: 'org-access' },
  { id: 'port-access-permit', label: 'Port Access Permit', category: 'organisation', adapter: 'org-access' },
  { id: 'govt-certificate', label: 'Government Certificate', category: 'organisation', adapter: 'govt-certificate' },
  { id: 'auto', label: 'Auto-detect Document Type', category: 'special', adapter: 'generic' },
  { id: 'other', label: 'Other / Unknown Document', category: 'special', adapter: 'generic' },
]

export const docTypeById = (id: DocTypeId): DocTypeDef => DOC_TYPES.find((d) => d.id === id) ?? DOC_TYPES[DOC_TYPES.length - 1]

export type PurposeDef = { id: PurposeId; label: string; hint: string; primary: DocTypeId[]; movement: boolean }

const IDENT: DocTypeId[] = ['aadhaar', 'pan', 'voter-id', 'passport', 'driving-licence', 'govt-id']
const BORDER_PASSES: DocTypeId[] = ['border-resident-pass', 'daily-movement-pass', 'border-trade-pass', 'local-movement-permit', 'temporary-entry-pass', 'visitor-pass', 'other-border-permit']

export const PURPOSES: PurposeDef[] = [
  { id: 'intl-border', label: 'International Border Checkpoint', hint: 'Passport, visa, travel documents, supported border permits', primary: ['passport', 'visa', 'travel-permit', ...BORDER_PASSES], movement: true },
  { id: 'border-resident', label: 'Border Resident Verification', hint: 'Resident passes, local movement permits, validity and movement limits', primary: ['border-resident-pass', 'daily-movement-pass', 'local-movement-permit', 'temporary-entry-pass', 'other-border-permit', 'aadhaar', 'voter-id', 'govt-id'], movement: true },
  { id: 'border-trade', label: 'Border Trade & Customs', hint: 'Trade permits, cargo documents, vehicle references, customs papers', primary: ['border-trade-pass', 'cargo-permit', 'customs-declaration', 'goods-transit-permit', 'vehicle-entry-permit', 'vehicle-registration', 'passport', 'govt-id'], movement: true },
  { id: 'immigration', label: 'Immigration', hint: 'Passport, visa, MRZ, validity checks', primary: ['passport', 'visa', 'travel-permit', 'temporary-entry-pass'], movement: false },
  { id: 'airport', label: 'Airport Security / Immigration', hint: 'Passport, visa, supported identity documents', primary: ['passport', 'visa', 'travel-permit', 'aadhaar', 'voter-id', 'driving-licence', 'govt-id'], movement: false },
  { id: 'police', label: 'Police Checkpoint', hint: 'Supported identity documents and applicable permits', primary: [...IDENT, 'vehicle-registration', 'vehicle-entry-permit', 'local-movement-permit'], movement: true },
  { id: 'govt-office', label: 'Government Office', hint: 'Identity documents and certificates', primary: [...IDENT, 'govt-certificate'], movement: false },
  { id: 'vehicle-gate', label: 'Vehicle Entry Gate', hint: 'Vehicle registration, entry permits, associated access passes', primary: ['vehicle-registration', 'vehicle-entry-permit', 'driving-licence', 'visitor-pass', 'contractor-pass'], movement: true },
  { id: 'industrial-gate', label: 'Industrial Security Gate', hint: 'Employee IDs, contractor passes, visitor permits', primary: ['employee-id', 'contractor-pass', 'industrial-access-permit', 'visitor-pass', 'govt-id'], movement: true },
  { id: 'port-cargo', label: 'Port & Cargo Terminal', hint: 'Port access, cargo and customs documents', primary: ['port-access-permit', 'cargo-permit', 'customs-declaration', 'vehicle-entry-permit', 'vehicle-registration', 'govt-id'], movement: true },
  { id: 'forestry', label: 'Forestry Checkpost', hint: 'Transit permits, goods movement documents, validity checks', primary: ['forestry-transit-permit', 'goods-transit-permit', 'vehicle-registration', 'driving-licence'], movement: true },
  { id: 'visitor-access', label: 'Visitor & Restricted-Area Access', hint: 'Visitor passes and identity documents', primary: ['visitor-pass', 'temporary-entry-pass', 'employee-id', 'contractor-pass', ...IDENT], movement: true },
  { id: 'general', label: 'General Document Verification', hint: 'Any supported document, no purpose-specific limits', primary: [], movement: true },
  { id: 'custom', label: 'Other / Custom Purpose', hint: 'Every check of the chosen document stays ON', primary: [], movement: true },
]

export const purposeById = (id: PurposeId): PurposeDef => PURPOSES.find((p) => p.id === id) ?? PURPOSES[PURPOSES.length - 2]

/** Options for the selector: the purpose's usual documents first, every other type still reachable under "other". */
export function docTypesForPurpose(purpose: PurposeId): { primary: DocTypeDef[]; other: DocTypeDef[] } {
  const p = purposeById(purpose)
  const real = DOC_TYPES.filter((d) => d.id !== 'auto' && d.id !== 'other')
  if (!p.primary.length) return { primary: real, other: [] }
  const primary = p.primary.map((id) => docTypeById(id))
  const other = real.filter((d) => !p.primary.includes(d.id))
  return { primary, other }
}

export type SelectionFit = 'primary' | 'limited' | 'unspecified'

export type Applicable = {
  fit: SelectionFit
  warnings: string[]
  /** per-check applicability for THIS purpose + document type */
  checks: Record<CheckId, Applicability>
  limits: string
  adapter: AdapterId
}

/**
 * Purpose + type -> applicable checks.
 * - the document adapter decides what CAN be checked;
 * - a purpose may only mark movement rules not-applicable, it can never turn security checks off;
 * - custom / general / unknown purposes keep every adapter check on.
 */
export function evaluateSelection(purpose: PurposeId, docType: DocTypeId): Applicable {
  const p = purposeById(purpose)
  const d = docTypeById(docType)
  const adapter = ADAPTERS[d.adapter]
  const checks = { ...adapter.checks }
  const warnings: string[] = []
  let fit: SelectionFit = 'unspecified'
  if (docType === 'auto') {
    warnings.push('Document type not chosen yet: only generic checks are shown until a type is confirmed.')
  } else if (docType === 'other') {
    warnings.push('Unknown document: generic analysis only. No document-specific rules are applied.')
  } else if (p.primary.length) {
    fit = p.primary.includes(docType) ? 'primary' : 'limited'
    if (fit === 'limited') warnings.push(`"${d.label}" is not a usual document for "${p.label}". The checks still run, but the result may not satisfy this purpose.`)
  }
  if (!p.movement && checks['movement-rules'] === 'applicable') checks['movement-rules'] = 'not-applicable'
  return { fit, warnings, checks, limits: adapter.limits, adapter: d.adapter }
}

/* ---------- auto-detect: only ever a SUGGESTION ---------- */
export type Suggestion = { id: DocTypeId | null; confidence: 'high' | 'low' | 'none'; candidates: DocTypeId[]; reason: string }

export function suggestDocType(text: string): Suggestion {
  const t = text.replace(/\s+/g, ' ')
  const hits: { id: DocTypeId; why: string }[] = []
  const add = (id: DocTypeId, why: string) => hits.push({ id, why })
  if (/(^|\n)\s*P[<A-Z][A-Z<]{3}[A-Z<]{39}/.test(text) || /P<[A-Z]{3}[A-Z<]{20,}/.test(t)) add('passport', 'MRZ line starting with P<')
  if (/\buidai\b|aadhaar|आधार/i.test(t)) add('aadhaar', 'Aadhaar / UIDAI wording')
  if (/income\s*tax\s*department|permanent\s*account\s*number/i.test(t) || /\b[A-Z]{5}\d{4}[A-Z]\b/.test(t)) add('pan', 'Income Tax / PAN wording or number shape')
  if (/election\s*commission|elector'?s?\s*photo|\bEPIC\b/i.test(t)) add('voter-id', 'Election Commission wording')
  if (/driving\s*licen[cs]e|\bDL\s*No\b/i.test(t)) add('driving-licence', 'Driving licence wording')
  if (/\bvisa\b/i.test(t) && /(entries|valid\s*until|duration of stay|visa\s*type)/i.test(t)) add('visa', 'Visa wording with visa fields')
  if (/(border|resident)\s*(pass|permit)/i.test(t)) add('border-resident-pass', 'Border / resident pass wording')
  if (/daily\s*movement/i.test(t)) add('daily-movement-pass', 'Daily movement wording')
  if (/local\s*movement/i.test(t)) add('local-movement-permit', 'Local movement wording')
  if (/trade\s*pass|border\s*trade/i.test(t)) add('border-trade-pass', 'Trade pass wording')
  if (/temporary\s*entry/i.test(t)) add('temporary-entry-pass', 'Temporary entry wording')
  if (/visitor\s*(pass|permit)/i.test(t)) add('visitor-pass', 'Visitor pass wording')
  if (/forest(ry)?\s*transit|transit\s*pass.*forest/i.test(t)) add('forestry-transit-permit', 'Forestry transit wording')
  if (/goods\s*transit/i.test(t)) add('goods-transit-permit', 'Goods transit wording')
  if (/customs\s*declaration|bill\s*of\s*entry/i.test(t)) add('customs-declaration', 'Customs declaration wording')
  if (/cargo\s*permit/i.test(t)) add('cargo-permit', 'Cargo permit wording')
  if (/vehicle\s*(entry)?\s*permit/i.test(t)) add('vehicle-entry-permit', 'Vehicle permit wording')
  if (/registration\s*certificate|certificate\s*of\s*registration/i.test(t)) add('vehicle-registration', 'Registration certificate wording')
  if (/contractor\s*pass/i.test(t)) add('contractor-pass', 'Contractor pass wording')
  if (/employee\s*(id|card)/i.test(t)) add('employee-id', 'Employee ID wording')
  if (/port\s*(access|entry)/i.test(t)) add('port-access-permit', 'Port access wording')
  const ids = [...new Set(hits.map((h) => h.id))]
  if (ids.length === 0) return { id: null, confidence: 'none', candidates: [], reason: 'No document wording recognised. Choose the type manually.' }
  if (ids.length === 1) return { id: ids[0], confidence: 'high', candidates: ids, reason: hits[0].why }
  return { id: null, confidence: 'low', candidates: ids, reason: `Several types match (${ids.join(', ')}). Pick one yourself.` }
}
