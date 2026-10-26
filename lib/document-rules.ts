import { validateTD1, validateTD3 } from './forensics'
import type { PermitFields } from './permit'
import type { DocTypeId } from './purposes'

export type DocumentRuleResult = {
  key: string
  label: string
  state: 'pass' | 'warn' | 'info'
  text: string
  review: boolean
}

const STATE_CODES = new Set(
  'AN AP AR AS BR CH CG DD DL DN GA GJ HP HR JH JK KA KL LA LD MH ML MN MP MZ NL OD OR PB PY RJ SK TN TR TS UK UP UA WB'.split(' '),
)

const mrzLines = (value: string) => value.toUpperCase().split(/\r?\n/).map((line) => line.replace(/\s/g, '')).filter(Boolean)

function inspectTravelMrz(docType: DocTypeId, value: string): DocumentRuleResult {
  const lines = mrzLines(value)
  const isPassport = docType === 'passport'
  const prefix = isPassport ? 'Passport' : 'Visa'
  let checks: ReturnType<typeof validateTD1> = []

  const travelPrefix = isPassport ? /^P[A-Z<]/ : /^V[A-Z<]/
  if (
    lines.length === 2 &&
    /^[PV][A-Z<]{43}$/.test(lines[0]) &&
    /^[A-Z0-9<]{44}$/.test(lines[1]) &&
    travelPrefix.test(lines[0]) &&
    /^\d$/.test(lines[1][9]) &&
    /^\d$/.test(lines[1][19]) &&
    /^[MFX<]$/.test(lines[1][20]) &&
    /^\d$/.test(lines[1][27]) &&
    /^\d$/.test(lines[1][43])
  ) {
    checks = validateTD3(lines[1])
  } else if (
    isPassport &&
    lines.length === 3 &&
    /^[ACI][A-Z<]{29}$/.test(lines[0]) &&
    /^\d{7}[MF<]\d{7}[A-Z<]{14}\d$/.test(lines[1]) &&
    /^[A-Z<]{30}$/.test(lines[2])
  ) {
    checks = validateTD1(lines[0], lines[1])
  } else {
    return {
      key: 'travel-mrz',
      label: `${prefix} MRZ`,
      state: lines.length ? 'warn' : 'info',
      text: lines.length
        ? `Read text does not match the supported ${isPassport ? 'ICAO TD1/TD3 passport' : '44-character MRV-A visa'} shape. Confirm the document type and OCR manually.`
        : 'No supported MRZ lines were extracted; MRZ checks could not run.',
      review: !!lines.length,
    }
  }

  const failed = checks.filter((check) => !check.valid)
  return {
    key: 'travel-mrz',
    label: `${prefix} MRZ check digits`,
    state: failed.length ? 'warn' : 'pass',
    text: failed.length
      ? `${failed.map((check) => check.label).join(', ')} check digit(s) differ. OCR can misread characters; verify against the original.`
      : 'Supported MRZ structure and check digits are consistent. This is not issuer authentication.',
    review: failed.length > 0,
  }
}

function validateVehicleNumber(value: string): DocumentRuleResult {
  const normalized = value.toUpperCase().replace(/[\s-]/g, '')
  const match = normalized.match(/^([A-Z]{2})(\d{1,2})([A-Z]{0,3})(\d{1,4})$/)
  const valid = !!match && STATE_CODES.has(match[1]) && Number(match[2]) > 0 && Number(match[2]) <= 99
  return {
    key: 'vehicle-number',
    label: 'Vehicle registration number format',
    state: valid ? 'pass' : 'warn',
    text: valid
      ? 'Registration resembles an Indian state/RTO-series number. No VAHAN registry lookup is connected.'
      : 'Registration does not match the supported Indian state/RTO/series/number shape. Verify the OCR and local registration rules.',
    review: !valid,
  }
}

export function validateDocumentFields(docType: DocTypeId, fields: Partial<PermitFields>): DocumentRuleResult[] {
  if (docType === 'aadhaar' || docType === 'pan') return []

  const results: DocumentRuleResult[] = []
  const value = (key: keyof PermitFields) => (fields[key] ?? '').trim()
  const add = (result: DocumentRuleResult) => results.push(result)

  if (docType === 'passport' || docType === 'visa') add(inspectTravelMrz(docType, value('mrzText')))

  if (docType === 'vehicle-registration' || docType === 'vehicle-entry-permit') {
    const registration = value('vehicleNo')
    if (registration) add(validateVehicleNumber(registration))
    for (const [key, label, pattern] of [
      ['chassisNo', 'Chassis / VIN shape', /^[A-HJ-NPR-Z0-9-]{6,17}$/i],
      ['engineNo', 'Engine number shape', /^[A-Z0-9-]{5,20}$/i],
    ] as const) {
      const field = value(key)
      if (field) {
        const valid = pattern.test(field)
        add({
          key,
          label,
          state: valid ? 'pass' : 'warn',
          text: valid
            ? 'Value has a plausible character/length shape only; manufacturer records are not connected.'
            : 'Value has an unexpected shape. Confirm OCR and the manufacturer-specific format.',
          review: !valid,
        })
      }
    }
  }

  if (['cargo-permit', 'customs-declaration', 'goods-transit-permit', 'forestry-transit-permit', 'border-trade-pass'].includes(docType)) {
    const hsn = value('hsnCode')
    if (hsn) {
      const valid = /^\d{4}(?:\d{2}){0,2}$/.test(hsn.replace(/\s/g, ''))
      add({
        key: 'hsn-format',
        label: 'HSN code structure',
        state: valid ? 'pass' : 'warn',
        text: valid
          ? 'HSN has 4, 6, or 8 digits. No tariff database or goods-description match was checked.'
          : 'HSN should contain 4, 6, or 8 digits. Confirm the extracted value; this is not a tariff classification check.',
        review: !valid,
      })
    }
    for (const [key, label] of [['quantity', 'Quantity'], ['goodsValue', 'Goods value']] as const) {
      const field = value(key)
      if (field) {
        const normalized = field.replace(/,/g, '')
        const number = Number(normalized)
        const valid = /^\d+(?:\.\d+)?$/.test(normalized) && Number.isFinite(number) && number >= 0 && (key !== 'quantity' || number > 0)
        add({
          key,
          label: `${label} numeric check`,
          state: valid ? 'pass' : 'warn',
          text: valid ? 'A non-negative numeric value was read; no customs valuation or quantity database was checked.' : 'Value is not a plausible non-negative number. Confirm the OCR manually.',
          review: !valid,
        })
      }
    }
  }

  if (['govt-id', 'employee-id', 'contractor-pass', 'industrial-access-permit', 'port-access-permit', 'govt-certificate'].includes(docType)) {
    if (value('documentNo') || value('employeeId') || value('certificateId')) {
      add({
        key: 'issuer-id-rule',
        label: 'Issuer-specific ID rule',
        state: 'info',
        text: 'The extracted document/employee/certificate number is available for operator review; this issuer has no configured number specification or registry lookup.',
        review: false,
      })
    }
  }

  return results
}
