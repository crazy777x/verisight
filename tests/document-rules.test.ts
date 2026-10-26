import test from 'node:test'
import assert from 'node:assert/strict'
import { validateDocumentFields } from '../lib/document-rules'
import { emptyFields, extractPermitFields, runPermitChecks } from '../lib/permit'

const passportLine1 = 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<'
const passportLine2 = 'L898902C36UTO7408122F1204159ZE184226B<<<<<10'

test('passport MRZ check digits are reported without claiming issuer authentication', () => {
  const valid = validateDocumentFields('passport', { ...emptyFields(), mrzText: `${passportLine1}\n${passportLine2}` })
  assert.equal(valid[0].state, 'pass')
  assert.match(valid[0].text, /not issuer authentication/)

  const invalid = validateDocumentFields('passport', { ...emptyFields(), mrzText: `${passportLine1}\n${passportLine2.replace('740812', '740813')}` })
  assert.equal(invalid[0].state, 'warn')
  assert.equal(invalid[0].review, true)
})

test('44-character MRV-A visa MRZ check digits are supported', () => {
  const checks = validateDocumentFields('visa', { ...emptyFields(), mrzText: `${passportLine1.replace(/^P/, 'V')}\n${passportLine2}` })
  assert.equal(checks[0].state, 'pass')
})

test('vehicle number, chassis, and engine checks only report format plausibility', () => {
  const valid = validateDocumentFields('vehicle-registration', {
    ...emptyFields(),
    vehicleNo: 'KA 01 AB 1234',
    chassisNo: 'MALPC12345A123456',
    engineNo: 'ENG12345',
  })
  assert.deepEqual(valid.map((check) => check.state), ['pass', 'pass', 'pass'])
  assert.match(valid[0].text, /No VAHAN registry lookup/)
  assert.ok(valid.slice(1).every((check) => /plausible/.test(check.text)))

  const invalid = validateDocumentFields('vehicle-entry-permit', { ...emptyFields(), vehicleNo: 'XX00' })
  assert.equal(invalid[0].state, 'warn')
  assert.equal(invalid[0].review, true)
})

test('cargo checks validate HSN digit length and numeric amount only', () => {
  const valid = validateDocumentFields('cargo-permit', { ...emptyFields(), hsnCode: '123456', quantity: '12.5', goodsValue: '1,250.00' })
  assert.deepEqual(valid.map((check) => check.state), ['pass', 'pass', 'pass'])
  assert.match(valid[0].text, /No tariff database/)
  assert.match(valid[1].text, /numeric value/)
  assert.match(valid[2].text, /no customs valuation/)

  const invalid = validateDocumentFields('customs-declaration', { ...emptyFields(), hsnCode: '12345', quantity: '-1' })
  assert.deepEqual(invalid.map((check) => check.state), ['warn', 'warn'])
})

test('Aadhaar and PAN receive no additional document-rule checks', () => {
  assert.deepEqual(validateDocumentFields('aadhaar', { ...emptyFields(), vehicleNo: 'BAD' }), [])
  assert.deepEqual(validateDocumentFields('pan', { ...emptyFields(), hsnCode: 'bad' }), [])
})

test('document-specific checks appear in the permit report for vehicle records', async () => {
  const report = await runPermitChecks({
    purpose: 'vehicle-gate',
    docType: 'vehicle-registration',
    fields: { ...emptyFields(), vehicleNo: 'XX00' },
    reviewed: true,
    extraction: { ran: false },
    qrPayloads: null,
    nowMs: Date.parse('2026-10-26T12:00:00Z'),
    trustedKeys: [],
  })
  assert.equal(report.rows.find((row) => row.key === 'document-vehicle-number')?.state, 'warn')
})

test('OCR field extraction captures labelled cargo fields and supported MRZ lines', () => {
  const extracted = extractPermitFields(
    `HSN Code: 123456\nQuantity: 5\nGoods value: 100.00\n${passportLine1}\n${passportLine2}`,
    [],
  )
  assert.equal(extracted.fields.hsnCode, '123456')
  assert.equal(extracted.fields.quantity, '5')
  assert.equal(extracted.fields.goodsValue, '100.00')
  assert.equal(extracted.fields.mrzText, `${passportLine1}\n${passportLine2}`)
})
