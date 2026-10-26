import test from 'node:test'
import assert from 'node:assert/strict'
import { findMrz, mrzFor } from '../lib/analysis'
import { analyzeMetadata } from '../lib/metadata'
import { shouldSkipPixelAnalysis } from '../lib/tamper'

test('address text read by OCR is never an MRZ (the bug that flagged a genuine Aadhaar)', () => {
  assert.equal(findMrz('AL<PRABIBUEPATTIPOST<PRABHATPU\nSOGRANESHWARVADBUDEATPRABHUPAT\nAL<PRABBUEPATTIPOS<PRABHATPUTT'), null)
})
const td3 = 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10'
test('real passport MRZ (ICAO specimen) is detected and every checksum passes', () => {
  const m = findMrz(td3)!
  assert.equal(m.kind, 'TD3')
  assert.ok(mrzFor(m).every((f) => f.valid))
})
test('one wrong digit in a real MRZ fails exactly that checksum', () => {
  const m = findMrz(td3.replace('L898902C36', 'L898902C37'))!
  assert.equal(mrzFor(m).filter((f) => !f.valid).length >= 1, true)
})
test('OCR O/0 confusion in a numeric slot is repaired', () => {
  assert.equal(findMrz(td3.replace('7408122', '74O8122'))?.kind, 'TD3')
})
test('TD1 ID card MRZ detected', () => {
  assert.equal(findMrz('I<UTOD231458907<<<<<<<<<<<<<<<\n7408122F1204159UTO<<<<<<<<<<<6\nERIKSSON<<ANNA<MARIA<<<<<<<<<<')?.kind, 'TD1')
})

const enc = (s: string) => new TextEncoder().encode(s)
test('metadata: declared AI marker is found, plain file is not accused', () => {
  assert.ok(analyzeMetadata(enc('\xff\xd8 .. trainedAlgorithmicMedia ..'), 'image/jpeg', 'a.jpg').aiMarkers.length > 0)
  assert.ok(analyzeMetadata(enc('\xff\xd8 plain'), 'image/jpeg', 'a.jpg').aiMarkers.length === 0)
  assert.ok(analyzeMetadata(enc('\x89PNG Gemini ChatGPT'), 'image/png', 'a.png').aiMarkers.length > 0)
})
test('metadata: PDF producer naming an editor is reported, modified-after-created is reported', () => {
  const pdf = '%PDF-1.7\n/Producer (iLovePDF) /Creator (Word) /CreationDate (D:20240101100000) /ModDate (D:20240601100000)\n%%EOF\n%%EOF'
  const m = analyzeMetadata(enc(pdf), 'application/pdf', 'a.pdf')
  assert.deepEqual(m.editorTags, ['iLovePDF'])
  assert.equal(m.pdfModifiedAfterCreation, true)
  assert.equal(m.pdfRevisions, 2)
})
test('metadata: screenshot (no camera EXIF) is not treated as reliable for pixel forensics', () => {
  const m = analyzeMetadata(new Uint8Array([0xff, 0xd8, 0xff, 0xd9]), 'image/jpeg', 's.jpg')
  assert.equal(m.pixelForensicsReliable, false)
})
test('pixel forensics run on images without EXIF and are skipped only for PDFs', () => {
  assert.equal(shouldSkipPixelAnalysis(new Uint8Array([0xff, 0xd8, 0xff])), false)
  assert.equal(shouldSkipPixelAnalysis(new Uint8Array([0x89, 0x50, 0x4e, 0x47])), false)
  assert.equal(shouldSkipPixelAnalysis(new TextEncoder().encode('%PDF-1.7')), true)
  assert.equal(shouldSkipPixelAnalysis(new TextEncoder().encode('prefix%PDF-1.7')), true)
})
