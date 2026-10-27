import test from 'node:test'
import assert from 'node:assert/strict'
import { compareIdentityFields } from '../lib/cross-document'

test('cross-document comparison matches normalized names, dates, and gender', () => {
  const rows = compareIdentityFields(
    { name: 'Riya Kumari', dob: '1995-08-14', gender: 'Female', pincode: '110001' },
    { name: 'KUMARI, RIYA', dob: '14/08/1995', gender: 'F', pincode: '110001' },
  )
  assert.deepEqual(rows.map((row) => row.result), ['match', 'match', 'match', 'match'])
})

test('cross-document comparison reports mismatches and partial year-only DOBs', () => {
  const rows = compareIdentityFields(
    { name: 'RIYA KUMARI', dob: '1995', gender: 'F' },
    { name: 'RIYA SHARMA', dob: '14-08-1995', gender: 'M' },
  )
  assert.equal(rows[0].result, 'mismatch')
  assert.equal(rows[1].result, 'partial')
  assert.equal(rows[2].result, 'mismatch')
})

test('cross-document comparison marks unavailable fields instead of treating them as matches', () => {
  const rows = compareIdentityFields({ name: 'RIYA KUMARI' }, { dob: '1995' })
  assert.ok(rows.every((row) => row.result === 'unavailable'))
})

test('cross-document comparison rejects impossible or unparseable dates', () => {
  const rows = compareIdentityFields({ dob: '31/02/1995' }, { dob: '31/02/1995' })
  assert.equal(rows.find((row) => row.field === 'dob')?.result, 'mismatch')
})
