/* ============================================================
 * INDIAN ID FORMAT RULES + SHARED TEXT HELPERS
 * Everything here is deterministic format / structure validation.
 * (PAN, Driving Licence and EPIC have NO public checksum, so these checks
 * prove "format is impossible", never "format is genuine".)
 * ============================================================ */

export type IdKind = 'aadhaar' | 'pan' | 'dl' | 'epic' | 'mrz' | 'none'

export type IdCheck = {
  ok: boolean
  /** critical = cannot exist on a genuine document; high = very unlikely; medium = worth a look */
  severity: 'critical' | 'high' | 'medium'
  title: string
  detail: string
  points: number
}

/* ---------- name plausibility (rejects OCR garbage like "AIT AATETT ALY ggdaTA") ---------- */
export function plausibleWord(w: string): boolean {
  if (!/^[A-Za-z][A-Za-z.'-]*$/.test(w) || w.replace(/[^A-Za-z]/g, '').length < 2) return false
  const letters = w.replace(/[^A-Za-z]/g, '')
  if (!/[aeiouyAEIOUY]/.test(letters) && letters.length > 2) return false
  if (/[a-z][A-Z]/.test(letters)) return false // ggdaTA
  if (/(.)\1\1/i.test(letters)) return false // AAA
  const vowels = (letters.match(/[aeiouy]/gi) ?? []).length
  const ratio = vowels / letters.length
  if (letters.length >= 4 && (ratio < 0.15 || ratio > 0.8)) return false
  if (/[bcdfghjklmnpqrstvwxz]{5,}/i.test(letters)) return false
  return true
}

export function plausibleName(raw: string, allowSingle = false): string {
  const l = raw.replace(/[^A-Za-z .'-]/g, ' ').replace(/\s+/g, ' ').trim()
  const words = l.split(' ').filter(Boolean)
  if (!words.length || words.length > 5) return ''
  if (words.length === 1 && !(allowSingle && words[0].length >= 3)) return ''
  if (l.length < 3) return ''
  if (!words.every(plausibleWord)) return ''
  // at most one single-letter initial is fine ("Rahul K Sharma") but every real word must be >=2 letters
  return l
}

/* ---------- DOB ---------- */
export type DobCheck = { ok: boolean; reason: string; age: number | null }
export function dobSanity(dob: string, now = new Date()): DobCheck {
  if (!dob) return { ok: true, reason: '', age: null }
  const d = dob.replace(/\D/g, '')
  let y: number
  let m = 0
  let day = 0
  if (/^\d{4}$/.test(dob.trim())) y = +dob.trim()
  else if (d.length === 8) {
    // DD-MM-YYYY (printed) or YYYY-MM-DD
    if (+d.slice(0, 4) >= 1900 && +d.slice(0, 4) <= 2100) { y = +d.slice(0, 4); m = +d.slice(4, 6); day = +d.slice(6) }
    else { day = +d.slice(0, 2); m = +d.slice(2, 4); y = +d.slice(4) }
  } else return { ok: true, reason: '', age: null }
  if (m) {
    const dt = new Date(y, m - 1, day)
    if (m < 1 || m > 12 || day < 1 || dt.getMonth() !== m - 1 || dt.getDate() !== day) return { ok: false, reason: `${dob} is not a real calendar date`, age: null }
    if (dt.getTime() > now.getTime()) return { ok: false, reason: `Date of birth ${dob} is in the future`, age: null }
  } else if (y > now.getFullYear()) return { ok: false, reason: `Birth year ${y} is in the future`, age: null }
  const age = now.getFullYear() - y
  if (age > 110) return { ok: false, reason: `Age would be ${age} years (implausible)`, age }
  return { ok: true, reason: '', age }
}

/* ---------- PAN ---------- */
const PAN_ENTITY: Record<string, string> = {
  P: 'Individual', C: 'Company', H: 'Hindu Undivided Family', F: 'Firm / LLP', A: 'Association of Persons', T: 'Trust',
  B: 'Body of Individuals', L: 'Local Authority', J: 'Artificial Juridical Person', G: 'Government', K: 'Krish (Trust-AOP)',
}
const toL: Record<string, string> = { '0': 'O', '1': 'I', '5': 'S', '8': 'B', '2': 'Z', '6': 'G' }
const toD: Record<string, string> = { O: '0', I: '1', S: '5', B: '8', Z: '2', G: '6', D: '0', Q: '0' }

/** OCR confuses O/0, I/1, S/5, B/8: fix each position according to the PAN pattern AAAAA9999A. */
export function fixPanToken(t: string): string {
  if (t.length !== 10) return ''
  const out = t.split('').map((ch, i) => {
    const wantLetter = i < 5 || i === 9
    if (wantLetter) return /[A-Z]/.test(ch) ? ch : toL[ch] ?? ch
    return /\d/.test(ch) ? ch : toD[ch] ?? ch
  })
  const s = out.join('')
  return /^[A-Z]{5}\d{4}[A-Z]$/.test(s) ? s : ''
}

export function findPan(text: string): string {
  const up = text.toUpperCase().replace(/[|]/g, ' ')
  for (const m of up.matchAll(/\b[A-Z0-9]{10}\b/g)) {
    const f = fixPanToken(m[0])
    if (f) return f
  }
  return ''
}

export function hasPanKeywords(text: string) {
  return /(INCOME\s*TAX|PERMANENT\s*ACCOUNT|आयकर|स्थायी\s*लेखा)/i.test(text)
}

export function validatePan(pan: string, name: string, fatherName: string): IdCheck[] {
  const out: IdCheck[] = []
  if (!/^[A-Z]{5}\d{4}[A-Z]$/.test(pan)) {
    out.push({ ok: false, severity: 'critical', title: 'PAN format is invalid', detail: 'A real PAN is exactly 5 letters + 4 digits + 1 letter (AAAAA9999A).', points: 55 })
    return out
  }
  const ent = PAN_ENTITY[pan[3]]
  if (!ent) out.push({ ok: false, severity: 'critical', title: `PAN 4th character "${pan[3]}" is not a valid holder type`, detail: 'Allowed: P C H F A T B L J G K. A genuine PAN cannot have this letter.', points: 50 })
  if (ent && pan[3] === 'P' && name) {
    const parts = name.trim().split(/\s+/)
    const surname = parts[parts.length - 1]
    if (surname && surname[0].toUpperCase() !== pan[4]) {
      out.push({
        ok: false,
        severity: 'high',
        title: `PAN 5th letter "${pan[4]}" does not match surname "${surname}"`,
        detail: 'For an individual PAN, the 5th character is the first letter of the surname. Mismatch can also be OCR error or a name that was changed after issue, so confirm visually.',
        points: 25,
      })
    }
  }
  if (/^0{4}$/.test(pan.slice(5, 9))) out.push({ ok: false, severity: 'high', title: 'PAN serial digits are 0000', detail: 'Sequence 0000 is never issued.', points: 30 })
  void fatherName
  return out
}

/* ---------- Driving licence ---------- */
const STATE_CODES = new Set('AN AP AR AS BR CH CG DD DL DN GA GJ HP HR JH JK KA KL LA LD MH ML MN MP MZ NL OD OR PB PY RJ SK TN TR TS UK UP UA WB'.split(' '))
export function findDl(text: string): string {
  const m = text.toUpperCase().replace(/[|]/g, ' ').match(/\b([A-Z]{2})[\s-]?(\d{2})[\s-]?((?:19|20)\d{2})[\s-]?(\d{7})\b/)
  return m ? `${m[1]}${m[2]}${m[3]}${m[4]}` : ''
}
export function hasDlKeywords(t: string) {
  return /(DRIVING\s*LICEN[CS]E|DRIVING\s*LICENCE|MOTOR\s*VEHICLE|FORM\s*7|DL\s*No)/i.test(t)
}
export function validateDl(dl: string, now = new Date()): IdCheck[] {
  const out: IdCheck[] = []
  const m = dl.match(/^([A-Z]{2})(\d{2})((?:19|20)\d{2})(\d{7})$/)
  if (!m) return [{ ok: false, severity: 'high', title: 'Driving licence number format is invalid', detail: 'Expected SS-RR-YYYY-NNNNNNN (state, RTO code, year, 7-digit serial).', points: 35 }]
  if (!STATE_CODES.has(m[1])) out.push({ ok: false, severity: 'critical', title: `Licence state code "${m[1]}" does not exist`, detail: 'The first two letters must be a valid Indian state / UT code.', points: 45 })
  if (+m[3] > now.getFullYear()) out.push({ ok: false, severity: 'critical', title: `Licence issue year ${m[3]} is in the future`, detail: 'A licence cannot be issued in a future year.', points: 50 })
  if (m[2] === '00') out.push({ ok: false, severity: 'high', title: 'RTO code 00 is not valid', detail: 'RTO numbering starts at 01.', points: 30 })
  return out
}

/* ---------- Voter ID (EPIC) ---------- */
export function findEpic(text: string): string {
  const m = text.toUpperCase().replace(/[|]/g, ' ').match(/\b([A-Z]{3})\s?(\d{7})\b/)
  return m ? m[1] + m[2] : ''
}
export function hasEpicKeywords(t: string) {
  return /(ELECTION\s*COMMISSION|ELECTORS?\s*PHOTO|EPIC\s*No|VOTER)/i.test(t)
}
export function validateEpic(epic: string): IdCheck[] {
  if (!/^[A-Z]{3}\d{7}$/.test(epic)) return [{ ok: false, severity: 'high', title: 'Voter ID (EPIC) format is invalid', detail: 'Expected 3 letters + 7 digits.', points: 35 }]
  if (/^(\d)\1{6}$/.test(epic.slice(3))) return [{ ok: false, severity: 'high', title: 'EPIC serial is a repeated digit', detail: 'Looks like a made-up number.', points: 30 }]
  return []
}

/** Obvious dummy sequences such as 1234567890 / 0000000. */
export function dummyDigits(s: string): boolean {
  const d = s.replace(/\D/g, '')
  if (d.length < 6) return false
  if (/^(\d)\1+$/.test(d)) return true
  let run = 1
  for (let i = 1; i < d.length; i++) {
    run = (+d[i] - +d[i - 1] + 10) % 10 === 1 ? run + 1 : 1
    if (run >= 6) return true
  }
  return false
}
