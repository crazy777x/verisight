/* ============================================================
 * QR PATTERN DETECTOR (no decoding)
 * Tells apart "no QR at all" from "a QR-shaped picture is printed but it cannot
 * be decoded" (typical of AI-generated / hand-made fake cards: the QR looks real
 * but contains no valid data). Looks for the three QR finder squares, which have
 * a 1:1:3:1:1 dark/light run ratio along any line through their centre.
 * ============================================================ */

export type QrPattern = {
  present: boolean
  finders: number
  /** bounding box of the suspected QR, normalised 0..1 on the page it was found */
  box: { x: number; y: number; w: number; h: number } | null
  page: number
}

type Finder = { x: number; y: number; m: number }

function rotated(src: HTMLCanvasElement, deg: number): HTMLCanvasElement {
  if (!deg) return src
  const rad = (deg * Math.PI) / 180
  const w = src.width
  const h = src.height
  const nw = Math.ceil(Math.abs(w * Math.cos(rad)) + Math.abs(h * Math.sin(rad)))
  const nh = Math.ceil(Math.abs(w * Math.sin(rad)) + Math.abs(h * Math.cos(rad)))
  const c = document.createElement('canvas')
  c.width = nw
  c.height = nh
  const ctx = c.getContext('2d')!
  ctx.fillStyle = '#fff'
  ctx.fillRect(0, 0, nw, nh)
  ctx.translate(nw / 2, nh / 2)
  ctx.rotate(rad)
  ctx.drawImage(src, -w / 2, -h / 2)
  return c
}

function binarise(c: HTMLCanvasElement, maxW: number) {
  const s = Math.min(1.5, maxW / c.width)
  const W = Math.round(c.width * s)
  const H = Math.round(c.height * s)
  const t = document.createElement('canvas')
  t.width = W
  t.height = H
  const ctx = t.getContext('2d', { willReadFrequently: true })!
  ctx.fillStyle = '#fff'
  ctx.fillRect(0, 0, W, H)
  ctx.drawImage(c, 0, 0, W, H)
  const d = ctx.getImageData(0, 0, W, H).data
  const g = new Uint8Array(W * H)
  const hist = new Array(256).fill(0)
  for (let i = 0; i < W * H; i++) {
    g[i] = (d[i * 4] * 299 + d[i * 4 + 1] * 587 + d[i * 4 + 2] * 114) / 1000
    hist[g[i]]++
  }
  // local-ish threshold: Otsu on the whole image (cards are mostly uniformly lit)
  const n = W * H
  let sum = 0
  for (let v = 0; v < 256; v++) sum += v * hist[v]
  let sumB = 0
  let wB = 0
  let best = 0
  let thr = 128
  for (let v = 0; v < 256; v++) {
    wB += hist[v]
    if (!wB) continue
    const wF = n - wB
    if (!wF) break
    sumB += v * hist[v]
    const between = wB * wF * (sumB / wB - (sum - sumB) / wF) ** 2
    if (between > best) { best = between; thr = v }
  }
  const bin = new Uint8Array(n) // 1 = dark
  for (let i = 0; i < n; i++) bin[i] = g[i] <= thr ? 1 : 0
  return { bin, W, H, scale: s }
}

function ratioOk(runs: number[]) {
  const total = runs[0] + runs[1] + runs[2] + runs[3] + runs[4]
  if (total < 7) return 0
  const m = total / 7
  const tol = m * 0.75
  if (Math.abs(runs[0] - m) > tol || Math.abs(runs[1] - m) > tol || Math.abs(runs[3] - m) > tol || Math.abs(runs[4] - m) > tol) return 0
  if (Math.abs(runs[2] - 3 * m) > 3 * m * 0.7) return 0
  return m
}


/** A finder square is 1:1:3:1:1 vertically too. Rules out text strokes, table lines, barcodes. */
function verticalOk(bin: Uint8Array, W: number, H: number, cx: number, cy: number, m: number): boolean {
  const x = Math.round(cx)
  let y = Math.round(cy)
  if (x < 0 || x >= W || y < 0 || y >= H) return false
  const at = (yy: number) => bin[yy * W + x]
  if (at(y) !== 1) {
    // nudge to the nearest dark pixel of the centre block
    let ok = false
    for (let d = 1; d <= Math.ceil(m); d++) {
      if (y - d >= 0 && at(y - d) === 1) { y -= d; ok = true; break }
      if (y + d < H && at(y + d) === 1) { y += d; ok = true; break }
    }
    if (!ok) return false
  }
  const run = (from: number, dir: number, colour: number) => {
    let n = 0
    let yy = from
    while (yy >= 0 && yy < H && at(yy) === colour) { n++; yy += dir }
    return { n, next: yy }
  }
  const up0 = run(y, -1, 1)
  const dn0 = run(y + 1, 1, 1)
  const centre = up0.n + dn0.n
  const upL = run(up0.next, -1, 0)
  const upD = run(up0.next - upL.n, -1, 1)
  const dnL = run(dn0.next, 1, 0)
  const dnD = run(dn0.next + dnL.n, 1, 1)
  const tolM = m * 0.8
  return (
    Math.abs(centre - 3 * m) <= 3 * m * 0.6 &&
    Math.abs(upL.n - m) <= tolM && Math.abs(dnL.n - m) <= tolM &&
    Math.abs(upD.n - m) <= tolM && Math.abs(dnD.n - m) <= tolM
  )
}

function findFinders(bin: Uint8Array, W: number, H: number): Finder[] {
  type Hit = { x: number; y: number; m: number }
  const hits: Hit[] = []
  for (let y = 0; y < H; y++) {
    const runs: number[] = []
    const starts: number[] = []
    const cols: number[] = []
    let cur = bin[y * W]
    let len = 1
    let st = 0
    for (let x = 1; x <= W; x++) {
      const v = x < W ? bin[y * W + x] : cur ^ 1
      if (v === cur) { len++; continue }
      runs.push(len)
      starts.push(st)
      cols.push(cur)
      if (runs.length >= 5) {
        const k = runs.length - 5
        if (cols[k] === 1) {
          const five = runs.slice(k, k + 5)
          const m = ratioOk(five)
          if (m) hits.push({ x: starts[k] + (five[0] + five[1] + five[2] + five[3] + five[4]) / 2, y, m })
        }
      }
      cur = v
      st = x
      len = 1
    }
  }
  // cluster hits that stack vertically at the same x
  hits.sort((a, b) => a.x - b.x || a.y - b.y)
  const used = new Array(hits.length).fill(false)
  const out: Finder[] = []
  for (let i = 0; i < hits.length; i++) {
    if (used[i]) continue
    const grp = [hits[i]]
    used[i] = true
    for (let j = i + 1; j < hits.length; j++) {
      if (used[j]) continue
      const g0 = grp[grp.length - 1]
      const m = g0.m
      if (Math.abs(hits[j].x - g0.x) <= m * 1.2 && hits[j].y - g0.y <= 2.5 && hits[j].y >= g0.y && Math.abs(hits[j].m - m) < m * 0.5) {
        grp.push(hits[j])
        used[j] = true
      }
    }
    const mAvg = grp.reduce((s, h) => s + h.m, 0) / grp.length
    const extent = grp[grp.length - 1].y - grp[0].y + 1
    // centre block of a finder is ~3 modules tall; a modest span also rules out long strokes
    if (mAvg >= 2 && grp.length >= 3 && extent >= mAvg * 1.6 && extent <= mAvg * 4.6) {
      const f = { x: grp.reduce((s, h) => s + h.x, 0) / grp.length, y: (grp[0].y + grp[grp.length - 1].y) / 2, m: mAvg }
      if (verticalOk(bin, W, H, f.x, f.y, f.m)) out.push(f)
    }
  }
  return out
}

function best(finders: Finder[]): Finder[] {
  // three finders at the corners of a right isosceles triangle (any rotation) = a QR code
  const n = finders.length
  for (let i = 0; i < n; i++)
    for (let j = i + 1; j < n; j++)
      for (let k = j + 1; k < n; k++) {
        const t = [finders[i], finders[j], finders[k]]
        const ms = t.map((q) => q.m)
        if (Math.max(...ms) / Math.min(...ms) > 1.6) continue
        const d = (p: Finder, q: Finder) => Math.hypot(p.x - q.x, p.y - q.y)
        const sides = [d(t[0], t[1]), d(t[1], t[2]), d(t[0], t[2])].sort((x, y) => x - y)
        const mAvg = ms.reduce((a, c) => a + c, 0) / 3
        if (sides[0] / mAvg < 6 || sides[2] / mAvg > 190) continue
        if (sides[1] / sides[0] > 1.3) continue // two short legs of similar length
        const hyp = Math.hypot(sides[0], sides[1])
        if (Math.abs(hyp - sides[2]) / sides[2] > 0.18) continue // right angle
        return t
      }
  // two finders can still be accepted when one corner is hidden by glare / crop: they must align with the pixel grid
  for (let i = 0; i < n; i++)
    for (let j = i + 1; j < n; j++) {
      const a = finders[i]
      const b = finders[j]
      const r = a.m / b.m
      if (r < 0.7 || r > 1.4) continue
      const dist = Math.hypot(a.x - b.x, a.y - b.y) / a.m
      const aligned = Math.abs(a.y - b.y) < a.m * 0.6 || Math.abs(a.x - b.x) < a.m * 0.6
      if (aligned && dist >= 8 && dist <= 160) return [a, b]
    }
  return []
}

export function detectQrPattern(pages: HTMLCanvasElement[]): QrPattern {
  const none: QrPattern = { present: false, finders: 0, box: null, page: 0 }
  for (let p = 0; p < Math.min(2, pages.length); p++) {
    for (const deg of [0, -14, 14, -21, 21, -28, 28, -35, 35]) {
      try {
        const rc = rotated(pages[p], deg)
        const { bin, W, H, scale } = binarise(rc, 1100)
        const f = best(findFinders(bin, W, H))
        if (f.length >= 2) {
          if (deg !== 0) return { present: true, finders: f.length, box: null, page: p }
          const xs = f.map((q) => q.x)
          const ys = f.map((q) => q.y)
          const mm = Math.max(...f.map((q) => q.m))
          const x0 = Math.min(...xs) - 3.5 * mm
          const y0 = Math.min(...ys) - 3.5 * mm
          const x1 = Math.max(...xs) + 3.5 * mm
          const y1 = Math.max(...ys) + 3.5 * mm
          void scale
          return { present: true, finders: f.length, box: { x: Math.max(0, x0 / W), y: Math.max(0, y0 / H), w: Math.min(1, (x1 - x0) / W), h: Math.min(1, (y1 - y0) / H) }, page: p }
        }
      } catch {
        /* try next angle */
      }
    }
  }
  return none
}
