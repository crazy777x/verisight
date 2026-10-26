/* ============================================================
 * TAMPER LOCALISATION
 * Finds WHERE a document image was edited (not just "yes/no").
 *   1. ELA (JPEG q=0.90 re-save) compared against local neighbourhood
 *   2. Noise-residual inconsistency (pasted / smoothed / erased areas)
 *   3. Copy-move (cloned patches, consistent shift vector voting)
 *   4. Editor fingerprints in file metadata (Photoshop, Canva, GIMP ...)
 * All coordinates in the report are NORMALISED (0..1) so they can be drawn
 * on any size of the document image.
 * ============================================================ */

export type RegionKind = 'ELA' | 'NOISE' | 'COPY-MOVE'

export type OcrWord = { text: string; x0: number; y0: number; x1: number; y1: number; conf: number } // normalised

export type Region = {
  id: number
  x: number
  y: number
  w: number
  h: number
  score: number // 0..1
  kinds: RegionKind[]
  fields: string[] // printed words that sit inside this region
  note: string
}

export type TamperReport = {
  cols: number
  rows: number
  heat: number[] // cols*rows, 0..1
  regions: Region[]
  copyMoveBlocks: number
  editorTags: string[]
  elaReliable: boolean
  width: number
  height: number
}

export const TUNE = {
  cell: 16, // px per analysis cell (on the 1400px-wide working image)
  elaZ: 4, // robust z-score a cell must exceed globally
  elaLocal: 1.8, // and how many times its neighbourhood median
  elaMin: 0.9, // absolute minimum mean error
  noiseHigh: 2.2, // noise > N x neighbourhood => pasted-in texture
  noiseLow: 0.3, // noise < N x neighbourhood => smoothed / erased
  noiseZ: 4,
  copyVotes: 80, // blocks that must agree on one shift vector (stride 2 => overlapping blocks)
  copyMinVar: 400,
  minCells: 2,
  maxRegions: 8,
}

const EDITORS = [
  'Photoshop', 'Adobe', 'GIMP', 'Canva', 'Picsart', 'PicsArt', 'Snapseed', 'Lightroom', 'Paint.NET', 'PhotoScape',
  'Pixlr', 'Fotor', 'Affinity', 'Illustrator', 'CorelDRAW', 'Inkscape', 'Krita', 'Figma', 'Sketch', 'iLovePDF',
  'Smallpdf', 'Sejda', 'PDFescape', 'Foxit', 'Nitro', 'WPS', 'Microsoft Word', 'LibreOffice',
]

function median(a: number[]) {
  if (!a.length) return 0
  const s = [...a].sort((x, y) => x - y)
  return s[Math.floor(s.length / 2)]
}

/* ---------- metadata ---------- */
export function findEditorTags(bytes: Uint8Array): string[] {
  const head = new TextDecoder('latin1').decode(bytes.slice(0, 200_000))
  const tail = bytes.length > 200_000 ? new TextDecoder('latin1').decode(bytes.slice(-80_000)) : ''
  const txt = head + tail
  const found = new Set<string>()
  for (const e of EDITORS) if (txt.includes(e)) found.add(e)
  return [...found]
}

export function shouldSkipPixelAnalysis(bytes: Uint8Array): boolean {
  const limit = Math.min(bytes.length - 4, 1020)
  for (let i = 0; i <= limit; i++) {
    if (bytes[i] === 0x25 && bytes[i + 1] === 0x50 && bytes[i + 2] === 0x44 && bytes[i + 3] === 0x46 && bytes[i + 4] === 0x2d) return true
  }
  return false
}

/* ---------- copy-move ---------- */
function copyMove(gray: Float32Array, W: number, H: number) {
  const B = 16
  const S = 2 // dense stride: a clone is rarely aligned to our grid
  const buckets = new Map<string, number[]>()
  const bx: number[] = []
  const by: number[] = []
  for (let y = 0; y + B <= H; y += S) {
    for (let x = 0; x + B <= W; x += S) {
      const m = new Float32Array(16)
      let sum = 0
      let sq = 0
      for (let yy = 0; yy < B; yy++) {
        const row = (y + yy) * W + x
        for (let xx = 0; xx < B; xx++) {
          const v = gray[row + xx]
          m[((yy >> 2) << 2) + (xx >> 2)] += v
          sum += v
          sq += v * v
        }
      }
      const mean = sum / (B * B)
      const variance = sq / (B * B) - mean * mean
      if (variance < TUNE.copyMinVar) continue
      let key = ''
      for (let k = 0; k < 16; k++) {
        const q = Math.max(-6, Math.min(6, Math.round((m[k] / 16 - mean) / 16)))
        key += String.fromCharCode(103 + q)
      }
      const idx = bx.length
      bx.push(x)
      by.push(y)
      const b = buckets.get(key)
      if (b) b.push(idx)
      else buckets.set(key, [idx])
    }
  }
  const votes = new Map<string, number[]>() // shift -> block indices
  buckets.forEach((list) => {
    if (list.length < 2 || list.length > 5) return
    for (let i = 0; i < list.length; i++)
      for (let j = i + 1; j < list.length; j++) {
        let a = list[i]
        let b = list[j]
        let dx = bx[b] - bx[a]
        let dy = by[b] - by[a]
        if (dy < 0 || (dy === 0 && dx < 0)) {
          ;[a, b] = [b, a]
          dx = -dx
          dy = -dy
        }
        if (Math.hypot(dx, dy) < 40) continue
        const k = `${Math.round(dx / 4)},${Math.round(dy / 4)}`
        const v = votes.get(k)
        if (v) v.push(a, b)
        else votes.set(k, [a, b])
      }
  })
  const out: { x0: number; y0: number; x1: number; y1: number; n: number }[] = []
  votes.forEach((blocks) => {
    const uniq = [...new Set(blocks)]
    if (uniq.length / 2 < TUNE.copyVotes) return
    const src: number[] = []
    const dst: number[] = []
    for (let i = 0; i < blocks.length; i += 2) {
      src.push(blocks[i])
      dst.push(blocks[i + 1])
    }
    for (const group of [src, dst]) {
      const g = [...new Set(group)]
      out.push({
        x0: Math.min(...g.map((i) => bx[i])),
        y0: Math.min(...g.map((i) => by[i])),
        x1: Math.max(...g.map((i) => bx[i] + B)),
        y1: Math.max(...g.map((i) => by[i] + B)),
        n: g.length,
      })
    }
  })
  return out
}

/* ---------- main ---------- */
export async function analyzeTamper(src: HTMLCanvasElement, bytes: Uint8Array, elaReliable: boolean): Promise<TamperReport> {
  const W = Math.min(1400, src.width)
  const H = Math.max(8, Math.round((src.height * W) / src.width))

  // PDFs are checked through their digital signature, not raster pixel heuristics.
  // Images without EXIF still get analyzed; their findings are marked low-confidence downstream.
  if (shouldSkipPixelAnalysis(bytes)) {
    return {
      cols: 0,
      rows: 0,
      heat: [],
      regions: [],
      copyMoveBlocks: 0,
      editorTags: findEditorTags(bytes),
      elaReliable: false,
      width: W,
      height: H
    };
  }

  const a = document.createElement('canvas')
  a.width = W
  a.height = H
  const actx = a.getContext('2d', { willReadFrequently: true })!
  actx.fillStyle = '#fff'
  actx.fillRect(0, 0, W, H)
  actx.drawImage(src, 0, 0, W, H)

  const blob: Blob = await new Promise((res, rej) => a.toBlob((b) => (b ? res(b) : rej(new Error('toBlob failed'))), 'image/jpeg', 0.9))
  const bmp = await createImageBitmap(blob)
  const b = document.createElement('canvas')
  b.width = W
  b.height = H
  const bctx = b.getContext('2d', { willReadFrequently: true })!
  bctx.drawImage(bmp, 0, 0)
  const d1 = actx.getImageData(0, 0, W, H).data
  const d2 = bctx.getImageData(0, 0, W, H).data

  const gray = new Float32Array(W * H)
  for (let i = 0; i < W * H; i++) gray[i] = 0.299 * d1[i * 4] + 0.587 * d1[i * 4 + 1] + 0.114 * d1[i * 4 + 2]

  const C = TUNE.cell
  const cols = Math.ceil(W / C)
  const rows = Math.ceil(H / C)
  const N = cols * rows
  const errS = new Float64Array(N)
  const edgeS = new Float64Array(N)
  const noiseS = new Float64Array(N)
  const cnt = new Float64Array(N)
  const smoothCnt = new Float64Array(N)

  for (let y = 1; y < H - 1; y++) {
    const cy = Math.floor(y / C)
    for (let x = 1; x < W - 1; x++) {
      const i = y * W + x
      const k = cy * cols + Math.floor(x / C)
      const p = i * 4
      const g = Math.abs(gray[i] - gray[i + 1]) + Math.abs(gray[i] - gray[i + W])
      errS[k] += (Math.abs(d1[p] - d2[p]) + Math.abs(d1[p + 1] - d2[p + 1]) + Math.abs(d1[p + 2] - d2[p + 2])) / 3
      edgeS[k] += g
      cnt[k]++
      if (g < 10) {
        const mean3 = (gray[i - W - 1] + gray[i - W] + gray[i - W + 1] + gray[i - 1] + gray[i] + gray[i + 1] + gray[i + W - 1] + gray[i + W] + gray[i + W + 1]) / 9
        noiseS[k] += Math.min(10, Math.abs(gray[i] - mean3))
        smoothCnt[k]++
      }
    }
  }
  const ela = new Float64Array(N)
  const edge = new Float64Array(N)
  const noise = new Float64Array(N)
  const ratio = new Float64Array(N)
  const content = new Uint8Array(N)
  const smooth = new Uint8Array(N)
  for (let k = 0; k < N; k++) {
    const c = Math.max(1, cnt[k])
    ela[k] = errS[k] / c
    edge[k] = edgeS[k] / c
    ratio[k] = ela[k] / (edge[k] + 6)
    content[k] = cnt[k] >= C * C * 0.4 && edge[k] >= 3 ? 1 : 0
    smooth[k] = smoothCnt[k] >= 60 ? 1 : 0
    noise[k] = smooth[k] ? noiseS[k] / smoothCnt[k] : 0
  }

  const stat = (arr: Float64Array, mask: Uint8Array) => {
    const v: number[] = []
    for (let k = 0; k < N; k++) if (mask[k]) v.push(arr[k])
    const m = median(v)
    return { m, mad: median(v.map((x) => Math.abs(x - m))) * 1.4826 + 0.01 }
  }
  const gE = stat(ratio, content)
  const gN = stat(noise, smooth)

  const nbMedian = (arr: Float64Array, mask: Uint8Array, cx: number, cy: number) => {
    const v: number[] = []
    for (let dy = -2; dy <= 2; dy++)
      for (let dx = -2; dx <= 2; dx++) {
        if (!dx && !dy) continue
        const x = cx + dx
        const y = cy + dy
        if (x < 0 || y < 0 || x >= cols || y >= rows) continue
        const q = y * cols + x
        if (mask[q]) v.push(arr[q])
      }
    return v.length >= 3 ? median(v) : -1
  }

  const hot = new Uint8Array(N)
  const heat = new Array<number>(N).fill(0)
  const kindsAt: Set<RegionKind>[] = Array.from({ length: N }, () => new Set<RegionKind>())
  const elaHot = new Uint8Array(N)
  const noiseHigh = new Float64Array(N)
  for (let cy = 0; cy < rows; cy++)
    for (let cx = 0; cx < cols; cx++) {
      const k = cy * cols + cx
      if (content[k]) {
        const nb = nbMedian(ratio, content, cx, cy)
        const z = (ratio[k] - gE.m) / gE.mad
        if (nb >= 0 && ela[k] > TUNE.elaMin && z > TUNE.elaZ && ratio[k] > TUNE.elaLocal * nb) {
          elaHot[k] = 1
          hot[k] = 1
          kindsAt[k].add('ELA')
          heat[k] = Math.max(heat[k], Math.min(1, z / 14))
        }
      }
      if (smooth[k]) {
        const nb = nbMedian(noise, smooth, cx, cy)
        const z = (noise[k] - gN.m) / gN.mad
        if (nb >= 0 && noise[k] > 0.8 && nb > 0.3 && noise[k] > TUNE.noiseHigh * nb && z > TUNE.noiseZ) {
          noiseHigh[k] = Math.min(1, z / 14)
        } else if (nb > 1.2 && noise[k] < TUNE.noiseLow * nb && -z > TUNE.noiseZ) {
          hot[k] = 1
          kindsAt[k].add('NOISE')
          heat[k] = Math.max(heat[k], Math.min(1, -z / 14))
        }
      }
    }

  for (let cy = 0; cy < rows; cy++)
    for (let cx = 0; cx < cols; cx++) {
      const k = cy * cols + cx
      if (!noiseHigh[k]) continue
      let near = false
      for (let dy = -1; dy <= 1 && !near; dy++)
        for (let dx = -1; dx <= 1; dx++) {
          const x = cx + dx
          const y = cy + dy
          if (x >= 0 && y >= 0 && x < cols && y < rows && elaHot[y * cols + x]) near = true
        }
      if (near) {
        hot[k] = 1
        kindsAt[k].add('NOISE')
        heat[k] = Math.max(heat[k], noiseHigh[k])
      }
    }

  const seen = new Uint8Array(N)
  const regions: Region[] = []
  for (let s = 0; s < N; s++) {
    if (!hot[s] || seen[s]) continue
    const stack = [s]
    seen[s] = 1
    let minX = cols
    let minY = rows
    let maxX = 0
    let maxY = 0
    let n = 0
    let top = 0
    const kinds = new Set<RegionKind>()
    while (stack.length) {
      const k = stack.pop()!
      const cx = k % cols
      const cy = (k / cols) | 0
      n++
      minX = Math.min(minX, cx)
      maxX = Math.max(maxX, cx)
      minY = Math.min(minY, cy)
      maxY = Math.max(maxY, cy)
      top = Math.max(top, heat[k])
      kindsAt[k].forEach((t) => kinds.add(t))
      for (let dy = -1; dy <= 1; dy++)
        for (let dx = -1; dx <= 1; dx++) {
          const x = cx + dx
          const y = cy + dy
          if (x < 0 || y < 0 || x >= cols || y >= rows) continue
          const q = y * cols + x
          if (hot[q] && !seen[q]) {
            seen[q] = 1
            stack.push(q)
          }
        }
    }
    if (n < TUNE.minCells) continue
    const both = kinds.size > 1 ? 0.15 : 0
    regions.push({
      id: 0,
      x: (minX * C) / W,
      y: (minY * C) / H,
      w: Math.min(1, ((maxX - minX + 1) * C) / W),
      h: Math.min(1, ((maxY - minY + 1) * C) / H),
      score: Math.min(1, top + both),
      kinds: [...kinds],
      fields: [],
      note: '',
    })
  }

  const cmScale = Math.min(1, 900 / W)
  let cmBlocks = 0
  if (cmScale < 1) {
    const w2 = Math.round(W * cmScale)
    const h2 = Math.round(H * cmScale)
    const t = document.createElement('canvas')
    t.width = w2
    t.height = h2
    const tctx = t.getContext('2d', { willReadFrequently: true })!
    tctx.drawImage(a, 0, 0, w2, h2)
    const dd = tctx.getImageData(0, 0, w2, h2).data
    const g2 = new Float32Array(w2 * h2)
    for (let i = 0; i < w2 * h2; i++) g2[i] = 0.299 * dd[i * 4] + 0.587 * dd[i * 4 + 1] + 0.114 * dd[i * 4 + 2]
    for (const r of copyMove(g2, w2, h2)) {
      cmBlocks += r.n
      regions.push({ id: 0, x: r.x0 / w2, y: r.y0 / h2, w: (r.x1 - r.x0) / w2, h: (r.y1 - r.y0) / h2, score: Math.min(1, 0.6 + r.n / 120), kinds: ['COPY-MOVE'], fields: [], note: '' })
    }
  } else {
    for (const r of copyMove(gray, W, H)) {
      cmBlocks += r.n
      regions.push({ id: 0, x: r.x0 / W, y: r.y0 / H, w: (r.x1 - r.x0) / W, h: (r.y1 - r.y0) / H, score: Math.min(1, 0.6 + r.n / 120), kinds: ['COPY-MOVE'], fields: [], note: '' })
    }
  }

  const isGraphic = (r: Region) => {
    const x0 = Math.max(1, Math.floor(r.x * W))
    const y0 = Math.max(1, Math.floor(r.y * H))
    const x1 = Math.min(W - 2, Math.ceil((r.x + r.w) * W))
    const y1 = Math.min(H - 2, Math.ceil((r.y + r.h) * H))
    let tot = 0
    let flatSat = 0
    for (let y = y0; y < y1; y += 2)
      for (let x = x0; x < x1; x += 2) {
        const i = y * W + x
        const p = i * 4
        tot++
        const sat = Math.max(d1[p], d1[p + 1], d1[p + 2]) - Math.min(d1[p], d1[p + 1], d1[p + 2])
        if (sat >= 55 && Math.abs(gray[i] - gray[i + 1]) + Math.abs(gray[i] - gray[i + W]) < 8) flatSat++
      }
    return tot > 0 && flatSat / tot >= 0.14
  }
  for (let i = regions.length - 1; i >= 0; i--) if (isGraphic(regions[i])) regions.splice(i, 1)

  regions.sort((p, q) => q.score - p.score)
  const shown = elaReliable ? regions : regions.filter((r) => r.score >= 0.7)
  const top = shown.slice(0, TUNE.maxRegions)
  top.forEach((r, i) => {
    r.id = i + 1
    r.note = r.kinds.includes('COPY-MOVE')
      ? 'Same pixel pattern appears twice: a part of the document was cloned.'
      : r.kinds.length > 1
      ? 'Compression AND noise pattern differ from surroundings: pasted or re-drawn area.'
      : r.kinds[0] === 'ELA'
      ? 'Re-compression level differs from surroundings: edited after the original save.'
      : 'Noise texture differs from surroundings: pasted, smoothed or erased area.'
  })

  return { cols, rows, heat, regions: top, copyMoveBlocks: cmBlocks, editorTags: findEditorTags(bytes), elaReliable, width: W, height: H }
}

export function labelRegions(regions: Region[], words: OcrWord[]) {
  for (const r of regions) {
    const hit = words.filter((w) => {
      const ix = Math.min(r.x + r.w, w.x1) - Math.max(r.x, w.x0)
      const iy = Math.min(r.y + r.h, w.y1) - Math.max(r.y, w.y0)
      if (ix <= 0 || iy <= 0) return false
      const area = (w.x1 - w.x0) * (w.y1 - w.y0)
      return area > 0 && (ix * iy) / area > 0.4
    })
    r.fields = hit.map((w) => w.text).filter((t) => t.trim().length > 0).slice(0, 6)
  }
}