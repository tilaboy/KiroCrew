/**
 * What a memory read lights on the graph, and when: pure helpers.
 * graphActivityRunner.ts owns the clock, the canvas and the uploads.
 *
 * A read the gateway reports (`memory_activity`, kiro_crew/memory_graph_activity.py)
 * makes each recalled memory "fire". How the light spreads depends on what the
 * view shows at its zoom (graphView `linkLevel`):
 * - `topics`: a wave runs out from the hit through its own topic's disc, each
 *   mark lighting as the front passes it; nothing crosses into another topic;
 * - `within`: the same wave, then a faint pulse along the topic links
 *   (`topicLinks`) to the neighbouring topics, which glow faintly;
 * - `near`: from mark to mark along the drawn links, as far as `REACH_SHARE` of
 *   the view's short side, dimmer the farther it is on screen from the hit.
 * Everything one hit lights fades out together, so a spread takes `TOTAL_MS` at
 * every level. A mark two pulses reach lights once, at the stronger value.
 */
import type { DrawnLink, LinkLevel, Point, Size, View } from './graphView'
import { toScreen } from './graphView'

/** A lit mark rises over this long. */
export const RISE_MS = 60
/** The wave reaches the far edge of its disc (or the reach) this long after the hit. */
export const WAVE_MS = 680
/** Everything lit then holds this long, */
export const HOLD_MS = 100
/** and eases back over this long. */
export const FADE_MS = 620
/** A spread from hit to dark, the same at every level. */
export const TOTAL_MS = WAVE_MS + RISE_MS + HOLD_MS + FADE_MS
/** How far a `near` spread reaches, as a share of the view's short side. */
export const REACH_SHARE = 1 / 3
/** A mark's strength at the edge of the reach; the hit is 1. */
export const EDGE_STRENGTH = 0.35
/** How strongly a neighbouring topic glows at the `within` level. */
export const FAINT = 0.25
/** The share of the wave a pulse to a neighbouring topic takes to arrive. */
export const NEIGHBOUR_TRAVEL = 0.7

/** When a read lit a mark (ms), how long it holds after rising, and how strongly (0 to 1). */
export type Light = { at: number; hold: number; s: number }
/** A pulse along a drawn link (`a` to `b` as drawn), running `from` one end from `t0` to `t1`. */
export type Pulse = { a: Point; b: Point; reverse: boolean; t0: number; t1: number; s: number; cluster: number }
/** What one hit lights: marks by index, pulses along links, and where on the
 *  view's edge to glow when the hit is off screen. */
export type Spread = { lights: Map<number, Light>; pulses: Pulse[]; edge: Point | null; end: number }

/** How bright a light is at `now`: rises, holds, then eases back, as the
 *  point shader draws it (scripts/cosmos-graph-activity.mjs). */
export function lightAt(l: Light, now: number): number {
  const dt = now - l.at
  if (dt < 0 || l.s <= 0) return 0
  if (dt < RISE_MS) return l.s * (dt / RISE_MS)
  if (dt < RISE_MS + l.hold) return l.s
  const f = Math.min(1, (dt - RISE_MS - l.hold) / FADE_MS)
  return l.s * (1 - f * f * (3 - 2 * f))
}

/** When a light is out. */
export const lightEnd = (l: Light) => l.at + RISE_MS + l.hold + FADE_MS

/** One light for a mark two reads lit: from the earlier start to the later
 *  hold's end, at the stronger value, so a lit mark never dips between them. */
export function union(a: Light, b: Light): Light {
  const at = Math.min(a.at, b.at)
  const until = Math.max(a.at + a.hold, b.at + b.hold)
  return { at, hold: until - at, s: Math.max(a.s, b.s) }
}

/** The farthest a `near` spread reaches in `size`'s view, in screen px. */
export const reachPx = (size: Size) => REACH_SHARE * Math.min(size.width, size.height)

/** A mark's strength `d` screen px from the hit. */
export const strengthAt = (d: number, reach: number) => 1 - (1 - EDGE_STRENGTH) * Math.min(1, d / reach)

/** Where the line from the view's centre toward an off-screen `p` (screen px)
 *  meets the view's edge; null when `p` is on screen. */
export function edgePoint(p: Point, size: Size): Point | null {
  const { width: w, height: h } = size
  if (p.x >= 0 && p.y >= 0 && p.x <= w && p.y <= h) return null
  const cx = w / 2, cy = h / 2, dx = p.x - cx, dy = p.y - cy
  const t = Math.min(dx ? Math.abs(cx / dx) : Infinity, dy ? Math.abs(cy / dy) : Infinity)
  return { x: cx + dx * t, y: cy + dy * t }
}

/** Each topic's mark indices. */
export function byCluster(items: readonly { cluster: number }[]): Map<number, number[]> {
  const out = new Map<number, number[]>()
  items.forEach((p, i) => { const m = out.get(p.cluster); if (m) m.push(i); else out.set(p.cluster, [i]) })
  return out
}

export type SpreadInput = {
  /** The hit's index in `items`. */
  hit: number
  now: number
  level: LinkLevel
  items: readonly { x: number; y: number; cluster: number }[]
  /** Each topic's mark indices (`byCluster(items)`). */
  members: Map<number, number[]>
  /** The memory links drawn now, which a `near` spread travels. */
  links: readonly DrawnLink[]
  /** The links between neighbouring topics, which a `within` pulse travels. */
  topicLinks: readonly DrawnLink[]
  view: View
  size: Size
}

function keep(lights: Map<number, Light>, i: number, light: Light) {
  const had = lights.get(i)
  lights.set(i, had ? union(had, light) : light)
}

/** A light from `t` that holds until `until` and then fades. */
const lightFrom = (t: number, until: number, s: number): Light => ({ at: Math.round(t), hold: Math.max(0, Math.round(until - t)), s })

/** The wave from layout point `from` through topic `cluster`: each mark lights
 *  when the front passes it, the farthest `waveMs` after `t0`. */
function wave(input: SpreadInput, lights: Map<number, Light>, cluster: number, from: Point, t0: number, waveMs: number, scale: number, until: number) {
  const { items, view, size } = input
  const members = input.members.get(cluster) ?? []
  const origin = toScreen(view, size, from), reach = reachPx(size)
  let far = 0
  for (const i of members) far = Math.max(far, Math.hypot(items[i].x - from.x, items[i].y - from.y))
  for (const i of members) {
    const p = items[i], at = toScreen(view, size, p)
    const t = t0 + (far > 0 ? (waveMs * Math.hypot(p.x - from.x, p.y - from.y)) / far : 0)
    keep(lights, i, lightFrom(t, until, scale * strengthAt(Math.hypot(at.x - origin.x, at.y - origin.y), reach)))
  }
}

/** What a recall of mark `input.hit` lights at `input.level`. */
export function spread(input: SpreadInput): Spread {
  const { hit, now, level, items, view, size } = input
  const lights = new Map<number, Light>()
  const pulses: Pulse[] = []
  const until = now + WAVE_MS + HOLD_MS
  const origin = toScreen(view, size, items[hit])
  keep(lights, hit, lightFrom(now, until, 1))
  if (level === 'near') {
    // Out along the drawn links, nearest on screen first, at one speed: the
    // reach is crossed in WAVE_MS and nothing past it lights.
    const reach = reachPx(size), speed = reach / WAVE_MS
    const next = new Map<number, { j: number; px: number; link: DrawnLink }[]>()
    for (const l of input.links) {
      const a = toScreen(view, size, items[l.a]), b = toScreen(view, size, items[l.b])
      const px = Math.hypot(a.x - b.x, a.y - b.y)
      for (const [i, j] of [[l.a, l.b], [l.b, l.a]]) {
        const list = next.get(i)
        if (list) list.push({ j, px, link: l }); else next.set(i, [{ j, px, link: l }])
      }
    }
    const best = new Map<number, number>([[hit, 0]])
    const via = new Map<number, { from: number; link: DrawnLink }>()
    // shortcut: a scan for the nearest open mark; a reach holds a few hundred
    // marks at most. Use a heap if a spread ever covers thousands.
    const open = new Set([hit])
    while (open.size) {
      let u = -1, du = Infinity
      for (const i of open) { const d = best.get(i)!; if (d < du) { du = d; u = i } }
      open.delete(u)
      for (const { j, px, link } of next.get(u) ?? []) {
        const dv = du + px
        if (dv > reach || dv >= (best.get(j) ?? Infinity)) continue
        best.set(j, dv); via.set(j, { from: u, link }); open.add(j)
      }
    }
    for (const [j, d] of best) {
      if (j === hit) continue
      const at = toScreen(view, size, items[j])
      const s = strengthAt(Math.hypot(at.x - origin.x, at.y - origin.y), reach)
      keep(lights, j, lightFrom(now + d / speed, until, s))
      const { from, link } = via.get(j)!
      pulses.push({ a: items[link.a], b: items[link.b], reverse: link.a !== from, t0: now + best.get(from)! / speed, t1: now + d / speed, s, cluster: items[from].cluster })
    }
  } else {
    const own = items[hit].cluster
    wave(input, lights, own, items[hit], now, WAVE_MS, 1, until)
    if (level === 'within') {
      // A faint pulse from this topic's hub to each neighbour's, arriving when the
      // wave is most of the way out; the neighbour then glows faintly from its hub.
      const arrive = now + WAVE_MS * NEIGHBOUR_TRAVEL
      for (const l of input.topicLinks) {
        const mine = items[l.a].cluster === own ? l.a : items[l.b].cluster === own ? l.b : -1
        if (mine < 0) continue
        const theirs = mine === l.a ? l.b : l.a
        pulses.push({ a: items[l.a], b: items[l.b], reverse: mine !== l.a, t0: now, t1: arrive, s: FAINT, cluster: own })
        wave(input, lights, items[theirs].cluster, items[theirs], arrive, WAVE_MS * (1 - NEIGHBOUR_TRAVEL), FAINT, until)
      }
    }
  }
  let end = now
  for (const l of lights.values()) end = Math.max(end, lightEnd(l))
  return { lights, pulses, edge: edgePoint(origin, size), end }
}

/** What a session start lit: the mark flashes once, with no spread. */
export function flash(hit: number, now: number): Spread {
  const light = lightFrom(now, now + HOLD_MS, 1)
  return { lights: new Map([[hit, light]]), pulses: [], edge: null, end: lightEnd(light) }
}

/** cosmos.gl's conic weight for a curved link (`curvedLinkWeight`'s default). */
export const CURVE_WEIGHT = 0.8

/** A point (layout units) on the curve cosmos.gl draws link `a`→`b` along: its
 *  conic, with the control point `bow` of the link's length to the link's left. */
export function curveAt(a: Point, b: Point, t: number, bow: number, w = CURVE_WEIGHT): Point {
  const dx = b.x - a.x, dy = b.y - a.y
  const cx = (a.x + b.x) / 2 - dy * bow, cy = (a.y + b.y) / 2 + dx * bow
  const u = 1 - t, d = u * u + 2 * u * t * w + t * t
  return { x: (u * u * a.x + 2 * u * t * w * cx + t * t * b.x) / d, y: (u * u * a.y + 2 * u * t * w * cy + t * t * b.y) / d }
}

/**
 * Hits waiting to light, at most `rate` a second: a burst lights its first
 * `rate` at once and the rest as the budget comes back. Past `cap` waiting the
 * oldest are dropped, so a flood never queues work for later.
 */
export class HitQueue {
  private waiting: { id: string; kind: string }[] = []
  private tokens: number
  private last: number | null = null
  constructor(readonly rate = 20, readonly cap = 20) { this.tokens = rate }
  private refill(now: number) {
    if (this.last !== null) this.tokens = Math.min(this.rate, this.tokens + ((now - this.last) / 1000) * this.rate)
    this.last = now
  }
  push(ids: readonly string[], kind: string, now: number) {
    this.refill(now)
    for (const id of ids) {
      if (this.waiting.some(w => w.id === id)) continue
      this.waiting.push({ id, kind })
      if (this.waiting.length > this.cap) this.waiting.shift()
    }
  }
  /** The hits that may light now. */
  take(now: number): { id: string; kind: string }[] {
    this.refill(now)
    const n = Math.min(Math.floor(this.tokens), this.waiting.length)
    this.tokens -= n
    return this.waiting.splice(0, n)
  }
  get size() { return this.waiting.length }
  clear() { this.waiting = [] }
}
