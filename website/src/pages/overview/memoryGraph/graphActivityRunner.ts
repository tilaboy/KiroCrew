/**
 * Runs the memory graph's live activity on one canvas: the idle breathing and
 * the light a memory read spreads (graphActivity.ts).
 *
 * The point shader does the per-mark work (scripts/cosmos-graph-activity.mjs):
 * each frame this only rewrites three uniforms in place. A read uploads, once,
 * when each lit mark lights and how strongly. Pulses along links and the glow on
 * the view's edge are a few dots on a 2D canvas over the graph.
 *
 * The breathing redraws at `BREATH_FPS`: a ±5% sine over 6 s changes a mark's
 * brightness by under 0.5% between two such frames. A spread redraws every frame
 * until it is dark. Nothing runs under reduced motion or while the tab is hidden,
 * and a read that arrives then is dropped: nobody saw it happen.
 */
import type { Graph as CosmosGraph } from '@cosmos.gl/graph'
import type { GraphBbox, GraphCluster, GraphNodeRow } from '../../../api/client/memory'
import type { Rgb } from './graphColors'
import { linkLevel, toScreen, zoomFromFit, type DrawnLink, type Point, type Size, type View } from './graphView'
import { HitQueue, byCluster, curveAt, flash, lightAt, lightEnd, spread, union, type Light, type Pulse, type Spread } from './graphActivity'

/** One breath, in ms. */
export const BREATH_MS = 6000
/** How far a breath moves a mark's brightness, either way. */
export const BREATH_AMP = 0.05
/** How far apart in phase the middle of the map and its edge breathe. */
export const BREATH_SPREAD = Math.PI
/** Redraws a second while only the breathing moves. */
export const BREATH_FPS = 20
/** How much larger a mark is drawn at full light, and how far it moves toward
 *  white on a dark theme or toward black on a light one, so it stands out on either. */
export const LIT_GROWTH = 0.7
export const LIT_WHITEN = 0.35
export const LIT_DARKEN = 0.3
/** A frame interval past this (ms) means the last draw ran late. */
const LATE_MS = 24
/** The wait between draws after a late one, and the longest it grows to. */
const MIN_SLOW_GAP_MS = 60
const MAX_GAP_MS = 1000
/** A pulse's dot and a hit's edge glow, in CSS px. */
const PULSE_PX = 3.5
const EDGE_PX = 28
/** Hits off screen whose edge points fall this close (CSS px) share one glow. */
const EDGE_MERGE_PX = 80
/** cosmos.gl's `curvedLinkControlPointDistance` the tab draws with. */
export const LINK_BOW = 0.15

/** The uniforms the patched point shader reads each draw (`config.kcActivity`). */
export type ActivityUniforms = { clock: number[]; centre: number[]; light: number[] }

/** The window event useWebSocket raises for each `memory_activity` frame. */
export const MEMORY_ACTIVITY_EVENT = 'mc:memory-activity'

/** A `memory_activity` frame (kiro_crew/memory_graph_activity.py). */
export type ActivityFrame = { store: string; kind: string; ids: string[]; ts: number }

export type RunnerDeps = {
  graph: () => CosmosGraph | null
  shown: () => { mode: 'clusters' | 'nodes'; items: readonly (GraphCluster | GraphNodeRow)[] }
  /** A node by id, loaded but maybe not drawn: in the cluster view, its disc lights. */
  node: (id: string) => GraphNodeRow | undefined
  view: () => View
  size: () => Size
  bounds: () => GraphBbox | undefined
  links: () => readonly DrawnLink[]
  topicLinks: () => readonly DrawnLink[]
  colour: (cluster: number) => Rgb
  accent: () => Rgb
  dark: () => boolean
  /** When the view last moved: cosmos.gl redraws a moving view itself. */
  movedAt: () => number
  overlay: () => HTMLCanvasElement | null
  now?: () => number
}

export class ActivityRunner {
  readonly uniforms: ActivityUniforms = { clock: [0, 0, 0, 0], centre: [0, 0, LIT_GROWTH, 0], light: [0, 0, 0, 0] }
  private readonly queue = new HitQueue()
  private lights = new Map<number, Light>()
  private pulses: Pulse[] = []
  private edges: { at: Point; light: Light; rgb: Rgb }[] = []
  private end = 0
  private frame: number | null = null
  private lastDraw = -Infinity
  private lastTick = -Infinity
  /** Frames still watched for lateness after a draw (cosmos.gl draws on the next
   *  one), and the extra wait between draws a slow GPU earned. */
  private watch = 0
  private slowGap = 0
  private overlayDirty = false
  private on = false
  /** cosmos.gl holds lights this runner uploaded. */
  private uploaded = false
  private items: readonly unknown[] | null = null
  private index = new Map<string, number>()
  private members = new Map<number, number[]>()
  private readonly base: number
  private readonly now: () => number

  constructor(private readonly deps: RunnerDeps) {
    this.now = deps.now ?? (() => performance.now())
    // shortcut: the activation clock is ms since this canvas started, as a float32
    // in the shader, exact for 4.6 hours and then a few ms coarse; rebase it when
    // idle if a tab is ever kept open for weeks.
    this.base = this.now()
  }

  /** Breathe and light reads, or stop both (reduced motion, a hidden tab). */
  setRunning(on: boolean) {
    if (on === this.on) return
    this.on = on
    this.uniforms.clock[2] = on ? BREATH_AMP : 0
    this.uniforms.light[0] = 60
    this.uniforms.light[2] = on ? 620 : 0
    this.uniforms.light[3] = this.deps.dark() ? LIT_WHITEN : -LIT_DARKEN
    if (on) { this.schedule(); return }
    if (this.frame !== null) cancelAnimationFrame(this.frame)
    this.frame = null
    this.queue.clear()
    this.clearLights()
    const g = this.deps.graph()
    if (g) draw(g)
  }

  get running() { return this.on }

  /** A read the gateway reported, for the store this canvas draws. */
  push(frame: ActivityFrame) {
    if (!this.on || !Array.isArray(frame.ids)) return
    this.queue.push(frame.ids.filter(i => typeof i === 'string'), frame.kind, this.now())
    this.schedule()
  }

  /** The drawn set changed: indices no longer name the same marks. */
  reset() {
    this.items = null
    this.clearLights()
  }

  dispose() {
    if (this.frame !== null) cancelAnimationFrame(this.frame)
    this.frame = null
    this.on = false
  }

  private clearLights() {
    this.lights.clear(); this.pulses = []; this.edges = []; this.end = 0
    if (this.uploaded) this.upload(this.deps.shown().items.length)
    this.overlayDirty = true
    this.drawOverlay(this.now())
  }

  private schedule() {
    if (this.frame === null && this.on) this.frame = requestAnimationFrame(() => { this.frame = null; this.tick() })
  }

  private indexed() {
    const shown = this.deps.shown()
    if (this.items !== shown.items) {
      this.items = shown.items
      this.index = new Map()
      if (shown.mode === 'nodes') {
        shown.items.forEach((n, i) => this.index.set((n as GraphNodeRow).id, i))
        this.members = byCluster(shown.items as GraphNodeRow[])
      } else {
        this.members = new Map()
      }
    }
    return shown
  }

  /** Light the hits allowed now; true when something was lit. */
  private lightHits(now: number): boolean {
    const hits = this.queue.take(now)
    if (!hits.length) return false
    const shown = this.indexed()
    const view = this.deps.view(), size = this.deps.size()
    const level = linkLevel(zoomFromFit(view, size, this.deps.bounds()))
    const spreads: Spread[] = []
    for (const { id, kind } of hits) {
      if (shown.mode === 'clusters') {
        // A store too large to draw whole shows topics here: the hit's disc lights.
        const node = this.deps.node(id)
        const disc = node ? shown.items.findIndex(c => (c as GraphCluster).id === node.cluster) : -1
        if (disc >= 0) spreads.push(flash(disc, now))
        continue
      }
      const hit = this.index.get(id)
      if (hit === undefined) continue
      spreads.push(kind === 'recall'
        ? spread({ hit, now, level, items: shown.items as GraphNodeRow[], members: this.members, links: this.deps.links(), topicLinks: this.deps.topicLinks(), view, size })
        : flash(hit, now))
      const s = spreads[spreads.length - 1]
      const edge = s.edge
      if (edge) {
        const near = this.edges.find(e => Math.hypot(e.at.x - edge.x, e.at.y - edge.y) < EDGE_MERGE_PX)
        if (near) near.light = union(near.light, s.lights.get(hit)!)
        else this.edges.push({ at: edge, light: s.lights.get(hit)!, rgb: this.deps.accent() })
      }
    }
    if (!spreads.length) return false
    // Lights still on are kept: a mark two reads lit stays lit through both.
    for (const [i, l] of this.lights) if (lightEnd(l) <= now) this.lights.delete(i)
    for (const s of spreads) {
      for (const [i, l] of s.lights) { const had = this.lights.get(i); this.lights.set(i, had ? union(had, l) : l) }
      this.pulses.push(...s.pulses)
      this.end = Math.max(this.end, s.end)
    }
    this.upload(shown.items.length)
    return true
  }

  /** Hand cosmos.gl when each lit mark lit and how strongly, in the image channels. */
  private upload(n: number) {
    const g = this.deps.graph()
    if (!g) return
    const at = new Float32Array(n).fill(-1), hold = new Float32Array(n)
    for (const [i, l] of this.lights) {
      if (i >= n) continue
      at[i] = Math.max(0, l.at - this.base)
      hold[i] = Math.max(0, l.hold) + Math.min(0.999, Math.max(0.001, l.s))
    }
    g.setPointImageIndices(at)
    g.setPointImageSizes(hold)
    g.render(0, 0)
    this.uploaded = this.lights.size > 0
  }

  private tick() {
    if (!this.on) return
    const now = this.now(), t = now - this.base
    const lit = this.lightHits(now)
    const bounds = this.deps.bounds()
    if (bounds) {
      const cx = (bounds[0] + bounds[2]) / 2, cy = (bounds[1] + bounds[3]) / 2
      const r = Math.max(1e-9, Math.max(bounds[2] - bounds[0], bounds[3] - bounds[1]) / 2)
      this.uniforms.centre[0] = cx; this.uniforms.centre[1] = cy
      this.uniforms.clock[3] = BREATH_SPREAD / r
    }
    this.uniforms.clock[0] = t
    this.uniforms.light[3] = this.deps.dark() ? LIT_WHITEN : -LIT_DARKEN
    this.uniforms.clock[1] = (2 * Math.PI * t) / BREATH_MS
    const active = lit || now < this.end
    const g = this.deps.graph()
    // A moving view is redrawn by cosmos.gl, with these uniforms, every frame.
    const moving = now - this.deps.movedAt() < 150
    // A frame that came late right after a draw means the GPU could not keep up:
    // wait longer between draws, and shorten the wait again while frames come on
    // time. A slow GPU then draws the breathing and a spread less often, and the
    // page keeps its frame rate.
    const behind = now - this.lastTick > LATE_MS
    this.lastTick = now
    if (this.watch > 0) {
      if (behind) { this.slowGap = Math.min(MAX_GAP_MS, Math.max(MIN_SLOW_GAP_MS, this.slowGap * 2)); this.watch = 0 }
      else if (--this.watch === 0) this.slowGap = this.slowGap * 0.7 < MIN_SLOW_GAP_MS / 2 ? 0 : this.slowGap * 0.7
    }
    const gap = Math.max(active ? 0 : 1000 / BREATH_FPS, this.slowGap)
    if (g && !moving && !behind && (this.watch === 0 || this.slowGap === 0) && now - this.lastDraw >= gap) {
      this.lastDraw = now
      this.watch = 2
      draw(g)
    }
    if (this.pulses.length || this.edges.length || this.overlayDirty) this.drawOverlay(now)
    if (!active && this.lights.size) this.lights.clear()
    this.schedule()
  }

  /** Pulses along their links and the glow toward off-screen hits. */
  private drawOverlay(now: number) {
    const canvas = this.deps.overlay()
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return
    const size = this.deps.size(), dpr = window.devicePixelRatio || 1
    if (canvas.width !== Math.round(size.width * dpr) || canvas.height !== Math.round(size.height * dpr)) {
      canvas.width = Math.round(size.width * dpr); canvas.height = Math.round(size.height * dpr)
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, size.width, size.height)
    this.pulses = this.pulses.filter(p => now < p.t1 + 120)
    this.edges = this.edges.filter(e => now < lightEnd(e.light))
    this.overlayDirty = this.pulses.length > 0 || this.edges.length > 0
    const view = this.deps.view()
    for (const p of this.pulses) {
      if (now < p.t0) continue
      const f = Math.min(1, (now - p.t0) / Math.max(1, p.t1 - p.t0))
      // A dot with a short tail, travelling the same curve cosmos.gl draws the link on.
      for (const [back, alpha] of [[0, 1], [0.08, 0.5], [0.16, 0.25]] as const) {
        const u = Math.max(0, f - back), along = p.reverse ? 1 - u : u
        const at = toScreen(view, size, curveAt(p.a, p.b, along, LINK_BOW))
        const fade = now > p.t1 ? 1 - (now - p.t1) / 120 : 1
        dot(ctx, at, PULSE_PX * (1 - back * 2), this.deps.colour(p.cluster), alpha * fade * (0.4 + 0.6 * p.s))
      }
    }
    for (const e of this.edges) dot(ctx, e.at, EDGE_PX, e.rgb, 0.3 * lightAt(e.light, now))
  }
}

/**
 * One more frame through cosmos.gl's own loop. Its loop collects a picking or
 * hover read behind a fence on a later frame; `renderOneFrame` collects it at
 * once and stalls the page until the GPU catches up (150 ms frames on the
 * 23,000-memory store in software WebGL). `requestRender` is not in cosmos.gl's
 * types; the pinned version has it (dist/index.js `requestRender()`).
 */
function draw(g: CosmosGraph) {
  const own = (g as unknown as { requestRender?: () => void }).requestRender
  if (own) own.call(g); else g.renderOneFrame()
}

/** A soft round glow of `px` radius. */
function dot(ctx: CanvasRenderingContext2D, at: Point, px: number, [r, g, b]: Rgb, alpha: number) {
  if (alpha <= 0.01) return
  const c = `${Math.round(r * 255)},${Math.round(g * 255)},${Math.round(b * 255)}`
  const grad = ctx.createRadialGradient(at.x, at.y, 0, at.x, at.y, px * 2)
  grad.addColorStop(0, `rgba(${c},${alpha})`)
  grad.addColorStop(0.4, `rgba(${c},${alpha * 0.6})`)
  grad.addColorStop(1, `rgba(${c},0)`)
  ctx.fillStyle = grad
  ctx.fillRect(at.x - px * 2, at.y - px * 2, px * 4, px * 4)
}
