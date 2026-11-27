import { describe, expect, it } from 'vitest'
import {
  EDGE_STRENGTH, FAINT, HitQueue, NEIGHBOUR_TRAVEL, TOTAL_MS, WAVE_MS, byCluster, curveAt, edgePoint, flash,
  lightAt, lightEnd, reachPx, spread, strengthAt, union, type SpreadInput,
} from '../pages/overview/memoryGraph/graphActivity'
import type { DrawnLink } from '../pages/overview/memoryGraph/graphView'

// Topic 0 is a row of four memories, topic 1 two more to its right. At k = 10 a
// layout unit is 10 px, and the 600 x 300 view reaches 100 px (10 units).
const items = [
  { x: 0, y: 0, cluster: 0 }, { x: 1, y: 0, cluster: 0 }, { x: 2, y: 0, cluster: 0 }, { x: 3, y: 0, cluster: 0 },
  { x: 10, y: 0, cluster: 1 }, { x: 11, y: 0, cluster: 1 },
]
const link = (a: number, b: number, hub = false): DrawnLink => ({ a, b, sim: 0.8, cluster: items[a].cluster, hub })
const base = (over: Partial<SpreadInput> = {}): SpreadInput => ({
  hit: 0, now: 1000, level: 'topics', items, members: byCluster(items),
  links: [link(0, 1), link(1, 2), link(2, 3), link(3, 5)], topicLinks: [link(3, 4, true)],
  view: { cx: 0, cy: 0, k: 10 }, size: { width: 600, height: 300 }, ...over,
})

describe('spreading a recall over the graph', () => {
  it('at the farthest zoom lights only the hit topic, as a wave reaching its far edge in WAVE_MS', () => {
    const s = spread(base({ level: 'topics' }))
    expect([...s.lights.keys()].sort()).toEqual([0, 1, 2, 3])
    expect(s.pulses).toEqual([])
    expect(s.lights.get(0)!.at).toBe(1000)
    expect(s.lights.get(1)!.at).toBe(1000 + Math.round(WAVE_MS / 3))
    expect(s.lights.get(3)!.at).toBe(1000 + WAVE_MS)
    // The whole disc fades together.
    expect(new Set([...s.lights.values()].map(lightEnd)).size).toBe(1)
  })

  it('in the middle zoom lights the whole topic, then a faint pulse reaches the neighbouring topic', () => {
    const s = spread(base({ level: 'within' }))
    for (const i of [0, 1, 2, 3]) expect(s.lights.get(i)!.s).toBeGreaterThan(FAINT)
    for (const i of [4, 5]) {
      expect(s.lights.get(i)!.s).toBeLessThanOrEqual(FAINT)
      expect(s.lights.get(i)!.at).toBeGreaterThanOrEqual(1000 + WAVE_MS * NEIGHBOUR_TRAVEL)
    }
    expect(s.pulses).toHaveLength(1)
    expect(s.pulses[0]).toMatchObject({ s: FAINT, cluster: 0, t1: 1000 + WAVE_MS * NEIGHBOUR_TRAVEL })
  })

  it('close in travels mark to mark along drawn links and stops at the screen reach', () => {
    const s = spread(base({ level: 'near' }))
    // 0 -> 3 is 30 px; 3 -> 5 is another 80 px, past the 100 px reach.
    expect(reachPx(base().size)).toBe(100)
    expect([...s.lights.keys()].sort()).toEqual([0, 1, 2, 3])
    expect(s.lights.get(3)!.s).toBeCloseTo(strengthAt(30, 100))
    expect(s.lights.get(1)!.s).toBeGreaterThan(s.lights.get(3)!.s)
    // Arrival time is screen distance at one speed: the reach in WAVE_MS.
    expect(s.lights.get(3)!.at).toBe(1000 + Math.round((30 / 100) * WAVE_MS))
    expect(s.pulses.map(p => [p.t0, p.t1])).toHaveLength(3)
    // A wider view reaches farther in layout units: the same links now carry it to 5.
    const wide = spread(base({ level: 'near', size: { width: 1200, height: 600 } }))
    expect(wide.lights.has(5)).toBe(true)
  })

  it('takes the same time end to end at every zoom', () => {
    for (const level of ['topics', 'within', 'near'] as const) expect(spread(base({ level })).end - 1000).toBe(TOTAL_MS)
    expect(TOTAL_MS).toBeGreaterThanOrEqual(1200)
    expect(TOTAL_MS).toBeLessThanOrEqual(1500)
  })

  it('lights a mark reached twice once, at the stronger value, and never dims it between', () => {
    const a = { at: 100, hold: 300, s: 0.4 }, b = { at: 200, hold: 300, s: 0.9 }
    expect(union(a, b)).toEqual({ at: 100, hold: 400, s: 0.9 })
    // Two links into mark 3: it keeps its one strongest light.
    const s = spread(base({ level: 'near', links: [link(0, 3), link(0, 1), link(1, 3)] }))
    expect(s.lights.get(3)!.s).toBeCloseTo(strengthAt(30, 100))
  })

  it('glows on the view edge toward a hit off screen', () => {
    const s = spread(base({ view: { cx: -100, cy: 0, k: 10 } }))
    expect(s.edge).toEqual({ x: 600, y: 150 })
    expect(spread(base()).edge).toBeNull()
    expect(edgePoint({ x: 300, y: -500 }, { width: 600, height: 300 })).toEqual({ x: 300, y: 0 })
  })

  it('rises, holds and eases back, and is dark once over', () => {
    const l = { at: 0, hold: 200, s: 0.8 }
    expect(lightAt(l, -1)).toBe(0)
    expect(lightAt(l, 30)).toBeCloseTo(0.4)
    expect(lightAt(l, 150)).toBe(0.8)
    expect(lightAt(l, lightEnd(l))).toBeCloseTo(0)
    expect(flash(2, 0).lights.get(2)!.s).toBe(1)
    expect(strengthAt(100, 100)).toBeCloseTo(EDGE_STRENGTH)
  })

  it('follows the bow cosmos.gl draws a link with', () => {
    const a = { x: 0, y: 0 }, b = { x: 10, y: 0 }
    expect(curveAt(a, b, 0, 0.15)).toEqual(a)
    expect(curveAt(a, b, 1, 0.15)).toEqual(b)
    expect(curveAt(a, b, 0.5, 0.15).y).toBeGreaterThan(0)
  })
})

describe('the hit throttle', () => {
  it('lights about 20 hits a second, a burst coalesced, a flood cut to the newest', () => {
    const q = new HitQueue()
    q.push(Array.from({ length: 30 }, (_, i) => `m${i}`), 'recall', 0)
    const first = q.take(0)
    expect(first).toHaveLength(0 + 20)
    // The flood kept its newest 20, so the first 10 were dropped.
    expect(first[0].id).toBe('m10')
    q.push(['a', 'b', 'c', 'a'], 'recall', 0)
    expect(q.take(0)).toHaveLength(0)
    expect(q.take(100).map(h => h.id)).toEqual(['a', 'b'])
    expect(q.take(1000).map(h => h.id)).toEqual(['c'])
  })
})
