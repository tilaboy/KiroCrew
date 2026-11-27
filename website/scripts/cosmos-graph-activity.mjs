/**
 * Lets the memory graph's point shader breathe and light up recalled memories
 * from a clock, so neither costs the main thread more than a uniform a frame
 * (memoryGraph/graphActivity.ts owns both). cosmos.gl has no per-frame hook in
 * its point shader, so this build-time transform adds one, the way
 * cosmos-rounded-marks.mjs rounds the marks:
 *
 * - three uniforms in the point draw's block, read each draw from
 *   `config.kcActivity` (`{ clock, centre, light }`, arrays the tab rewrites in
 *   place): `kcClock` = (activation clock ms, breath angle, breath amplitude,
 *   breath radians per layout unit), `kcCentre` = (layout centre x, y, size gain
 *   at full light, unused), `kcLight` = (rise ms, unused, fade ms, how far a lit
 *   mark goes toward white, or toward black when negative: a light theme);
 * - breathing: every mark's colour is scaled by `1 + amp * sin(angle - d * k)`,
 *   `d` its distance from the layout centre, so the wave drifts out from the
 *   middle of the spiral; brightness only, no size or place;
 * - activation: the graph never draws images, so a point's image index and image
 *   size, which cosmos.gl documents as ignored for a point without an image, carry
 *   when a read lit it (ms on the activation clock) and its hold in ms plus its
 *   strength (`hold + s`, `s` under 1). A lit mark rises, holds, then eases back.
 *
 * Every rewrite needs its anchor in the shipped text, so a cosmos.gl upgrade that
 * moves one fails the build here instead of drawing a graph that never lights.
 *
 * shortcut: like the rounded marks, the dev server pre-bundles cosmos.gl without
 * this transform, so there the graph neither breathes nor lights its marks (the
 * pulses along links, drawn on their own canvas, still show). Upgrade if a
 * dev-only difference ever matters.
 */

/** Marks a patched module, so a second pass leaves it alone. */
const MARKER = '// kiro-crew: graph activity'

const UNIFORM_TYPES = '          kcClock: "vec4<f32>",\n          kcCentre: "vec4<f32>",\n          kcLight: "vec4<f32>"'
const UNIFORM_DEFAULTS = '          kcClock: [0, 0, 0, 0],\n          kcCentre: [0, 0, 0, 0],\n          kcLight: [0, 0, 0, 0]'
const UNIFORM_READS = '      kcClock: t.kcActivity ? t.kcActivity.clock : [0, 0, 0, 0],\n      kcCentre: t.kcActivity ? t.kcActivity.centre : [0, 0, 0, 0],\n      kcLight: t.kcActivity ? t.kcActivity.light : [0, 0, 0, 0]'

/** Shader body, right after the mark's colour is resolved. */
export const ACTIVITY_GLSL = `
  ${MARKER}
  // Images are never drawn here: the image index is when a read lit the mark and
  // the image size its hold (ms) plus its strength. kcLight.z is 0 until the tab
  // turns this on, so a graph without it draws as cosmos.gl does.
  if (imageIndex >= 0.0 && kcLight.z > 0.0) {
    float kcDt = kcClock.x - imageIndex;
    float kcHold = floor(imageSize);
    float kcS = fract(imageSize);
    float kcA = 0.0;
    if (kcDt >= 0.0 && kcS > 0.0) {
      if (kcDt < kcLight.x) kcA = kcDt / kcLight.x;
      else if (kcDt < kcLight.x + kcHold) kcA = 1.0;
      else kcA = 1.0 - smoothstep(0.0, 1.0, (kcDt - kcLight.x - kcHold) / kcLight.z);
    }
    kcA *= kcS;
    pointColor.rgb = mix(pointColor.rgb, vec3(kcLight.w > 0.0 ? 1.0 : 0.0), abs(kcLight.w) * kcA);
    pointColor.a = max(pointColor.a, kcA);
    pointSize *= 1.0 + kcCentre.z * kcA;
  }
  pointColor.rgb *= 1.0 + kcClock.z * sin(kcClock.y - length(point - kcCentre.xy) * kcClock.w);
`

/** `[anchor, replacement]` for each rewrite, in the order they appear. */
const REWRITES = [
  // The uniform block's layout (std140): appended after its last member.
  ['  float animateStrokeWidths;\n} drawVertex;', '  float animateStrokeWidths;\n  vec4 kcClock;\n  vec4 kcCentre;\n  vec4 kcLight;\n} drawVertex;'],
  ['#define animateStrokeWidths drawVertex.animateStrokeWidths\n', '#define animateStrokeWidths drawVertex.animateStrokeWidths\n#define kcClock drawVertex.kcClock\n#define kcCentre drawVertex.kcCentre\n#define kcLight drawVertex.kcLight\n'],
  ['uniform float animateStrokeWidths;\n', 'uniform float animateStrokeWidths;\nuniform vec4 kcClock;\nuniform vec4 kcCentre;\nuniform vec4 kcLight;\n'],
  ['    : resolveColor(targetColor, exit);\n', '    : resolveColor(targetColor, exit);\n' + ACTIVITY_GLSL],
  // The JS side: the block's types, its defaults, and the values each draw sends.
  ['          animateStrokeWidths: "f32"\n', '          animateStrokeWidths: "f32",\n' + UNIFORM_TYPES + '\n'],
  ['          animateStrokeWidths: 0\n', '          animateStrokeWidths: 0,\n' + UNIFORM_DEFAULTS + '\n'],
  ['      animateStrokeWidths: this.shouldAnimateStrokeWidths ? 1 : 0\n', '      animateStrokeWidths: this.shouldAnimateStrokeWidths ? 1 : 0,\n' + UNIFORM_READS + '\n'],
]

/** The patched module text, or an error when cosmos.gl's code moved. */
export function addGraphActivity(code) {
  if (code.includes(MARKER)) return code
  let out = code
  for (const [anchor, replacement] of REWRITES) {
    if (out.split(anchor).length !== 2) {
      throw new Error(`cosmos-graph-activity: the point shader or its uniforms in @cosmos.gl/graph changed (${JSON.stringify(anchor.trim().slice(0, 40))}); update scripts/cosmos-graph-activity.mjs for the new version.`)
    }
    out = out.replace(anchor, replacement)
  }
  return out
}

/** Vite plugin: rewrite cosmos.gl's bundle at build time. */
export function cosmosGraphActivityPlugin() {
  return {
    name: 'cosmos-graph-activity',
    enforce: 'pre',
    transform(code, id) {
      if (!/[\\/]@cosmos\.gl[\\/]graph[\\/]dist[\\/]index\.js$/.test(id.split('?')[0])) return null
      return { code: addGraphActivity(code), map: null }
    },
  }
}
