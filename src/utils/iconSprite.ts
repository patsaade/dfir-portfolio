// Builds the external icon sprite served at /icons.svg, and the content-hashed
// href every <Icon> and the BaseHead preload point at.
//
// WHY AN EXTERNAL SPRITE. Icon.astro used to inline each icon's geometry at
// every call site. There are 869 <Icon> call sites over 71 distinct icons, so a
// typical page carried 110-700 inline <svg> bodies (51-270 KB raw). Brotli
// squashes that repetition well, but not for free: measured over 6 representative
// pages, replacing the bodies with a <use> reference saves ~3,916 B brotli per
// page. The sprite itself is ~4 KB brotli, fetched once and then served from the
// HTTP cache and the service worker's cache-first tier — so a single-page visit
// is roughly a wash and every page after the first is a straight win.
//
// THE ONE INVARIANT THAT MAKES THIS SAFE — no paint attributes on the <symbol>.
// A presentation attribute inside the referenced document beats the value the
// host <svg> inherits down into the shadow tree. Icon.astro keeps fill, stroke,
// stroke-width, stroke-linecap and stroke-linejoin on the HOST element only, so
// each call site can still override them:
//   - 15 call sites pass a custom `strokeWidth` (0, 2.25, 2.5)
//   - 7 `star` sites pass strokeWidth={0} PLUS a class setting `fill`, turning a
//     stroked outline into a solid accent glyph. CSS on the host beats the host's
//     own fill="none" presentation attribute, then inherits in.
// Bake any of those five into the symbol and all 22 of those call sites silently
// stop working, with `star` degrading to a hollow outline. test/iconSprite.test.ts
// asserts every emitted <symbol> tag carries nothing but `id` and `viewBox`.
//
// `currentColor` and `color` DO cross the boundary (both inherit), which is what
// keeps `tag`'s inner dot and all six of `grip-horizontal`'s dots painted — and
// what makes a live palette change repaint sprite-referenced icons correctly.
// Verified live in a real browser before this conversion, not assumed.
import { ICONS, type IconName } from '../data/icons';

/** Symbol id for one icon. Short on purpose — it repeats at every call site. */
export const symbolId = (name: IconName | string) => `i-${name}`;

/**
 * The sprite document. A bare <svg> root holding one <symbol> per icon.
 *
 * `xmlns` is REQUIRED and is not optional boilerplate here: inline SVG inside an
 * HTML document infers the namespace, but this is served as a standalone
 * image/svg+xml document, and without the namespace it does not parse as SVG at
 * all — every icon site-wide would go blank.
 *
 * Each <symbol> repeats the same `viewBox="0 0 24 24"` the host <svg> declares.
 * That is not redundant: the symbol's viewBox establishes the nested viewport
 * that maps the geometry onto the host's box. Since both are identical it's an
 * identity transform, so clipping behaviour is unchanged from inlining.
 */
export function buildIconSprite(): string {
  const symbols = (Object.keys(ICONS) as IconName[])
    .map((name) => `<symbol id="${symbolId(name)}" viewBox="0 0 24 24">${ICONS[name]}</symbol>`)
    .join('');
  return `<svg xmlns="http://www.w3.org/2000/svg">${symbols}</svg>`;
}

/**
 * FNV-1a over the sprite text, base36. Deliberately a hand-rolled hash rather
 * than node:crypto — this module is imported by Icon.astro and BaseHead.astro,
 * and while both only run at build today, a node-only import would be a landmine
 * if either is ever touched by a client bundle. 32 bits is ample for a cache
 * buster over 71 icons.
 */
function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    // Math.imul keeps the multiply in 32-bit space; a plain * overflows to a
    // double and silently stops being FNV.
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(36);
}

/**
 * The href every consumer uses: `/icons.svg?v=<hash of the sprite>`.
 *
 * The query string is load-bearing, not cosmetic. `/icons.svg` is NOT
 * content-hashed the way `/_astro/*` filenames are, but it IS in public/sw.js's
 * cache-first tier — and that tier's stated precondition is "filenames change on
 * every change, so a cached copy is never wrong." Without a buster, adding or
 * editing an icon would serve the OLD sprite forever to every returning visitor
 * with the SW installed, and a reference to an id the old sprite lacks renders
 * NOTHING: no error, no console warning, no fallback. This ties the URL to the
 * sprite's content so a changed icon is a changed URL, restoring that
 * precondition. Vercel serves the static file regardless of the query string.
 */
export const ICON_SPRITE_HREF = `/icons.svg?v=${fnv1a(buildIconSprite())}`;

/** Full `<use href>` value for one icon. */
export const iconHref = (name: IconName) => `${ICON_SPRITE_HREF}#${symbolId(name)}`;
