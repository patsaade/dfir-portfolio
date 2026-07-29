import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ICONS, type IconName } from '../src/data/icons';
import { buildIconSprite, symbolId, iconHref, ICON_SPRITE_HREF } from '../src/utils/iconSprite';

const SPRITE = buildIconSprite();
const NAMES = Object.keys(ICONS) as IconName[];

describe('icon sprite', () => {
  it('declares the SVG namespace on the root', () => {
    // NOT boilerplate. The sprite is served as a standalone image/svg+xml
    // document; without xmlns it does not parse as SVG and every <use> into it
    // fails, blanking every icon site-wide.
    expect(SPRITE.startsWith('<svg xmlns="http://www.w3.org/2000/svg">')).toBe(true);
    expect(SPRITE.endsWith('</svg>')).toBe(true);
  });

  it('emits exactly one <symbol> per icon, and nothing else', () => {
    const ids = [...SPRITE.matchAll(/<symbol id="([^"]+)"/g)].map((m) => m[1]);
    expect(ids).toHaveLength(NAMES.length);
    expect(new Set(ids).size).toBe(NAMES.length); // no duplicate ids
    expect(ids).toEqual(NAMES.map((n) => symbolId(n)));
  });

  // THE load-bearing assertion for this whole approach.
  //
  // A presentation attribute inside the referenced document beats the value the
  // host <svg> inherits down into the <use> shadow tree. Icon.astro deliberately
  // keeps all five paint attributes on the host so each call site can override
  // them; 15 call sites pass a custom strokeWidth, and 7 `star` sites pass
  // strokeWidth={0} together with a CSS `fill` to render a solid accent glyph
  // instead of a stroked outline.
  //
  // Bake any of these into a <symbol> and those 22 call sites silently stop
  // working — no error, no build failure, just wrong-looking icons. Nothing else
  // in the suite would catch it, and it cannot be checked from the DOM at
  // runtime either (a <use> shadow tree is not script-inspectable).
  it('never puts a paint attribute on a <symbol>', () => {
    const openingTags = [...SPRITE.matchAll(/<symbol[^>]*>/g)].map((m) => m[0]);
    expect(openingTags).toHaveLength(NAMES.length);
    for (const tag of openingTags) {
      expect(tag, `paint attribute leaked into: ${tag}`).not.toMatch(
        /\s(fill|stroke|stroke-width|stroke-linecap|stroke-linejoin)=/
      );
      // Positively pin the allowed shape rather than only blocklisting: an
      // attribute nobody thought to ban is just as capable of overriding the host.
      expect(tag).toMatch(/^<symbol id="i-[a-z0-9-]+" viewBox="0 0 24 24">$/);
    }
  });

  it('gives every symbol the same viewBox the host <svg> declares', () => {
    // Identical host and symbol viewBoxes make the nested viewport an identity
    // transform, so clipping behaviour matches the old inlined rendering.
    const viewBoxes = [...SPRITE.matchAll(/<symbol [^>]*viewBox="([^"]+)"/g)].map((m) => m[1]);
    expect(new Set(viewBoxes)).toEqual(new Set(['0 0 24 24']));
  });

  it('carries every icon body through verbatim', () => {
    for (const name of NAMES) {
      expect(SPRITE).toContain(`<symbol id="${symbolId(name)}" viewBox="0 0 24 24">${ICONS[name]}</symbol>`);
    }
  });

  it('is deterministic', () => {
    // The href embeds a hash of this output, and the whole site's icon caching
    // keys on it — a build-to-build difference would bust every visitor's cache
    // for nothing.
    expect(buildIconSprite()).toBe(SPRITE);
  });
});

describe('ICON_SPRITE_HREF', () => {
  it('is /icons.svg with a content-hash query', () => {
    expect(ICON_SPRITE_HREF).toMatch(/^\/icons\.svg\?v=[0-9a-z]+$/);
  });

  it('builds a fragment reference per icon', () => {
    expect(iconHref('shield')).toBe(`${ICON_SPRITE_HREF}#i-shield`);
    for (const name of NAMES) {
      expect(iconHref(name)).toBe(`${ICON_SPRITE_HREF}#${symbolId(name)}`);
    }
  });

  it('changes when the sprite content changes', () => {
    // Reimplements the hash to prove the href actually tracks content, rather
    // than asserting a frozen literal that would have to be updated by hand
    // every time an icon is added (and would therefore teach the next author to
    // treat a changed hash as noise).
    const fnv = (s: string) => {
      let h = 0x811c9dc5;
      for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
      }
      return (h >>> 0).toString(36);
    };
    expect(ICON_SPRITE_HREF).toBe(`/icons.svg?v=${fnv(SPRITE)}`);
    expect(fnv(SPRITE)).not.toBe(fnv(SPRITE + '<symbol id="i-x" viewBox="0 0 24 24"/>'));
  });
});

describe('<Icon> call sites', () => {
  // Every `name` is typed as IconName, so `astro check` already rejects a typo'd
  // literal. This covers what the type cannot: a name reaching the component
  // through a cast or a non-literal expression. With a sprite, an unresolvable
  // reference renders nothing at all — silently, with no build error and no
  // runtime warning — so it's worth a second, textual net.
  const SRC = join(process.cwd(), 'src');

  const walk = (dir: string): string[] =>
    readdirSync(dir).flatMap((entry) => {
      const p = join(dir, entry);
      return statSync(p).isDirectory() ? walk(p) : p.endsWith('.astro') ? [p] : [];
    });

  it('only references icons that exist in the map', () => {
    const bad: string[] = [];
    for (const file of walk(SRC)) {
      const src = readFileSync(file, 'utf8');
      for (const m of src.matchAll(/<Icon\b[^>]*?\bname="([^"]+)"/g)) {
        if (!(m[1] in ICONS)) bad.push(`${file}: name="${m[1]}"`);
      }
    }
    expect(bad).toEqual([]);
  });
});
