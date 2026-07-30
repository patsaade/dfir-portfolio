// Guards the curated auto-matched glossary allowlist (AUTO_TERMS in
// src/data/hovercards.ts), which HoverCards.astro wraps in prose.
//
// The failure this prevents is silent: a slug that no longer resolves still gets
// its word wrapped in a `.hovercard` trigger with a `help` cursor and a dotted
// underline, but `dataFor()` returns null so the card never opens. The reader
// gets an affordance that does nothing, and nothing at build or runtime says so.
// test/termTags.test.ts does the same job for hand-written <Term slug> tags in
// .astro sources; this is its counterpart for the automatic set.
import { describe, it, expect } from 'vitest';
import { AUTO_TERMS } from '../src/data/hovercards';
import { SECURITY_TERMS } from '../src/data/securityTerms';

const SLUGS = new Set(SECURITY_TERMS.map((t) => t.slug));

describe('AUTO_TERMS', () => {
  it('resolves every slug against the glossary', () => {
    const unresolved = AUTO_TERMS.filter((t) => !SLUGS.has(t.slug)).map((t) => t.slug);
    expect(unresolved, 'these slugs are not in SECURITY_TERMS — renamed or removed?').toEqual([]);
  });

  it('lists each slug at most once', () => {
    const seen = new Map<string, number>();
    for (const t of AUTO_TERMS) seen.set(t.slug, (seen.get(t.slug) ?? 0) + 1);
    expect([...seen.entries()].filter(([, n]) => n > 1).map(([s]) => s)).toEqual([]);
  });

  it('gives every entry at least one alias, none of them blank', () => {
    for (const t of AUTO_TERMS) {
      expect(t.aliases.length, `"${t.slug}" has no aliases`).toBeGreaterThan(0);
      for (const a of t.aliases) expect(a.trim(), `"${t.slug}" has a blank alias`).not.toBe('');
    }
  });

  // Matching is case-insensitive and word-boundary anchored, so a very short
  // alias is the one real way this feature turns into noise — it would fire
  // inside ordinary prose all over the site. Three characters is the floor that
  // still admits the genuine short ones we do want (YARA, LNK).
  it('has no alias short enough to fire on ordinary prose', () => {
    const tooShort = AUTO_TERMS.flatMap((t) => t.aliases.filter((a) => a.trim().length < 4).map((a) => `${t.slug}: "${a}"`));
    expect(tooShort).toEqual([]);
  });

  // An alias that is a whole-word substring of a LONGER alias is fine (longest
  // wins, the matcher sorts by length). An alias that duplicates another entry's
  // alias exactly is not — which of the two fires would depend on sort order.
  it('has no alias claimed by two different terms', () => {
    const owner = new Map<string, string>();
    const clashes: string[] = [];
    for (const t of AUTO_TERMS) {
      for (const a of t.aliases) {
        const k = a.toLowerCase();
        const prev = owner.get(k);
        if (prev && prev !== t.slug) clashes.push(`"${a}" claimed by both ${prev} and ${t.slug}`);
        owner.set(k, t.slug);
      }
    }
    expect(clashes).toEqual([]);
  });
});
