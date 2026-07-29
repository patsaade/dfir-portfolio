import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { KQL_CHEAT_SHEET, KQL_CATEGORY_SOURCES } from '../src/data/kqlCheatSheet';
import { SPL_CHEAT_SHEET, SPL_CATEGORY_SOURCES } from '../src/data/splCheatSheet';
import { S1_CHEAT_SHEET, S1_CATEGORY_SOURCES } from '../src/data/s1CheatSheet';

// Structural self-consistency for the three query-language cheat sheets, modelled
// on test/regexCheatSheet.test.ts — the same guard, applied to the three datasets
// that shipped alongside it without one.
//
// The failure this exists to catch: each page keeps its CATEGORY_META (icon +
// blurb per category) in the .astro file rather than the data module, so a
// category renamed or typo'd in the data silently falls back to FALLBACK_META —
// a blank blurb and a generic icon — instead of failing loudly. The same is true
// of the per-section source link in *_CATEGORY_SOURCES.
//
// There's no Astro-aware vitest plugin (see vitest.config.ts), so the page is
// read as text — the technique card-consistency.test.ts already uses.

const root = resolve(__dirname, '..');

interface SyntaxEntry {
  category: string;
  syntax: string;
  description: string;
  example: string;
}

const SHEETS: {
  name: string;
  entries: SyntaxEntry[];
  sources: Record<string, { name: string; url: string }>;
  page: string;
}[] = [
  { name: 'KQL', entries: KQL_CHEAT_SHEET, sources: KQL_CATEGORY_SOURCES, page: 'src/pages/reference/kql-cheatsheet.astro' },
  { name: 'SPL', entries: SPL_CHEAT_SHEET, sources: SPL_CATEGORY_SOURCES, page: 'src/pages/reference/spl-cheatsheet.astro' },
  { name: 'SentinelOne', entries: S1_CHEAT_SHEET, sources: S1_CATEGORY_SOURCES, page: 'src/pages/reference/s1-cheatsheet.astro' },
];

describe.each(SHEETS)('$name cheat sheet data', ({ entries, sources, page }) => {
  const categories = [...new Set(entries.map((e) => e.category))];

  it('has entries', () => {
    expect(entries.length).toBeGreaterThan(0);
  });

  it('every entry has non-empty syntax, description, and example', () => {
    for (const entry of entries) {
      expect(entry.syntax.trim(), `empty syntax in "${entry.category}"`).not.toBe('');
      expect(entry.description.trim(), `empty description for "${entry.syntax}"`).not.toBe('');
      expect(entry.example.trim(), `empty example for "${entry.syntax}"`).not.toBe('');
    }
  });

  it('has no duplicate syntax token within the same category', () => {
    const seenByCategory = new Map<string, Set<string>>();
    for (const entry of entries) {
      const seen = seenByCategory.get(entry.category) ?? new Set<string>();
      expect(seen.has(entry.syntax), `duplicate "${entry.syntax}" in category "${entry.category}"`).toBe(false);
      seen.add(entry.syntax);
      seenByCategory.set(entry.category, seen);
    }
  });

  it('every category has a CATEGORY_META entry on its page', () => {
    const pageSrc = readFileSync(resolve(root, page), 'utf-8');
    const metaBlock = pageSrc.match(/const CATEGORY_META:[\s\S]*?\n};/);
    expect(metaBlock, `expected a CATEGORY_META object in ${page}`).not.toBeNull();
    const body = metaBlock![0];
    for (const category of categories) {
      // Keys are bare identifiers or quoted strings depending on whether the
      // name is a valid bare JS identifier — accept either form.
      const hasEntry = body.includes(`'${category}':`) || body.includes(`${category}:`);
      expect(hasEntry, `missing CATEGORY_META for "${category}" — falls back to FALLBACK_META on the page`).toBe(true);
    }
  });

  it('every category has a source, and every source maps to a real category', () => {
    for (const category of categories) {
      expect(sources[category], `no source registered for category "${category}"`).toBeDefined();
    }
    for (const key of Object.keys(sources)) {
      expect(categories, `source registered for "${key}", which no entry uses`).toContain(key);
    }
  });

  it('every source has a name and an https URL', () => {
    for (const [category, src] of Object.entries(sources)) {
      expect(src.name.trim(), `source for "${category}" has no name`).not.toBe('');
      expect(src.url, `source for "${category}" is not https`).toMatch(/^https:\/\//);
    }
  });
});
