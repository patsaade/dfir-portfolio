import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { REGEX_CHEAT_SHEET } from '../src/data/regexCheatSheet';

// Structural self-consistency checks for the Regex Syntax Cheat Sheet dataset —
// same category as securityTerms.test.ts/d3fend.test.ts's own dataset-integrity
// checks. regex-cheatsheet.astro's CATEGORY_META (icon + blurb per category) is
// presentational metadata kept in the page rather than this data file (by
// design — regexCheatSheet.ts stays pure content), so a category typo'd or
// renamed here silently falls back to FALLBACK_META instead of failing loudly.
// There's no Astro-aware vitest plugin configured (see vitest.config.ts), so
// this reads the page's source as text — the same technique
// card-consistency.test.ts already uses — rather than importing the .astro
// file directly.

const root = resolve(__dirname, '..');

describe('regex cheat sheet data', () => {
  const categories = [...new Set(REGEX_CHEAT_SHEET.map((e) => e.category))];

  it('has entries', () => {
    expect(REGEX_CHEAT_SHEET.length).toBeGreaterThan(0);
  });

  it('every category has a CATEGORY_META entry on the cheat sheet page', () => {
    const pageSrc = readFileSync(resolve(root, 'src/pages/tools/regex-cheatsheet.astro'), 'utf-8');
    const metaBlock = pageSrc.match(/const CATEGORY_META:[\s\S]*?\n};/);
    expect(metaBlock, 'expected a CATEGORY_META object in regex-cheatsheet.astro').not.toBeNull();
    const body = metaBlock![0];
    for (const category of categories) {
      // Category keys are either bare identifiers (e.g. `Flags:`) or quoted
      // strings (e.g. `'Anchors & Boundaries':`) depending on whether the
      // name is a valid bare JS identifier — accept either form.
      const quoted = `'${category}':`;
      const bare = `${category}:`;
      const hasEntry = body.includes(quoted) || body.includes(bare);
      expect(hasEntry, `missing CATEGORY_META entry for "${category}" — falls back to FALLBACK_META on the page`).toBe(true);
    }
  });

  it('has no duplicate syntax token within the same category', () => {
    const seenByCategory = new Map<string, Set<string>>();
    for (const entry of REGEX_CHEAT_SHEET) {
      const seen = seenByCategory.get(entry.category) ?? new Set<string>();
      expect(seen.has(entry.syntax), `duplicate syntax "${entry.syntax}" in category "${entry.category}"`).toBe(false);
      seen.add(entry.syntax);
      seenByCategory.set(entry.category, seen);
    }
  });

  it('never embeds a literal zero-width/invisible character in prose fields', () => {
    // Regression guard: an earlier draft of the \\uHHHH entry pasted a real
    // U+200B zero-width space into `example` instead of writing out the
    // visible "\\u200B" escape text, which rendered as an essentially blank
    // regex on the page. Any zero-width/invisible Unicode character in a
    // prose field is a content bug here, not intentional data.
    // eslint-disable-next-line no-misleading-character-class
    const invisibleCharPattern = /[​‌‍⁠﻿]/;
    for (const entry of REGEX_CHEAT_SHEET) {
      for (const field of ['syntax', 'description', 'example'] as const) {
        expect(
          invisibleCharPattern.test(entry[field]),
          `entry "${entry.syntax}" field "${field}" contains a literal invisible/zero-width character`,
        ).toBe(false);
      }
    }
  });
});
