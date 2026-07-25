import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Enforces the standing rule: every card-grid tile — Glossary, Tools, Certifications,
// the ATT&CK map, and the D3FEND map — must render at the same size. The `card` Panda
// recipe (panda.config.ts) is the single source of truth for padding, minimum height,
// background, border, and radius; each page composes it via `${card()} ${css({...})}`
// rather than hand-rolling those properties. This test statically checks the source of
// each page so a future edit that reintroduces a hand-rolled card (and lets sizes drift
// apart again) fails here instead of shipping.

const root = resolve(__dirname, '..');

const PAGES = [
  { name: 'DFIR landing page', path: 'src/pages/dfir.astro' },
  { name: 'IT landing page', path: 'src/pages/it.astro' },
  { name: 'Glossary', path: 'src/pages/glossary/index.astro' },
  { name: 'Tools', path: 'src/pages/tools.astro' },
  { name: 'Certifications', path: 'src/pages/certifications.astro' },
  { name: 'ATT&CK map', path: 'src/pages/attack-map.astro' },
  { name: 'D3FEND map', path: 'src/pages/d3fend/index.astro' },
  { name: 'Event ID Reference', path: 'src/pages/event-ids.astro' },
  { name: 'Regex Syntax Cheat Sheet', path: 'src/pages/tools/regex-cheatsheet.astro' },
];

describe('card-grid size consistency', () => {
  it('fixes the shared card recipe to one padding, min-height, and radius', () => {
    const config = readFileSync(resolve(root, 'panda.config.ts'), 'utf-8');
    const recipe = config.match(/card:\s*{[\s\S]*?className:\s*'card'[\s\S]*?\n\s{8}},\n\s{6}},/);
    expect(recipe, 'expected a `card` recipe in panda.config.ts recipes block').not.toBeNull();
    const body = recipe![0];
    expect(body).toMatch(/p:\s*'0\.7rem 0\.85rem'/);
    expect(body).toMatch(/minH:\s*'4rem'/);
    expect(body).toMatch(/borderRadius:\s*'md'/);
    expect(body).toMatch(/bg:\s*'bgCard'/);
    expect(body).toMatch(/border:\s*'1px solid token\(colors\.border\)'/);
  });

  it.each(PAGES)('$name imports the shared card recipe', ({ path }) => {
    const src = readFileSync(resolve(root, path), 'utf-8');
    expect(src).toMatch(/import\s*{[^}]*\bcard\b[^}]*}\s*from\s*'styled-system\/recipes'/);
  });

  it.each(PAGES)('$name composes card() instead of hand-rolling the tile styles', ({ path }) => {
    const src = readFileSync(resolve(root, path), 'utf-8');
    expect(src).toMatch(/\bcard\(\)/);
    // minH is fixed by the recipe only — a page-local minH would let that page's
    // cards drift to a different floor height than every other card-grid page.
    expect(src).not.toMatch(/minH:/);
  });
});
