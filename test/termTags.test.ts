import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { SECURITY_TERMS } from '../src/data/securityTerms';

// Enforces the guidance in CLAUDE.md invariant 11 — "tag terms with <Term>" —
// which is otherwise just prose: nothing previously caught a <Term slug="..."/>
// pointing at a glossary entry that doesn't exist (a typo, a renamed/removed
// term) until a reader actually clicked it and got nothing. Walks every
// .astro file under src/ as plain text (no Astro compiler needed, same
// static-source-scan technique as card-consistency.test.ts) and checks every
// `<Term slug="...">` against the real glossary dataset.

const root = resolve(__dirname, '..');
const srcDir = resolve(root, 'src');
const validSlugs = new Set(SECURITY_TERMS.map((t) => t.slug));

function findAstroFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...findAstroFiles(full));
    else if (entry.endsWith('.astro')) out.push(full);
  }
  return out;
}

describe('<Term slug="..."> resolves to a real glossary entry', () => {
  const files = findAstroFiles(srcDir);
  const cases: { file: string; slug: string }[] = [];
  for (const file of files) {
    const src = readFileSync(file, 'utf-8');
    for (const m of src.matchAll(/<Term\s+slug=["']([^"']+)["']/g)) {
      // Skip doc-comment mentions like `<Term slug="…">` (an illustrative
      // placeholder, not a real usage) — a real slug is always lowercase
      // kebab-case, which this excludes cleanly without needing to detect
      // `//` comment context line-by-line.
      if (!/^[a-z0-9-]+$/.test(m[1])) continue;
      cases.push({ file: file.slice(root.length + 1), slug: m[1] });
    }
  }

  it('found at least one <Term> usage to check (sanity check the scan itself works)', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases)('$file: slug "$slug" exists in SECURITY_TERMS', ({ slug }) => {
    expect(validSlugs.has(slug), `"${slug}" is not a real glossary slug`).toBe(true);
  });
});
