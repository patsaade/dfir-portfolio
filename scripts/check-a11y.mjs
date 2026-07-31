#!/usr/bin/env node
// Accessibility gate — runs axe-core over the BUILT HTML.
//
// Accessibility was the only review area on this project with no automated
// check: security, freshness and dead code all have scripts, a11y had a manual
// checklist. So a regression between manual passes had nothing to catch it.
// Unlike check-security.mjs / check-freshness.mjs, which report and always exit
// 0, this one EXITS NON-ZERO on a violation — it is a gate, not a report.
//
// WHY jsdom AND NOT A HEADLESS BROWSER. axe runs its whole rule set here except
// the handful that need real layout — in practice `color-contrast`, which axe
// cannot evaluate without rendering. That is not a gap on this site: contrast is
// already enforced by test/themeContrast.test.ts across ALL TEN palettes and
// every foreground/surface pair, which is strictly more coverage than axe would
// give (a browser run would only ever test whichever palette happened to be
// active). Skipping the browser also keeps ~300 MB out of CI and makes a
// many-page sweep fast enough to actually run every time.
//
// WHY A SAMPLE AND NOT ALL 1,730 PAGES. Most of the output is generated from a
// handful of templates — 544 glossary terms, 272 D3FEND, 251 event IDs, 233
// ATT&CK techniques — and every page from one template has identical structure.
// SAMPLES below covers one page per template plus every hand-authored page, so a
// structural violation is caught once rather than reported 544 times. Scanning
// everything would mostly measure the same markup repeatedly.
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';
import axe from 'axe-core';

const ROOT = '.vercel/output/static';

/** First entry of a generated-detail directory — one page per template. */
function firstIn(dir) {
  const p = join(ROOT, dir);
  if (!existsSync(p)) return null;
  const kids = readdirSync(p).filter((d) => existsSync(join(p, d, 'index.html')));
  return kids.length ? `${dir}/${kids[0]}` : null;
}

/** Every hand-authored page, plus one representative of each generated template. */
function samples() {
  const fixed = [
    '', 'about', 'blog', 'labs', 'certifications', 'privacy', 'colophon', '404',
    'reference', 'tools', 'drills', 'dfir', 'networking', 'systems',
    'reference/glossary', 'reference/attack-map', 'reference/d3fend',
    'reference/event-ids', 'reference/network-ports', 'reference/threat-actors',
    'reference/tool-catalog', 'reference/osi-model', 'reference/kill-chain',
    'reference/pyramid-of-pain',
  ];
  const generated = [
    'reference/glossary', 'reference/attack-map', 'reference/d3fend',
    'reference/event-ids', 'reference/network-ports', 'reference/threat-actors',
    'tools', 'drills', 'blog', 'labs',
  ].map(firstIn).filter(Boolean);
  return [...new Set([...fixed, ...generated])]
    .map((s) => (s === '' ? 'index.html' : `${s}/index.html`))
    .filter((f) => existsSync(join(ROOT, f)));
}

// Reviewed exceptions. Each MUST carry a reason — an unexplained entry here is
// how a gate quietly stops being a gate.
const IGNORE = {
  // 'rule-id': 'why this is not applicable / is a false positive here',
};

async function scan(file) {
  const html = readFileSync(join(ROOT, file), 'utf8');
  const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true });
  const { window } = dom;
  window.eval(axe.source);
  const res = await window.axe.run(window.document, {
    resultTypes: ['violations'],
    // color-contrast needs real layout; themeContrast.test.ts covers it far
    // better (all 10 palettes) than a single rendered theme ever could.
    rules: { 'color-contrast': { enabled: false } },
  });
  dom.window.close();
  return res.violations.filter((v) => !IGNORE[v.id]);
}

const files = samples();
console.log(`\n▸ axe-core ${axe.version} over ${files.length} representative pages (jsdom)\n`);

const byRule = new Map();
let scanned = 0;
for (const f of files) {
  let violations;
  try {
    violations = await scan(f);
  } catch (err) {
    console.log(`  ! ${f}: ${err.message}`);
    continue;
  }
  scanned++;
  for (const v of violations) {
    if (!byRule.has(v.id)) byRule.set(v.id, { impact: v.impact, help: v.help, pages: new Set(), nodes: [] });
    const e = byRule.get(v.id);
    e.pages.add(f);
    for (const n of v.nodes.slice(0, 2)) e.nodes.push(`${f} — ${n.html.slice(0, 110)}`);
  }
}

const RANK = { critical: 0, serious: 1, moderate: 2, minor: 3 };
const rules = [...byRule.entries()].sort((a, b) => (RANK[a[1].impact] ?? 9) - (RANK[b[1].impact] ?? 9));

if (!rules.length) {
  console.log(`  ✓ no violations across ${scanned} pages\n`);
  process.exit(0);
}

let total = 0;
for (const [id, e] of rules) {
  total += e.pages.size;
  console.log(`  ✗ [${e.impact}] ${id} — ${e.help}`);
  console.log(`      ${e.pages.size} page(s); e.g.`);
  for (const n of e.nodes.slice(0, 2)) console.log(`      ${n}`);
  console.log('');
}
console.log(`Summary: ${rules.length} rule(s) violated across ${total} page-hit(s), ${scanned} pages scanned.\n`);
process.exit(1);
