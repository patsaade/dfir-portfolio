#!/usr/bin/env node
// Generates src/data/lastmod.generated.json — the per-source last-modified dates
// the sitemap's `lastmod` is built from.
//
// WHY THIS IS GENERATED AND COMMITTED, rather than computed at build time.
// The first version of this read git during the build. It worked locally and
// produced NOTHING on Vercel: the deployed sitemap had all 1,540 URLs and zero
// <lastmod> elements. Vercel's build step can't be relied on for per-file git
// history — which the repo already half-knew, since utils/version.ts prefers
// VERCEL_GIT_COMMIT_SHA over asking git and carries a build-date fallback.
//
// Reading a committed map instead makes the output identical in every
// environment. That matters beyond convenience: dates that changed depending on
// where the build ran would be exactly the kind of unreliable lastmod Google
// discounts site-wide.
//
// Same shape as the other generators here (gen-attack-map, gen-d3fend-map,
// gen-threat-actors): run it by hand, commit the result. Re-run when content
// changes meaningfully — see CLAUDE.md's Maintenance & freshness process.
//
//   node scripts/gen-lastmod.mjs
import { execFileSync } from 'node:child_process';
import { existsSync, writeFileSync, readdirSync } from 'node:fs';

const OUT = 'src/data/lastmod.generated.json';

/** Latest committer date across paths (ISO 8601), or null. */
function gitDate(paths) {
  let newest = null;
  for (const p of paths.filter(existsSync)) {
    try {
      const out = execFileSync('git', ['log', '-1', '--format=%cI', '--', p], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (out && (!newest || out > newest)) newest = out;
    } catch {
      /* no history for this path */
    }
  }
  return newest;
}

// URL prefix -> the dataset that generates every page beneath it. One git lookup
// covers hundreds of URLs, and "when the data changed" really is when those
// pages changed.
const GENERATED = {
  '/reference/glossary/': ['src/data/securityTerms.ts', 'src/data/terms'],
  '/reference/attack-map/': ['src/data/attack-techniques.generated.ts', 'src/data/attack-overlay.ts'],
  '/reference/d3fend/': ['src/data/d3fend-techniques.generated.ts', 'src/data/d3fend.ts'],
  '/reference/event-ids/': ['src/data/eventIds.ts'],
  '/reference/network-ports/': ['src/data/networkPorts.ts'],
  '/reference/threat-actors/': ['src/data/threat-actors.generated.ts', 'src/data/threatActorNaming.ts'],
  '/reference/tool-catalog/': ['src/data/tools.ts'],
};

/** Every routable source file, so ordinary pages get their own real date. */
function pageFiles(dir, acc = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) pageFiles(p, acc);
    else if (/\.(astro|md|mdx)$/.test(e.name)) acc.push(p);
  }
  return acc;
}

const prefixes = {};
for (const [prefix, sources] of Object.entries(GENERATED)) {
  const d = gitDate(sources);
  if (d) prefixes[prefix] = d;
}

// Per-page dates, keyed by the URL path the file produces.
const pages = {};
for (const f of pageFiles('src/pages')) {
  const d = gitDate([f]);
  if (!d) continue;
  let route = f
    .replace(/^src\/pages/, '')
    .replace(/\/index\.(astro|md|mdx)$/, '/')
    .replace(/\.(astro|md|mdx)$/, '/');
  if (route === '') route = '/';
  if (route.includes('[')) continue; // dynamic routes are covered by GENERATED
  pages[route] = d;
}

// Content-collection posts, keyed by their route.
for (const collection of ['blog', 'labs']) {
  const dir = `src/content/${collection}`;
  if (!existsSync(dir)) continue;
  for (const f of pageFiles(dir)) {
    const d = gitDate([f]);
    if (!d) continue;
    const slug = f.replace(`${dir}/`, '').replace(/\.(md|mdx)$/, '').replace(/\/index$/, '');
    pages[`/${collection}/${slug}/`] = d;
  }
}

writeFileSync(OUT, JSON.stringify({ prefixes, pages }, null, 2) + '\n');
console.log(
  `${OUT}: ${Object.keys(prefixes).length} dataset prefixes, ${Object.keys(pages).length} pages`,
);
