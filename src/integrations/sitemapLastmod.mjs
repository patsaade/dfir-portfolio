// Real `lastmod` dates for the sitemap, derived from git history.
//
// WHY NOT JUST STAMP THE BUILD DATE. Google uses `lastmod` to prioritise
// re-crawling, but only while it stays believable — their stated position is
// that an unreliable lastmod gets the whole signal ignored for the site. Writing
// the build date onto all 1,541 URLs would claim every page changed on every
// deploy, which is both false and exactly the pattern that gets it discounted.
// Omitting it entirely (the previous state) is honest but forfeits the signal on
// a site that has just moved ~1,700 URLs and wants an efficient re-crawl.
//
// So each URL gets the committer date of the source that actually produces it:
//  - a generated detail route (glossary terms, ATT&CK, D3FEND, event IDs, ports,
//    threat actors) is dated by ITS DATASET — when that data last changed is
//    genuinely when those pages last changed, and one `git log` covers hundreds
//    of URLs;
//  - every other page is dated by its own file under src/pages/.
//
// Blog and lab posts are handled by the caller instead (they carry a real
// `updatedDate`/`pubDate` in frontmatter, which is more accurate than any git
// date — a typo fix shouldn't advertise the post as freshly updated).
//
// FAILS SOFT, ALWAYS. If git is unavailable or a path has no history, the URL
// simply gets no lastmod rather than a wrong one or a broken build. (Vercel
// builds do have full history here — see CLAUDE.md invariant 9, which already
// depends on it for the commit-count version string.)
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';

/** Latest committer date across the given paths, ISO 8601, or null. */
function gitDate(paths) {
  const found = paths.filter((p) => existsSync(p));
  if (!found.length) return null;
  let newest = null;
  for (const p of found) {
    try {
      const out = execFileSync('git', ['log', '-1', '--format=%cI', '--', p], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (out && (!newest || out > newest)) newest = out;
    } catch {
      /* no history for this path, or no git — fall through */
    }
  }
  return newest;
}

// URL prefix -> the dataset that generates every page under it. Longest prefix
// wins, so /reference/glossary/<slug>/ matches before /reference/.
const GENERATED = [
  ['/reference/glossary/', ['src/data/securityTerms.ts', 'src/data/terms']],
  ['/reference/attack-map/', ['src/data/attack-techniques.generated.ts', 'src/data/attack-overlay.ts']],
  ['/reference/d3fend/', ['src/data/d3fend-techniques.generated.ts', 'src/data/d3fend.ts']],
  ['/reference/event-ids/', ['src/data/eventIds.ts']],
  ['/reference/network-ports/', ['src/data/networkPorts.ts']],
  ['/reference/threat-actors/', ['src/data/threat-actors.generated.ts', 'src/data/threatActorNaming.ts']],
  ['/reference/tool-catalog/', ['src/data/tools.ts']],
];

const cache = new Map();
function cached(key, compute) {
  if (!cache.has(key)) cache.set(key, compute());
  return cache.get(key);
}

/**
 * `lastmod` for one sitemap URL, or null to omit it.
 * @param {string} url absolute URL as the sitemap integration supplies it
 */
export function lastmodFor(url) {
  let path;
  try {
    path = new URL(url).pathname;
  } catch {
    return null;
  }

  for (const [prefix, sources] of GENERATED) {
    // The listing page itself (/reference/glossary/) is generated from the same
    // dataset as its children, so an exact match counts too.
    if (path === prefix || path.startsWith(prefix)) {
      return cached('gen:' + prefix, () => gitDate(sources));
    }
  }

  const rel = path.replace(/^\/+|\/+$/g, '');

  // Blog and lab POSTS live in a content collection, not src/pages — their
  // route is /blog/<slug>/ but their source is src/content/blog/<slug>.md(x).
  // The git date of the post file is the right answer here: if an author edits
  // a post they commit that edit, so it tracks real content changes. (The
  // listing pages /blog/ and /labs/ are ordinary src/pages routes and fall
  // through to the branch below.)
  const post = /^(blog|labs)\/(.+)$/.exec(rel);
  if (post) {
    const [, collection, slug] = post;
    return cached(`post:${collection}/${slug}`, () =>
      gitDate([
        `src/content/${collection}/${slug}.md`,
        `src/content/${collection}/${slug}.mdx`,
        `src/content/${collection}/${slug}/index.md`,
        `src/content/${collection}/${slug}/index.mdx`,
      ]),
    );
  }

  // Otherwise: the page's own source file. /reference/osi-model/ ->
  // src/pages/reference/osi-model.astro, or .../index.astro for a directory route.
  const base = rel ? `src/pages/${rel}` : 'src/pages/index';
  return cached('page:' + base, () => gitDate([`${base}.astro`, `${base}/index.astro`, `${base}.ts`, `${base}.md`]));
}
