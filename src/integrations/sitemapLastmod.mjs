// Resolves a sitemap URL to its `lastmod`, from the committed map that
// scripts/gen-lastmod.mjs produces.
//
// WHY A COMMITTED MAP AND NOT GIT AT BUILD TIME. The first version of this
// shelled out to `git log` during the build. It worked perfectly locally and
// produced NOTHING in production: the deployed sitemap carried all 1,540 URLs
// and zero <lastmod> elements, because Vercel's build step can't be relied on
// for per-file git history. (utils/version.ts already worked around the same
// thing by preferring VERCEL_GIT_COMMIT_SHA over asking git.) It failed soft, as
// designed — no wrong dates, no broken build — but silently delivered nothing
// where it actually mattered.
//
// Reading a committed map makes the result byte-identical in every environment.
// That is not just convenience: a lastmod that changed depending on where the
// build ran is precisely the unreliable signal Google discounts site-wide, so
// determinism is the feature.
//
// WHY NOT THE BUILD DATE. Stamping every URL with "now" claims the whole site
// changed on every deploy. Same discounting problem, plus it is simply false.
//
// Regenerate with `node scripts/gen-lastmod.mjs` when content changes
// meaningfully. A slightly stale but true date is far better than a fresh false
// one; nothing here degrades if it isn't re-run for a while.
import lastmodMap from '../data/lastmod.generated.json' with { type: 'json' };

const { prefixes = {}, pages = {} } = lastmodMap;

// Longest prefix first, so /reference/glossary/<slug>/ resolves against the
// glossary dataset rather than any shallower entry.
const orderedPrefixes = Object.entries(prefixes).sort((a, b) => b[0].length - a[0].length);

/**
 * `lastmod` for one sitemap URL, or null to omit it entirely.
 * @param {string} url absolute URL as the sitemap integration supplies it
 */
export function lastmodFor(url) {
  let path;
  try {
    path = new URL(url).pathname;
  } catch {
    return null;
  }

  // An exact page match wins over a dataset prefix: /reference/glossary/ is a
  // real page with its own history, even though its children are dataset-driven.
  if (pages[path]) return pages[path];

  for (const [prefix, date] of orderedPrefixes) {
    if (path.startsWith(prefix)) return date;
  }
  return null;
}
