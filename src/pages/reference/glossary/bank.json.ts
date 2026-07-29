// Compact term bank for the client-side daily rotation, served as one cached,
// prerendered JSON file. The site-wide ticker (and the index's featured card)
// fetch this once rather than inlining ~500 terms into every page's HTML.
//
// Shape: an ordered array of [slug, term, short, category] — the array order IS
// the rotation order, so the client picks index = daySerial mod length (the same
// math as termForDate()).
import type { APIRoute } from 'astro';
import { SECURITY_TERMS } from '../../../data/securityTerms';

export const prerender = true;

export const GET: APIRoute = () => {
  const data = SECURITY_TERMS.map((t) => [t.slug, t.term, t.short, t.category]);
  return new Response(JSON.stringify(data), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'public, max-age=3600, stale-while-revalidate=86400',
    },
  });
};
