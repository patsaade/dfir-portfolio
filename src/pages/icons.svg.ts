// The external icon sprite — one <symbol> per entry in src/data/icons.ts,
// referenced by every <Icon> via <use href="/icons.svg?v=<hash>#i-NAME">.
//
// Generated from the SAME map Icon.astro renders against, so adding an icon puts
// it in the sprite with no second step. See src/utils/iconSprite.ts for why the
// symbols must stay free of paint attributes, and why the href is content-hashed.
//
// Prerendered like every other route (CLAUDE.md invariant 6), so this is a plain
// static file on Vercel's CDN, not an on-demand function. A dotted final segment
// is exempt from `trailingSlash: 'always'`, so it really is served at
// `/icons.svg` — same as /search-index.json and /rss.xml.
export const prerender = true;
import type { APIRoute } from 'astro';
import { buildIconSprite } from '../utils/iconSprite';

export const GET: APIRoute = () =>
  new Response(buildIconSprite(), {
    headers: {
      // Explicit and non-negotiable: vercel.json sets X-Content-Type-Options:
      // nosniff, so a wrong or missing type is fatal with no sniffing rescue —
      // the sprite would fail to load and every icon site-wide would go blank.
      'Content-Type': 'image/svg+xml; charset=utf-8',
      // Safe to cache hard because the URL carries a hash of the sprite's own
      // content (ICON_SPRITE_HREF): a changed icon is a changed URL.
      'Cache-Control': 'public, max-age=31536000, immutable',
    },
  });
