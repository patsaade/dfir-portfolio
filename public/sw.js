/* Minimal, safe service worker — offline reading + fast repeat loads.
 *
 * Strategy (chosen to never serve stale content while online):
 *  - Immutable, content-hashed build assets (/_astro/, /fonts/, /icons.svg) →
 *    cache-first. Their filenames change on every change, so a cached copy is
 *    never "wrong". /icons.svg is the one entry whose *path* is stable, so it
 *    earns its place here only because every reference to it carries a hash of
 *    the sprite's own content as a `?v=` query (ICON_SPRITE_HREF in
 *    src/utils/iconSprite.ts) and the cache is keyed on the full URL. Edit an
 *    icon and the URL changes, so this tier can never serve a stale sprite.
 *    Do NOT add a path here that lacks that property: a stale sprite means a
 *    <use> pointing at an id the cached copy doesn't have, which renders
 *    NOTHING — no error, no console warning, no fallback.
 *  - Page navigations (HTML)  → network-first: always fresh when online, falls
 *    back to the cached copy (then the cached home page) only when offline.
 *  - Everything else is left to the network.
 *
 * Caches are versioned and old ones are purged on activate; the worker takes over
 * immediately (skipWaiting + clients.claim) so a new deploy supersedes the old SW.
 * To force a hard refresh of all caches, bump VERSION.
 */
const VERSION = 'v4';
const ASSET_CACHE = 'assets-' + VERSION;
const PAGE_CACHE = 'pages-' + VERSION;

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== ASSET_CACHE && k !== PAGE_CACHE).map((k) => caches.delete(k)));
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // same-origin only

  // Immutable hashed assets → cache-first. (`/icons.svg` is content-hashed via
  // its `?v=` query, not its filename — see the header note.)
  if (url.pathname.startsWith('/_astro/') || url.pathname.startsWith('/fonts/') || url.pathname === '/icons.svg') {
    event.respondWith(
      caches.open(ASSET_CACHE).then(async (cache) => {
        const hit = await cache.match(req);
        if (hit) return hit;
        const res = await fetch(req);
        if (res && res.ok) cache.put(req, res.clone());
        return res;
      }),
    );
    return;
  }

  // Page navigations → network-first, cached copy (or home) as the offline fallback.
  const accept = req.headers.get('accept') || '';
  if (req.mode === 'navigate' || accept.includes('text/html')) {
    event.respondWith(
      (async () => {
        try {
          const res = await fetch(req);
          if (res && res.ok) {
            const cache = await caches.open(PAGE_CACHE);
            cache.put(req, res.clone());
          }
          return res;
        } catch (err) {
          const cache = await caches.open(PAGE_CACHE);
          return (await cache.match(req)) || (await cache.match('/')) || Response.error();
        }
      })(),
    );
  }
});
