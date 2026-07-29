/* Minimal, safe service worker — offline reading + fast repeat loads.
 *
 * Strategy (chosen to never serve stale content while online):
 *  - Immutable, content-hashed build assets (/_astro/, /fonts/) → cache-first.
 *    Their filenames change on every change, so a cached copy is never "wrong".
 *  - Page navigations (HTML)  → network-first: always fresh when online, falls
 *    back to the cached copy (then the cached home page) only when offline.
 *  - Everything else is left to the network.
 *
 * Caches are versioned and old ones are purged on activate; the worker takes over
 * immediately (skipWaiting + clients.claim) so a new deploy supersedes the old SW.
 * To force a hard refresh of all caches, bump VERSION.
 */
const VERSION = 'v3';
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

  // Immutable hashed assets → cache-first.
  if (url.pathname.startsWith('/_astro/') || url.pathname.startsWith('/fonts/')) {
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
