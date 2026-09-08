/**
 * Spa Therapist Operations Portal (STOP) — Service Worker
 *
 * Purpose: faster repeat loads (serves the app shell from cache
 * instantly, then refreshes it in the background) and unlocks
 * Android Chrome's native "Install app" prompt, which requires a
 * registered service worker to appear at all.
 *
 * This does NOT provide offline data access — the app depends on a
 * live connection to the Cloudflare Worker for logins, schedules,
 * products, etc. Only same-origin requests (the app file itself) are
 * cached; every request to the sync backend always goes straight to
 * the network, untouched.
 */

const CACHE_NAME = 'stop-shell-v1';

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Never intercept anything but simple GETs (never cache POSTs/writes).
  if(req.method !== 'GET') return;

  const url = new URL(req.url);

  // Only handle same-origin requests (the app shell). Anything going to
  // the Cloudflare Worker or any other origin is left completely alone.
  if(url.origin !== self.location.origin) return;

  event.respondWith(
    caches.open(CACHE_NAME).then(async (cache) => {
      const cached = await cache.match(req);
      const networkFetch = fetch(req)
        .then((res) => {
          if(res && res.ok) cache.put(req, res.clone());
          return res;
        })
        .catch(() => cached);
      // Stale-while-revalidate: serve the cached shell instantly if we
      // have one, while quietly fetching a fresh copy for next time.
      return cached || networkFetch;
    })
  );
});
