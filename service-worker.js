/**
 * The Ledger — Service Worker
 *
 * Purpose: unlocks Android Chrome's native "Install app" prompt, which
 * requires a registered service worker to appear at all, and provides
 * an offline fallback if the app is opened with no connection.
 *
 * Caching strategy: network-first. Every load tries the real network
 * first, so a newly deployed update is visible on the very next load —
 * not the load after that. The cache is only ever consulted as a
 * fallback when there's no network at all. (An earlier version served
 * the cached copy first and refreshed it quietly in the background,
 * which meant a deployed update could take two reopens to actually
 * show up — this version fixes that.)
 *
 * This does NOT provide offline data access — the app depends on a
 * live connection to the Cloudflare Worker for logins, schedules,
 * products, etc. Only same-origin requests (the app file itself) are
 * cached; every request to the sync backend always goes straight to
 * the network, untouched.
 */

const CACHE_NAME = 'stop-shell-v3';

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      // Clear out any cache from a previous version of this service
      // worker, so nothing stale lingers in storage indefinitely.
      caches.keys().then((names) =>
        Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
      ),
    ])
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Never intercept anything but simple GETs (never cache POSTs/writes).
  if(req.method !== 'GET') return;

  const url = new URL(req.url);

  // Only handle same-origin requests (the app shell). Anything going to
  // the Cloudflare Worker or any other origin is left completely alone.
  if(url.origin !== self.location.origin) return;

  // Network-first: always try to fetch the latest version first, so a
  // newly deployed update is visible on the very next load rather than
  // needing an extra reopen. The cache exists purely as an offline
  // fallback for when there's no connection at all — it's a safety net,
  // not the default source of truth the way it was before.
  event.respondWith(
    fetch(req)
      .then((res) => {
        if(res && res.ok){
          caches.open(CACHE_NAME).then((cache) => cache.put(req, res.clone()));
        }
        return res;
      })
      .catch(() => caches.open(CACHE_NAME).then((cache) => cache.match(req)))
  );
});
