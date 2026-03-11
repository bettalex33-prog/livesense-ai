const CACHE_NAME = 'livesense-v6';
const OFFLINE_URLS = ['/', '/index.html', '/manifest.json'];

// ── Install: cache core files ─────────────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(OFFLINE_URLS))
  );
  self.skipWaiting();
});

// ── Activate: clean old caches ────────────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── Fetch: serve from cache when offline ─────────────────────────────────────
self.addEventListener('fetch', event => {
  if (event.request.url.includes('localhost:3001')) return; // Don't cache API
  event.respondWith(
    fetch(event.request)
      .then(res => {
        const clone = res.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        return res;
      })
      .catch(() => caches.match(event.request))
  );
});

// ── Push notifications ────────────────────────────────────────────────────────
self.addEventListener('push', event => {
  const data = event.data?.json() || {};
  event.waitUntil(
    self.registration.showNotification(data.title || '🧠 Live Sense AI Alert', {
      body: data.body || 'Patient alert — check the dashboard',
      icon: 'icon-192.png',
      badge: 'icon-192.png',
      vibrate: [200, 100, 200],
      tag: 'patient-alert',
      requireInteraction: data.critical || false,
      data: { url: data.url || '/' },
      actions: [
        { action: 'view', title: '👁 View Patient' },
        { action: 'dismiss', title: 'Dismiss' }
      ]
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'view') {
    event.waitUntil(clients.openWindow(event.notification.data.url));
  }
});

// ── Background sync: queue vitals when offline ────────────────────────────────
self.addEventListener('sync', event => {
  if (event.tag === 'sync-vitals') {
    event.waitUntil(syncOfflineVitals());
  }
});

async function syncOfflineVitals() {
  const cache = await caches.open('offline-vitals');
  const keys = await cache.keys();
  for (const req of keys) {
    const res = await cache.match(req);
    const body = await res.json();
    try {
      await fetch(req, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      await cache.delete(req);
    } catch (e) {}
  }
}
