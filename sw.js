// Kaslog Service Worker
// ÖNEMLİ: Her yeni sürümde CACHE adını değiştir — eski cache otomatik silinir.
const CACHE = 'kaslog-v2.3';
const STATIC = [
  './',
  './index.html'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  // Sadece GET isteklerini cache'le
  if(e.request.method !== 'GET') return;

  const url = e.request.url;
  // API/dış servis isteklerini cache'leme
  if(url.includes('firestore') || url.includes('googleapis') ||
     url.includes('anthropic') || url.includes('openfoodfacts') ||
     url.includes('/api/')) return;

  // Ağ öncelikli (network-first): çevrimiçiyken HER ZAMAN güncel sürüm gelir,
  // çevrimdışıyken cache'e düşer.
  e.respondWith(
    fetch(e.request)
      .then(res => {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
