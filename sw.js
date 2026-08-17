// Kaslog Service Worker
// ÖNEMLİ: Her yeni sürümde CACHE adını değiştir — eski cache otomatik silinir.
const CACHE = 'kaslog-v2.5.1';
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

// ============================================================
// ARKA PLAN BESLENME KUYRUĞU (Background Sync)
//
// Sayfa kapalıyken JavaScript durur; bunu değiştiremeyiz. Yapabildiğimiz şey
// tarayıcının service worker'ı uyandırıp bekleyen AI isteğini GÖNDERMESİ.
// Böylece Gemini'nin 5-30 saniyelik yanıt süresi uygulama kapalıyken geçer;
// kullanıcı uygulamayı açtığında sonuç hazır olur ve anında işlenir.
//
// Service worker kasten "aptal" tutuldu: sadece hazır istek gövdesini POST
// eder ve ham yanıtı saklar. Ayrıştırma/JSON kurtarma mantığı sayfada kalır,
// yani iki yerde kopyalanmaz ve burada bozulmaz.
//
// Sınırlar (dürüstçe): Background Sync Chrome/Android'de çalışır, iOS
// Safari'de YOKTUR. Tetiklenme zamanı tarayıcının insafındadır. Çalışmazsa
// sayfa açıldığında istek normal şekilde gönderilir — hiçbir şey kaybolmaz.
// ============================================================

const QUEUE_STORE = 'nutQueue';

function openDb() {
  return new Promise((res, rej) => {
    // Sürüm VERİLMİYOR: şema yönetimi sayfaya ait. Burada sürüm belirtmek
    // sayfa yükseltme yaparken kilitlenmeye yol açardı.
    const r = indexedDB.open('KaslogDB2');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}

function txStore(db, mode) {
  return db.transaction(QUEUE_STORE, mode).objectStore(QUEUE_STORE);
}

function idbReq(req) {
  return new Promise((res, rej) => {
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

async function flushNutQueue() {
  let db;
  try { db = await openDb(); } catch { return; }
  if (!db.objectStoreNames.contains(QUEUE_STORE)) return;

  let jobs = [];
  try { jobs = await idbReq(txStore(db, 'readonly').getAll()) || []; } catch { return; }

  const waiting = jobs.filter(j => j && j.status === 'pending' && j.url && j.body);
  for (const job of waiting) {
    try {
      const resp = await fetch(job.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(job.body),
      });
      const text = await resp.text();
      await idbReq(txStore(db, 'readwrite').put({
        ...job, status: resp.ok ? 'done' : 'failed',
        httpStatus: resp.status, response: text, finishedAt: Date.now(),
      }));
    } catch (err) {
      // Ağ hâlâ yok: 'pending' bırak ki bir sonraki sync tekrar denesin.
      await idbReq(txStore(db, 'readwrite').put({
        ...job, lastError: String(err && err.message || err), triedAt: Date.now(),
      })).catch(() => {});
    }
  }

  // Sayfa açıksa hemen haber ver — beklemeden işlesin
  const clients = await self.clients.matchAll({ includeUncontrolled: true });
  for (const c of clients) c.postMessage({ type: 'nut-queue-flushed' });
}

self.addEventListener('sync', e => {
  if (e.tag === 'kaslog-nut-queue') e.waitUntil(flushNutQueue());
});

// Background Sync desteklenmiyorsa sayfa bunu doğrudan tetikleyebilir
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'flush-nut-queue') e.waitUntil(flushNutQueue());
});
