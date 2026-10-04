// ============================================================
// GEMINI PROXY — Güvenli API Erişimi
// ============================================================

// ⚠️  Vercel deploy ettikten sonra kendi URL'ini yaz:
// ── SÜRÜM DAMGASI ─────────────────────────────────────────────
// Her yeni build'de BUILD değerini artır. Ayarlar'ın en altında görünür.
const APP_VERSION = '2.7 beta';
const APP_BUILD   = '2026-10-04.2';
const PROXY_URL = 'https://kaslog19.vercel.app/api/gemini';

// GÜVENLİK NOTU (v2.4):
//   Burada eskiden APP_SECRET vardı ve proxy'ye HMAC imzalı istek atılıyordu.
//   Ancak istemci kodu herkese açık olduğu için o sır da herkese açıktı —
//   imza hiçbir şey kanıtlamıyordu. Kaldırıldı.
//   Kötüye kullanım artık sunucuda engelleniyor: origin beyaz listesi,
//   IP başına hız sınırı ve global günlük tavan (bkz. api/gemini.js).
//   Ortak kota dolduğunda kullanıcı kendi key'ini girmeye yönlendirilir.

// Gemini çağrısı — kişisel key varsa direkt, yoksa güvenli proxy
// JSON bekleyen çağrılar için: düşünme bütçesini kapat, JSON modunu aç.
// (gemini-2.5-flash varsayılan olarak "thinking" yapar; çıktı bütçesini tüketip
//  BOŞ yanıt dönebilir — fotoğraf analiz hatasının en olası sebebi bu.)
const NUT_GEN_CFG = { responseMimeType: 'application/json', maxOutputTokens: 1024, temperature: 0.2, thinkingConfig: { thinkingBudget: 0 } };
let _genCfgSupported = true; // proxy kabul etmezse otomatik kapanır

async function callGemini(contents, model, genCfg) {
  model = model || ST.settings.geminiModel || 'gemini-2.5-flash';

  // Kişisel key ayarlı → direkt çağrı (gelişmiş kullanıcılar için)
  if (ST.settings.geminiKey?.trim()) {
    const body = { contents };
    if (genCfg) body.generationConfig = genCfg;
    const resp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${ST.settings.geminiKey.trim()}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body) }
    );
    return resp.json();
  }

  // Proxy üzerinden — ortak kota. Sır yok; koruma sunucu tarafında.
  const useCfg = !!(genCfg && _genCfgSupported);
  const payload = useCfg ? { model, contents, generationConfig: genCfg } : { model, contents };

  const resp = await fetch(PROXY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    let errMsg = typeof err.error === 'string' ? err.error : (err.error?.message || err.message || '');
    const code = err.code || '';

    // Kota bitti → kullanıcıya kendi key'ini girmesini söyleyeceğiz.
    // Üç ayrı durum aynı çözüme çıkar: kişisel key gir.
    if (code === 'RATE_LIMIT_GLOBAL' || code === 'RATE_LIMIT_UPSTREAM') errMsg = 'SHARED_QUOTA_OUT';
    else if (code === 'RATE_LIMIT_IP') errMsg = 'RATE_LIMIT_IP:' + (err.retryAfter || 0);
    else if (code === 'ORIGIN_DENIED') errMsg = 'ORIGIN_DENIED';
    else if (code === 'TOO_LARGE' || resp.status === 413) errMsg = 'too large';
    // Proxy'den gelen İngilizce sistem mesajlarını Türkçeleştir
    else if (!errMsg || errMsg.includes('high demand') || errMsg.includes('overloaded') || resp.status === 503 || resp.status === 529)
      errMsg = 'high demand'; // Üst katmanda yakalanacak
    else if (resp.status === 429 || errMsg.includes('quota') || errMsg.includes('RESOURCE_EXHAUSTED'))
      errMsg = 'SHARED_QUOTA_OUT';
    else if (resp.status === 401 || resp.status === 403)
      errMsg = 'API_KEY invalid';
    else
      errMsg = errMsg || `Proxy hatası (${resp.status})`;
    // Eski bir proxy sürümü hâlâ ayaktaysa generationConfig'i reddedebilir.
    // Tanımadığımız bir 400 gelirse configsiz bir kez daha dene.
    if (useCfg && resp.status === 400 && !code) {
      _genCfgSupported = false;
      return callGemini(contents, model, null);
    }
    throw new Error(errMsg);
  }
  return resp.json();
}

// ============================================================
// DB
// ============================================================
const DB = (() => {
  let db;
  function open() {
    return new Promise((res,rej) => {
      // v4: mealRoutines (öğrenilen öğün rutinleri)
      // v5: nutQueue (service worker'ın arka planda göndereceği AI istekleri)
      const req = indexedDB.open('KaslogDB2',5);
      req.onupgradeneeded = e => {
        const d = e.target.result;
        ['settings','routines','workoutLogs','measurements','customExercises','prs','nutritionLogs','foodDb','mealRoutines','nutQueue'].forEach(s => {
          if (!d.objectStoreNames.contains(s)) d.createObjectStore(s,{keyPath:'id'});
        });
      };
      req.onsuccess = e => {
        db = e.target.result;
        // Başka bir bağlam (service worker, eski sekme) sürüm yükseltmek ya da
        // veritabanını silmek isterse bağlantıyı bırak; yoksa o işlem sonsuza
        // kadar bekler ("Tüm verileri sil" sessizce takılıyordu).
        db.onversionchange = () => { db.close(); db = null; };
        res(db);
      };
      req.onerror = () => rej(req.error);
      req.onblocked = () => console.warn('[kaslog] veritabanı açılışı başka bir bağlam tarafından bekletiliyor');
    });
  }
  function close() { if (db) { db.close(); db = null; } }
  const tx = (s,m='readonly') => db.transaction(s,m).objectStore(s);
  const get = (s,id) => new Promise((res,rej) => { const r=tx(s).get(id); r.onsuccess=()=>res(r.result||null); r.onerror=()=>rej(r.error); });
  const getAll = (s) => new Promise((res,rej) => { const r=tx(s).getAll(); r.onsuccess=()=>res(r.result||[]); r.onerror=()=>rej(r.error); });
  const put = (s,d) => new Promise((res,rej) => { const r=tx(s,'readwrite').put(d); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); });
  const del = (s,id) => new Promise((res,rej) => { const r=tx(s,'readwrite').delete(id); r.onsuccess=()=>res(); r.onerror=()=>rej(r.error); });
  return {open,close,get,getAll,put,del};
})();
