// ============================================================
// Kaslog — proxy uçlarının ortak güvenlik katmanı
//
// Alt çizgiyle başlayan dosyalar Vercel tarafından uç (route) sayılmaz,
// yalnızca içe aktarılır. gemini.js ve usda.js aynı origin kontrolünü ve
// aynı hız sınırı sayaçlarını paylaşsın diye burada duruyor: iki yerde
// kopyalanırsa biri düzeltilip diğeri unutuluyor.
// ============================================================

const REDIS_URL   = process.env.UPSTASH_REDIS_REST_URL   || process.env.KV_REST_API_URL   || '';
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || '';

export function num(v, d) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : d;
}

export const RATE_IP_HOUR    = num(process.env.RATE_IP_HOUR,    20);
export const RATE_IP_DAY     = num(process.env.RATE_IP_DAY,     60);
export const RATE_GLOBAL_DAY = num(process.env.RATE_GLOBAL_DAY, 1500);

// ── Origin ──────────────────────────────────────────────────
// Tarayıcı POST isteklerinde Origin başlığını her zaman gönderir ve sayfa
// JS'i bunu değiştiremez. curl ile taklit edilebilir — bu yüzden asıl
// koruma hız sınırıdır; bu katman gelişigüzel kullanımı keser.
export function buildAllowedOrigins() {
  const set = new Set();
  for (const o of (process.env.ALLOWED_ORIGINS || '').split(',')) {
    const t = o.trim().replace(/\/+$/, '');
    if (t) set.add(t);
  }
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) set.add('https://' + process.env.VERCEL_PROJECT_PRODUCTION_URL);
  if (process.env.VERCEL_URL)                    set.add('https://' + process.env.VERCEL_URL);
  return set;
}

export function isOriginAllowed(origin, allowed) {
  if (!origin) return false;
  const o = origin.replace(/\/+$/, '');
  if (allowed.has(o)) return true;
  if (process.env.ALLOW_LOCALHOST === '1' && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o)) return true;
  return false;
}

export function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.headers['x-real-ip'] || 'unknown';
}

/**
 * CORS + origin kontrolünü uygula.
 * @returns {boolean} istek devam edebilir mi (false ise yanıt gönderilmiştir)
 */
export function applyCorsAndOrigin(req, res) {
  const allowed  = buildAllowedOrigins();
  const origin   = req.headers.origin;
  const enforce  = process.env.ORIGIN_ENFORCE !== 'off';
  const originOk = isOriginAllowed(origin, allowed);

  if (originOk) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.status(originOk || !enforce ? 200 : 403).end(); return false; }
  if (req.method !== 'POST')    { res.status(405).json({ error: 'Method not allowed' }); return false; }

  if (enforce && !originOk) {
    // Reddedilen origin'i söylüyoruz: sır değil, kurulum hatasını ayıklatır.
    res.status(403).json({ error: 'İzin verilmeyen origin: ' + (origin || '(yok)'), code: 'ORIGIN_DENIED' });
    return false;
  }
  return true;
}

// ── Hız sınırı ──────────────────────────────────────────────
// Sabit pencere sayaçları. Anahtar adı saat/gün kovasını içerdiği için
// pencere kaydığında anahtar da değişir; eski anahtar TTL ile silinir.

async function redisPipeline(commands) {
  const r = await fetch(REDIS_URL + '/pipeline', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + REDIS_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(commands),
    signal: AbortSignal.timeout(2500),
  });
  if (!r.ok) throw new Error('Redis HTTP ' + r.status);
  return r.json();
}

// Upstash yoksa / erişilemezse devreye giren yedek. Lambda örneği başına
// ayrı sayar ve yeniden başlayınca sıfırlanır — zayıftır ama hiç yoktan iyi.
const memCounters = new Map();
function memIncr(key, ttlSec) {
  const now = Date.now();
  const cur = memCounters.get(key);
  if (!cur || cur.expires <= now) {
    memCounters.set(key, { count: 1, expires: now + ttlSec * 1000 });
    if (memCounters.size > 5000) {
      for (const [k, v] of memCounters) if (v.expires <= now) memCounters.delete(k);
    }
    return 1;
  }
  cur.count++;
  return cur.count;
}

/**
 * Üç sayacı birlikte artırır ve aşılan limiti döner.
 * @param {string} ip
 * @param {string} scope Sayaç ailesi. Uçlar ayrı kovalar kullanabilir;
 *                       varsayılan 'ai' ile gemini ve usda aynı bütçeyi paylaşır.
 * @returns {{ok:true}|{ok:false, scope:'ip'|'global', retryAfter:number}}
 */
export async function checkRateLimit(ip, scope = 'ai') {
  const now  = Date.now();
  const hour = Math.floor(now / 3_600_000);
  const day  = Math.floor(now / 86_400_000);

  const kHour   = `kaslog:${scope}:ip:${ip}:h${hour}`;
  const kDay    = `kaslog:${scope}:ip:${ip}:d${day}`;
  const kGlobal = `kaslog:${scope}:all:d${day}`;

  let hourCount, dayCount, globalCount;

  if (REDIS_URL && REDIS_TOKEN) {
    try {
      const res = await redisPipeline([
        ['INCR', kHour],   ['EXPIRE', kHour, 3600],
        ['INCR', kDay],    ['EXPIRE', kDay, 86400],
        ['INCR', kGlobal], ['EXPIRE', kGlobal, 86400],
      ]);
      hourCount   = Number(res[0]?.result);
      dayCount    = Number(res[2]?.result);
      globalCount = Number(res[4]?.result);
    } catch (err) {
      console.warn('[kaslog-proxy] Redis erişilemedi, bellek sayacına düşüldü:', err.message);
    }
  }

  if (!Number.isFinite(hourCount)) {
    hourCount   = memIncr(kHour, 3600);
    dayCount    = memIncr(kDay, 86400);
    globalCount = memIncr(kGlobal, 86400);
  }

  const secsToNextHour = 3600  - Math.floor((now % 3_600_000) / 1000);
  const secsToNextDay  = 86400 - Math.floor((now % 86_400_000) / 1000);

  if (globalCount > RATE_GLOBAL_DAY) return { ok: false, scope: 'global', retryAfter: secsToNextDay };
  if (dayCount    > RATE_IP_DAY)     return { ok: false, scope: 'ip',     retryAfter: secsToNextDay };
  if (hourCount   > RATE_IP_HOUR)    return { ok: false, scope: 'ip',     retryAfter: secsToNextHour };
  return { ok: true };
}

/** Hız sınırı aşıldıysa yanıtı gönder. @returns {boolean} devam edilebilir mi */
export function sendRateLimited(res, rl) {
  res.setHeader('Retry-After', String(rl.retryAfter));
  res.status(429).json({
    error: rl.scope === 'global' ? 'Ortak günlük kota doldu' : 'Çok fazla istek gönderdin',
    code:  rl.scope === 'global' ? 'RATE_LIMIT_GLOBAL' : 'RATE_LIMIT_IP',
    retryAfter: rl.retryAfter,
  });
  return false;
}
