// ============================================================
// Kaslog — Gemini API Proxy  (v3)
// Vercel Serverless Function
//
// NEDEN DEĞİŞTİ (v2.3 → v3):
//   v2.3 HMAC-SHA256 imza doğruluyordu, ama imza anahtarı (APP_SECRET)
//   index.html içinde düz metin ve depo herkese açıktı. Sırrı herkes
//   görebildiği için imza "bu istek Kaslog'dan geldi" garantisi
//   VERMİYORDU — sahte güvenlikti. Kaldırıldı.
//
//   Uygulama herkese açık olduğu için istemciyle saldırganı ayırt edecek
//   bir sır yok. O yüzden hedef "erişimi imkânsız kılmak" değil,
//   ZARAR TAVANINI SABİTLEMEK:
//
//   1. Origin beyaz listesi     → tarayıcıdan gelen rastgele kullanımı keser
//   2. IP başına hız sınırı     → tek kişinin kotayı süpürmesini engeller
//   3. Global günlük tavan      → en kötü senaryoda toplam harcamayı sabitler
//   4. Model beyaz listesi      → beklenmedik/pahalı model çağrısını önler
//   5. generationConfig filtresi→ maxOutputTokens'ı tavanlar
//   6. Gövde/parça sınırları    → dev payload ile maliyet şişirmeyi önler
//
//   Kotası dolan kullanıcı istemcide "kendi Gemini key'ini gir" akışına
//   yönlendirilir (index.html → callGemini kişisel key'i doğrudan kullanır).
//
// ── Vercel Environment Variables ─────────────────────────────
// ZORUNLU:
//   GEMINI_KEY                  Gerçek Gemini API key (asla client'a gitmez)
//
// ÖNERİLEN:
//   ALLOWED_ORIGINS             Virgülle ayrık origin listesi.
//                               Örn: https://kaslog19.vercel.app
//                               Boşsa Vercel'in kendi production/preview
//                               URL'leri otomatik kabul edilir.
//   UPSTASH_REDIS_REST_URL      Upstash Redis REST endpoint'i (hız sınırı
//   UPSTASH_REDIS_REST_TOKEN    paylaşımlı sayılsın diye). Vercel Marketplace
//                               entegrasyonu KV_REST_API_* adıyla da kurar;
//                               ikisi de desteklenir. Yoksa bellek içi
//                               sayaca düşer (zayıf ama çalışır).
//
// OPSİYONEL (sayılar):
//   RATE_IP_HOUR    varsayılan 20    tek IP / saat
//   RATE_IP_DAY     varsayılan 60    tek IP / gün
//   RATE_GLOBAL_DAY varsayılan 1500  tüm kullanıcılar / gün
//   ALLOW_LOCALHOST 1 → http://localhost:* kabul edilir (yerel geliştirme)
//   ORIGIN_ENFORCE  off → origin kontrolü kapanır (acil kaçış kapısı)
//
// ARTIK KULLANILMIYOR: APP_SECRET. Vercel'den SİL.
// ============================================================

// Origin kontrolü ve hız sınırı api/_shared.js'te: usda.js ile AYNI kodu ve
// AYNI sayaçları paylaşıyorlar. İki yerde kopyalanırsa biri düzeltilip
// diğeri unutuluyor.
import { applyCorsAndOrigin, clientIp, checkRateLimit, sendRateLimited } from './_shared.js';

const GEMINI_KEY = process.env.GEMINI_KEY;

// İzin verilen Gemini modelleri — beklenmedik model enjeksiyonunu önler
const ALLOWED_MODELS = new Set([
  'gemini-2.5-flash',
  'gemini-2.5-pro',
  'gemini-3-flash-preview',
  'gemini-3.1-flash-lite-preview',
  'gemini-3.1-pro-preview',
  'gemini-2.0-flash',
  'gemini-1.5-flash',
]);

// generationConfig içinde iletilmesine izin verilen alanlar
const ALLOWED_GEN_KEYS = new Set([
  'temperature', 'topP', 'topK', 'maxOutputTokens',
  'responseMimeType', 'responseSchema', 'stopSequences',
  'candidateCount', 'thinkingConfig', 'seed',
]);

const MAX_OUTPUT_TOKENS_CAP = 8192;      // maliyet güvenliği
const MAX_BODY_CHARS        = 4_000_000; // ~4 MB — Vercel platform sınırının altı
const MAX_CONTENTS          = 8;         // tur sayısı
const MAX_PARTS_TOTAL       = 12;        // toplam metin+görsel parçası
const MAX_INLINE_CHARS      = 1_500_000; // tek görselin base64 uzunluğu (~1.1 MB)

// ── İstek gövdesi doğrulama ─────────────────────────────────

/**
 * generationConfig'i temizle: sadece bilinen alanları geçir,
 * maxOutputTokens'ı sınırla. Bilinmeyen alan gelirse yok sayılır.
 */
function sanitizeGenerationConfig(cfg) {
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return null;
  const out = {};
  for (const [k, v] of Object.entries(cfg)) {
    if (!ALLOWED_GEN_KEYS.has(k)) continue;
    if (k === 'maxOutputTokens') {
      const n = Number(v);
      if (Number.isFinite(n) && n > 0) out[k] = Math.min(Math.floor(n), MAX_OUTPUT_TOKENS_CAP);
      continue;
    }
    if (k === 'thinkingConfig') {
      // { thinkingBudget: number } — sadece sayıyı geçir
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        const b = Number(v.thinkingBudget);
        if (Number.isFinite(b) && b >= 0) out.thinkingConfig = { thinkingBudget: Math.floor(b) };
      }
      continue;
    }
    out[k] = v;
  }
  return Object.keys(out).length ? out : null;
}

/** contents'i boyut ve şekil açısından doğrula. Hata varsa mesaj döner. */
function validateContents(contents) {
  if (!Array.isArray(contents) || contents.length === 0) return 'Geçersiz contents';
  if (contents.length > MAX_CONTENTS) return 'Çok fazla mesaj turu';
  let partCount = 0;
  for (const c of contents) {
    const parts = c?.parts;
    if (!Array.isArray(parts) || parts.length === 0) return 'Geçersiz contents parçası';
    partCount += parts.length;
    if (partCount > MAX_PARTS_TOTAL) return 'Çok fazla içerik parçası';
    for (const p of parts) {
      const data = p?.inlineData?.data;
      if (typeof data === 'string' && data.length > MAX_INLINE_CHARS) return 'Görsel çok büyük';
    }
  }
  return null;
}

// ── Handler ─────────────────────────────────────────────────

export default async function handler(req, res) {
  if (!applyCorsAndOrigin(req, res)) return;

  if (!GEMINI_KEY) {
    console.error('[kaslog-proxy] GEMINI_KEY env var eksik');
    return res.status(500).json({ error: 'Sunucu yapılandırılmamış', code: 'NO_SERVER_KEY' });
  }

  const rl = await checkRateLimit(clientIp(req), 'ai');
  if (!rl.ok) return sendRateLimited(res, rl);

  // ── Gövde doğrulama ───────────────────────────────────────
  const body = req.body || {};
  // v2.3 istemcileri payload'ı sarmalayıp gönderiyordu; ikisini de kabul et.
  const payload = body.payload && typeof body.payload === 'object' ? body.payload : body;

  const model = payload.model || 'gemini-2.5-flash';
  if (!ALLOWED_MODELS.has(model)) {
    return res.status(400).json({ error: `İzin verilmeyen model: ${model}`, code: 'BAD_MODEL' });
  }

  const contentsErr = validateContents(payload.contents);
  if (contentsErr) return res.status(400).json({ error: contentsErr, code: 'BAD_CONTENTS' });

  const geminiBody = { contents: payload.contents };
  const genCfg = sanitizeGenerationConfig(payload.generationConfig);
  if (genCfg) geminiBody.generationConfig = genCfg;

  const serialized = JSON.stringify(geminiBody);
  if (serialized.length > MAX_BODY_CHARS) {
    return res.status(413).json({ error: 'İstek çok büyük', code: 'TOO_LARGE' });
  }

  // ── Gemini'ye forward ─────────────────────────────────────
  try {
    const geminiResp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_KEY}`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    serialized,
      }
    );

    const data = await geminiResp.json();

    // Teşhis kolaylığı: boş yanıt geldiyse logla (client de mesaj gösteriyor)
    if (geminiResp.ok) {
      const cand  = data?.candidates?.[0];
      const parts = cand?.content?.parts;
      const hasText = Array.isArray(parts) && parts.some(p => p.text);
      if (!hasText) {
        console.warn('[kaslog-proxy] BOŞ yanıt — finishReason:', cand?.finishReason,
                     '| blockReason:', data?.promptFeedback?.blockReason,
                     '| genCfg:', JSON.stringify(genCfg));
      }
    }

    // Sunucu key'inin kotası dolduysa istemciye net sinyal ver: kullanıcıyı
    // "kendi key'ini gir" akışına yönlendirsin.
    if (geminiResp.status === 429) {
      return res.status(429).json({
        error: 'Ortak Gemini kotası doldu',
        code:  'RATE_LIMIT_UPSTREAM',
      });
    }

    return res.status(geminiResp.ok ? 200 : geminiResp.status).json(data);

  } catch (err) {
    console.error('[kaslog-proxy] Gemini upstream hatası:', err.message);
    return res.status(502).json({ error: 'Upstream bağlantı hatası: ' + err.message, code: 'UPSTREAM' });
  }
}
