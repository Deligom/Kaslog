// ============================================================
// Kaslog — Gemini API Proxy
// Vercel Serverless Function
//
// Güvenlik katmanları:
//   1. HMAC-SHA256 imza doğrulama (APP_SECRET ile)
//   2. Timestamp replay attack koruması (±5 dakika pencere)
//   3. Timing-safe imza karşılaştırma
//   4. Model beyaz listesi
//   5. CORS başlıkları
//
// Vercel Environment Variables (zorunlu):
//   GEMINI_KEY  — Gerçek Gemini API key (asla client'a gönderilmez)
//   APP_SECRET  — HMAC imzalama için paylaşılan sır
//                 (index.html içindeki APP_SECRET ile AYNI olmalı)
// ============================================================

import crypto from 'crypto';

const GEMINI_KEY    = process.env.GEMINI_KEY;
const APP_SECRET    = process.env.APP_SECRET;
const REPLAY_WINDOW = 5 * 60 * 1000; // 5 dakika (ms)

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

/**
 * Sabit zamanlı string karşılaştırma.
 * Normal === karşılaştırması timing attack'e açık olabilir;
 * bu fonksiyon her iki string için aynı süreyi kullanır.
 */
function timingSafeEqual(a, b) {
  // Uzunluklar farklıysa timing bilgisi sızdırma
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) {
    // Yine de karşılaştır (sıfır olmayan zaman), sonra false dön
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

export default async function handler(req, res) {
  // ── CORS ──────────────────────────────────────────────────
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed' });

  // ── Sunucu yapılandırma kontrolü ──────────────────────────
  if (!GEMINI_KEY || !APP_SECRET) {
    console.error('[kaslog-proxy] GEMINI_KEY veya APP_SECRET env var eksik');
    return res.status(500).json({ error: 'Sunucu yapılandırılmamış' });
  }

  const { payload, timestamp, nonce, signature } = req.body || {};

  // ── 1. Alan varlık kontrolü ───────────────────────────────
  if (!payload || timestamp === undefined || !nonce || !signature) {
    return res.status(400).json({ error: 'Eksik alan: payload, timestamp, nonce, signature gerekli' });
  }

  // ── 2. Timestamp tip ve replay koruması ───────────────────
  const ts  = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return res.status(400).json({ error: 'Geçersiz timestamp' });
  }
  const age = Date.now() - ts;
  if (age < -30_000 || age > REPLAY_WINDOW) {
    // -30s tolerans: saat farkı olan cihazlar için
    return res.status(401).json({ error: 'İstek süresi dolmuş veya gelecekten' });
  }

  // ── 3. HMAC-SHA256 imza doğrulama ─────────────────────────
  // Frontend ile tamamen aynı mesaj formatı
  const message     = `${timestamp}:${nonce}:${JSON.stringify(payload)}`;
  const expectedSig = crypto
    .createHmac('sha256', APP_SECRET)
    .update(message)
    .digest('hex');

  if (!timingSafeEqual(signature, expectedSig)) {
    // Hata mesajı kasıtlı belirsiz — neyin yanlış olduğunu saldırgan bilmesin
    return res.status(401).json({ error: 'Yetkisiz istek' });
  }

  // ── 4. Model beyaz listesi ────────────────────────────────
  const model = payload.model || 'gemini-2.5-flash';
  if (!ALLOWED_MODELS.has(model)) {
    return res.status(400).json({ error: `İzin verilmeyen model: ${model}` });
  }

  // ── 5. İçerik alan kontrolü ──────────────────────────────
  if (!Array.isArray(payload.contents) || payload.contents.length === 0) {
    return res.status(400).json({ error: 'Geçersiz contents' });
  }

  // ── 6. Gemini API'ye forward ──────────────────────────────
  try {
    const geminiResp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_KEY}`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ contents: payload.contents }),
      }
    );

    const data = await geminiResp.json();

    // Gemini hata yanıtlarını olduğu gibi ilet
    return res.status(geminiResp.ok ? 200 : geminiResp.status).json(data);

  } catch (err) {
    console.error('[kaslog-proxy] Gemini upstream hatası:', err.message);
    return res.status(502).json({ error: 'Upstream bağlantı hatası: ' + err.message });
  }
}

// Büyük fotoğraflar için body limit artırıldı (varsayılan 1mb → 12mb)
export const config = {
  api: {
    bodyParser: {
      sizeLimit: '12mb',
    },
  },
};
