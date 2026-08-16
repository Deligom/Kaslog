// ============================================================
// Kaslog proxy güvenlik testleri
//
// Çalıştırma (bağımlılık yok, sadece Node 18+):
//   node test/proxy.test.mjs
//
// Gemini'ye ve Upstash'e GERÇEK istek atılmaz; ikisi de taklit edilir.
//
// Her senaryo ayrı bir alt süreçte koşar: hız sınırı sayaçları süreç
// belleğinde tutulduğu için aynı süreçte koşan testler birbirini kirletir.
// ============================================================

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const MODES = ['temel', 'hiz', 'global', 'legacy', 'redis', 'redisKopuk'];
const SELF = fileURLToPath(import.meta.url);
const MODE = process.argv[2];

// ── Alt süreç yoksa: tüm modları sırayla çalıştır ve özetle ──
if (!MODE) {
  let failed = 0;
  for (const m of MODES) {
    const r = spawnSync(process.execPath, [SELF, m], { stdio: 'inherit' });
    if (r.status !== 0) failed++;
  }
  console.log(failed ? `\n✗ ${failed}/${MODES.length} senaryo başarısız` : `\n✓ ${MODES.length}/${MODES.length} senaryo geçti`);
  process.exit(failed ? 1 : 0);
}

// ── Ortam ────────────────────────────────────────────────────
process.env.GEMINI_KEY      = 'test-key';
process.env.ALLOWED_ORIGINS = 'https://kaslog19.vercel.app';
// Doğrulama testleri hız sınırından ÖNCE takılmasın diye limitler bol
// tutulur; sınırı ölçen senaryolar kendi düşük değerini ayarlar.
process.env.RATE_IP_HOUR    = MODE === 'hiz'    ? '3' : '100000';
process.env.RATE_IP_DAY     = MODE === 'hiz'    ? '50' : '100000';
process.env.RATE_GLOBAL_DAY = MODE === 'global' ? '3' : '100000';

if (MODE === 'redis' || MODE === 'redisKopuk') {
  process.env.UPSTASH_REDIS_REST_URL   = 'https://sahte-upstash.invalid';
  process.env.UPSTASH_REDIS_REST_TOKEN = 'sahte-token';
  process.env.RATE_IP_HOUR = '3';
}

// ── Sahte upstream'ler ───────────────────────────────────────
const redisStore = new Map();
let sent = null, upstreamCalls = 0, redisCalls = 0;

globalThis.fetch = async (url, opts) => {
  if (String(url).includes('sahte-upstash')) {
    redisCalls++;
    if (MODE === 'redisKopuk') throw new Error('ECONNREFUSED');
    // Upstash /pipeline davranışı: her komut için { result }
    const cmds = JSON.parse(opts.body);
    const out = cmds.map(([cmd, key]) => {
      if (cmd === 'INCR') { const v = (redisStore.get(key) || 0) + 1; redisStore.set(key, v); return { result: v }; }
      return { result: 1 }; // EXPIRE
    });
    return { ok: true, status: 200, json: async () => out };
  }
  upstreamCalls++;
  sent = opts?.body ? JSON.parse(opts.body) : null;
  return { ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text: 'ok' }] } }] }) };
};

const { default: handler } = await import('../api/gemini.js');

// ── Yardımcılar ──────────────────────────────────────────────
function mockRes() {
  const r = { statusCode: 0, body: null, headers: {} };
  r.setHeader = (k, v) => { r.headers[k] = v; };
  r.status = (c) => { r.statusCode = c; return r; };
  r.json = (b) => { r.body = b; return r; };
  r.end = () => r;
  return r;
}

const OK_ORIGIN = 'https://kaslog19.vercel.app';
const goodContents = [{ parts: [{ text: 'merhaba' }] }];

// DİKKAT: origin için varsayılan parametre kullanma — `origin: undefined`
// geçince varsayılan devreye girer ve "origin yok" senaryosu test edilemez.
async function call(opts = {}) {
  const headers = { 'x-forwarded-for': opts.ip || '1.2.3.4' };
  if ('origin' in opts) { if (opts.origin != null) headers.origin = opts.origin; }
  else headers.origin = OK_ORIGIN;
  const req = { method: opts.method || 'POST', headers, body: opts.body || {} };
  const res = mockRes();
  await handler(req, res);
  return res;
}

let pass = 0, fail = 0;
const check = (name, cond, extra = '') => {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra ? ' → ' + extra : '')); }
};
const tag = (r) => r.statusCode + (r.body?.code ? ':' + r.body.code : '');

// ── Senaryolar ───────────────────────────────────────────────
if (MODE === 'temel') {
  console.log('\n[1] Origin beyaz listesi');
  let r = await call({ origin: 'https://kotu-site.com', body: { contents: goodContents } });
  check('yabancı origin reddedilir', r.statusCode === 403 && r.body.code === 'ORIGIN_DENIED', tag(r));
  r = await call({ origin: null, body: { contents: goodContents } });
  check('Origin başlığı yoksa reddedilir (curl)', r.statusCode === 403 && r.body.code === 'ORIGIN_DENIED', tag(r));
  r = await call({ origin: OK_ORIGIN + '/', body: { contents: goodContents } });
  check('sondaki eğik çizgi tolere edilir', r.statusCode === 200, tag(r));
  r = await call({ body: { contents: goodContents } });
  check('izinli origin geçer', r.statusCode === 200, tag(r));
  check('CORS yalnızca izinli origin\'i yansıtır', r.headers['Access-Control-Allow-Origin'] === OK_ORIGIN);
  check('Vary: Origin gönderilir', r.headers['Vary'] === 'Origin');

  console.log('\n[2] Gövde doğrulama');
  r = await call({ body: { model: 'gpt-4', contents: goodContents } });
  check('beyaz listede olmayan model reddedilir', r.statusCode === 400 && r.body.code === 'BAD_MODEL', tag(r));
  r = await call({ body: { contents: [] } });
  check('boş contents reddedilir', r.statusCode === 400 && r.body.code === 'BAD_CONTENTS', tag(r));
  r = await call({ body: { contents: [{ parts: [{ inlineData: { data: 'A'.repeat(1_600_000) } }] }] } });
  check('devasa görsel reddedilir', r.statusCode === 400 && r.body.code === 'BAD_CONTENTS', tag(r));
  r = await call({ body: { contents: Array.from({ length: 9 }, () => ({ parts: [{ text: 'x' }] })) } });
  check('çok fazla tur reddedilir', r.statusCode === 400 && r.body.code === 'BAD_CONTENTS', tag(r));

  console.log('\n[3] generationConfig temizliği');
  r = await call({ body: { contents: goodContents, generationConfig: {
    maxOutputTokens: 999999, temperature: 0.2, kotuAlan: 'zararlı', thinkingConfig: { thinkingBudget: 0 } } } });
  const gc = sent?.generationConfig || {};
  check('maxOutputTokens 8192\'ye tavanlanır', gc.maxOutputTokens === 8192, JSON.stringify(gc));
  check('bilinmeyen alan atılır', gc.kotuAlan === undefined);
  check('thinkingBudget korunur', gc.thinkingConfig?.thinkingBudget === 0);
  check('temperature korunur', gc.temperature === 0.2);
}

if (MODE === 'hiz') {
  console.log('\n[4] IP başına hız sınırı (saatlik = 3)');
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push(tag(await call({ ip: '5.5.5.5', body: { contents: goodContents } })));
  check('ilk 3 istek geçer', codes.slice(0, 3).every(c => c === '200'), codes.join(' | '));
  check('4. ve 5. istek engellenir', codes[3] === '429:RATE_LIMIT_IP' && codes[4] === '429:RATE_LIMIT_IP', codes.join(' | '));
  const r = await call({ ip: '6.6.6.6', body: { contents: goodContents } });
  check('başka IP etkilenmez', r.statusCode === 200, tag(r));
}

if (MODE === 'global') {
  console.log('\n[5] Global günlük tavan (= 3)');
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push(tag(await call({ ip: '10.0.0.' + i, body: { contents: goodContents } })));
  check('ilk 3 istek geçer', codes.slice(0, 3).every(c => c === '200'), codes.join(' | '));
  check('tavan aşılınca RATE_LIMIT_GLOBAL', codes[3] === '429:RATE_LIMIT_GLOBAL', codes.join(' | '));
  const r = await call({ ip: '11.0.0.1', body: { contents: goodContents } });
  check('Retry-After başlığı gönderilir', Number(r.headers['Retry-After']) > 0, String(r.headers['Retry-After']));
}

if (MODE === 'legacy') {
  console.log('\n[6] Eski istemci uyumluluğu (v2.3 payload sarmalı)');
  const r = await call({ body: { payload: { model: 'gemini-2.5-flash', contents: goodContents },
                                 timestamp: Date.now(), nonce: 'abc', signature: 'deadbeef' } });
  check('sarmalanmış payload kabul edilir', r.statusCode === 200, tag(r));
  check('contents doğru iletilir', sent?.contents?.[0]?.parts?.[0]?.text === 'merhaba', JSON.stringify(sent));
  const r2 = await call({ body: { contents: goodContents } });
  check('yeni düz format da kabul edilir', r2.statusCode === 200, tag(r2));
}

if (MODE === 'redis') {
  console.log('\n[7] Upstash Redis yolu (saatlik = 3)');
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push(tag(await call({ ip: '7.7.7.7', body: { contents: goodContents } })));
  check('Redis gerçekten çağrılır', redisCalls === 5, 'redisCalls=' + redisCalls);
  check('ilk 3 istek geçer', codes.slice(0, 3).every(c => c === '200'), codes.join(' | '));
  check('4. istek engellenir', codes[3] === '429:RATE_LIMIT_IP', codes.join(' | '));
  // INCR sonuçları pipeline'da 0/2/4 indekslerinden okunuyor; yanlış indeks
  // sessizce "limit hiç çalışmıyor" demek olurdu.
  const ipHourKey = [...redisStore.keys()].find(k => k.includes('7.7.7.7') && k.includes(':h'));
  check('IP-saat sayacı 5 kez arttı', redisStore.get(ipHourKey) === 5, `${ipHourKey}=${redisStore.get(ipHourKey)}`);
  const globalKey = [...redisStore.keys()].find(k => k.startsWith('kaslog:all:'));
  check('global sayaç da arttı', redisStore.get(globalKey) === 5, `${globalKey}=${redisStore.get(globalKey)}`);
}

if (MODE === 'redisKopuk') {
  console.log('\n[8] Redis erişilemezse belleğe düşme (saatlik = 3)');
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push(tag(await call({ ip: '8.8.8.8', body: { contents: goodContents } })));
  check('servis çalışmaya devam eder', codes[0] === '200', codes.join(' | '));
  check('bellek sayacı limiti uygular', codes[3] === '429:RATE_LIMIT_IP', codes.join(' | '));
}

console.log(`  ${MODE}: ${pass} geçti, ${fail} kaldı`);
process.exit(fail ? 1 : 0);
