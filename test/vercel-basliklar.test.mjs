// ============================================================
// Kaslog güvenlik başlıkları (vercel.json) testleri
//
// Çalıştırma: node test/vercel-basliklar.test.mjs
//
// İki şeyi doğrular:
//   1. CSP, kodun gerçekten ulaştığı her dış adresi İÇERİYOR (yoksa canlıda sessizce
//      bozulur: AI/besin araması çalışmaz) ve tehlikeli gevşeklikler (joker, eval) YOK.
//   2. Yerel sunucunun (tools/yerel-sunucu.mjs) başlık eşlemesi vercel.json ile uyumlu.
// ============================================================

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, JS, HTML } from './_kaynak.mjs';
import { baslikKurallari, basliklariUygula } from '../tools/yerel-sunucu.mjs';

let pass = 0, fail = 0;
function check(label, actual, expected) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; console.log(`  ✓ ${label}`); }
  else { fail++; console.log(`  ✗ ${label}\n      beklenen: ${e}\n      gelen   : ${a}`); }
}
const scenario = n => console.log(`\n▸ ${n}`);

const vercel = JSON.parse(readFileSync(join(ROOT, 'vercel.json'), 'utf8'));
const kurallar = baslikKurallari(vercel);
const sayfa = basliklariUygula(kurallar, '/index.html');
const cspMetni = sayfa['Content-Security-Policy'] || '';
const csp = Object.fromEntries(cspMetni.split(';').map(s => s.trim()).filter(Boolean).map(d => {
  const [ad, ...deger] = d.split(/\s+/); return [ad, deger];
}));

scenario('CSP: kodun ulaştığı adresler izinli');
check('sayfaya CSP gönderiliyor', cspMetni.length > 0, true);
const hostlar = s => [...s.matchAll(/https:\/\/([a-z0-9.-]+)/gi)].map(m => m[1].toLowerCase());
// fetch( içeren satırlardaki ve sabitlerdeki (PROXY_URL) adresler
const fetchHostlari = new Set();
for (const satir of JS.split('\n')) if (/fetch\(|PROXY_URL\s*=/.test(satir)) hostlar(satir).forEach(h => fetchHostlari.add(h));
const izinliBaglanti = new Set(hostlar((csp['connect-src'] || []).join(' ')));
const eksik = [...fetchHostlari].filter(h => !izinliBaglanti.has(h));
check('fetch ile ulaşılan her dış adres connect-src içinde', eksik, []);
check('connect-src "self" içeriyor (yerel veri/yemek tablosu)', (csp['connect-src'] || []).includes("'self'"), true);

const dis = [...HTML.matchAll(/(?:href|src)="(https:\/\/[^"]+)"/g)].map(m => new URL(m[1]).host);
const stilFont = new Set([...hostlar((csp['style-src'] || []).join(' ')), ...hostlar((csp['font-src'] || []).join(' '))]);
check('index.html\'in yüklediği dış kaynaklar (yazı tipi) izinli', dis.filter(h => !stilFont.has(h) && h !== 'fonts.googleapis.com'), []);
check('Google Fonts CSS ve dosyaları izinli', ['fonts.googleapis.com', 'fonts.gstatic.com'].every(h => stilFont.has(h)), true);

scenario('CSP: tehlikeli gevşeklik yok');
const tum = cspMetni;
check('joker (*) kaynak yok', /(^|\s)\*(\s|;|$)/.test(tum), false);
check('unsafe-eval yok', tum.includes('unsafe-eval'), false);
check('object-src none', csp['object-src'], ["'none'"]);
check('base-uri self', csp['base-uri'], ["'self'"]);
check('frame-ancestors none (tıklama hırsızlığı)', csp['frame-ancestors'], ["'none'"]);
check('form-action self', csp['form-action'], ["'self'"]);
check('görseller yalnız yerel/data/blob (görüntü işaretçisiyle sızdırma yok)', csp['img-src'], ["'self'", 'data:', 'blob:']);
check('default-src self', csp['default-src'], ["'self'"]);
check('uygulama kodunda eval/new Function yok', /\beval\(|new Function\(/.test(JS), false);

scenario('Diğer başlıklar ve eşleme');
check('nosniff', sayfa['X-Content-Type-Options'], 'nosniff');
check('çerçeveleme yasak', sayfa['X-Frame-Options'], 'DENY');
check('Referrer-Policy', sayfa['Referrer-Policy'], 'strict-origin-when-cross-origin');
check('/sw.js önbelleğe takılmaz (güncelleme hemen gelsin)', basliklariUygula(kurallar, '/sw.js')['Cache-Control'], 'no-cache');
check('/api/* yanıtları saklanmaz', basliklariUygula(kurallar, '/api/gemini')['Cache-Control'], 'no-store');
check('/js/*.js de CSP alır (joker kural)', 'Content-Security-Policy' in basliklariUygula(kurallar, '/js/core.js'), true);

console.log(`\n${fail ? '✗' : '✓'} ${pass}/${pass + fail} kontrol geçti`);
process.exit(fail ? 1 : 0);
