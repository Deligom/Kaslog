// ============================================================
// Yerel geliştirme sunucusu — vercel.json'daki başlıkları BİREBİR uygular
//
//   node tools/yerel-sunucu.mjs            (varsayılan: http://localhost:4173)
//   PORT=8080 node tools/yerel-sunucu.mjs
//
// Neden `python -m http.server` değil: o sunucu hiçbir güvenlik başlığı göndermez.
// Içerik Güvenliği Politikası (CSP) gibi başlıklar yalnızca canlıda devreye
// girerse bir kaynağın engellendiği ancak yayına çıkınca anlaşılır. Burada aynı
// başlıklar yerelde de gelir; tarayıcı konsolunda "Refused to ..." görürsen
// politika bir şeyi gerçekten engelliyordur.
//
// /api/* uçları burada ÇALIŞMAZ (Vercel fonksiyonları): yalnızca statik dosyalar.
// ============================================================

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const KOK = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.PORT) || 4173;
const TURLER = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json',
};

/** vercel.json "headers" kurallarını yükle. source: "/api/(.*)", "/(.*)", "/sw.js" gibi basit kalıplar. */
export function baslikKurallari(vercelJson) {
  const kurallar = [];
  for (const k of vercelJson.headers || []) {
    const re = new RegExp('^' + k.source.replace(/[.+?^${}|[\]\\]/g, '\\$&').replace(/\(\\\.\*\)|\(\.\*\)/g, '.*') + '$');
    kurallar.push({ re, headers: k.headers });
  }
  return kurallar;
}

export function basliklariUygula(kurallar, urlYolu) {
  const out = {};
  for (const k of kurallar) if (k.re.test(urlYolu)) for (const h of k.headers) out[h.key] = h.value;
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const kurallar = baslikKurallari(JSON.parse(fs.readFileSync(path.join(KOK, 'vercel.json'), 'utf8')));
  http.createServer((req, res) => {
    let yol = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (yol.endsWith('/')) yol += 'index.html';
    const dosya = path.normalize(path.join(KOK, yol));
    if (!dosya.startsWith(KOK) || dosya.includes(path.sep + '.git' + path.sep)) { res.writeHead(403).end('403'); return; }
    fs.readFile(dosya, (err, veri) => {
      const basliklar = { ...basliklariUygula(kurallar, yol) };
      if (err) { res.writeHead(404, basliklar).end('404'); return; }
      basliklar['Content-Type'] = TURLER[path.extname(dosya)] || 'application/octet-stream';
      res.writeHead(200, basliklar).end(veri);
    });
  }).listen(PORT, () => console.log(`Kaslog yerel sunucu: http://localhost:${PORT}  (vercel.json başlıklarıyla)`));
}
