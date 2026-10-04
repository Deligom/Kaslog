// Testlerin ortak kaynak okuyucusu.
//
// Uygulama kodu index.html içindeki <script src> sırasıyla yüklenen klasik
// betiklere bölünmüş durumda (js/*.js). Testler gerçek kodu söküp çalıştırdığı
// için burada AYNI sırayla tek metne birleştirilir: tarayıcıda hangi sırayla
// çalışıyorsa test de onu görür.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const HTML = readFileSync(join(ROOT, 'index.html'), 'utf8');
export const BODY = HTML.slice(HTML.indexOf('<body>'));
export const SCRIPT_FILES = [...HTML.matchAll(/<script src="([^"]+)"><\/script>/g)].map(m => m[1]);
export const JS = SCRIPT_FILES.map(f => readFileSync(join(ROOT, f), 'utf8')).join('\n');
export const CSS = readFileSync(join(ROOT, 'css/app.css'), 'utf8');

export function slice(startMark, endMark, label) {
  const a = JS.indexOf(startMark);
  if (a < 0) throw new Error(`bulunamadı: ${label} (başlangıç)`);
  const b = JS.indexOf(endMark, a);
  if (b < 0) throw new Error(`bulunamadı: ${label} (bitiş)`);
  return JS.slice(a, b);
}
