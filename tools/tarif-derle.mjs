// ============================================================
// Tarif derleyici — bileşik yemekler için kanonik besin tablosu üretir
//
// Çalıştırma:
//   node tools/tarif-derle.mjs                 (yapılandırmadaki tüm yemekler)
//   node tools/tarif-derle.mjs "mercimek çorbası"
//
// NE YAPAR
//   1. Tarif sayfasındaki schema.org/Recipe verisini okur (sayfa HTML'ini
//      ayrıştırmaz — site bu veriyi zaten makineler için yayınlıyor).
//   2. Malzeme satırlarını Türkçe ölçü birimlerine göre grama çevirir.
//   3. Malzeme referans tablosundan besin değerlerini toplar.
//   4. Pişmiş ağırlığı buharlaşma modeliyle tahmin eder.
//   5. Aynı yemeğin birden çok tarifini derleyip MEDYANINI alır.
//   6. Sitenin kendi kalori bilgisiyle çapraz doğrulama yapar.
//
// NE SAKLAR
//   Yalnızca türetilmiş sayılar (100 g başına kcal/protein/karbonhidrat/yağ)
//   ve kaynak URL'leri. Tarif metni, anlatım, fotoğraf SAKLANMAZ.
//
// NEDEN MEDYAN
//   Tek bir tarif aşırı yağlı ya da aşırı sulu olabilir. Ortalama bu aykırı
//   değerden etkilenir, medyan etkilenmez.
// ============================================================

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MALZEMELER, OLCULER, GRAM_BIRIMLER, BUHARLASMA } from './malzeme-tablosu.mjs';

const KOK = path.dirname(fileURLToPath(import.meta.url));
const UA  = 'KaslogRecipeAggregator/1.0 (kisisel beslenme takibi; sadece besin degeri turetir)';
const BEKLE_MS = 1500;   // sitelere yüklenmemek için istekler arası bekleme

// ── Türkçe normalizasyon ────────────────────────────────────
function norm(s) {
  return (s || '').toLocaleLowerCase('tr-TR')
    .replace(/[çÇ]/g,'c').replace(/[ğĞ]/g,'g').replace(/[ıİiI]/g,'i')
    .replace(/[öÖ]/g,'o').replace(/[şŞ]/g,'s').replace(/[üÜ]/g,'u')
    .replace(/[^a-z0-9., ]/g,' ').replace(/\s+/g,' ').trim();
}

// Malzeme adı → tablo kaydı. Alias'lar ve kısmi eşleşme desteklenir.
const ARAMA = [];
for (const [ad, v] of Object.entries(MALZEMELER)) {
  ARAMA.push({ anahtar: norm(ad), ad, v });
  for (const a of v.alias || []) ARAMA.push({ anahtar: norm(a), ad, v });
}
// Uzun adlar önce denensin: "tavuk gogsu", "tavuk"tan önce eşleşmeli
ARAMA.sort((a, b) => b.anahtar.length - a.anahtar.length);

// Parantez içi hazırlık notunu at. Kritik: "2 su bardağı pirinç ((ılık suda
// bekletilmiş))" satırında not içindeki "ılık su", "pirinç"ten UZUN olduğu
// için malzeme SU sanılıyordu — pilav 29 kcal/100g çıkıyordu.
function notlariAt(metin) {
  return String(metin).replace(/\(+[^()]*\)+/g, ' ').replace(/\s+/g, ' ').trim();
}

// Olcu birimlerini ve miktar kelimelerini metinden temizle.
// Uzun birim adlari once silinir: "su bardagi" silinmeden "bardak" silinirse
// geriye "su" kalir ve malzeme sanilir.
const BIRIM_ADLARI = [...Object.keys(OLCULER), ...Object.keys(GRAM_BIRIMLER),
  'adet','dis','demet','bas','dilim','tane','orta boy','buyuk boy','kucuk boy','paket','yarim','ceyrek']
  .sort((a, b) => b.length - a.length);

function birimleriAt(metin) {
  let n = ' ' + norm(metin) + ' ';
  for (const b of BIRIM_ADLARI) n = n.split(' ' + norm(b) + ' ').join(' ');
  return n.replace(/\s+/g, ' ').trim();
}

function malzemeBul(metin) {
  // Regex yerine bosluk dolgulu arama: kacis karakteri derdi yok, kelime
  // siniri garanti. "un" artik "dogranmis" icinde eslesmez.
  // Olcu birimini CIKAR, sonra malzeme ara. Yoksa "2 su bardagi pirinc"
  // satirinda birimin icindeki "su", basa daha yakin oldugu icin "pirinc"i
  // yeniyordu ve pilav 26 kcal/100g cikiyordu.
  const hay = ' ' + norm(birimleriAt(notlariAt(metin))) + ' ';
  let en = null;
  for (const k of ARAMA) {
    const i = hay.indexOf(' ' + k.anahtar + ' ');
    if (i < 0) continue;
    // Malzeme adi miktardan hemen sonra gelir: BASA EN YAKIN olan kazanir,
    // esitlikte daha uzun (daha ozgul) anahtar kazanir.
    if (!en || i < en.poz || (i === en.poz && k.anahtar.length > en.anahtar.length)) en = { ...k, poz: i };
  }
  return en;
}

// "1,5 su bardağı" / "3 yemek kaşığı" / "250 gr" / "2 adet" → sayı + birim
function miktarCoz(satir) {
  const n = norm(notlariAt(satir));
  // Kesirler: "1/2", "yarım", "çeyrek"
  let carpan = 1, kalan = n;
  const kesir = kalan.match(/(\d+)\s*\/\s*(\d+)/);
  let sayi = null;

  if (kesir) { sayi = Number(kesir[1]) / Number(kesir[2]); kalan = kalan.replace(kesir[0], ' '); }
  else {
    const m = kalan.match(/(\d+(?:[.,]\d+)?)/);
    if (m) { sayi = Number(m[1].replace(',', '.')); kalan = kalan.replace(m[0], ' '); }
  }
  if (/\byarim\b/.test(n)) { sayi = (sayi ?? 1) * 0.5; }
  if (/\bceyrek\b/.test(n)) { sayi = (sayi ?? 1) * 0.25; }
  if (sayi == null) sayi = 1;

  // Gram cinsinden birim var mı?
  for (const [b, kat] of Object.entries(GRAM_BIRIMLER)) {
    if (new RegExp('\\b' + b + '\\b').test(kalan)) return { tip: 'gram', deger: sayi * kat };
  }
  // Hacim birimi (uzun adlar önce)
  const olcuAdlari = Object.keys(OLCULER).sort((a, b) => b.length - a.length);
  for (const o of olcuAdlari) {
    if (kalan.includes(norm(o))) return { tip: 'hacim', deger: sayi * OLCULER[o] };
  }
  // "adet", "diş", "demet" → parça
  if (/\b(adet|dis|demet|bas|dilim|tane|orta boy|buyuk boy|kucuk boy)\b/.test(kalan) || /^\s*\d/.test(n)) {
    return { tip: 'parca', deger: sayi };
  }
  return { tip: 'parca', deger: sayi };
}

// Bir malzeme satırını grama çevir
function satirGram(satir) {
  const k = malzemeBul(satir);
  if (!k) return { gram: 0, bilinmeyen: satir };
  const m = miktarCoz(satir);
  let gram;
  if (m.tip === 'gram')       gram = m.deger;
  else if (m.tip === 'hacim') gram = m.deger * (k.v.yog ?? 1);
  else                        gram = m.deger * (k.v.birim ?? 100);   // parça
  return { gram, malzeme: k.ad, v: k.v };
}

// ── schema.org/Recipe çekme ─────────────────────────────────
async function tarifCek(url) {
  const r = await fetch(url, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(25000) });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  const html = await r.text();

  // Sayfadaki tüm ld+json bloklarını topla, içinde Recipe olanı bul
  const bloklar = [...html.matchAll(/<script[^>]*application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(m => m[1]);
  for (const b of bloklar) {
    let veri; try { veri = JSON.parse(b); } catch { continue; }
    const aday = [];
    const gez = (o) => {
      if (!o || typeof o !== 'object') return;
      if (Array.isArray(o)) { o.forEach(gez); return; }
      if (o['@type'] === 'Recipe' || (Array.isArray(o['@type']) && o['@type'].includes('Recipe'))) aday.push(o);
      Object.values(o).forEach(gez);
    };
    gez(veri);
    if (aday.length) return aday[0];
  }
  throw new Error('Recipe şeması bulunamadı');
}

// ── Tek tarifi 100 g başına değere çevir ────────────────────
function tarifHesapla(recipe, kategori) {
  // recipeIngredient bazen iç içe dizi geliyor
  let malzemeler = recipe.recipeIngredient || recipe.ingredients || [];
  if (Array.isArray(malzemeler[0])) malzemeler = malzemeler.flat();
  if (!malzemeler.length) throw new Error('malzeme listesi yok');

  let hamGram = 0, kcal = 0, p = 0, k = 0, y = 0;
  const bilinmeyenler = [];

  for (const satir of malzemeler) {
    const s = satirGram(String(satir));
    if (!s.gram) { bilinmeyenler.push(String(satir)); continue; }
    hamGram += s.gram;
    const f = s.gram / 100;
    kcal += (s.v.kcal || 0) * f;
    p    += (s.v.p    || 0) * f;
    k    += (s.v.k    || 0) * f;
    y    += (s.v.y    || 0) * f;
  }
  if (hamGram <= 0) throw new Error('gram hesaplanamadı');

  // Bilinmeyen malzeme oranı yüksekse bu tarife güvenme
  const bilinmeyenOran = bilinmeyenler.length / malzemeler.length;
  if (bilinmeyenOran > 0.35) throw new Error('malzemelerin %' + Math.round(bilinmeyenOran*100) + "'i tanınmadı");

  const kayip = BUHARLASMA[kategori] ?? 0.12;
  const pismisGram = hamGram * (1 - kayip);

  // Sitenin kendi kalorisi varsa capraz dogrulama + KALIBRASYON.
  // Tarifler "servis icin" sos gruplarini da listeler (mercimek corbasinda
  // uzerine gezdirilen yag + tereyagi ~570 kcal); bunlarin tamamini yemiyoruz.
  // Site rakami tum tarif icin hesaplanmis oldugundan capa olarak kullanilir:
  // makro ORANLARI bizim malzemelerden, TOPLAM siteden gelir.
  // Ama site rakami da bazen sacma (bir tarifte 540 kcal yaziyor, gercek 1865)
  // — yalnizca makul araliktaysa (0.5x-2x) guveniyoruz.
  let dogrulama = null, olcek = 1;
  const kalMetin = recipe.nutrition?.calories;
  const porsiyon = String(recipe.recipeYield || '').match(/(\d+)/);
  if (kalMetin && porsiyon) {
    const kalSayi = Number(String(kalMetin).match(/(\d+)/)?.[1] || 0);
    if (kalSayi > 0 && kcal > 0) {
      // "Toplam 687 kcal" gibi ifadeler zaten TUM tarif icin; porsiyonla
      // carparsak 6 katina cikar. "290 kalori" ise porsiyon basina.
      const toplamMi = /toplam/i.test(String(kalMetin));
      const siteToplam = toplamMi ? kalSayi : kalSayi * Number(porsiyon[1]);
      const oran = siteToplam / kcal;
      const guvenilir = oran >= 0.5 && oran <= 2.0;
      if (guvenilir) olcek = oran;
      dogrulama = { siteToplam, bizimToplam: Math.round(kcal), guvenilir,
                    sapmaYuzde: Math.round((kcal - siteToplam) / siteToplam * 100) };
    }
  }

  const per100 = {
    kcal:    Math.round(kcal * olcek / pismisGram * 100),
    protein: Math.round(p * olcek / pismisGram * 100 * 10) / 10,
    carbs:   Math.round(k * olcek / pismisGram * 100 * 10) / 10,
    fat:     Math.round(y * olcek / pismisGram * 100 * 10) / 10,
  };

  return { per100, hamGram: Math.round(hamGram), pismisGram: Math.round(pismisGram),
           bilinmeyenler, dogrulama, kalibre: olcek !== 1 };
}

const medyan = (a) => {
  const s = [...a].sort((x, y) => x - y);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m-1] + s[m]) / 2;
};

// ── Ana akış ────────────────────────────────────────────────
async function derle(yapilandirma, filtre) {
  const sonuc = {};
  for (const yemek of yapilandirma.yemekler) {
    if (filtre && norm(yemek.ad) !== norm(filtre)) continue;
    console.log('\n=== ' + yemek.ad + ' (' + yemek.kategori + ') ===');
    const olcumler = [];

    for (const url of yemek.kaynaklar) {
      try {
        const recipe = await tarifCek(url);
        const h = tarifHesapla(recipe, yemek.kategori);
        olcumler.push({ url, ...h });
        const d = h.dogrulama;
        console.log('  ✓ ' + h.per100.kcal + ' kcal/100g  (ham ' + h.hamGram + 'g → pişmiş ' + h.pismisGram + 'g)'
          + (d ? '  | site: ' + d.siteToplam + ' kcal, biz: ' + d.bizimToplam + ' kcal, sapma %' + d.sapmaYuzde : '')
          + (h.kalibre ? '  | KALIBRE' : '') + (h.bilinmeyenler.length ? '  | tanınmayan: ' + h.bilinmeyenler.length : ''));
        if (h.bilinmeyenler.length) h.bilinmeyenler.forEach(b => console.log('      ? ' + b));
      } catch (e) {
        console.log('  ✗ ' + url.replace(/^https?:\/\//,'').slice(0,50) + ' — ' + e.message);
      }
      await new Promise(r => setTimeout(r, BEKLE_MS));
    }

    if (!olcumler.length) { console.log('  → kullanılabilir tarif yok, atlandı'); continue; }

    const per100 = {
      kcal:    Math.round(medyan(olcumler.map(o => o.per100.kcal))),
      protein: Math.round(medyan(olcumler.map(o => o.per100.protein)) * 10) / 10,
      carbs:   Math.round(medyan(olcumler.map(o => o.per100.carbs))   * 10) / 10,
      fat:     Math.round(medyan(olcumler.map(o => o.per100.fat))     * 10) / 10,
    };
    const yayilim = Math.max(...olcumler.map(o => o.per100.kcal)) - Math.min(...olcumler.map(o => o.per100.kcal));
    console.log('  → MEDYAN: ' + per100.kcal + ' kcal/100g  (tarifler arası yayılım: ' + yayilim + ' kcal)');

    sonuc[norm(yemek.ad)] = {
      ad: yemek.ad,
      esanlamlilar: yemek.esanlamlilar || [],
      kategori: yemek.kategori,
      per100,
      tarifSayisi: olcumler.length,
      yayilimKcal: yayilim,
      kaynaklar: olcumler.map(o => o.url),
      derlenme: new Date().toISOString().slice(0, 10),
    };
  }
  return sonuc;
}

// ── Çalıştır ────────────────────────────────────────────────
const yapilandirma = JSON.parse(fs.readFileSync(path.join(KOK, 'tarif-kaynaklari.json'), 'utf8'));
const filtre = process.argv[2];
const cikti = await derle(yapilandirma, filtre);

const hedef = path.join(KOK, '..', 'data', 'yemekler.json');
fs.mkdirSync(path.dirname(hedef), { recursive: true });
let mevcut = {};
if (fs.existsSync(hedef)) mevcut = JSON.parse(fs.readFileSync(hedef, 'utf8'));
const birlesik = { ...mevcut, ...cikti };
fs.writeFileSync(hedef, JSON.stringify(birlesik, null, 1));
console.log('\nYazıldı: data/yemekler.json (' + Object.keys(birlesik).length + ' yemek)');
