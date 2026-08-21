// ============================================================
// Malzeme referans tablosu — 100 g başına besin değerleri
//
// Tarif derleyicinin çekirdeği. Değerler USDA FoodData Central ve TürKomp
// referans aralıklarına dayanır; yemeklik ham/pişmiş ayrımı ilgili yerde
// belirtilmiştir.
//
// NEDEN GÖMÜLÜ: Derleme çevrimdışı ve YENİDEN ÜRETİLEBİLİR olmalı. Her
// çalıştırmada ağdan çekilse sonuçlar tarihe göre değişir; oysa amacımız
// "aynı yemek her seferinde aynı sayı". Tablo repoda durur, değişirse
// git geçmişinde görünür.
//
// yog: g/ml yoğunluk — hacim ölçüsünü (bardak, kaşık) grama çevirmek için.
// suCeker: pişerken kendi ağırlığının kaç katı su emer (kuru bakliyat/tahıl).
// ============================================================

export const MALZEMELER = {
  // ── Bakliyat / tahıl (KURU ağırlık) ──────────────────────
  'kirmizi mercimek': { kcal:352, p:24.6, k:63.1, y:1.1, yog:0.85, suCeker:2.4, alias:['mercimek','sari mercimek','kirmizi ya da sari mercimek'] },
  'yesil mercimek':   { kcal:352, p:24.6, k:63.1, y:1.1, yog:0.85, suCeker:2.4 },
  'nohut':            { kcal:364, p:19.3, k:60.7, y:6.0, yog:0.80, suCeker:1.8 },
  'kuru fasulye':     { kcal:333, p:23.6, k:60.3, y:0.8, yog:0.80, suCeker:2.0 },
  'pirinc':           { kcal:360, p:6.6,  k:79.3, y:0.6, yog:0.85, suCeker:2.2, alias:['bal­do pirinc','baldo pirinc','pirinç'] },
  'bulgur':           { kcal:342, p:12.3, k:75.9, y:1.3, yog:0.75, suCeker:2.3 },
  'sehriye':          { kcal:371, p:13.0, k:74.7, y:1.5, yog:0.45, suCeker:2.0, alias:['arpa sehriye','tel sehriye'] },
  'makarna':          { kcal:371, p:13.0, k:74.7, y:1.5, yog:0.45, suCeker:2.0 },
  'un':               { kcal:364, p:10.3, k:76.3, y:1.0, yog:0.55 },
  'irmik':            { kcal:360, p:12.7, k:72.8, y:1.1, yog:0.65 },
  'yulaf':            { kcal:389, p:16.9, k:66.3, y:6.9, yog:0.40, suCeker:2.5 },

  // ── Sebze (çiğ) ──────────────────────────────────────────
  'sogan':      { kcal:40,  p:1.1, k:9.3,  y:0.1, yog:0.55, birim:110, alias:['kuru sogan'] },
  'havuc':      { kcal:41,  p:0.9, k:9.6,  y:0.2, yog:0.60, birim:70 },
  'patates':    { kcal:77,  p:2.0, k:17.5, y:0.1, yog:0.65, birim:150 },
  'domates':    { kcal:18,  p:0.9, k:3.9,  y:0.2, yog:0.65, birim:120 },
  'biber':      { kcal:26,  p:1.0, k:6.0,  y:0.2, yog:0.55, birim:40, alias:['sivri biber','yesil biber','carliston biber'] },
  'patlican':   { kcal:25,  p:1.0, k:5.9,  y:0.2, yog:0.60, birim:200 },
  'kabak':      { kcal:17,  p:1.2, k:3.1,  y:0.3, yog:0.60, birim:200 },
  'ispanak':    { kcal:23,  p:2.9, k:3.6,  y:0.4, yog:0.25 },
  'sarimsak':   { kcal:149, p:6.4, k:33.1, y:0.5, yog:0.60, birim:4, alias:['sarimsak disi','dis sarimsak'] },
  'maydanoz':   { kcal:36,  p:3.0, k:6.3,  y:0.8, yog:0.20, birim:40, alias:['maydanoz demet'] },
  'salca':      { kcal:82,  p:4.3, k:18.9, y:0.5, yog:1.10, alias:['domates salcasi','biber salcasi'] },

  // ── Et / protein ─────────────────────────────────────────
  'kiyma':          { kcal:250, p:17.2, k:0,   y:20.0, yog:0.95, alias:['dana kiyma','kuzu kiyma'] },
  'tavuk gogsu':    { kcal:120, p:22.5, k:0,   y:2.6,  yog:1.00 },
  'tavuk but':      { kcal:172, p:18.0, k:0,   y:10.9, yog:1.00 },
  'dana eti':       { kcal:187, p:20.0, k:0,   y:11.8, yog:1.00, alias:['kusbasi et','dana kusbasi','et'] },
  'yumurta':        { kcal:143, p:12.6, k:0.7, y:9.5,  yog:1.03, birim:55 },

  // ── Süt ürünleri ─────────────────────────────────────────
  'sut':        { kcal:61,  p:3.2,  k:4.8, y:3.3,  yog:1.03, alias:['tam yagli sut'] },
  'yogurt':     { kcal:61,  p:3.5,  k:4.7, y:3.3,  yog:1.03 },
  'suzme yogurt':{kcal:97,  p:10.0, k:3.6, y:5.0,  yog:1.05 },
  'tereyagi':   { kcal:717, p:0.9,  k:0.1, y:81.1, yog:0.95 },
  'peynir':     { kcal:264, p:17.6, k:1.3, y:21.1, yog:1.00, alias:['beyaz peynir'] },
  'kasar':      { kcal:350, p:25.0, k:2.0, y:27.0, yog:1.00, alias:['kasar peyniri'] },
  'krema':      { kcal:340, p:2.1,  k:2.8, y:36.0, yog:1.00 },

  // ── Yağ / sıvı ───────────────────────────────────────────
  'aycicek yagi': { kcal:884, p:0, k:0, y:100, yog:0.92, alias:['sivi yag','yag','misir yagi'] },
  'zeytinyagi':   { kcal:884, p:0, k:0, y:100, yog:0.92 },
  'su':           { kcal:0,   p:0, k:0, y:0,   yog:1.00, alias:['sicak su','soguk su','ilik su'] },
  'et suyu':      { kcal:4,   p:0.5,k:0.4,y:0.1, yog:1.00, alias:['tavuk suyu','et suyu tablet','bulyon'] },
  'limon suyu':   { kcal:22,  p:0.4,k:6.9,y:0.2, yog:1.02 },

  // ── Baharat (kalori katkısı ihmal edilebilir ama gram lazım) ──
  'tuz':       { kcal:0, p:0, k:0, y:0, yog:1.20 },
  'karabiber': { kcal:251, p:10.4, k:63.9, y:3.3, yog:0.50 },
  'pul biber': { kcal:282, p:12.0, k:49.7, y:14.3, yog:0.45 },
  'nane':      { kcal:70,  p:3.8,  k:14.9, y:0.9,  yog:0.20, alias:['kuru nane'] },
  'kimyon':    { kcal:375, p:17.8, k:44.2, y:22.3, yog:0.50 },
  'seker':     { kcal:387, p:0, k:100, y:0, yog:0.85, alias:['toz seker'] },
};

// ── Türkçe ölçü birimleri → mililitre ────────────────────────
// Hacim ölçüsü grama çevrilirken malzemenin yoğunluğuyla çarpılır.
export const OLCULER = {
  'su bardagi':     200,
  'cay bardagi':    110,
  'kahve fincani':  80,
  'bardak':         200,
  'yemek kasigi':   15,
  'tatli kasigi':   8,
  'cay kasigi':     5,
  'kasik':          15,
  'litre':          1000,
  'lt':             1000,
  'ml':             1,
  'cl':             10,
};

// Doğrudan gram olan birimler
export const GRAM_BIRIMLER = { 'g':1, 'gr':1, 'gram':1, 'kg':1000, 'kilo':1000 };

// ── Pişirme sonrası ağırlık modeli ───────────────────────────
// Çiğ malzeme toplamı ile tencereden çıkan ağırlık aynı değildir:
// çorba kaynarken buharlaşır, pilav suyu çeker. Kategori başına
// buharlaşma oranı (0.12 = ağırlığın %12'si uçar).
export const BUHARLASMA = {
  corba:   0.12,
  yemek:   0.15,   // sulu yemek, güveç
  pilav:   0.05,   // su büyük ölçüde emiliyor
  makarna: 0.05,
  kizartma:0.05,
  hamur:   0.10,
  salata:  0.00,
  icecek:  0.00,
};
