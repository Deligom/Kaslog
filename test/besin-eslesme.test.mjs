// ============================================================
// Kaslog besin eşleştirme testleri (Open Food Facts + yemek tablosu)
//
// Çalıştırma: node test/besin-eslesme.test.mjs
//
// js/*.js içindeki GERÇEK eşleştirme kodu söküp çalıştırılır. OFF fikstürleri
// gerçek yanıtların biçimini taklit eder (alan adları, gürültü türleri):
// aynı ürüne farklı kalori, markasız/tutarsız kayıtlar, kalorisiz kayıtlar.
// ============================================================

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, slice } from './_kaynak.mjs';

const code = [
  slice('function _foodNorm', '// "2 adet ülker gofret"', 'foodNorm'),
  slice('function _kelimeGecer', 'function _lookupLocalFood', 'kelimeGecer'),
  slice('const ROUTINE_STOPWORDS', 'function _routineItemKey', 'stopwords'),
  slice('function _tokenAkin', '// İki oturum imzası', 'tokenAkin'),
  slice('function _routineQueryTokens', '/**\n * Yazılan metne en uygun', 'queryTokens'),
  slice('/** 100 g başına kcal.', '// 2. KADEME: Open Food Facts isimle ara', 'off'),
  slice('function _parseFoodText', '// Bir ürünün geçmişte', 'parseFoodText'),
  slice('const PORSIYON_KAPLARI', 'function _recipePer100', 'porsiyonKaplari'),
  slice('function _portionWord', '/**\n * Bu girişte kaç gram', 'portionWord'),
  slice('const DISH_HAM_OLABILIR', '/** Ham JSON → eşleştirmeye hazır liste.', 'ham'),
  slice('/** Ham JSON → eşleştirmeye hazır liste.', 'async function loadDishTable', 'prepDishes'),
  slice('/**\n * Yazılan metin tablodaki bir yemeği mi', 'function _dishName', 'matchDish'),
].join('\n');
const E = new Function(code + '\nreturn { _offKcal, _offPer100Ok, _offToFood, _pickOFFProduct, _offDisplayName, _prepDishes, _matchDish };')();

let pass = 0, fail = 0;
function check(label, actual, expected) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; console.log(`  ✓ ${label}`); }
  else { fail++; console.log(`  ✗ ${label}\n      beklenen: ${e}\n      gelen   : ${a}`); }
}
const scenario = n => console.log(`\n▸ ${n}`);

const P = (brands, name, kcal, p, c, f, extra = {}) => ({
  brands, product_name: name, code: String(Math.floor(Math.random() * 1e12)),
  nutriments: { 'energy-kcal_100g': kcal, proteins_100g: p, carbohydrates_100g: c, fat_100g: f }, ...extra,
});

// ============================================================
scenario('Besin değeri tutarlılığı');
check('kcal ≈ 4p+4c+9f ise tutarlı', E._offPer100Ok({ kcal: 70, protein: 4, carbs: 4.6, fat: 4 }), true);
check('kcal makrolarla çelişiyorsa reddedilir', E._offPer100Ok({ kcal: 20, protein: 50, carbs: 50, fat: 50 }), false);
check('makroları hiç olmayan (yalnız kcal) kayıt reddedilir', E._offPer100Ok({ kcal: 120, protein: 0, carbs: 0, fat: 0 }), false);
check('100 g\'da 105 g\'dan fazla makro olamaz', E._offPer100Ok({ kcal: 600, protein: 60, carbs: 60, fat: 20 }), false);
check('kcal yoksa reddedilir', E._offPer100Ok({ kcal: 0, protein: 5, carbs: 5, fat: 5 }), false);
check('900 kcal/100 g üstü reddedilir', E._offPer100Ok({ kcal: 1200, protein: 0, carbs: 0, fat: 100 }), false);
check('kJ → kcal çevrilir (418,4 kJ = 100 kcal)', Math.round(E._offKcal({ 'energy_100g': 418.4 })), 100);
check('düz "energy-kcal" (porsiyon başına olabilir) YOK sayılır', E._offKcal({ 'energy-kcal': 250 }), 0);

// ============================================================
scenario('Markasız (temel yiyecek) sorgu OFF\'a gitmez');
const yogurt = [
  P('Dost', 'Doğal Yoğurt', 70, 4, 4.6, 4),
  P('Dost', 'Yarım yağlı yoğurt', 49, 4, 4.6, 1.5),
  P('Sütaş', 'Sütaş Tava Yoğurt 1000 G', 96, 4.7, 7, 5.5),
  P("Lay's", 'Yoğurt & Mevsim Yeşillikleri Çeşnili birlik', 537, 6.2, 52, 33),
  P('Sütaş', 'Tam Yağlı Süt', 61, 3, 4.5, 3.5),
];
const yumurta = [
  P('ANADOLU CIFTLIGI', 'Yumurta', 116, 10, 4, 6),
  P('Anadolu Çiftliği', 'Yumurta', 143, 13, 0, 10.16),
  P('CP Yumurta', '', 126.84, 11.5, 0.41, 8.8),
  P('Keskinoğlu', 'Yumurta', 128, 13, 0, 8.5),
];
check('"yoğurt" → eşleşme yok (rastgele marka seçilmez)', E._pickOFFProduct('yoğurt', yogurt), null);
check('"yumurta" → eşleşme yok (üreticiye göre 116-143 kcal)', E._pickOFFProduct('yumurta', yumurta), null);
check('"tavuk göğsü" → eşleşme yok', E._pickOFFProduct('tavuk göğsü', [P('Banvit', 'Tavuk Göğsü', 105, 23.5, 0, 0.7)]), null);

// ============================================================
scenario('Markalı sorgu doğru ürünü seçer');
const sut = E._pickOFFProduct('sütaş tava yoğurt', yogurt);
check('marka + ürün → o ürün', sut && sut.per100, { kcal: 96, protein: 4.7, carbs: 7, fat: 5.5 });
check('ad, marka iki kez yazılmadan', sut && sut.name, 'Sütaş Tava Yoğurt 1000 G');
const dost = E._pickOFFProduct('dost yoğurt', yogurt);
check('"dost yoğurt" → Dost markasından bir yoğurt (başka marka değil)', dost && /^Dost .*[Yy]oğurt/.test(dost.name), true);
check('"sütaş yoğurt" → süt değil yoğurt (kelime tutmayan ürün elenir)', E._pickOFFProduct('sütaş yoğurt', yogurt).name, 'Sütaş Tava Yoğurt 1000 G');
check('Ek almış marka yazımı ("lays")', E._pickOFFProduct('lays yoğurt', yogurt).per100.kcal, 537);

// ============================================================
scenario('Bozuk kayıtlar elenir');
check('tutarsız besin değeri', E._pickOFFProduct('marka x ürün', [P('Marka', 'X Ürün', 20, 50, 50, 50)]), null);
check('kalorisi olmayan kayıt', E._pickOFFProduct('marka x ürün', [{ brands: 'Marka', product_name: 'X Ürün', nutriments: {} }]), null);
check('markası olmayan kayıt', E._pickOFFProduct('x ürün', [P('', 'X Ürün', 100, 5, 15, 3)]), null);
check('marka eşleşse de ürün kelimesi tutmazsa seçilmez', E._pickOFFProduct('dost kefir', yogurt), null);
check('kJ ile gelen kayıt kullanılabilir', E._pickOFFProduct('dost sade',
  [{ brands: 'Dost', product_name: 'Dost Sade', code: '1', nutriments: { energy_100g: 292.9, proteins_100g: 4, carbohydrates_100g: 4.6, fat_100g: 4 } }]).per100.kcal, 70);

// ============================================================
scenario('Yemek tablosu (data/yemekler.json) — veri sağlığı');
const raw = JSON.parse(readFileSync(join(ROOT, 'data/yemekler.json'), 'utf8'));
const dishes = E._prepDishes(raw);
check('tablodaki her yemek yüklenebiliyor (tutarsız kayıt yok)', dishes.length, Object.keys(raw).length);
check('her yemekte en az bir ad ve geçerli kategori', dishes.every(d => d.adlar.length >= 1 && ['corba', 'pilav', 'yemek'].includes(d.kategori)), true);
check('kaynak URL\'leri https', Object.values(raw).every(v => (v.kaynaklar || []).length > 0 && v.kaynaklar.every(u => /^https:\/\//.test(u))), true);
check('bozuk kayıt (kcal ile makrolar çelişiyor) atılır',
  E._prepDishes({ x: { ad: 'x', kategori: 'yemek', per100: { kcal: 10, protein: 50, carbs: 50, fat: 50 } } }).length, 0);

scenario('Yemek tablosu — eşleşme kuralları');
const m = t => { const r = E._matchDish(t, dishes); return r ? r.dish.key : null; };
check('"1 kase mercimek çorbası" eşleşir', m('1 kase mercimek çorbası'), 'mercimek corbasi');
check('yazım varyantı ("mercimek corbasi")', m('mercimek corbasi'), 'mercimek corbasi');
check('eşanlamlı ("kırmızı mercimek çorbası")', m('kırmızı mercimek çorbası'), 'mercimek corbasi');
check('gramla ("300 gr mercimek çorbası")', m('300 gr mercimek çorbası'), 'mercimek corbasi');
check('"ezogelin çorbası"', m('1 kase ezogelin çorbası'), 'ezogelin corbasi');
check('"pilav" (tek kelime, gram yok) eşleşir', m('pilav'), 'pirinc pilavi');
check('"menemen"', m('menemen'), 'menemen');
check('"mercimek" tek başına eşleşmez (ham mercimek olabilir)', m('mercimek'), null);
check('"200gr mercimek" eşleşmez', m('200gr mercimek'), null);
check('"200gr fasulye" eşleşmez (kuru ağırlık olabilir)', m('200gr fasulye'), null);
check('"150gr pilav" eşleşir (pilav yalnız pişmiş yemektir)', m('150gr pilav'), 'pirinc pilavi');
check('"1 tabak fasulye" eşleşir (kap → pişmiş yemek)', m('1 tabak fasulye'), 'kuru fasulye');
check('"tavuklu pilav" eşleşmez (yalnız sade pilav var)', m('tavuklu pilav'), null);
check('"yeşil mercimek çorbası" eşleşmez (tabloda kırmızı)', m('yeşil mercimek çorbası'), null);
check('iki ayrı yiyecek ("mercimek çorbası ve ekmek") eşleşmez', m('1 kase mercimek çorbası ve ekmek'), null);
check('"taze fasulye" eşleşmez', m('taze fasulye'), null);
check('alakasız metin', m('200gr tavuk göğsü'), null);

console.log(`\n${fail ? '✗' : '✓'} ${pass}/${pass + fail} kontrol geçti`);
process.exit(fail ? 1 : 0);
