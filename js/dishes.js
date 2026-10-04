// ============================================================
// KANONİK YEMEK TABLOSU — data/yemekler.json
//
// Bileşik yemeklerin ("mercimek çorbası", "pilav", "menemen") 100 g başına
// değerleri. tools/tarif-derle.mjs birden çok tarifin MEDYANINDAN üretir; bu
// dosya o tabloyu uygulamaya bağlar. Sıralama (en güvenilirden başlayarak):
//
//   1. Kullanıcının kendi tarifi/rutini      (kendi ölçümü — her zaman önce)
//   2. Bu tablo                              (birkaç tarifin medyanı)
//   3. Kayıtlı ürün → Open Food Facts (yalnız markalı) → AI + USDA
//
// Yemek tablosu AI tahmininden iyidir çünkü sayı sabittir: aynı yemek her
// seferinde aynı 100 g değerini verir. Yine de bir ortalamadır; porsiyonda
// kaç gram yendiği ayrı bir belirsizlik. O yüzden gram yazılmadıysa (ör. "1 kase")
// bir kez sorulur ve hatırlanır — kendi tarifindeki "porsiyon hafızası" gibi.
// ============================================================

const DISH_URL = 'data/yemekler.json';
let _dishes = [];           // [{key, ad, kategori, per100, tarifSayisi, adlar:[[token…], …]}]

// Tipik porsiyon ağırlıkları (g). Kullanıcıya "tipik bir kase ≈ 250 g" diye
// önerilir; tarttığı değeri yazınca o geçerli olur ve hep hatırlanır.
const DISH_TYPICAL_GRAMS = {
  corba: { kase: 250, tabak: 300, bardak: 200, kepce: 80,  kupa: 250, canak: 250, porsiyon: 250 },
  pilav: { tabak: 200, kase: 150, kepce: 70, porsiyon: 150 },
  yemek: { tabak: 250, kase: 200, kepce: 90, porsiyon: 250 },
};
const DISH_EMOJI = { corba: '🍲', pilav: '🍚', yemek: '🍛' };

// Hem hammaddenin hem yemeğin adı olabilen kelimeler: "200gr fasulye" kuru
// ağırlık olabilir, "1 tabak fasulye" pişmiş yemektir. "pilav", "ezogelin",
// "menemen" ise yalnızca pişmiş yemeği anlatır ("pirinç" ham olandır).
const DISH_HAM_OLABILIR = new Set(['fasulye', 'mercimek', 'nohut', 'pirinc', 'bulgur', 'makarna', 'sehriye', 'yulaf']);

/** Ham JSON → eşleştirmeye hazır liste. Tutarsız/eksik kayıtlar atılır. */
function _prepDishes(raw) {
  const out = [];
  if (!raw || typeof raw !== 'object') return out;
  for (const [key, v] of Object.entries(raw)) {
    if (!v || typeof v !== 'object' || !_offPer100Ok(v.per100)) continue;
    const adlar = [v.ad, ...(Array.isArray(v.esanlamlilar) ? v.esanlamlilar : [])]
      .map(a => _routineQueryTokens(String(a || ''))).filter(t => t.length);
    if (!adlar.length) continue;
    out.push({ key, ad: String(v.ad || key), kategori: v.kategori || 'yemek', per100: v.per100,
               tarifSayisi: +v.tarifSayisi || 1, adlar });
  }
  return out;
}

async function loadDishTable() {
  try {
    const r = await fetch(DISH_URL, { signal: AbortSignal.timeout(6000) });
    if (!r.ok) return;
    _dishes = _prepDishes(await r.json());
  } catch { /* tablo yoksa bu kademe sessizce atlanır */ }
}

/**
 * Yazılan metin tablodaki bir yemeği mi anlatıyor?
 * Eşleşme İKİ YÖNLÜ ve tam olmalı: yazdığın her kelime yemeğin adında, yemeğin
 * adındaki her kelime yazdığında bulunmalı. Böylece
 *   "mercimek"            → eşleşmez (ham mercimek olabilir)
 *   "tavuklu pilav"       → eşleşmez (tabloda yalnız sade pilav var)
 *   "çorba ve ekmek"      → eşleşmez (iki ayrı yiyecek)
 *   "mercimek çorbası"    → eşleşir
 * Hammadde olabilen tek kelimelik ad + yazılı gram ("200gr fasulye") kuru ağırlık
 * olabileceğinden eşleşmez; porsiyon kabı varsa ("1 kase fasulye") pişmiş yemek
 * kastedilir. "150gr pilav" gibi yalnızca yemeği anlatan adlar eşleşir.
 */
function _matchDish(text, dishes) {
  const qt = _routineQueryTokens(text);
  if (!qt.length) return null;
  const { grams } = _parseFoodText(text);
  const kap = _portionWord(text);
  for (const d of dishes || []) {
    for (const ad of d.adlar) {
      const hepsiAdda = qt.every(w => ad.some(t => _tokenAkin(w, t)));
      const adinHepsiYazida = ad.every(t => qt.some(w => _tokenAkin(w, t)));
      if (!(hepsiAdda && adinHepsiYazida)) continue;
      if (ad.length < 2 && grams > 0 && !kap && ad.some(t => DISH_HAM_OLABILIR.has(t))) continue;
      return { dish: d };
    }
  }
  return null;
}

function _dishName(d) { return d.ad.charAt(0).toLocaleUpperCase('tr-TR') + d.ad.slice(1); }

function _dishPortionNote(d) {
  return '📚 ' + (d.tarifSayisi >= 3 ? d.tarifSayisi + ' tarifin medyanı' : 'tek tarif — yaklaşık');
}

function _dishLearned(d, kap) {
  const g = ST.settings.dishPortions?.[d.key]?.[kap];
  return g > 0 ? g : null;
}

/** Yemeği verilen toplam ağırlıkla bugüne ekle. */
async function applyDish(d, gram, rawText) {
  const f = gram / 100;
  const entry = {
    id: 'n_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    date: todayDateKey(),
    name: _dishName(d) + ' ' + Math.round(gram) + 'g',
    calories: Math.round(d.per100.kcal * f),
    protein: Math.round(d.per100.protein * f * 10) / 10,
    carbs: Math.round(d.per100.carbs * f * 10) / 10,
    fat: Math.round(d.per100.fat * f * 10) / 10,
    emoji: DISH_EMOJI[d.kategori] || '🍽️',
    portionNote: _dishPortionNote(d),
    matchSource: 'dish', dishKey: d.key, raw: rawText || '',
    pending: false, createdAt: Date.now(),
  };
  await DB.put('nutritionLogs', entry);
  ST.nutritionLogs.push(entry);
  // renderBeslenme kutudaki yazıyı geri yüklediği için ÖNCE temizle
  const kutu = document.getElementById('nut-input');
  if (kutu && rawText && kutu.value.trim() === rawText.trim()) kutu.value = '';
  renderBeslenme();
  showActionToast('📚 ' + entry.name + ' eklendi', 'Geri al', () => _undoRoutineApply([entry.id], null));
  return entry;
}

/**
 * Eşleşen yemeği uygula. true → işlendi (normal analiz akışına DÜŞME).
 * Gram yazıldıysa o geçerli; "1 kase" gibi bir kap yazıldıysa öğrenilmiş
 * ağırlık; hiçbiri yoksa kullanıcıya sorulur.
 */
async function _uygulaYemek(match, text) {
  const d = match.dish;
  const { qty, grams } = _parseFoodText(text);
  const kap = _portionWord(text) || 'porsiyon';
  if (grams > 0) { await applyDish(d, grams, text); return true; }
  const ogrenilmis = _dishLearned(d, kap);
  if (ogrenilmis) { await applyDish(d, ogrenilmis * (qty || 1), text); return true; }
  sorYemekPorsiyonu(d, kap, text, qty || 1);
  return true;
}

// ---- Porsiyon sorusu (kendi tarifin için olan "modal-porsiyon" ile aynı pencere) ----
function sorYemekPorsiyonu(d, kap, text, adet) {
  _porsiyonBekleyen = { dishKey: d.key, kap, text, adet };
  document.getElementById('porsiyon-baslik').textContent = '1 ' + kap + ' ' + d.ad;
  const tipik = DISH_TYPICAL_GRAMS[d.kategori]?.[kap] ?? DISH_TYPICAL_GRAMS.yemek.porsiyon;
  const inp = document.getElementById('porsiyon-input');
  inp.value = _dishLearned(d, kap) || tipik;
  document.getElementById('porsiyon-oneri').textContent =
    'Tipik bir ' + kap + ' yaklaşık ' + tipik + ' g. Tartıp yazarsan daha doğru olur ve bir daha sorulmaz — '
    + 'bundan sonraki her "' + kap + '" bu ağırlıkla hesaplanır.';
  openModal('modal-porsiyon');
  setTimeout(() => inp.focus(), 120);
}

/** kaydetPorsiyon() yemek tablosu için çağrıldığında: ağırlığı hatırla ve ekle. */
async function kaydetYemekPorsiyonu(b, g) {
  const d = _dishes.find(x => x.key === b.dishKey);
  if (!d) return;
  const dp = { ...(ST.settings.dishPortions || {}) };
  dp[d.key] = { ...(dp[d.key] || {}), [b.kap]: g };
  ST.settings.dishPortions = dp;
  await DB.put('settings', { id: 'main', ...ST.settings });
  await applyDish(d, g * (b.adet || 1), b.text);
}
