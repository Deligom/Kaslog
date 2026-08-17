// ============================================================
// Kaslog — USDA FoodData Central Proxy
//
// NEDEN VAR: Open Food Facts paketli/markalı ürünlerde iyi, ham yiyeceklerde
// (tavuk göğsü, pilav, süt, yumurta) zayıf. Orada şu ana kadar AI tahminine
// düşülüyordu ve AI besin değerlerinde yanılıyor. USDA resmî laboratuvar
// verisi sunar; sayıları oradan alıp AI'yı yalnızca "bu ne ve kaç gram"
// sorusunda kullanıyoruz.
//
// Anahtar burada tutuluyor çünkü istemciye konulsa herkes görürdü.
//
// Vercel Environment Variables:
//   USDA_KEY  — https://fdc.nal.usda.gov/api-key-signup.html (ücretsiz, anında)
//               TANIMLI DEĞİLSE bu uç 503 döner ve istemci kademeyi atlar.
// ============================================================

import { applyCorsAndOrigin, clientIp, checkRateLimit, sendRateLimited } from './_shared.js';

const USDA_KEY = process.env.USDA_KEY;

// Yalnızca gerçek ölçüme dayanan veri tipleri. "Branded" dahil edilmiyor:
// orası kullanıcı katkısı ve OFF zaten o işi yapıyor.
const DATA_TYPES = ['Foundation', 'SR Legacy', 'Survey (FNDDS)'];

// USDA besin numaraları (100 g başına)
const NUT = { kcal: 1008, protein: 1003, fat: 1004, carbs: 1005 };

function pickNutrients(food) {
  const out = { kcal: 0, protein: 0, carbs: 0, fat: 0 };
  for (const n of food.foodNutrients || []) {
    const id  = n.nutrientId ?? n.nutrient?.id;
    const val = n.value ?? n.amount ?? 0;
    if (id === NUT.kcal)    out.kcal    = Math.round(val);
    if (id === NUT.protein) out.protein = Math.round(val * 10) / 10;
    if (id === NUT.carbs)   out.carbs   = Math.round(val * 10) / 10;
    if (id === NUT.fat)     out.fat     = Math.round(val * 10) / 10;
  }
  return out;
}

export default async function handler(req, res) {
  if (!applyCorsAndOrigin(req, res)) return;

  if (!USDA_KEY) {
    // Kurulmamışsa sessizce devre dışı: istemci bu kademeyi atlayıp devam eder.
    return res.status(503).json({ error: 'USDA yapılandırılmamış', code: 'NO_USDA_KEY' });
  }

  const rl = await checkRateLimit(clientIp(req), 'ai');
  if (!rl.ok) return sendRateLimited(res, rl);

  const q = String(req.body?.query || '').trim();
  if (!q || q.length > 120) {
    return res.status(400).json({ error: 'Geçersiz sorgu', code: 'BAD_QUERY' });
  }

  try {
    const url = 'https://api.nal.usda.gov/fdc/v1/foods/search'
      + '?api_key=' + encodeURIComponent(USDA_KEY)
      + '&query='   + encodeURIComponent(q)
      + '&pageSize=3&requireAllWords=false'
      + DATA_TYPES.map(t => '&dataType=' + encodeURIComponent(t)).join('');

    const r = await fetch(url, { signal: AbortSignal.timeout(6000) });
    if (!r.ok) {
      return res.status(502).json({ error: 'USDA yanıt vermedi (' + r.status + ')', code: 'UPSTREAM' });
    }
    const data = await r.json();
    const food = (data.foods || []).find(f => (f.foodNutrients || []).length);
    if (!food) return res.status(200).json({ found: false });

    const per100 = pickNutrients(food);
    if (!per100.kcal) return res.status(200).json({ found: false });

    return res.status(200).json({
      found: true,
      name: food.description || q,
      fdcId: food.fdcId || null,
      dataType: food.dataType || null,
      per100,
    });
  } catch (err) {
    console.error('[kaslog-usda] hata:', err.message);
    return res.status(502).json({ error: 'USDA bağlantı hatası', code: 'UPSTREAM' });
  }
}
