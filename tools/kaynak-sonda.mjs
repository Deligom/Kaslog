// Aday tarif sayfalarını yoklar: schema.org/Recipe verisi var mı,
// malzeme listesi okunabiliyor mu? Kaynak listesini genişletmeden önce
// hangi sitelerin kullanılabilir olduğunu ölçer.
const UA = 'KaslogRecipeAggregator/1.0 (kisisel beslenme takibi)';

async function sonda(url) {
  try {
    const r = await fetch(url, { headers: { 'User-Agent': UA }, redirect: 'follow',
                                 signal: AbortSignal.timeout(20000) });
    if (!r.ok) return { url, sonuc: 'HTTP ' + r.status };
    const html = await r.text();
    const bloklar = [...html.matchAll(/<script[^>]*application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
    for (const b of bloklar) {
      let v; try { v = JSON.parse(b); } catch { continue; }
      const ad = [];
      const gez = o => { if (!o || typeof o !== 'object') return;
        if (Array.isArray(o)) { o.forEach(gez); return; }
        if (o['@type'] === 'Recipe' || (Array.isArray(o['@type']) && o['@type'].includes('Recipe'))) ad.push(o);
        Object.values(o).forEach(gez); };
      gez(v);
      if (ad.length) {
        let m = ad[0].recipeIngredient || ad[0].ingredients || [];
        if (Array.isArray(m[0])) m = m.flat();
        return { url, sonuc: 'RECIPE VAR', malzeme: m.length,
                 yield: ad[0].recipeYield || '-',
                 kalori: ad[0].nutrition?.calories || '-',
                 ornek: (m[0] || '').toString().slice(0, 46) };
      }
    }
    return { url, sonuc: 'sema yok' };
  } catch (e) { return { url, sonuc: 'hata: ' + e.message.slice(0, 40) }; }
}

const urls = process.argv.slice(2);
for (const u of urls) {
  const s = await sonda(u);
  const host = u.replace(/^https?:\/\/(www\.)?/, '').split('/')[0];
  console.log(host.padEnd(28), '|', s.sonuc.padEnd(12),
    s.malzeme != null ? ('malzeme:' + String(s.malzeme).padStart(2) + '  yield:' + String(s.yield).slice(0,12).padEnd(12) + ' kcal:' + String(s.kalori).slice(0,12)) : '',
    s.ornek ? '\n' + ' '.repeat(30) + '| ör: ' + s.ornek : '');
  await new Promise(r => setTimeout(r, 1200));
}
