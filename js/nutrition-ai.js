// ============================================================
// NUTRITION QUEUE ENGINE
// ============================================================
const _nutQueue = [];
let _nutQueueProcessing = false;

// ---- Fotoğraf seçim & önizleme sistemi ----
let _nutSelectedPhotos = []; // [{file, dataUrl}]

async function onNutPhotoSelected(input) {
  const files = Array.from(input.files || []);
  if (!files.length) return;
  input.value = '';

  // Her dosyayı dataUrl'e çevir ve listeye ekle
  for (const file of files) {
    const dataUrl = await new Promise((res, rej) => {
      const r = new FileReader();
      r.onload = () => res(r.result);
      r.onerror = rej;
      r.readAsDataURL(file);
    });
    _nutSelectedPhotos.push({ file, dataUrl });
  }
  renderBeslenme();
}

function removeNutPhoto(idx) {
  _nutSelectedPhotos.splice(idx, 1);
  renderBeslenme();
}

function clearNutPhotos() {
  _nutSelectedPhotos = [];
  renderBeslenme();
}

// ---- Görüntüyü küçült + JPEG'e çevir (payload'ı ~20-40 kat küçültür) ----
// Ham telefon fotoğrafı 3-6MB → base64 ile ~8MB gövde → proxy/API reddi.
// Ayrıca HEIC/PNG gibi desteklenmeyen formatları JPEG'e normalize eder.
async function _prepImagePart(file, maxDim = 1280, quality = 0.85) {
  try {
    const bmp = await createImageBitmap(file);
    let { width: w, height: h } = bmp;
    const scale = Math.min(1, maxDim / Math.max(w, h));
    w = Math.round(w * scale); h = Math.round(h * scale);
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bmp, 0, 0, w, h);
    bmp.close?.();
    const dataUrl = canvas.toDataURL('image/jpeg', quality);
    return { inline_data: { mime_type: 'image/jpeg', data: dataUrl.split(',')[1] } };
  } catch (e) {
    // Canvas başarısız olursa ham dosyaya düş
    const b64 = await new Promise((res, rej) => {
      const r = new FileReader();
      r.onload = () => res(r.result.split(',')[1]);
      r.onerror = rej;
      r.readAsDataURL(file);
    });
    return { inline_data: { mime_type: file.type || 'image/jpeg', data: b64 } };
  }
}

// ---- Gemini yanıtından metni güvenle çıkar (boş/kesik yanıtı teşhis eder) ----
function _geminiText(data) {
  const cand = data?.candidates?.[0];
  const fr = cand?.finishReason;
  const parts = cand?.content?.parts;
  const txt = Array.isArray(parts) ? parts.map(p => p.text || '').join('').trim() : '';
  if (!txt) {
    if (fr === 'MAX_TOKENS') throw new Error('EMPTY_MAX_TOKENS');
    if (fr === 'SAFETY' || fr === 'PROHIBITED_CONTENT') throw new Error('EMPTY_SAFETY');
    if (data?.promptFeedback?.blockReason) throw new Error('EMPTY_SAFETY');
    throw new Error('EMPTY_RESPONSE' + (fr ? ':' + fr : ''));
  }
  return txt;
}

// ---- Metinden JSON'u kurtar (model açıklama/markdown eklerse bile) ----
function _extractJson(raw) {
  let s = raw.replace(/```json/gi, '').replace(/```/g, '').trim();
  try { return JSON.parse(s); } catch {}
  const i = s.indexOf('{'), j = s.lastIndexOf('}');
  if (i !== -1 && j > i) {
    try { return JSON.parse(s.slice(i, j + 1)); } catch {}
  }
  throw new Error('BAD_JSON');
}

// ---- Hata mesajını insan diline çevir ----
function _nutErrMsg(err) {
  const m = err?.message || '';
  // Ortak kota bitti → çözüm kendi key'ini girmek. Ayarlar'a yönlendir.
  if (m.includes('SHARED_QUOTA_OUT'))
    return '🔋 Ortak AI kotası doldu — Ayarlar\'dan kendi ücretsiz Gemini key\'ini gir';
  if (m.startsWith('RATE_LIMIT_IP')) {
    const secs = parseInt(m.split(':')[1], 10) || 0;
    const mins = Math.ceil(secs / 60);
    return '🚦 Çok hızlı gittin — ' + (mins > 60 ? 'yarın' : mins + ' dk sonra') + ' tekrar dene';
  }
  if (m.includes('ORIGIN_DENIED')) return '🔒 Bu adresten AI erişimi kapalı — uygulamayı resmi adresinden aç';
  if (m.includes('EMPTY_MAX_TOKENS')) return '🧠 Model yanıtı yarıda kesildi — tekrar dene';
  if (m.includes('EMPTY_SAFETY'))     return '🚫 Model bu görseli analiz etmedi — başka açıdan çek';
  if (m.includes('EMPTY_RESPONSE'))   return '📭 Model boş yanıt verdi — tekrar dene';
  if (m.includes('BAD_JSON'))         return '🧩 Yanıt okunamadı — tekrar dene';
  if (m.includes('413') || m.includes('too large') || m.includes('PayloadTooLarge'))
    return '🖼️ Fotoğraf çok büyük — daha küçük/yakın çek';
  if (m.includes('high demand') || m.includes('503') || m.includes('529'))
    return '⏳ Sunucu yoğun, biraz sonra tekrar dene';
  if (m.includes('quota') || m.includes('429')) return '🚦 Kota doldu, biraz bekle';
  if (m.includes('API_KEY')) return '🔑 API anahtarı geçersiz — Ayarlar\'ı kontrol et';
  if (m.includes('network') || m.includes('Failed') || m.includes('timeout'))
    return '📡 Bağlantı hatası — interneti kontrol et';
  if (/\b400\b/.test(m)) return '⚠️ İstek reddedildi (400) — fotoğrafı yeniden çek';
  return '📷 Analiz hatası: ' + (m.slice(0, 60) || 'bilinmeyen');
}

// ---- Fotoğraftan beslenme analizi ----
async function handleNutPhotos(files, userText = '') {
  if (!files.length) return;

  const addBtn = document.getElementById('nut-add-btn');
  if (addBtn) addBtn.classList.add('loading');

  async function toBase64(file) {
    return new Promise((res, rej) => {
      const r = new FileReader();
      r.onload = () => res(r.result.split(',')[1]);
      r.onerror = rej;
      r.readAsDataURL(file);
    });
  }

  let ok = false;
  try {
    // ---- KADEME A: Barkod tara → Open Food Facts (kesin veri) ----
    const barcode = await _detectBarcode(files);
    if (barcode) {
      const food = await _lookupOFFByBarcode(barcode);
      if (food) {
        await _learnFood(food); // öğren
        const { qty, grams } = _parseFoodText(userText || '1');
        const mac = _foodToMacros(food, qty, grams);
        const entry = {
          id: 'n_' + Date.now() + '_' + Math.random().toString(36).slice(2,6),
          date: todayDateKey(),
          name: food.name + (qty !== 1 ? ' ×' + qty : ''),
          calories: mac.calories, protein: mac.protein, carbs: mac.carbs, fat: mac.fat,
          emoji: '📦', pending: false, fromPhoto: true,
          portionNote: mac.portionNote, matchSource: 'barcode', foodId: food.id,
          createdAt: Date.now(),
        };
        await DB.put('nutritionLogs', entry);
        ST.nutritionLogs.push(entry);
        renderBeslenme();
        showToast('📦 Barkod eşleşti: ' + food.name);
        return true;   // finally 'loading'i kaldırır; true → çağıran fotoğrafı temizler
      }
      // Barkod okundu ama OFF'ta yok → Gemini'ye düş (etiket okuyabilir)
    }

    // ---- KADEME B: Gemini görsel tanıma / etiket okuma ----
    // Fotoğrafları küçült (1280px, JPEG) — ham dosya proxy limitini aşıyordu
    const imageParts = await Promise.all(files.map(f => _prepImagePart(f)));

    const textPart = {
      text: `Sen bir beslenme uzmanısın. Bu görsellerdeki yiyecek/ürünü analiz et.
Birden fazla fotoğraf varsa aynı ürünün farklı tarafları olabilir — hepsini birlikte değerlendir.
ÖNCE beslenme etiketi var mı diye bak — varsa değerleri TAMAMEN ETİKETTEN oku, tahmin yapma.
Etiket yoksa görsel içeriğe göre tahmin et.
${userText ? `\nKullanıcı notu: "${userText}" — bu notu gramaj/porsiyon hesaplarken dikkate al.` : ''}

Kurallar:
1. SADECE JSON döndür. Markdown yok, açıklama yok.
2. Şema: {"name":"string","totalKcal":number,"totalProtein":number,"totalCarbs":number,"totalFat":number,"emoji":"string","source":"label|estimate","portionNote":"string","productQuery":"string|null","per100":{"kcal":number,"protein":number,"carbs":number,"fat":number}|null,"packageG":number|null}
3. name: Türkçe ürün adı. Gramaj/paket bilgisi varsa ekle (örn: "Dido Gofret Bar (47g)").
4. Değerler TAM PAKET / GÖRÜNEN PORSİYON için — 100g baz değil.
5. source: "label" etiket okuduysan, "estimate" tahmin ettiysen.
6. portionNote: kısa not, örn "47g paket değerleri" veya "1 dilim tahmin".
7. productQuery: paketli/markalı ürünse arama sorgusu (örn "Ülker Çikolatalı Gofret"), ev yemeği/tabaksa null.
8. per100: etiketi okuduysan 100g başına değerler, okuyamadıysan null.
9. packageG: paket gramajı görünüyorsa sayı, yoksa null.
SADECE JSON:`
    };

    const data = await callGemini([{ parts: [...imageParts, textPart] }], null, NUT_GEN_CFG);
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));

    const parsed = _extractJson(_geminiText(data));

    // ---- KADEME C: Markalı ürün tanındıysa önce lokal/OFF'tan KESİN veri dene ----
    if (parsed.productQuery && parsed.source !== 'label') {
      const q = (userText ? userText + ' ' : '') + parsed.productQuery;
      const resolved = await _cascadeResolveText(q);
      if (resolved) {
        const entry = {
          id: 'n_' + Date.now() + '_' + Math.random().toString(36).slice(2,6),
          date: todayDateKey(),
          name: resolved.name,
          calories: resolved.calories, protein: resolved.protein,
          carbs: resolved.carbs, fat: resolved.fat,
          emoji: resolved.emoji, pending: false, fromPhoto: true,
          portionNote: resolved.portionNote, matchSource: resolved.matchSource, foodId: resolved.foodId||null,
          createdAt: Date.now(),
        };
        await DB.put('nutritionLogs', entry);
        ST.nutritionLogs.push(entry);
        renderBeslenme();
        showToast((resolved.matchSource==='local'?'📗':'🌐') + ' Ürün tanındı: ' + resolved.name);
        return true;
      }
    }

    // ---- Etiket okunduysa ürünü ÖĞREN (bir daha sorulmaz) ----
    if (parsed.source === 'label' && parsed.per100?.kcal && parsed.productQuery) {
      await _learnFood({
        id: 'food_' + _foodNorm(parsed.productQuery).replace(/ /g,'_'),
        name: parsed.productQuery, norm: _foodNorm(parsed.productQuery),
        barcode: null,
        per100: { kcal: Math.round(parsed.per100.kcal), protein: +(parsed.per100.protein||0),
                  carbs: +(parsed.per100.carbs||0), fat: +(parsed.per100.fat||0) },
        servingG: parsed.packageG || null,
        source: 'label', addedAt: Date.now()
      });
    }

    const sourceIcon = parsed.source === 'label' ? '🏷️' : '🤖';
    const pendingId = 'n_' + Date.now() + '_' + Math.random().toString(36).slice(2,6);
    const entry = {
      id: pendingId,
      date: todayDateKey(),
      name: parsed.name || 'Fotoğraf öğünü',
      calories: Math.round(parsed.totalKcal || 0),
      protein:  Math.round((parsed.totalProtein || 0) * 10) / 10,
      carbs:    Math.round((parsed.totalCarbs   || 0) * 10) / 10,
      fat:      Math.round((parsed.totalFat     || 0) * 10) / 10,
      emoji: parsed.emoji || '📷',
      pending: false,
      fromPhoto: true,
      portionNote: parsed.portionNote || '',
      createdAt: Date.now(),
    };
    await DB.put('nutritionLogs', entry);
    ST.nutritionLogs.push(entry);
    renderBeslenme();
    showToast(`${sourceIcon} ${parsed.source === 'label' ? 'Etiket okundu' : 'AI tahmini'}: ${entry.name}`);
    ok = true;
  } catch(err) {
    console.error('[Beslenme foto]', err);
    showToast(_nutErrMsg(err), true);
  } finally {
    if (addBtn) addBtn.classList.remove('loading');
  }
  return ok; // false → çağıran fotoğrafı ve yazıyı SİLMEZ
}

// ============================================================
// KADEMELİ BESİN EŞLEŞTİRME (Cascade)
// Metin:    Lokal DB → Open Food Facts → Gemini (tahmin)
// Fotoğraf: Barkod → OFF | Gemini görsel tanıma → metin akışı
// Her başarılı eşleşme lokal DB'ye kaydedilir → sistem öğrenir.
// ============================================================

// Türkçe-duyarlı normalizasyon (İ/ı sorunu dahil)
function _foodNorm(s){
  return (s||'').toLocaleLowerCase('tr-TR')
    .replace(/[çÇ]/g,'c').replace(/[ğĞ]/g,'g').replace(/[ıİiI]/g,'i')
    .replace(/[öÖ]/g,'o').replace(/[şŞ]/g,'s').replace(/[üÜ]/g,'u')
    .replace(/[^a-z0-9 ]/g,' ').replace(/\s+/g,' ').trim();
}

// "2 adet ülker gofret", "150g pilav", "yarım ekmek" → {qty, grams, product}
function _parseFoodText(text){
  let t=text.trim(), qty=1, grams=null;
  const g=t.match(/(\d+(?:[.,]\d+)?)\s*(?:g|gr|gram)\b/i);
  if(g) grams=parseFloat(g[1].replace(',','.'));
  const m=t.match(/^(\d+(?:[.,]\d+)?)\s*(?:x|adet|tane|paket|porsiyon|dilim|kase|bardak)?\s+(.+)/i);
  if(m && !t.match(/^\d+\s*(?:g|gr|gram)\b/i)){ qty=parseFloat(m[1].replace(',','.')); t=m[2]; }
  if(/^yar[ıi]m\s+/i.test(t)){ qty=0.5; t=t.replace(/^yar[ıi]m\s+/i,''); }
  // gramaj metni ürün adından temizle
  t=t.replace(/\d+(?:[.,]\d+)?\s*(?:g|gr|gram)\b/i,'').trim();
  return { qty, grams, product:t };
}

// Bir ürünün geçmişte kaç kez yendiği. Belirsiz eşleşmede "en sık yediğin"
// kazansın diye: "yarım tavuk" yazınca sürekli aldığın ürüne gitmeli.
let _foodFreqCache=null, _foodFreqCacheAt=0;
function _foodFrequency(){
  if(_foodFreqCache && Date.now()-_foodFreqCacheAt<30000) return _foodFreqCache;
  const f={};
  for(const e of ST.nutritionLogs||[]){
    if(!e.foodId||e.pending||e.error) continue;
    f[e.foodId]=(f[e.foodId]||0)+1;
  }
  _foodFreqCache=f; _foodFreqCacheAt=Date.now();
  return f;
}

// 1. KADEME: Lokal foodDb'de ara (öğrenilmiş ürünler). Basit skorlu eşleşme.
/**
 * Kelime SINIRINA saygılı eşleşme.
 * Düz `includes` "su"yu "Sütaş"ın içinde buluyordu ve su, tereyağı olarak
 * kaydediliyordu. Türkçe ek toleransı için 4+ harfli sorgular kelime başında
 * da eşleşebilir ("mercimek" → "mercimeği"), kısa sorgular tam kelime ister.
 */
function _kelimeGecer(ad, kelime){
  const h=' '+ad+' ';
  if(h.includes(' '+kelime+' ')) return true;
  if(kelime.length>=4) return h.includes(' '+kelime);   // ek almış hâli
  return false;
}

function _lookupLocalFood(query){
  const q=_foodNorm(query); if(!q||!ST.foodDb?.length) return null;
  // Miktar/birim kelimeleri eşleşme oranını haksız yere düşürüyordu:
  // "1 kase gevrek" 3 kelime sayılıp 1/3 skor alıyor ve %75 eşiğini geçemiyordu.
  const qWords=_routineQueryTokens(q);
  if(!qWords.length) return null;
  const freq=_foodFrequency();
  let best=null,bestScore=0,bestRank=-1;
  for(const f of ST.foodDb){
    const n=f.norm||_foodNorm(f.name);
    if(n===q) return f; // tam eşleşme
    let hit=0;
    for(const w of qWords) if(_kelimeGecer(n,w)) hit++;
    const score=hit/qWords.length;
    if(score<0.75) continue; // kelimelerin ≥%75'i eşleşmeli
    // Sıklık yalnızca eşiği geçenler arasında SIRALAMA yapar; eşiği düşürmez.
    const rank=score+Math.min(0.2,(freq[f.id]||0)*0.02);
    if(rank>bestRank){bestRank=rank;bestScore=score;best=f;}
  }
  return best;
}

// ── Open Food Facts ─────────────────────────────────────────
// OFF kullanıcı katkılı bir veritabanı: aynı "Yumurta" için üreticiye göre 116
// ile 143 kcal, "yoğurt" aramasında 537 kcal'lik bir cips çıkabiliyor, bazı
// kayıtların kalorisi ya da makroları yok. İki ilke:
//   1. OFF yalnızca MARKALI sorguda kullanılır ("Sütaş süzme yoğurt"). Markasız
//      ham/temel yiyecekte ("tavuk göğsü", "yumurta") paketli ürünün değeri
//      kimin kastedildiğini bilmeden seçilmiş rastgele bir marka olur — o durum
//      AI + USDA kademesine bırakılır (bkz. KURULUM.md).
//   2. Gelen sayı tutarlı olmalı: kcal ≈ 4·protein + 4·karb + 9·yağ.

/** 100 g başına kcal. Yalnızca _100g alanları: düz "energy-kcal" porsiyon başına olabilir. */
function _offKcal(nu){
  const kcal=Number(nu['energy-kcal_100g']);
  if(kcal>0) return kcal;
  const kj=Number(nu['energy_100g']);          // kJ → kcal
  return kj>0 ? kj/4.184 : 0;
}

/** Besin değerleri kullanılabilir ve kendi içinde tutarlı mı? */
function _offPer100Ok(p){
  if(!p || !(p.kcal>0) || p.kcal>900) return false;
  const {protein,carbs,fat}=p;
  if([protein,carbs,fat].some(v=>!Number.isFinite(v)||v<0)) return false;
  const toplam=protein+carbs+fat;
  if(toplam===0 || toplam>105) return false;   // 100 g'da 105 g makro olamaz
  const beklenen=4*protein+4*carbs+9*fat;
  return Math.abs(p.kcal-beklenen) <= Math.max(30, 0.35*p.kcal);   // lif/polyol/alkol payı için pay
}

/** OFF çoğu üründe markayı product_name'in içine de yazıyor: "Sütaş Sütaş Tava…" olmasın. */
function _offDisplayName(marka, ad){
  marka=(marka||'').trim(); ad=(ad||'').trim();
  if(!marka) return ad;
  return _foodNorm(ad).includes(_foodNorm(marka)) ? ad : (marka+' '+ad).trim();
}

function _offToFood(p,name){
  const nu=p.nutriments||{};
  const num=(a,b)=>{ const v=Number(nu[a]??nu[b]); return Number.isFinite(v)?v:NaN; };
  return {
    id:'food_'+(p.code||_foodNorm(name).replace(/ /g,'_')),
    name, norm:_foodNorm(name), barcode:p.code||null,
    per100:{kcal:Math.round(_offKcal(nu)),
            protein:+(num('proteins_100g')||0),
            carbs:+(num('carbohydrates_100g')||0),
            fat:+(num('fat_100g')||0)},
    servingG:parseFloat(p.serving_quantity)||null,
    source:'off', addedAt:Date.now()
  };
}

/**
 * OFF arama sonuçlarından sorguya uyan TEK ürünü seç ya da hiçbirini.
 * Ürünün markası sorguda geçmiyorsa (markasız/temel yiyecek sorgusu) null döner.
 * @param {string} query  kullanıcının yazdığı ürün metni (miktarsız)
 * @param {object[]} products  OFF `products` dizisi
 */
function _pickOFFProduct(query, products){
  const qTokens=_routineQueryTokens(query);
  if(!qTokens.length) return null;
  let best=null, bestScore=0;
  for(const p of (products||[])){
    const marka=((p.brands||'').split(',')[0]||'').trim();
    const ad=(p.product_name||'').trim();
    if(!marka || !ad) continue;                           // adı/markası olmayan kayıt güvenilmez
    const bTokens=_routineQueryTokens(marka);
    // Marka sorguda geçiyor mu? (ek/yazım toleransıyla: "ülker" ~ "Ülker")
    const markaVar=bTokens.length>0 && bTokens.every(b=>qTokens.some(w=>_tokenAkin(w,b)));
    if(!markaVar) continue;
    const nN=_foodNorm(marka+' '+ad);
    // Sorgunun marka dışı kelimeleri üründe geçmeli
    const rest=qTokens.filter(w=>!bTokens.some(b=>_tokenAkin(w,b)));
    const cov=rest.length ? rest.filter(w=>_kelimeGecer(nN,w)).length/rest.length : 1;
    if(cov<(rest.length>2?0.75:0.99)) continue;
    // Ürün adı, sorgunun anlattığından çok daha uzunsa başka bir ürün olabilir
    const nTokens=_routineQueryTokens(ad).filter(w=>!bTokens.some(b=>_tokenAkin(w,b)));
    const prec=nTokens.length ? nTokens.filter(w=>qTokens.some(q=>_tokenAkin(q,w))).length/nTokens.length : 1;
    const food=_offToFood(p, _offDisplayName(marka,ad));
    if(!_offPer100Ok(food.per100)) continue;
    const score=cov+prec;
    if(score>bestScore){ bestScore=score; best=food; }
  }
  return best;
}

// 2. KADEME: Open Food Facts isimle ara (yalnızca markalı sorgularda eşleşir)
async function _lookupOFFByName(query){
  try{
    const url='https://tr.openfoodfacts.org/cgi/search.pl?search_terms='+encodeURIComponent(query)
      +'&search_simple=1&action=process&json=1&page_size=10&fields=product_name,brands,nutriments,serving_quantity,code';
    const r=await fetch(url,{signal:AbortSignal.timeout(6000)});
    if(!r.ok) return null;
    const d=await r.json();
    return _pickOFFProduct(query, d.products);
  }catch{return null;}
}

// Barkodla OFF sorgusu (fotoğraf akışı). Besin değeri eksik/tutarsızsa null:
// çağıran Gemini'ye (etiket okuma) düşer. Eskiden kalorisiz ürün "Barkod
// eşleşti" diye 0 kcal'lik kayıt olarak ekleniyordu.
async function _lookupOFFByBarcode(code){
  try{
    const r=await fetch('https://world.openfoodfacts.org/api/v2/product/'+code
      +'.json?fields=product_name,brands,nutriments,serving_quantity,code',{signal:AbortSignal.timeout(6000)});
    if(!r.ok) return null;
    const d=await r.json();
    if(d.status!==1||!d.product) return null;
    const p=d.product;
    const food=_offToFood(p,_offDisplayName((p.brands||'').split(',')[0], p.product_name||'Ürün'));
    return _offPer100Ok(food.per100) ? food : null;
  }catch{return null;}
}

// Öğren: ürünü lokal DB'ye kaydet (varsa güncelle)
async function _learnFood(food){
  if(!food?.per100?.kcal) return;
  const ex=ST.foodDb.findIndex(f=>f.id===food.id);
  if(ex!==-1) ST.foodDb[ex]=food; else ST.foodDb.push(food);
  await DB.put('foodDb',food);
}

// food + miktar → girişe yazılacak makrolar
function _foodToMacros(food,qty,grams){
  const p=food.per100;
  let factor, note;
  if(grams){ factor=grams/100; note=grams+'g'; }
  else if(food.servingG){ factor=(food.servingG*qty)/100; note=qty+'\u00d7 '+food.servingG+'g'; }
  else { factor=qty; note=qty+'\u00d7 100g'; } // porsiyon bilinmiyorsa 100g varsay
  return {
    calories:Math.round(p.kcal*factor),
    protein:Math.round(p.protein*factor*10)/10,
    carbs:Math.round(p.carbs*factor*10)/10,
    fat:Math.round(p.fat*factor*10)/10,
    portionNote:note
  };
}

// Kademeli metin çözümleme. Başarıda entry alanları döner, null → Gemini'ye düş.
async function _cascadeResolveText(text){
  const {qty,grams,product}=_parseFoodText(text);
  if(!product) return null;
  // 1) Lokal (öğrenilmiş ürünler)
  let food=_lookupLocalFood(product);
  if(food) return {..._foodToMacros(food,qty,grams),name:food.name+(qty!==1?' \u00d7'+qty:''),emoji:'\ud83d\udcd7',matchSource:'local',foodId:food.id};
  // 2) Open Food Facts
  food=await _lookupOFFByName(product);
  if(food){ await _learnFood(food); // öğren → bir dahakine lokalden gelir
    return {..._foodToMacros(food,qty,grams),name:food.name+(qty!==1?' \u00d7'+qty:''),emoji:'\ud83c\udf10',matchSource:'off',foodId:food.id};
  }
  return null; // 3) Gemini tahminine düşecek
}

// Fotoğraflarda barkod ara (Android Chrome: native BarcodeDetector)
async function _detectBarcode(files){
  if(!('BarcodeDetector' in window)) return null;
  try{
    const det=new BarcodeDetector({formats:['ean_13','ean_8','upc_a','upc_e','code_128']});
    for(const f of files){
      const bmp=await createImageBitmap(f);
      const codes=await det.detect(bmp);
      bmp.close?.();
      if(codes.length) return codes[0].rawValue;
    }
  }catch{}
  return null;
}

async function addNutritionEntry() {
  const input = document.getElementById('nut-input');
  const text  = input?.value?.trim();

  // Fotoğraf seçiliyse: fotoğraf + yazı birlikte gönder
  if (_nutSelectedPhotos.length > 0) {
    const userText = text || '';
    input.value = '';
    const okPhoto = await handleNutPhotos(_nutSelectedPhotos.map(p => p.file), userText);
    if (okPhoto) { _nutSelectedPhotos = []; }
    renderBeslenme();
    if (!okPhoto && userText) { const i2 = document.getElementById('nut-input'); if (i2) i2.value = userText; }
    return;
  }

  if (!text) return;

  // ÖĞRENİLMİŞ RUTİN — KESİN eşleşme: anında uygula, AI'ya hiç gitme.
  // Belirsiz eşleşmede burada karar VERİLMEZ; kuyrukta AI'ya sorulur, çünkü
  // ağ turu sürerken kullanıcıyı boş ekranda bekletmek istemiyoruz.
  // Tür önemli: TARİF yazılı gramla ölçeklenir (miktar bilgisi İŞE YARAR),
  // RUTİN sabit porsiyon taşır (miktar yazıldıysa dayatılmamalı).
  const { match } = _matchMealRoutine(text);
  if (match) {
    const onceki = input.value;
    input.value = '';
    if (await _uygulaEslesme(match, text)) return;
    input.value = onceki;   // uygulanmadı, normal analize düşsün
  }

  // KANONİK YEMEK TABLOSU: "1 kase mercimek çorbası" gibi bileşik yemekler için
  // sabit 100 g değeri; kendi rutin/tarifin yoksa AI tahmininden önce gelir.
  // Yazı, yemek EKLENENE kadar kutuda kalır (porsiyon sorusundan vazgeçilirse kaybolmasın).
  const dm = _matchDish(text, _dishes);
  if (dm && await _uygulaYemek(dm, text)) return;

  // Hemen listede göster — pending durumda
  const pendingId = 'n_' + Date.now() + '_' + Math.random().toString(36).slice(2,6);
  const pendingEntry = {
    id: pendingId,
    date: todayDateKey(),
    name: text,
    calories: 0, protein: 0, carbs: 0, fat: 0,
    emoji: '⏳',
    raw: text,
    pending: true,
    createdAt: Date.now(),
  };
  await DB.put('nutritionLogs', pendingEntry);
  ST.nutritionLogs.push(pendingEntry);
  input.value = '';
  renderBeslenme();

  // Kuyruğa ekle ve işle. Aynı isteği service worker'a da bırak: uygulama
  // kapanırsa analiz arka planda tamamlansın, açılınca hazır olsun.
  _nutQueue.push({ text, pendingId });
  _enqueueBgJob(pendingId, text);
  if (!_nutQueueProcessing) _processNutQueue();
}

// ---- Arka plan kuyruğu (service worker ile) --------------------
// Uygulama kapatıldığında JavaScript durur; bu değiştirilemez. Yapılabilen
// şey, isteği service worker'ın göndermesi: Gemini'nin 5-30 saniyelik yanıt
// süresi uygulama kapalıyken geçer, açtığında sonuç hazır olur.
// Chrome/Android'de çalışır, iOS Safari'de Background Sync yoktur.
// Çalışmazsa hiçbir şey kaybolmaz — sayfa açılınca normal akış devreye girer.

function _nutTextPrompt(text){
  // Kayıtlı rutinler AYNI isteğe iliştirilir. Ayrı bir "hangi rutin?" çağrısı
  // yapmak yerine, zaten yapılan analiz çağrısında sorulur: ek maliyet yok,
  // üstelik model bağlamı görerek karar verir. Kelime benzerliği sıfır olsa
  // bile ("sabah gevreğim") doğru rutini bulabilir.
  const rs=(ST.mealRoutines||[]).slice(0,12);
  const routineBlock = rs.length ? `
Kullanıcının kayıtlı öğün rutinleri:
${rs.map(r=>`- id=${r.id} | ad="${r.name}" | içerik: ${r.items.map(i=>i.name).join(', ')} | daha önce şöyle yazmıştı: ${(r.triggers||[]).map(t=>`"${t}"`).join(', ')||'—'}`).join('\n')}

Bu giriş yukarıdaki rutinlerden BİRİNİ kastediyorsa routineId alanına o id'yi yaz.
Farklı kelimeler kullanmış olabilir — anlamı değerlendir, kelime benzerliğine takılma.
Ama rutinin sadece BİR parçasını yazmışsa (rutin süt+gevrek iken sadece "süt" gibi)
routineId null olsun: tek bir yiyecek kastediyordur. Emin değilsen null.
` : '';
  return `Sen bir beslenme uzmanısın. Kullanıcının yazdığı yiyeceği/öğünü analiz et.
${routineBlock}
Kurallar:
1. SADECE JSON döndür. Markdown yok, açıklama yok, kod bloğu yok.
2. Şema: {"name":"string","emoji":"string","productQuery":"string|null","routineId":"string|null","items":[{"name":"string","en":"string|null","grams":number|null,"kcal":number,"protein":number,"carbs":number,"fat":number,"emoji":"string"}]}
2b. items[].en: SADECE tek malzemeli temel yiyeceklerde doldur (et, tahıl, süt
    ürünü, meyve, sebze, yumurta, bakliyat). İngilizce karşılığını yaz ve
    PİŞİRME DURUMUNU MUTLAKA BELİRT: "grilled chicken breast", "cooked white
    rice", "raw spinach", "boiled egg", "whole milk", "banana".
    Pişmiş bir yiyeceğe "raw" karşılık verirsen kalori yanlış hesaplanır.
    Şu durumlarda null yaz: markalı paketli ürün; birden çok malzemeden oluşan
    yemek/çorba/tabak (mercimek çorbası, kuru fasulye, menemen, döner, pide).
    Bu tür yemeklerde kendi tahminin daha isabetli olur.
2c. items[].grams: o kalemin gram cinsinden ağırlığı (sıvılarda ml≈g say). Bilmiyorsan makul tahmin et.
2d. KURU/PİŞMİŞ AYRIMI — en sık yapılan hata budur. Bakliyat (mercimek,
    nohut, fasulye), pirinç, bulgur, makarna, yulaf gibi malzemelerde
    kullanıcının yazdığı gramaj KURU ağırlıktır; "pişmiş/haşlanmış" demedikçe
    KURU değerlerden hesapla. 300 g kuru mercimek ~1056 kcal ve ~74 g
    proteindir; pişmiş sanılırsa ~350 kcal ve ~27 g protein çıkar ve sonuç
    üçte birine düşer.
3. items: Girişteki HER AYRI YİYECEK için bir kalem. "250ml süt 50gr gevrek" → 2 kalem.
   Tek yiyecek varsa tek kalemlik dizi döndür.
4. items[].name: Türkçe isim + miktar (örn: "Süt 250ml", "Kahvaltılık Gevrek 50g").
   Marka belirtilmişse başa ekle (örn: "Kellogg's Kahvaltılık Gevrek 50g").
   ADLANDIRMAYI TUTARLI TUT: aynı yiyecek için her seferinde AYNI temel adı
   kullan (hep "Kahvaltılık Gevrek", bazen "Gevreği" bazen "Mısır Gevreği" değil).
   Yalnızca miktar kısmı değişsin.
   items[].emoji: o yiyeceğe ait olsun (süt 🥛, gevrek 🥣, tavuk 🍗).
5. items[] değerleri o kalemin GERÇEK miktarı için — 100g baz DEĞİL.
6. name: öğünün kısa toplu adı (örn: "Sütlü Gevrek"). emoji: öğün için tek emoji.
7. productQuery: Girişte YAZIM HATASI olabilir. Markalı paketli TEK bir ürünse doğru marka+ürün adını yaz (örn "Üpker çokonat maxi" → "Ülker Çokonat Maxi"). Birden fazla yiyecek varsa veya ev yemeğiyse null.
Giriş: "${text}"
SADECE JSON:`;
}

// callGemini ile AYNI isteği kur — service worker sadece POST edebilsin diye
function _nutGeminiRequest(text){
  const model=ST.settings.geminiModel||'gemini-2.5-flash';
  const contents=[{parts:[{text:_nutTextPrompt(text)}]}];
  const key=ST.settings.geminiKey?.trim();
  if(key) return { url:`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
                   body:{contents,generationConfig:NUT_GEN_CFG} };
  return { url:PROXY_URL, body:{model,contents,generationConfig:NUT_GEN_CFG} };
}

async function _enqueueBgJob(pendingId, text){
  try{
    const {url,body}=_nutGeminiRequest(text);
    await DB.put('nutQueue',{ id:'q_'+pendingId, pendingId, text, url, body,
      status:'pending', createdAt:Date.now() });
    // DİKKAT: sync BURADA kaydedilmiyor. Kaydedilince tarayıcı onu anında
    // tetikliyor, sayfa da kendi isteğini sürdürüyordu; aynı öğün İKİ KEZ
    // analiz edilip iki ayrı kart olarak ekleniyordu. Arka plan yalnızca
    // uygulama arka plana atıldığında devreye girmeli.
  }catch{ /* destek yoksa sessizce geç — sayfa akışı zaten çalışıyor */ }
}

// Uygulama arka plana atılırken bekleyen iş varsa devri service worker'a ver
async function _registerNutSync(){
  try{
    const jobs=await DB.getAll('nutQueue');
    if(!jobs.some(j=>j.status==='pending')) return;
    const reg=await navigator.serviceWorker?.ready;
    if(reg?.sync) await reg.sync.register('kaslog-nut-queue');
  }catch{}
}

async function _dropBgJob(pendingId){
  try{ await DB.del('nutQueue','q_'+pendingId); }catch{}
}

// Uygulama analiz sürerken kapanır/öldürülürse kayıt sonsuza kadar "⏳ AI analiz
// ediyor" kalıyordu: bellek içi kuyruk gidiyor, Background Sync ise iOS'ta yok
// (Android'de de garanti değil) ve silmekten başka çare kalmıyordu. Açılışta
// kuyrukta olmayan her bekleyen kaydı yeniden kuyruğa al. Arka plan işi çoktan
// bitirdiyse _drainBgJobs bunu önceden sonuçlandırmış olur (kayıt artık pending değil).
async function _recoverPendingMeals(){
  const orphans=ST.nutritionLogs.filter(e=>e.pending && !_nutQueue.some(q=>q.pendingId===e.id));
  for(const e of orphans){
    const text=e.raw||e.name; if(!text) continue;
    _nutQueue.push({ text, pendingId:e.id });
    _enqueueBgJob(e.id, text);      // yine kapanırsa SW devralabilsin
  }
  if(orphans.length && !_nutQueueProcessing) _processNutQueue();
}

// Arka planda tamamlanmış işleri sonuçlandır
async function _drainBgJobs(){
  let jobs=[];
  try{ jobs=await DB.getAll('nutQueue'); }catch{ return; }
  let changed=false;
  for(const j of jobs){
    const idx=ST.nutritionLogs.findIndex(e=>e.id===j.pendingId);
    // Kayıt yoksa ya da sayfa zaten tamamladıysa iş gereksiz
    if(idx===-1 || !ST.nutritionLogs[idx].pending){ await DB.del('nutQueue',j.id); continue; }
    if(j.status!=='done'){
      // 6 saatten eski ve hâlâ bitmemişse bırak, sayfa normal akışta halleder
      if(Date.now()-(j.createdAt||0)>6*3600000) await DB.del('nutQueue',j.id);
      continue;
    }
    try{
      const parsed=_extractJson(_geminiText(JSON.parse(j.response)));
      if(!(await _applyRoutineIfPicked(parsed, j.pendingId, j.text)))
        await _writeParsedMeal(j.pendingId, parsed, j.text);
      changed=true;
    }catch{ /* yanıt bozuk: işi sil, sayfa akışı yeniden dener */ }
    await DB.del('nutQueue',j.id);
  }
  if(changed) renderBeslenme();
}

// "250ml süt 50gr gevrek" gibi birden fazla miktar işareti taşıyan satırda
// tek ürün araması yanlış eşleşme üretir — doğrudan kalem ayrıştırmasına git.
/**
 * Kullanıcı açıkça miktar yazmış mı? ("240ml", "40gr")
 * Yazmışsa rutin DAYATILMAZ: rutinin ortalaması uygulanırsa kullanıcının
 * bilerek girdiği miktar yok sayılır ve yanlış kalori kaydedilir. Üstelik
 * yeni ölçüm hiç öğrenilmez. Bu durumda normal analiz yapılır, sonuç da
 * rutinin ortalamasına katılır.
 * Miktarsız kısa yazım ("kahvaltılık gevrek") ise rutini tetikler.
 */
function _hasExplicitAmounts(text){
  return /\d+\s*(g|gr|gram|ml|lt|litre)\b/i.test(text||'');
}

function _looksMultiFood(text){
  const m=(text||'').match(/\d+(?:[.,]\d+)?\s*(?:g|gr|gram|ml|lt|litre|adet|tane|dilim|kase|bardak|porsiyon)\b/gi);
  return !!m && m.length>=2;
}

// ---- USDA FoodData Central ------------------------------------
// AI besin değerlerinde yanılıyor; buna karşılık "bu ne ve kaç gram"
// sorusunda iyi. Bu yüzden iş bölümü: ANLAMA + ÇEVİRİ AI'da, SAYILAR USDA'da.
// USDA resmî laboratuvar verisi verir ve ham yiyeceklerde (tavuk, pilav, süt)
// Open Food Facts'in zayıf kaldığı boşluğu kapatır.
// Anahtar kurulmamışsa uç 503 döner, kademe sessizce atlanır.
const USDA_URL = PROXY_URL.replace(/\/api\/gemini$/, '/api/usda');
let _usdaDisabled = false;          // 503 gelince bir daha deneme
const _usdaCache = new Map();

async function _lookupUSDA(query){
  if(_usdaDisabled || !query) return null;
  const key=_foodNorm(query);
  if(!key) return null;
  if(_usdaCache.has(key)) return _usdaCache.get(key);
  try{
    const r=await fetch(USDA_URL,{ method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({query}), signal:AbortSignal.timeout(7000) });
    if(r.status===503){ _usdaDisabled=true; return null; }   // kurulmamış
    if(!r.ok) return null;
    const d=await r.json();
    const val=d?.found ? d : null;
    _usdaCache.set(key,val);
    return val;
  }catch{ return null; }
}

/**
 * AI'nın tahmin ettiği makroları, mümkün olan kalemlerde USDA verisiyle
 * değiştir. Bulunamayan kalem AI tahmininde kalır — hiç veri olmamasından iyi.
 */
async function _refineItemsWithUSDA(items){
  for(const it of items){
    const g=+it.grams||0;
    if(!it.en || !(g>0)) continue;
    const u=await _lookupUSDA(it.en);
    if(!u?.per100?.kcal) continue;
    const f=g/100;
    it.kcal    = Math.round(u.per100.kcal*f);
    it.protein = Math.round((u.per100.protein||0)*f*10)/10;
    it.carbs   = Math.round((u.per100.carbs||0)*f*10)/10;
    it.fat     = Math.round((u.per100.fat||0)*f*10)/10;
    it.source  = 'usda';
  }
  return items;
}

/**
 * Gemini yanıtını öğün kayıtlarına yaz.
 * Tek kalemse bekleyen kayıt güncellenir. Birden fazlaysa kalemler AYRI
 * kayıtlar olarak yazılır ama ortak bir groupId paylaşır: listede tek satır
 * gibi görünürler, dokununca açılırlar. Rutin ortalaması bileşen düzeyinde
 * ancak böyle çalışabiliyor.
 * Model şemaya uymayıp eski toplu biçimi dönerse ona da düşer.
 */
async function _writeParsedMeal(pendingId, parsed, rawText){
  const idx = ST.nutritionLogs.findIndex(e => e.id === pendingId);
  if (idx === -1) return;
  const base = ST.nutritionLogs[idx];
  // Sayfa ve service worker aynı anda bitirirse ikincisi hiçbir şey yapmasın;
  // yoksa öğün iki kez yazılır.
  if (!base.pending) return;

  let items = Array.isArray(parsed.items) ? parsed.items.filter(i => i && (i.kcal || i.name)) : [];
  if (!items.length) {
    items = [{ name: parsed.name || rawText, kcal: parsed.totalKcal, protein: parsed.totalProtein,
               carbs: parsed.totalCarbs, fat: parsed.totalFat, emoji: parsed.emoji }];
  }
  // Sayıları mümkün olduğunca gerçek veriyle değiştir (AI tahmini son çare)
  await _refineItemsWithUSDA(items);

  const mk = (it, i) => ({
    id: i === 0 ? base.id : 'n_' + Date.now() + '_' + Math.random().toString(36).slice(2,6),
    date: base.date,
    name: it.name || rawText,
    calories: Math.round(+it.kcal || 0),
    protein: Math.round((+it.protein || 0) * 10) / 10,
    carbs:   Math.round((+it.carbs   || 0) * 10) / 10,
    fat:     Math.round((+it.fat     || 0) * 10) / 10,
    emoji: it.emoji || parsed.emoji || '🍽️',
    // Kullanıcı sayının nereden geldiğini görsün: ölçüm mü, tahmin mi?
    portionNote: it.source==='usda' ? '🔬 USDA verisi' : '~AI tahmini',
    matchSource: it.source==='usda' ? 'usda' : 'ai',
    raw: rawText,
    pending: false,
    createdAt: (base.createdAt || Date.now()) + i,
  });

  if (items.length === 1) {
    const up = { ...base, ...mk(items[0], 0) };
    ST.nutritionLogs[idx] = up;
    await DB.put('nutritionLogs', up);
    return;
  }

  const groupId = 'g_' + Date.now() + '_' + Math.random().toString(36).slice(2,6);
  const groupName = parsed.name || rawText;
  // Öğünün kendi emojisi ayrı tutulur: grup satırında ilk kalemin ikonunu
  // (ör. süt bardağı) göstermek yanıltıcıydı — öğün "sütlü gevrek" ise
  // kase ikonu doğru olan.
  const groupEmoji = parsed.emoji || '🍽️';
  const rows = items.map((it, i) => ({ ...mk(it, i), groupId, groupName, groupEmoji }));
  ST.nutritionLogs[idx] = rows[0];
  await DB.put('nutritionLogs', rows[0]);
  for (let i = 1; i < rows.length; i++) {
    ST.nutritionLogs.push(rows[i]);
    await DB.put('nutritionLogs', rows[i]);
  }
}

async function _processNutQueue() {
  if (_nutQueue.length === 0) { _nutQueueProcessing = false; return; }
  _nutQueueProcessing = true;
  const { text, pendingId } = _nutQueue.shift();

  try {
    // ---- KADEME 1-2: Lokal DB → Open Food Facts (sıfır AI hatası) ----
    // Rutin adayı varsa lokal aramayı ATLA: yoksa foodDb tek bir ürünü kapıp
    // rutini gölgeler ve AI'nın karar verme şansı hiç doğmaz.
    const { candidates } = _matchMealRoutine(text);
    // "1 kase kırmızı mercimek" yazan kişi PİŞMİŞ bir yemek kastediyor.
    // Ham/paketli ürüne eşleşirse 100 g KURU mercimeğin değerleri yazılıyordu
    // (320 kcal, 26 g protein) — hem miktar hem içerik yanlış oluyordu.
    const kapVar = !!_portionWord(text);
    const skipCascade = _looksMultiFood(text) || candidates.length > 0 || kapVar;
    const resolved = skipCascade ? null : await _cascadeResolveText(text);
    if (resolved) {
      const idx = ST.nutritionLogs.findIndex(e => e.id === pendingId);
      if (idx !== -1) {
        const updated = {
          ...ST.nutritionLogs[idx],
          name: resolved.name, calories: resolved.calories,
          protein: resolved.protein, carbs: resolved.carbs, fat: resolved.fat,
          emoji: resolved.emoji, portionNote: resolved.portionNote,
          matchSource: resolved.matchSource, foodId: resolved.foodId||null, pending: false,
        };
        ST.nutritionLogs[idx] = updated;
        await DB.put('nutritionLogs', updated);
      }
      showToast((resolved.matchSource==='local'?'📗 Kayıtlı üründen':'🌐 Open Food Facts') + ': ' + resolved.name);
      renderBeslenme();
      await new Promise(r => setTimeout(r, 100));
      _processNutQueue();
      return;
    }

    // ---- KADEME 3: Gemini tahmini (yaklaşık değer) ----
    // ÖNEMLİ: Artık toplam DEĞİL, KALEM KALEM isteniyor. "250ml süt 50gr gevrek"
    // tek satır yazılsa bile süt ve gevrek ayrı kalemler olarak dönüyor.
    // Rutin ortalaması ancak böyle bileşen düzeyinde çalışabiliyor
    // (250→230ml süt ortalaması, 50→40g gevrek ortalaması).
    const prompt = _nutTextPrompt(text);

    const data = await callGemini([{ parts: [{ text: prompt }] }], null, NUT_GEN_CFG);
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    const parsed = _extractJson(_geminiText(data));

    // Yazım hatası düzeltildiyse kademeyi tekrar dene (kesin veri > AI tahmini)
    if (parsed.productQuery && _foodNorm(parsed.productQuery) !== _foodNorm(_parseFoodText(text).product)) {
      const { qty, grams } = _parseFoodText(text);
      const fixed = await _cascadeResolveText(
        (qty !== 1 ? qty + ' ' : '') + parsed.productQuery + (grams ? ' ' + grams + 'g' : '')
      );
      if (fixed) {
        const i0 = ST.nutritionLogs.findIndex(e => e.id === pendingId);
        if (i0 !== -1) {
          const up = { ...ST.nutritionLogs[i0], name: fixed.name, calories: fixed.calories,
            protein: fixed.protein, carbs: fixed.carbs, fat: fixed.fat, emoji: fixed.emoji,
            portionNote: fixed.portionNote, matchSource: fixed.matchSource,
            foodId: fixed.foodId || null, pending: false };
          ST.nutritionLogs[i0] = up;
          await DB.put('nutritionLogs', up);
        }
        showToast('✍️ "' + parsed.productQuery + '" olarak düzeltildi');
        renderBeslenme();
        await new Promise(r => setTimeout(r, 100));
        _processNutQueue();
        return;
      }
    }

    // Model bunun kayıtlı bir rutin olduğunu söylediyse rutini uygula
    if (await _applyRoutineIfPicked(parsed, pendingId, text)) {
      await _dropBgJob(pendingId);
      renderBeslenme();
      await new Promise(r => setTimeout(r, 100));
      _processNutQueue();
      return;
    }

    // Tarif mi öğün mü? Emin değilsek kullanıcıya soralım — yanlış karar
    // günlük toplamı yüzlerce kalori şişiriyor.
    if (_tarifGibiMi(text, parsed.items)) {
      await _dropBgJob(pendingId);
      sorTarifMi(parsed, pendingId, text);
      await new Promise(r => setTimeout(r, 100));
      _processNutQueue();
      return;
    }

    await _writeParsedMeal(pendingId, parsed, text);
    await _dropBgJob(pendingId);   // sayfa hallettiyse arka plan işi gereksiz
  } catch(err) {
    const idx = ST.nutritionLogs.findIndex(e => e.id === pendingId);
    if (idx !== -1) {
      const errEntry = {
        ...ST.nutritionLogs[idx],
        emoji: '❌', pending: false, error: true,
        errMsg: _nutErrMsg(err),
        name: ST.nutritionLogs[idx].raw || ST.nutritionLogs[idx].name,
      };
      ST.nutritionLogs[idx] = errEntry;
      await DB.put('nutritionLogs', errEntry);
    }
    // Kullanıcı dostu hata mesajı
    const raw = err.message || '';
    let friendlyMsg;
    if (raw.includes('high demand') || raw.includes('overloaded') || raw.includes('503') || raw.includes('529'))
      friendlyMsg = '⏳ Sunucu yoğun, biraz sonra 🔄 tekrar dene';
    else if (raw.includes('quota') || raw.includes('429') || raw.includes('RESOURCE_EXHAUSTED'))
      friendlyMsg = '🚦 Kota doldu, biraz bekle ve tekrar dene';
    else if (raw.includes('network') || raw.includes('fetch') || raw.includes('Failed'))
      friendlyMsg = '📡 Bağlantı hatası — internet bağlantını kontrol et';
    else if (raw.includes('401') || raw.includes('403') || raw.includes('API_KEY'))
      friendlyMsg = '🔑 API anahtarı hatası — Ayarlar\'dan kontrol et';
    else
      friendlyMsg = '❌ AI analiz başarısız — 🔄 butona bas tekrar dene';
    showToast(friendlyMsg, true);
  }

  renderBeslenme();
  // Rate limit için kısa bekleme
  await new Promise(r => setTimeout(r, 250));
  _processNutQueue();
}


async function retryNutritionEntry(id) {
  const idx = ST.nutritionLogs.findIndex(e => e.id === id);
  if (idx === -1) return;
  const entry = ST.nutritionLogs[idx];
  const text = entry.raw || entry.name;
  if (!text) return;
  // Pending'e döndür
  const retried = { ...entry, emoji: '⏳', pending: true, error: false };
  ST.nutritionLogs[idx] = retried;
  await DB.put('nutritionLogs', retried);
  renderBeslenme();
  showToast('🔄 Tekrar deneniyor...');
  // Kuyruğa ekle
  _nutQueue.push({ text, pendingId: id });
  if (!_nutQueueProcessing) _processNutQueue();
}

