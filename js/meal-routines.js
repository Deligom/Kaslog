// ============================================================
// ÖĞÜN RUTİNİ MOTORU — öğrenen beslenme
//
// Amaç: aynı öğünü ikinci kez girdiğinde sistem bunu fark etsin, rutin
// yapmayı teklif etsin, sonraki seferlerde tek kelimeyle tamamını eklesin.
//
// İşleyiş:
//   1. nutritionLogs zaman boşluğuna göre "oturum"lara bölünür — 30 dakikadan
//      uzun boşluk yeni öğün demektir. (Bu pencere aynı öğünün kalemlerini
//      birbirine bağlamak içindir; tekrarın ne kadar sonra geldiğiyle ilgisi
//      yoktur, iki gün de olabilir iki ay da.)
//   2. Oturum imzası = içindeki yiyecek kimliklerinin sıralı kümesi.
//      MİKTAR İMZAYA GİRMEZ: 250ml süt + 45g gevrek ile 240ml süt + 50g
//      gevrek aynı rutindir.
//   3. Aynı imza ikinci kez görülünce "rutin yapayım mı?" diye sorulur.
//   4. Her tekrarda miktarlar ortalamaya çekilir — sistem senin gerçek
//      porsiyonunu zamanla öğrenir. Uçuk sapan bir örnek (yarısı/iki katı
//      dışında) ortalamayı bozmasın diye elenir.
//   5. Yazdığın kısa metin bir rutine benziyorsa tamamı eklenir. Aday
//      seçiminde sıklık ve tazelik ağırlık taşır; yanlışsa "Geri al" var.
// ============================================================

const ROUTINE_SESSION_GAP_MS = 30 * 60 * 1000; // aynı öğün penceresi
const ROUTINE_MIN_SAMPLES    = 2;              // kaçıncı tekrarda sorulsun
const ROUTINE_AVG_LOW        = 0.5;            // ortalamaya katılacak alt sınır
const ROUTINE_AVG_HIGH       = 2;              // ve üst sınır (kat olarak)

// Miktar/birim kelimeleri: eşleştirmede anlam taşımaz, elenirler.
// "yarım tavuk" → ["tavuk"] olur ve "Önder Yarım Ekmek Arası Tavuk"u bulur.
const ROUTINE_STOPWORDS = new Set([
  'adet','tane','paket','porsiyon','dilim','kase','bardak','kasik','kaşık',
  'gr','gram','ml','lt','litre','yarim','buyuk','kucuk','orta','bir','iki','uc',
  'dort','bes','tam','az','cok','biraz','tabak','kutu','sise','avuc','parca'
]);

// Bir girişin "hangi yiyecek" olduğunu kimliklendir. Miktar dışarıda kalır.
function _routineItemKey(e){
  if(e.foodId) return 'f:'+e.foodId;
  const n=_foodNorm(e.name||'').replace(/\d+/g,' ').replace(/\s+/g,' ').trim();
  return n ? 'n:'+n : '';
}

// Girişleri zaman boşluğuna göre öğün oturumlarına böl (eskiden yeniye)
function _nutSessions(){
  const ok=(ST.nutritionLogs||[])
    .filter(e=>!e.pending && !e.error && e.createdAt && (e.calories||0)>0)
    .sort((a,b)=>a.createdAt-b.createdAt);
  const out=[]; let cur=null;
  for(const e of ok){
    // Tek satırda yazılan öğün (aynı groupId) TAM OLARAK bir oturumdur —
    // 5 dakika sonra yenen salata ona karışmasın. groupId yoksa eski
    // 30 dakika kuralı geçerli.
    const sameGroup   = cur && e.groupId && cur.groupId===e.groupId;
    const withinWindow= cur && !e.groupId && !cur.groupId &&
                        e.date===cur.date && e.createdAt-cur.last<=ROUTINE_SESSION_GAP_MS;
    if(sameGroup || withinWindow){
      cur.entries.push(e); cur.last=e.createdAt;
    }else{
      cur={date:e.date,first:e.createdAt,last:e.createdAt,groupId:e.groupId||null,entries:[e]};
      out.push(cur);
    }
  }
  return out;
}

/**
 * Oturum imzası — "bu iki öğün aynı mı?" sorusunun cevabı.
 *
 * ÖNCE KULLANICININ YAZDIĞI METNE bakar. Sebebi: kalem adlarını AI üretiyor
 * ve bunlar kararsız. Aynı kahvaltıya bir sefer "Kahvaltılık Gevrek 50g",
 * ertesi sefer "Kahvaltılık Gevreği 40g" diyebiliyor; ada dayalı imza
 * tutmuyor ve tekrar hiç fark edilmiyordu. Ham metin ise kullanıcı ne
 * yazdıysa odur: "...250ml süt 50gr gevrek" ile "...240ml süt 40gr gevrek"
 * miktarlar elendikten sonra aynı kelimelere iner.
 *
 * Ham metin yoksa (fotoğraftan gelen, elle eklenen kayıtlar) eski
 * kalem-kimliği yöntemine düşer.
 */
function _sessionSignature(entries){
  const raws=[...new Set(entries.map(e=>e.raw).filter(Boolean))];
  if(raws.length){
    const toks=[...new Set(raws.flatMap(r=>_routineQueryTokens(r)))].sort();
    if(toks.length) return 'r:'+toks.join('|');
  }
  const keys=entries.map(_routineItemKey).filter(Boolean);
  if(!keys.length) return '';
  return 'k:'+[...new Set(keys)].sort().join('|');
}

// Saate göre otomatik ad — kullanıcı sonradan değiştirebilir
function _routineAutoName(ts){
  const h=new Date(ts||Date.now()).getHours();
  if(h<11) return 'Kahvaltı rutini';
  if(h<16) return 'Öğle rutini';
  if(h<22) return 'Akşam rutini';
  return 'Gece atıştırması';
}

// Addaki gramaj/hacmi ayır: "Süt 250ml" → {base:'Süt', qty:250, unit:'ml'}
// Miktar da ortalanacağı için ad ile değerin tutarsız kalmasını önler
// (250 ve 240 ölçümünün ortalaması 157 kcal ise ad "Süt 245ml" olmalı).
function _splitPortionFromName(name){
  const m=(name||'').match(/^(.*?)[\s(]*(\d+(?:[.,]\d+)?)\s*(ml|lt|l|g|gr|gram)\b\)?\s*$/i);
  if(!m) return {base:(name||'Öğe').trim(), qty:null, unit:null};
  let unit=m[3].toLowerCase();
  if(unit==='gr'||unit==='gram') unit='g';
  if(unit==='l') unit='lt';
  const base=m[1].trim().replace(/[(\-–,]\s*$/,'').trim();
  return {base:base||'Öğe', qty:parseFloat(m[2].replace(',','.')), unit};
}

function _portionName(base,qty,unit){
  if(qty==null||!unit) return base;
  const q=Math.round(qty*10)/10;
  return base+' '+(Number.isInteger(q)?q:q.toFixed(1))+unit;
}

// Oturumdaki girişlerden rutin kalemleri üret. Aynı yiyecek iki kez
// girildiyse tek kaleme toplanır (imza zaten tekilleştiriyor).
function _routineItemsFromEntries(entries){
  const items=[];
  for(const e of entries){
    const key=_routineItemKey(e); if(!key) continue;
    const p=_splitPortionFromName(e.name);
    const ex=items.find(i=>i.key===key);
    if(ex){
      ex.calories+=+e.calories||0; ex.protein+=+e.protein||0;
      ex.carbs+=+e.carbs||0; ex.fat+=+e.fat||0;
      if(ex.portionQty!=null && p.qty!=null) ex.portionQty+=p.qty;
      ex.name=_portionName(ex.base,ex.portionQty,ex.portionUnit);
    }else{
      items.push({
        key, foodId:e.foodId||null,
        base:p.base, portionQty:p.qty, portionUnit:p.unit,
        name:_portionName(p.base,p.qty,p.unit), emoji:e.emoji||'🍽️',
        calories:+e.calories||0, protein:+e.protein||0,
        carbs:+e.carbs||0, fat:+e.fat||0,
        portionNote:e.portionNote||'', samples:1,
      });
    }
  }
  return items;
}

// Yeni bir gözlemi rutinin ortalamasına kat. Porsiyon yarıdan az ya da iki
// kattan fazla saparsa katma — kullanıcı bambaşka bir miktar yemiş demektir.
/**
 * İki kelime aynı şeyi mi anlatıyor?
 * Alt dize kontrolü Türkçede yetmiyor: "gevrek" ile "gevreği" birbirini
 * içermiyor (k→ğ yumuşaması + iyelik eki), oysa aynı yiyecek. Ortak kök
 * uzunluğuna bakmak bu ailenin tamamını yakalıyor.
 * Eşik yeterince yüksek: "tavuk"/"tavla" (3 harf) veya "pirinç"/"pirzola"
 * eşleşmez.
 */
function _tokenAkin(a,b){
  if(a===b) return true;
  if(a.includes(b)||b.includes(a)) return true;
  const n=Math.min(a.length,b.length);
  if(n<4) return false;
  let i=0; while(i<n && a[i]===b[i]) i++;
  return i>=4 && i>=Math.floor(n*0.7);
}

// İki oturum imzası aynı öğünü mü gösteriyor?
// Tam eşitlik ararsak kullanıcı bir sonraki sefer bir kelimeyi değiştirince
// ("kahvaltılık gevreği" yerine "kahvaltılık gevrek") tekrar hiç fark
// edilmez. Kelimelerin %70'i örtüşüyorsa aynı öğün sayılır.
function _sigTokens(sig){ return (sig||'').replace(/^[rk]:/,'').split('|').filter(Boolean); }
function _sigAkin(a,b){
  if(!a||!b) return false;
  if(a===b) return true;
  if(a[0]!==b[0]) return false;          // ham metin imzasıyla kalem imzası kıyaslanmaz
  const A=_sigTokens(a), B=_sigTokens(b);
  if(!A.length||!B.length) return false;
  const inter=A.filter(x=>B.some(y=>_tokenAkin(x,y))).length;
  return inter/Math.max(A.length,B.length)>=0.7;
}

// Rutin kalemini yeni gözlemlerle eşleştir. Önce tam kimlik; tutmazsa
// kelime örtüşmesi. AI ad üretimi kararsız olduğu için ("Gevrek" / "Gevreği")
// yalnızca tam eşleşmeye güvenmek ortalamayı sessizce devre dışı bırakıyordu.
function _matchObservedItem(it, pool){
  const exact=pool.findIndex(f=>f && f.key===it.key);
  if(exact!==-1) return exact;
  const a=_routineQueryTokens(it.base||it.name);
  if(!a.length) return -1;
  let best=-1,bestScore=0;
  pool.forEach((f,i)=>{
    if(!f) return;
    const b=_routineQueryTokens(f.base||f.name);
    if(!b.length) return;
    const hit=a.filter(w=>b.some(t=>_tokenAkin(w,t))).length;
    const score=hit/Math.max(a.length,b.length);
    if(score>bestScore){bestScore=score;best=i;}
  });
  return bestScore>=0.5?best:-1;
}

function _mergeRoutineObservation(routine, entries){
  const pool=_routineItemsFromEntries(entries);
  const items=routine.items.map(it=>{
    const idx=_matchObservedItem(it,pool);
    if(idx===-1) return it;
    const obs=pool[idx];
    pool[idx]=null;   // aynı gözlem iki kaleme sayılmasın
    const ratio=it.calories>0 ? (obs.calories/it.calories) : 1;
    if(!(ratio>=ROUTINE_AVG_LOW && ratio<=ROUTINE_AVG_HIGH)) return it; // aykırı
    const n=it.samples||1, m=n+1;
    const avg=(cur,val)=>Math.round((((cur*n)+(+val||0))/m)*10)/10;
    // Gramaj da ortalanır ve ada geri yazılır, yoksa "Süt 240ml" yazıp
    // 245ml'nin kalorisini gösteren tutarsız bir kalem kalır.
    const qty=(it.portionQty!=null&&obs.portionQty!=null)
      ? Math.round(((it.portionQty*n)+obs.portionQty)/m*10)/10
      : (it.portionQty ?? obs.portionQty ?? null);
    const unit=it.portionUnit||obs.portionUnit||null;
    const base=it.base||obs.base;
    return {...it,
      base, portionQty:qty, portionUnit:unit,
      name:_portionName(base,qty,unit),
      calories:Math.round(((it.calories*n)+(obs.calories))/m),
      protein:avg(it.protein,obs.protein),
      carbs:avg(it.carbs,obs.carbs),
      fat:avg(it.fat,obs.fat),
      portionNote:obs.portionNote||it.portionNote,
      samples:m};
  });
  return {...routine, items, samples:(routine.samples||1)+1};
}

// Eşleştirme için sorguyu anlamlı kelimelere indirge.
// Miktar taşıyan her şey elenir: "250ml", "50gr", "2" gibi tokenlar ürünün
// kimliği değil, ölçüsüdür — kaldıkça kapsama oranını sulandırıp gerçek
// eşleşmeleri eşiğin altına düşürüyorlardı. Tekrarlar da teklileştirilir.
function _routineQueryTokens(text){
  const out=[];
  for(const w of _foodNorm(text).split(' ')){
    if(w.length<2) continue;
    if(/^\d/.test(w)) continue;              // "250ml", "50gr", "3" ...
    if(ROUTINE_STOPWORDS.has(w)) continue;   // adet, kase, yarim ...
    if(!out.includes(w)) out.push(w);
  }
  return out;
}


/**
 * Yazılan metne en uygun rutini bul.
 *
 * Eşleştirme rutinin İÇERİĞİNE değil, kullanıcının GERÇEKTEN YAZDIĞI
 * ifadelere (tetiklere) bakar. Eskiden içerik kelimeleriyle örtüşme
 * aranıyordu ve tek başına "süt" yazmak tüm kahvaltı rutinini getiriyordu —
 * çünkü "süt" rutinin içindeydi. Artık tetik olarak öğrenilmemiş bir
 * kelime tek başına rutini açamaz.
 *
 * İki yönlü ölçü:
 *   coverage — yazdığın kelimeler tetiğin ne kadarını karşılıyor
 *   precision — yazdıklarının ne kadarı tetikte geçiyor
 * İkisi de yüksekse kesin eşleşme (anında, AI yok).
 * Zayıfsa aday listesi döner; karar AI'ya bırakılır.
 *
 * @returns {{match:object|null, candidates:object[]}}
 */
function _matchMealRoutine(text){
  const empty={match:null,candidates:[]};
  if(!ST.mealRoutines?.length) return empty;
  const qt=_routineQueryTokens(text);
  if(!qt.length) return empty;
  const now=Date.now();
  const scored=[];

  for(const r of ST.mealRoutines){
    const triggers=(r.triggers?.length?r.triggers:[r.name]).map(_routineQueryTokens).filter(t=>t.length);
    if(!triggers.length) continue;

    let bestCov=0,bestPrec=0;
    for(const tt of triggers){
      const hitQ=qt.filter(w=>tt.some(t=>t.includes(w)||w.includes(t))).length;
      const hitT=tt.filter(t=>qt.some(w=>t.includes(w)||w.includes(t))).length;
      const prec=hitQ/qt.length;      // yazdıklarının ne kadarı tanındı
      const cov =hitT/tt.length;      // tetiğin ne kadarı karşılandı
      if(prec+cov>bestPrec+bestCov){ bestPrec=prec; bestCov=cov; }
    }
    if(bestPrec===0) continue;        // hiç ilgisi yok

    const uses=r.useCount||0;
    const ageDays=r.lastUsedAt?(now-r.lastUsedAt)/86400000:999;
    scored.push({ routine:r, prec:bestPrec, cov:bestCov,
      rank:bestPrec+bestCov+Math.min(0.25,uses*0.03)+(ageDays<14?0.1:0) });
  }
  if(!scored.length) return empty;
  scored.sort((a,b)=>b.rank-a.rank);

  // Kesin eşleşme: yazdıklarının hepsi tanındı VE tetiğin yarısını karşıladı
  const top=scored[0];
  const confident = top.prec>=0.99 && top.cov>=0.5;
  // İkinci aday çok yakınsa "kesin" deme, AI karar versin
  const ambiguous = scored.length>1 && (scored[0].rank-scored[1].rank)<0.15;

  if(confident && !ambiguous) return { match:top.routine, candidates:scored.map(s=>s.routine) };
  return { match:null, candidates:scored.slice(0,6).map(s=>s.routine) };
}

/**
 * Analiz yanıtında model "bu şu rutin" dediyse rutini uygula.
 * Rutin kararı ayrı bir çağrıda değil, zaten yapılan analiz çağrısında
 * alınıyor — ek maliyet yok. Uygulandıysa true döner.
 */
/**
 * Yazılan metin bir TARİF mi anlatıyor, yoksa yenen bir ÖĞÜN mü?
 * Kullanıcı tencere tarifini beslenme kutusuna yazdığında uygulama bunu
 * yediği öğün sanıp günlük toplamına ekliyordu (869 kcal). Dört ve üzeri
 * ayrı malzeme + porsiyon sözcüğü olmaması tarif işaretidir.
 */
function _tarifGibiMi(text, items){
  if(!Array.isArray(items) || items.length < 4) return false;
  if(_portionWord(text)) return false;          // "1 kase ..." → yediğini anlatıyor
  // Ayırt edici işaret: PORSİYONDA tek ölçü olur ("300gr çorba"), TARİFTE
  // her malzemenin kendi ölçüsü vardır ("300gr mercimek, 3 diş sarımsak,
  // 7 su bardağı su"). Sadece gramaj varlığına bakmak yanlıştı — tarifler
  // de gramaj içeriyor ve hiçbir tarif algılanamıyordu.
  const olcuSayisi = (String(text).match(
    /[0-9]+(?:[.,][0-9]+)?[ ]*(?:g|gr|gram|ml|lt|litre|adet|di[sş]|tane|demet|ka[sş][ıi][kğ]|barda[kğ]|paket|dilim)/gi) || []).length;
  return olcuSayisi >= 3;
}

let _tarifKarari=null;   // {parsed, pendingId, text}

function sorTarifMi(parsed, pendingId, text){
  _tarifKarari={parsed, pendingId, text};
  const items=parsed.items||[];
  const kcal=Math.round(items.reduce((a,i)=>a+(+i.kcal||0),0));
  document.getElementById('tarifmi-ozet').textContent=
    items.length+' malzeme · toplam '+kcal+' kcal';
  document.getElementById('tarifmi-liste').textContent=
    items.map(i=>i.name).join(' · ');
  openModal('modal-tarif-mi');
}

async function tarifMiCevap(secim){
  const b=_tarifKarari; if(!b) { closeModal('modal-tarif-mi'); return; }
  _tarifKarari=null;
  closeModal('modal-tarif-mi');
  if(secim==='ogun'){
    await _writeParsedMeal(b.pendingId, b.parsed, b.text);
    renderBeslenme();
    return;
  }
  // Tarif olarak kaydet: bekleyen kaydı sil, tarifi oluştur, tencere
  // ağırlığını isteyebilmek için düzenleme ekranını aç.
  await DB.del('nutritionLogs', b.pendingId);
  ST.nutritionLogs=ST.nutritionLogs.filter(e=>e.id!==b.pendingId);
  const items=(b.parsed.items||[]).map(i=>{
    const p=_splitPortionFromName(i.name||'');
    return { key:'m:'+_foodNorm(i.name||'').replace(/\d+/g,' ').replace(/\s+/g,' ').trim(),
      foodId:null, base:p.base, portionQty:p.qty, portionUnit:p.unit,
      name:_portionName(p.base,p.qty,p.unit), emoji:i.emoji||'🍽️',
      calories:Math.round(+i.kcal||0), protein:Math.round((+i.protein||0)*10)/10,
      carbs:Math.round((+i.carbs||0)*10)/10, fat:Math.round((+i.fat||0)*10)/10,
      portionNote:'', samples:1, fixed:true };
  });
  const r={ id:'mr_'+Date.now()+'_'+Math.random().toString(36).slice(2,6),
    name:b.parsed.name||b.text.slice(0,40), type:'recipe', emoji:b.parsed.emoji||'🍲',
    sig:'', triggers:[b.parsed.name||b.text.slice(0,40)], items,
    yieldG:0, per100:null, portions:{}, samples:1, useCount:0, lastUsedAt:null,
    createdAt:Date.now() };
  ST.mealRoutines.push(r);
  await DB.put('mealRoutines', r);
  renderBeslenme();
  showToast('🍲 Tarif kaydedildi — şimdi tencere ağırlığını gir');
  openRoutineEdit(r.id);
}

async function _applyRoutineIfPicked(parsed, pendingId, text){
  const id=parsed?.routineId;
  if(!id || !ST.mealRoutines.some(r=>r.id===id)) return false;
  if(_hasExplicitAmounts(text)) return false;  // yazdığı miktar geçerli, rutin değil
  await DB.del('nutritionLogs', pendingId);
  ST.nutritionLogs=ST.nutritionLogs.filter(e=>e.id!==pendingId);
  const res=await applyMealRoutine(id);
  if(!res) return false;
  await _learnRoutineTrigger(id, text);   // bir dahakine AI'sız bulsun
  showActionToast('⭐ '+res.routine.name+' eklendi','Geri al',
    ()=>_undoRoutineApply(res.added,res.routine.id));
  return true;
}

// Kullanıcının yazdığı ifadeyi rutine tetik olarak ekle — sistem böylece
// senin kelimelerini öğrenir, kendi tahminini değil.
async function _learnRoutineTrigger(routineId, rawText){
  const idx=ST.mealRoutines.findIndex(r=>r.id===routineId);
  if(idx===-1||!rawText) return;
  const norm=_foodNorm(rawText);
  if(!norm) return;
  const r=ST.mealRoutines[idx];
  const triggers=r.triggers||[];
  if(triggers.some(t=>_foodNorm(t)===norm)) return;
  const upd={...r, triggers:[...triggers, rawText].slice(-8)};
  ST.mealRoutines[idx]=upd;
  await DB.put('mealRoutines',upd);
}

// Rutini bugüne uygula. Eklenen giriş id'lerini döner (geri alma için).