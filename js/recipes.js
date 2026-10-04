// ============================================================
// KİŞİSEL TARİF — tencere yöntemi
//
// Hiçbir veri tabanı senin annenin mercimek çorbasını bilmiyor. Ama sen
// bir kez ölçersen sonsuza kadar kesin olur:
//
//   Malzemeleri bir kez gir  →  tencerenin tamamını tart
//   → uygulama 100 g başına değeri hesaplar
//   → bundan sonra sadece kaseyi tartman yeter
//
// Rutinden farkı: RUTİN sabit porsiyonlar taşır (süt 245ml + gevrek 47g,
// hep aynı eklenir). TARİF 100 g başına değer taşır ve YEDİĞİN AĞIRLIKLA
// ölçeklenir. İkisi de mealRoutines'te durur, `type` ayırır.
// ============================================================

// Porsiyon kapları: "1 kase çorba" derken kastedilen kap. Kaç gram olduğu
// kişiden kişiye değişir, o yüzden ÖĞRENİLİR (bkz. r.portions).
const PORSIYON_KAPLARI = ['kase','tabak','bardak','kepce','porsiyon','kupa','canak','dilim'];

function _recipePer100(items, yieldG){
  if(!(yieldG>0) || !items?.length) return null;
  const t=items.reduce((a,i)=>({
    kcal:a.kcal+(+i.calories||0), p:a.p+(+i.protein||0),
    k:a.k+(+i.carbs||0), y:a.y+(+i.fat||0),
  }),{kcal:0,p:0,k:0,y:0});
  const f=100/yieldG;
  return { kcal:Math.round(t.kcal*f), protein:Math.round(t.p*f*10)/10,
           carbs:Math.round(t.k*f*10)/10, fat:Math.round(t.y*f*10)/10 };
}

// Metinde geçen porsiyon kabını bul ("1 kase mercimek çorbası" → "kase")
function _portionWord(text){
  const n=_foodNorm(text);
  for(const kap of PORSIYON_KAPLARI) if(n.includes(' '+kap) || n.startsWith(kap+' ')) return kap;
  return null;
}

/**
 * Bu girişte kaç gram yenmiş?
 * @returns {{gram:number, kaynak:'yazili'|'ogrenilmis'}|{gram:null, kap:string|null}}
 */
function _recipeGrams(text, r){
  // 1) Açıkça yazdıysa o geçerli — en güvenilir bilgi
  const {qty, grams}=_parseFoodText(text);
  if(grams>0) return { gram:grams, kaynak:'yazili' };

  // 2) Kabı daha önce tarttıysak biliyoruz
  const kap=_portionWord(text);
  if(kap && r.portions?.[kap]>0) return { gram:r.portions[kap]*(qty||1), kaynak:'ogrenilmis', kap };

  // 3) Bilinmiyor — kullanıcıya soracağız
  return { gram:null, kap:kap||'porsiyon' };
}

/** Tarifi belirtilen ağırlıkla uygula. Tek bir kayıt üretir. */
async function applyMealRecipe(recipeId, gram){
  const r=ST.mealRoutines.find(x=>x.id===recipeId);
  if(!r?.per100 || !(gram>0)) return null;
  const f=gram/100;
  const entry={
    id:'n_'+Date.now()+'_'+Math.random().toString(36).slice(2,6),
    date:todayDateKey(),
    name:r.name+' '+Math.round(gram)+'g',
    calories:Math.round(r.per100.kcal*f),
    protein:Math.round(r.per100.protein*f*10)/10,
    carbs:Math.round(r.per100.carbs*f*10)/10,
    fat:Math.round(r.per100.fat*f*10)/10,
    emoji:r.emoji||'🍲',
    portionNote:'📐 kendi tarifin',
    matchSource:'recipe', routineId:r.id,
    pending:false, createdAt:Date.now(),
  };
  await DB.put('nutritionLogs',entry);
  ST.nutritionLogs.push(entry);
  const upd={...r, useCount:(r.useCount||0)+1, lastUsedAt:Date.now()};
  const idx=ST.mealRoutines.findIndex(x=>x.id===r.id);
  ST.mealRoutines[idx]=upd;
  await DB.put('mealRoutines',upd);
  renderBeslenme();
  return {routine:upd, added:[entry.id]};
}

// ---- Porsiyon hafızası -----------------------------------------
// "1 kase" senin için belli bir gram. Bir kez sorulur, sonra hep bilinir.
let _porsiyonBekleyen=null;   // {recipeId, kap, text}

function sorPorsiyon(recipeId, kap, text){
  const r=ST.mealRoutines.find(x=>x.id===recipeId); if(!r) return;
  _porsiyonBekleyen={recipeId, kap, text};
  document.getElementById('porsiyon-baslik').textContent='1 ' + kap + ' ' + r.name;
  const inp=document.getElementById('porsiyon-input');
  inp.value = r.portions?.[kap] || '';
  document.getElementById('porsiyon-oneri').textContent =
    'Tartıp yazarsan bir daha sorulmaz — bundan sonraki her "' + kap + '" bu ağırlıkla hesaplanır.';
  openModal('modal-porsiyon');
  setTimeout(()=>inp.focus(),120);
}

async function kaydetPorsiyon(){
  const g=parseFloat(String(document.getElementById('porsiyon-input')?.value||'').replace(',','.'));
  if(!(g>0)){ showToast('Geçerli bir gram gir',true); return; }
  const b=_porsiyonBekleyen; if(!b) { closeModal('modal-porsiyon'); return; }
  if(b.dishKey){            // kanonik yemek tablosu (js/dishes.js)
    closeModal('modal-porsiyon'); _porsiyonBekleyen=null;
    await kaydetYemekPorsiyonu(b,g); return;
  }
  const idx=ST.mealRoutines.findIndex(x=>x.id===b.recipeId);
  if(idx!==-1){
    const r=ST.mealRoutines[idx];
    ST.mealRoutines[idx]={...r, portions:{...(r.portions||{}), [b.kap]:g}};
    await DB.put('mealRoutines',ST.mealRoutines[idx]);
  }
  closeModal('modal-porsiyon');
  const res=await applyMealRecipe(b.recipeId, g);
  _porsiyonBekleyen=null;
  if(res) showActionToast('📐 '+res.routine.name+' eklendi','Geri al',
    ()=>_undoRoutineApply(res.added,res.routine.id));
}

/**
 * Eşleşen kaydı türüne göre uygula.
 * @returns {boolean} işlendi mi (false ise normal analiz akışı sürsün)
 */
async function _uygulaEslesme(match, text){
  if(match.type==='recipe'){
    if(!match.per100){ showToast('Bu tarifin tencere ağırlığı girilmemiş',true); return false; }
    const g=_recipeGrams(text, match);
    if(g.gram==null){ sorPorsiyon(match.id, g.kap, text); return true; }
    const res=await applyMealRecipe(match.id, g.gram);
    if(!res) return false;
    await _learnRoutineTrigger(match.id, text);
    showActionToast('📐 '+res.routine.name+' eklendi'+(g.kaynak==='ogrenilmis'?' ('+Math.round(g.gram)+'g)':''),
      'Geri al', ()=>_undoRoutineApply(res.added,res.routine.id));
    return true;
  }
  // Rutin: sabit porsiyon taşır. Kullanıcı açıkça miktar yazdıysa onun
  // dediği geçerli, rutini dayatma — normal analize düşsün.
  if(_hasExplicitAmounts(text)) return false;
  const res=await applyMealRoutine(match.id);
  if(!res) return false;
  await _learnRoutineTrigger(match.id, text);
  showActionToast('⭐ '+res.routine.name+' eklendi','Geri al',
    ()=>_undoRoutineApply(res.added,res.routine.id));
  return true;
}

// ---- Tarif oluşturma -------------------------------------------
async function yeniTarifOlustur(){
  const ad=(document.getElementById('yeni-tarif-adi')?.value||'').trim();
  if(!ad){ showToast('Tarife bir ad ver',true); return; }
  const r={
    id:'mr_'+Date.now()+'_'+Math.random().toString(36).slice(2,6),
    name:ad, type:'recipe', emoji:'🍲',
    sig:'', triggers:[ad], items:[], yieldG:0, per100:null, portions:{},
    samples:1, useCount:0, lastUsedAt:null, createdAt:Date.now(),
  };
  ST.mealRoutines.push(r);
  await DB.put('mealRoutines',r);
  closeModal('modal-yeni-tarif');
  closeModal('modal-routine-picker');
  renderBeslenme();
  openRoutineEdit(r.id);
}

// Tencere ağırlığı değişince 100 g başına değeri yeniden hesapla
async function kaydetTencereAgirligi(val){
  const g=parseFloat(String(val).replace(',','.'));
  const idx=ST.mealRoutines.findIndex(x=>x.id===_editRoutineId);
  if(idx===-1) return;
  const r=ST.mealRoutines[idx];
  const upd={...r, yieldG: g>0?g:0};
  upd.per100=_recipePer100(upd.items, upd.yieldG);
  ST.mealRoutines[idx]=upd;
  await DB.put('mealRoutines',upd);
  _renderRoutineEdit();
  renderBeslenme();
}

async function applyMealRoutine(routineId){
  const r=ST.mealRoutines.find(x=>x.id===routineId);
  if(!r || !Array.isArray(r.items)) return null;
  const added=[];
  let i=0;
  // Çok kalemli rutin TEK KART olarak görünmeli. Eskiden groupId
  // verilmediği için süt ve gevrek ayrı ayrı satır oluyordu — oysa
  // kullanıcı onları tek öğün olarak kaydetmişti.
  const grup = r.items.length>1
    ? { groupId:'g_'+Date.now()+'_'+Math.random().toString(36).slice(2,6),
        groupName:r.name, groupEmoji:r.emoji||r.items[0]?.emoji||'🍽️' }
    : {};
  for(const it of r.items){
    const entry={
      id:'n_'+Date.now()+'_'+Math.random().toString(36).slice(2,6),
      date:todayDateKey(),
      name:it.name,
      calories:Math.round(it.calories||0),
      protein:Math.round((it.protein||0)*10)/10,
      carbs:Math.round((it.carbs||0)*10)/10,
      fat:Math.round((it.fat||0)*10)/10,
      emoji:it.emoji||'🍽️',
      portionNote:it.portionNote||'',
      matchSource:'routine', routineId:r.id,
      foodId:it.foodId||null, pending:false,
      createdAt:Date.now()+(i++),   // sıralama korunsun
      ...grup,
    };
    await DB.put('nutritionLogs',entry);
    ST.nutritionLogs.push(entry);
    added.push(entry.id);
  }
  const upd={...r, useCount:(r.useCount||0)+1, lastUsedAt:Date.now()};
  const idx=ST.mealRoutines.findIndex(x=>x.id===r.id);
  ST.mealRoutines[idx]=upd;
  await DB.put('mealRoutines',upd);
  renderBeslenme();
  return {routine:upd, added};
}

async function _undoRoutineApply(ids, routineId){
  for(const id of ids){
    await DB.del('nutritionLogs',id);
    ST.nutritionLogs=ST.nutritionLogs.filter(e=>e.id!==id);
  }
  // Kullanım sayacını da geri al — yanlış eşleşme sıklığı şişirmesin
  const idx=ST.mealRoutines.findIndex(x=>x.id===routineId);
  if(idx!==-1){
    const r={...ST.mealRoutines[idx], useCount:Math.max(0,(ST.mealRoutines[idx].useCount||1)-1)};
    ST.mealRoutines[idx]=r;
    await DB.put('mealRoutines',r);
  }
  renderBeslenme();
  showToast('↩️ Geri alındı');
}

// Rutini girişlerden oluştur (hem otomatik teklif hem elle seçim kullanır)
async function _createRoutineFromEntries(entries, name){
  const items=_routineItemsFromEntries(entries);
  if(!items.length) return null;
  // Tetikler kullanıcının GERÇEKTEN yazdığı ifadelerden doğar. Rutin
  // içeriğinden türetmek "süt" yazınca tüm kahvaltının gelmesine yol açıyordu.
  const triggers=[...new Set(entries.map(e=>e.raw).filter(Boolean))].slice(0,4);
  const routine={
    id:'mr_'+Date.now()+'_'+Math.random().toString(36).slice(2,6),
    name:name||_routineAutoName(entries[0]?.createdAt),
    sig:_sessionSignature(entries),
    items, triggers, samples:1, useCount:0, lastUsedAt:null,
    createdAt:Date.now(),
  };
  ST.mealRoutines.push(routine);
  await DB.put('mealRoutines',routine);
  return routine;
}

async function deleteMealRoutine(id){
  await DB.del('mealRoutines',id);
  ST.mealRoutines=ST.mealRoutines.filter(r=>r.id!==id);
  renderBeslenme();
  showToast('🗑️ Rutin silindi');
}

// ---- Tekrar tespiti ve teklif ----------------------------------

let _routineOfferTimer=null;

// Girişten hemen sonra sormak yanlış olur: kullanıcı hâlâ öğünün diğer
// kalemlerini yazıyor olabilir. Yazma durduktan sonra değerlendiririz.
function _scheduleRoutineCheck(delay=45000){
  clearTimeout(_routineOfferTimer);
  _routineOfferTimer=setTimeout(()=>{ _maybeOfferRoutine(); }, delay);
}

async function _maybeOfferRoutine(){
  const sessions=_nutSessions();
  if(sessions.length<2) return;
  const last=sessions[sessions.length-1];
  const sig=_sessionSignature(last.entries);
  if(!sig) return;

  // Zaten rutini var mı? Varsa gözlemi ortalamaya kat, tekrar sorma.
  const existing=ST.mealRoutines.find(r=>_sigAkin(r.sig,sig));
  if(existing){
    if(last.last>(existing.lastMergedAt||0)){
      const upd={..._mergeRoutineObservation(existing,last.entries), lastMergedAt:last.last};
      const idx=ST.mealRoutines.findIndex(r=>r.id===existing.id);
      ST.mealRoutines[idx]=upd;
      await DB.put('mealRoutines',upd);
      // Kullanıcının bu sefer yazdığı ifadeyi de tetik olarak öğren
      const raw=last.entries.map(e=>e.raw).find(Boolean);
      if(raw) await _learnRoutineTrigger(existing.id, raw);
      // Sessizce öğrenmek "sistem beni tanıyor" hissini vermiyor — göster
      showToast('⭐ "'+upd.name+'" güncellendi · '+(upd.samples||1)+' ölçümün ortalaması');
      renderBeslenme();
    }
    return;
  }

  // Kullanıcı daha önce "hayır" dediyse bir daha sorma
  const dismissed=ST.settings.dismissedMealSigs||[];
  if(dismissed.includes(sig)) return;

  // Aynı imza geçmişte kaç kez görüldü?
  const seen=sessions.filter(s=>_sigAkin(_sessionSignature(s.entries),sig)).length;
  if(seen<ROUTINE_MIN_SAMPLES) return;

  // Önizleme SON girişi değil, tüm ölçümlerin ORTALAMASINI göstermeli —
  // kullanıcıya "kaydedeceğim değerler bunlar" demiş oluyoruz.
  const matching=sessions.filter(s=>_sigAkin(_sessionSignature(s.entries),sig));
  let preview={items:_routineItemsFromEntries(matching[0].entries), samples:1};
  for(let i=1;i<matching.length;i++) preview=_mergeRoutineObservation(preview, matching[i].entries);
  const items=preview.items;
  const özet=items.map(i=>i.name).join(' + ');
  const kcal=Math.round(items.reduce((a,i)=>a+(i.calories||0),0));

  showConfirm('⭐','Bunu rutin yapayım mı?',
    `${özet} — toplam ${kcal} kcal. ${seen}. kez giriyorsun; bunlar ölçümlerinin ortalaması. `
    + `Rutine ne kadar çok veri girersen ortalaman o kadar isabetli olur. `
    + `Kaydedersem bir daha tek kelimeyle ekleyebilirsin.`,
    async()=>{
      closeModal('modal-alert');
      // İlk gözlemi de ortalamaya katmak için geçmişteki eşleşen oturumları birleştir
      let r=await _createRoutineFromEntries(last.entries);
      if(!r) return;
      const others=sessions.filter(s=>_sigAkin(_sessionSignature(s.entries),sig) && s!==last);
      // Tetikleri HER oturumdan topla. Sadece son girişten almak, kullanıcının
      // ilk gün yazdığı ("kahvaltılık gevrek") ifadeyi kaybettiriyordu ve
      // sistem kendi öğrettiği kelimeyi tanımıyordu.
      {
        const raws=[...new Set(matching.flatMap(s=>s.entries.map(e=>e.raw)).filter(Boolean))].slice(0,6);
        const i0=ST.mealRoutines.findIndex(x=>x.id===r.id);
        ST.mealRoutines[i0]={...ST.mealRoutines[i0], triggers:raws};
        r=ST.mealRoutines[i0];
      }
      for(const s of others){
        const idx=ST.mealRoutines.findIndex(x=>x.id===r.id);
        r=_mergeRoutineObservation(ST.mealRoutines[idx], s.entries);
        ST.mealRoutines[idx]=r;
      }
      r={...r, lastMergedAt:last.last};
      const idx=ST.mealRoutines.findIndex(x=>x.id===r.id);
      ST.mealRoutines[idx]=r;
      await DB.put('mealRoutines',r);
      renderBeslenme();
      showToast('⭐ "'+r.name+'" kaydedildi');
    }, 'primary');

  // "Hayır"a basılırsa bir daha sorulmasın
  const cancelBtn=document.getElementById('alert-cancel');
  if(cancelBtn) cancelBtn.onclick=async()=>{
    closeModal('modal-alert');
    ST.settings.dismissedMealSigs=[...dismissed,sig].slice(-50);
    await DB.put('settings',{id:'main',...ST.settings});
  };
}

// ---- Eylemli toast (Geri al) -----------------------------------

let _actionToastTimer=null;
function showActionToast(msg, actionLabel, onAction, ms=6000){
  let el=document.getElementById('action-toast');
  if(!el){
    el=document.createElement('div');
    el.id='action-toast';
    el.style.cssText='position:fixed;left:50%;transform:translateX(-50%) translateY(20px);'
      +'bottom:calc(var(--nav-h) + var(--safe-bot) + 16px);z-index:10000;display:flex;align-items:center;'
      +'gap:12px;padding:11px 14px;border-radius:14px;background:var(--surface2);border:1px solid var(--border);'
      +'box-shadow:0 6px 24px rgba(0,0,0,0.35);opacity:0;transition:opacity .25s,transform .25s;'
      // Kesin genişlik şart: içerik kadar genişleyen bir kapta çocukların
      // %100 genişliği çözümsüz kalıp 0px'e çöküyordu (geri sayım çubuğu
      // görünmüyordu).
      +'width:min(92vw,430px);font-size:13.5px;font-weight:600;color:var(--text)';
    document.body.appendChild(el);
  }
  el.innerHTML='';
  // Metin tek satıra sıkıştırılıp kesiliyordu ("Akşam rutini ekl..."),
  // uzun rutin adları okunamıyordu. İki satıra kadar sarsın.
  const satir=document.createElement('div');
  satir.style.cssText='display:flex;align-items:center;gap:12px;width:100%';
  const txt=document.createElement('span');
  txt.textContent=msg;
  txt.style.cssText='flex:1;min-width:0;line-height:1.35;display:-webkit-box;'
    +'-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden';
  const btn=document.createElement('button');
  btn.textContent=actionLabel;
  btn.style.cssText='flex-shrink:0;padding:6px 12px;border-radius:20px;border:1.5px solid var(--accent);'
    +'background:transparent;color:var(--accent-text);font-size:12.5px;font-weight:700;cursor:pointer';
  btn.onclick=async()=>{ hide(); await onAction(); };
  satir.append(txt,btn);

  // Rakamsız geri sayım: kullanıcı tuşun ne zaman kaybolacağını görsün.
  // Renk de akrepten kırmızıya döner, süre azaldıkça aciliyet artar.
  const yol=document.createElement('div');
  yol.style.cssText='width:100%;height:3px;border-radius:2px;background:var(--border);'
    +'margin-top:9px;overflow:hidden';
  const dolgu=document.createElement('div');
  dolgu.style.cssText='height:100%;width:100%;border-radius:2px;background:var(--accent);'
    +'transform-origin:left center;transition:transform '+ms+'ms linear, background-color '+ms+'ms linear';
  yol.appendChild(dolgu);

  el.style.flexDirection='column';
  el.style.alignItems='stretch';
  el.append(satir,yol);

  requestAnimationFrame(()=>{
    el.style.opacity='1'; el.style.transform='translateX(-50%) translateY(0)';
  });
  // Geçişin başlaması için tarayıcının BAŞLANGIÇ değerini görmesi gerek.
  // İç içe requestAnimationFrame bunu garanti etmiyordu; reflow'u zorluyoruz.
  dolgu.style.transform='scaleX(1)';
  void dolgu.offsetWidth;
  dolgu.style.transform='scaleX(0)';
  dolgu.style.backgroundColor='var(--danger)';
  clearTimeout(_actionToastTimer);
  _actionToastTimer=setTimeout(hide, ms);
  function hide(){
    clearTimeout(_actionToastTimer);
    el.style.opacity='0'; el.style.transform='translateX(-50%) translateY(20px)';
  }
}

// ---- Elle rutin oluşturma (günün listesinden seçerek) -----------

let _routineSelectMode=false;
let _routineSelected=new Set();

function toggleRoutineSelectMode(){
  _routineSelectMode=!_routineSelectMode;
  _routineSelected.clear();
  renderBeslenme();
}

// Grubun TAMAMINI seç/bırak. Ana kart eskiden hiç seçilemiyordu.
function toggleRoutineSelectionGroup(gid){
  const ids=ST.nutritionLogs.filter(e=>e.groupId===gid && !e.pending && !e.error).map(e=>e.id);
  const hepsi=ids.length>0 && ids.every(id=>_routineSelected.has(id));
  for(const id of ids){ if(hepsi) _routineSelected.delete(id); else _routineSelected.add(id); }
  renderBeslenme();
}

function toggleRoutineSelection(id){
  if(_routineSelected.has(id)) _routineSelected.delete(id);
  else _routineSelected.add(id);
  renderBeslenme();
}

async function createRoutineFromSelection(){
  const entries=getTodayNutrition().filter(e=>_routineSelected.has(e.id) && !e.pending && !e.error);
  if(!entries.length){ showToast('Önce öğe seç',true); return; }
  const r=await _createRoutineFromEntries(entries);
  _routineSelectMode=false; _routineSelected.clear();
  renderBeslenme();
  if(r) showToast('⭐ "'+r.name+'" kaydedildi');
}

// ---- Rutin düzenleme modalı ------------------------------------

let _editRoutineId=null;
function openRoutineEdit(id){
  const r=ST.mealRoutines.find(x=>x.id===id); if(!r) return;
  _editRoutineId=id;
  _renderRoutineEdit();
  openModal('modal-routine-edit');
}

function _renderRoutineEdit(){
  const r=ST.mealRoutines.find(x=>x.id===_editRoutineId); if(!r) return;
  const body=document.getElementById('routine-edit-content');
  // Eski sürümlerden kalan kayıtlarda items eksik olabiliyor; burada
  // patlarsa modal hiç açılmıyor ve kullanıcı rutini SİLEMİYORDU.
  if(!Array.isArray(r.items)) r.items=[];
  const kcal=Math.round(r.items.reduce((a,i)=>a+(i.calories||0),0));
  body.innerHTML=`
    <input class="form-input" id="routine-name-input" value="${esc(r.name||'')}" style="font-size:14px;padding:11px 12px;margin-bottom:14px">
    ${r.type==='recipe' ? `
      <div style="border:1px solid var(--accent);background:var(--accent-dim);border-radius:12px;padding:12px;margin-bottom:14px">
        <div style="font-size:12px;color:var(--text2);margin-bottom:8px">TENCERENİN TAMAMI — pişmiş hâlde tart</div>
        <input class="form-input" type="number" inputmode="decimal" step="1" min="0" placeholder="örn. 3200"
               value="${r.yieldG||''}" style="font-size:14px;padding:10px 11px"
               onchange="kaydetTencereAgirligi(this.value)">
        ${r.per100 ? `<div style="font-size:13px;font-weight:700;color:var(--accent-text);margin-top:10px">100 g başına: ${r.per100.kcal} kcal · ${r.per100.protein}p · ${r.per100.carbs}k · ${r.per100.fat}y</div>${Object.keys(r.portions||{}).length ? `<div style="font-size:11.5px;color:var(--text2);margin-top:6px">Öğrenilen porsiyonlar: ${Object.entries(r.portions).map(([kk,vv])=>kk+' = '+vv+'g').join(' · ')}</div>` : ''}` : `<div style="font-size:11.5px;color:var(--text3);margin-top:8px">Malzemeleri ekle ve tencere ağırlığını gir — 100 g başına değer burada çıkacak.</div>`}
      </div>
      <div style="font-size:12px;color:var(--text2);margin-bottom:8px">MALZEMELER — toplam ${kcal} kcal</div>
    ` : `
      <div style="font-size:12px;color:var(--text2);margin-bottom:8px">İÇERİK — ${kcal} kcal, ${r.samples||1} ölçümün ortalaması</div>
    `}
    <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:12px">
      ${r.items.map((i,ix)=>`<div style="display:flex;align-items:center;gap:8px;padding:9px 11px;border-radius:10px;background:var(--surface2);font-size:13px">
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(i.emoji||'🍽️')} ${esc(i.name)}${i.fixed?' <span style="color:var(--text3);font-size:11px">· sabit</span>':''}</span>
        <span style="color:var(--text2);flex-shrink:0">${Math.round(i.calories||0)} kcal</span>
        <button onclick="removeRoutineItem(${ix})" title="Kalemi çıkar" style="flex-shrink:0;background:transparent;border:none;color:var(--danger);font-size:15px;cursor:pointer;padding:2px 4px">✕</button>
      </div>`).join('')}
    </div>

    <!-- Kalem ekleme: makrolar ELLE girilmez. Kademeli sorgu yapılır:
         kayıtlı ürün → Open Food Facts → (son çare) AI tahmini. -->
    <div style="border-top:1px solid var(--border);padding-top:12px;margin-bottom:14px">
      <div style="font-size:12px;color:var(--text2);margin-bottom:7px">KALEM EKLE</div>
      <div style="display:flex;gap:6px">
        <input class="form-input" id="routine-add-input" placeholder='Örn: "1 muz" veya "200gr yoğurt"' autocomplete="off"
               style="flex:1;font-size:13px;padding:10px 11px" oninput="_renderRoutineAddSuggest(this.value)"
               onkeydown="if(event.key==='Enter'){event.preventDefault();addRoutineItemFromText();}">
        <button class="btn btn-primary" id="routine-add-btn" style="flex-shrink:0;padding:0 14px" onclick="addRoutineItemFromText()">Ekle</button>
      </div>
      <div id="routine-add-suggest" style="display:flex;flex-wrap:wrap;gap:5px;margin-top:7px"></div>
      <div style="font-size:11px;color:var(--text3);margin-top:7px;line-height:1.45">
        Besin değerlerini sen girmiyorsun: önce kayıtlı ürünlerine, sonra Open Food Facts'e bakılır; ikisi de bulamazsa AI tahmin eder.
      </div>
    </div>

    <div style="display:flex;gap:8px">
      <button class="btn btn-ghost" style="flex:1" onclick="closeModal('modal-routine-edit')">Kapat</button>
      <button class="btn btn-primary" style="flex:1" onclick="saveRoutineName()">Adı kaydet</button>
    </div>
    <button class="btn btn-danger" style="width:100%;margin-top:8px" onclick="deleteRoutineFromModal()">🗑️ Rutini sil</button>
  `;
  _renderRoutineAddSuggest(document.getElementById('routine-add-input')?.value||'');
}

// Yazarken kayıtlı ürünlerden öneri göster — "kayıtlılardan seçmek" için
// ayrı bir ekran gerekmiyor, aynı kutu ikisini de karşılıyor.
function _renderRoutineAddSuggest(q){
  const el=document.getElementById('routine-add-suggest'); if(!el) return;
  const n=_foodNorm(q||'');
  if(n.length<2){ el.innerHTML=''; return; }
  const freq=_foodFrequency();
  const list=(ST.foodDb||[])
    .filter(f=>(f.norm||_foodNorm(f.name)).includes(n))
    .sort((a,b)=>(freq[b.id]||0)-(freq[a.id]||0))
    .slice(0,5);
  el.innerHTML=list.map(f=>`<button onclick="addRoutineItemFromFood('${f.id}')" style="padding:5px 10px;border-radius:16px;background:var(--surface2);border:1.5px solid var(--border);color:var(--text2);font-size:11.5px;font-weight:600;cursor:pointer;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">📗 ${esc(f.name)}</button>`).join('');
}

async function _pushRoutineItems(newItems){
  const idx=ST.mealRoutines.findIndex(r=>r.id===_editRoutineId);
  if(idx===-1 || !newItems.length) return;
  const r=ST.mealRoutines[idx];
  const items=[...r.items];
  for(const it of newItems){
    const p=_splitPortionFromName(it.name);
    items.push({
      key:'m:'+_foodNorm(it.name).replace(/\d+/g,' ').replace(/\s+/g,' ').trim(),
      foodId:it.foodId||null,
      base:p.base, portionQty:p.qty, portionUnit:p.unit,
      name:_portionName(p.base,p.qty,p.unit),
      emoji:it.emoji||'🍽️',
      calories:Math.round(+it.calories||0),
      protein:Math.round((+it.protein||0)*10)/10,
      carbs:Math.round((+it.carbs||0)*10)/10,
      fat:Math.round((+it.fat||0)*10)/10,
      portionNote:it.portionNote||'',
      samples:1, fixed:true,   // elle eklendi — ölçüm ortalamasından gelmedi
    });
  }
  const upd={...r, items};
  // Tarifte malzeme değişince 100 g başına değer yeniden hesaplanmalı
  if(upd.type==='recipe') upd.per100=_recipePer100(upd.items, upd.yieldG);
  ST.mealRoutines[idx]=upd;
  await DB.put('mealRoutines',upd);
  _renderRoutineEdit();
  renderBeslenme();
  showToast('➕ '+newItems.map(i=>i.name).join(', ')+' eklendi');
}

async function addRoutineItemFromFood(foodId){
  const f=(ST.foodDb||[]).find(x=>x.id===foodId); if(!f) return;
  const raw=document.getElementById('routine-add-input')?.value||'';
  const {qty,grams}=_parseFoodText(raw);
  const mac=_foodToMacros(f,qty||1,grams);
  await _pushRoutineItems([{ name:f.name+(grams?' '+grams+'g':''), foodId:f.id, emoji:'📗',
    calories:mac.calories, protein:mac.protein, carbs:mac.carbs, fat:mac.fat, portionNote:mac.portionNote }]);
  const inp=document.getElementById('routine-add-input'); if(inp) inp.value='';
  _renderRoutineAddSuggest('');
}

async function addRoutineItemFromText(){
  const inp=document.getElementById('routine-add-input');
  const text=inp?.value?.trim(); if(!text) return;
  const btn=document.getElementById('routine-add-btn');
  if(btn){ btn.disabled=true; btn.textContent='...'; }
  try{
    // KADEME 1-2: kayıtlı ürün → Open Food Facts (gerçek veri, AI tahmini değil)
    const res=_looksMultiFood(text)?null:await _cascadeResolveText(text);
    if(res){
      await _pushRoutineItems([{ name:res.name, foodId:res.foodId||null, emoji:res.emoji,
        calories:res.calories, protein:res.protein, carbs:res.carbs, fat:res.fat, portionNote:res.portionNote }]);
    }else{
      // KADEME 3: son çare AI tahmini
      const data=await callGemini([{parts:[{text:_nutTextPrompt(text)}]}],null,NUT_GEN_CFG);
      if(data.error) throw new Error(data.error.message||JSON.stringify(data.error));
      const parsed=_extractJson(_geminiText(data));
      let items=Array.isArray(parsed.items)?parsed.items.filter(i=>i&&(i.kcal||i.name)):[];
      if(!items.length) items=[{name:parsed.name||text,kcal:parsed.totalKcal,protein:parsed.totalProtein,carbs:parsed.totalCarbs,fat:parsed.totalFat,emoji:parsed.emoji}];
      await _pushRoutineItems(items.map(i=>({ name:i.name||text, emoji:i.emoji||parsed.emoji||'🍽️',
        calories:+i.kcal||0, protein:+i.protein||0, carbs:+i.carbs||0, fat:+i.fat||0, portionNote:'~AI tahmini' })));
    }
    if(inp) inp.value='';
    _renderRoutineAddSuggest('');
  }catch(err){
    showToast(_nutErrMsg(err), true);
  }finally{
    const b=document.getElementById('routine-add-btn');
    if(b){ b.disabled=false; b.textContent='Ekle'; }
  }
}

async function removeRoutineItem(ix){
  const idx=ST.mealRoutines.findIndex(r=>r.id===_editRoutineId); if(idx===-1) return;
  const r=ST.mealRoutines[idx];
  if(r.items.length<=1){ showToast('Rutinde en az bir kalem kalmalı',true); return; }
  const upd={...r, items:r.items.filter((_,i)=>i!==ix)};
  if(upd.type==='recipe') upd.per100=_recipePer100(upd.items, upd.yieldG);
  ST.mealRoutines[idx]=upd;
  await DB.put('mealRoutines',upd);
  _renderRoutineEdit();
  renderBeslenme();
}

async function saveRoutineName(){
  const v=document.getElementById('routine-name-input')?.value?.trim();
  const idx=ST.mealRoutines.findIndex(r=>r.id===_editRoutineId);
  if(idx!==-1 && v){
    ST.mealRoutines[idx]={...ST.mealRoutines[idx],name:v};
    await DB.put('mealRoutines',ST.mealRoutines[idx]);
  }
  closeModal('modal-routine-edit');
  renderBeslenme();
}

async function deleteRoutineFromModal(){
  const id=_editRoutineId;
  closeModal('modal-routine-edit');
  await deleteMealRoutine(id);
}

// ---- Rutin seçici (⭐ düğmesi) ---------------------------------
// Çip satırı 4 rutinden fazlasını taşıyamıyor; 20-25 rutinde yatay kaydırma
// çile oluyor. Bu liste arama kutusuyla hepsine erişim veriyor.
let _routinePickQuery='';

function openRoutinePicker(){
  _routinePickQuery='';
  _renderRoutinePicker();
  openModal('modal-routine-picker');
  setTimeout(()=>document.getElementById('routine-pick-search')?.focus(),80);
}

function onRoutinePickSearch(v){ _routinePickQuery=v; _renderRoutinePicker(true); }

function _renderRoutinePicker(listOnly){
  const q=_foodNorm(_routinePickQuery);
  const list=[...(ST.mealRoutines||[])]
    .filter(r=>!q || _foodNorm(r.name).includes(q)
             || r.items.some(i=>_foodNorm(i.name).includes(q))
             || (r.triggers||[]).some(t=>_foodNorm(t).includes(q)))
    .sort((a,b)=>(b.useCount||0)-(a.useCount||0) || (b.lastUsedAt||0)-(a.lastUsedAt||0));

  const rows=list.length?list.map(r=>{
    const kcal=Math.round((r.items||[]).reduce((a,i)=>a+(i.calories||0),0));
    return `<div style="display:flex;align-items:center;gap:8px;padding:10px 11px;border-radius:10px;background:var(--surface2);border:1.5px solid var(--accent)">
      <button onclick="applyRoutineFromPicker('${r.id}')" style="flex:1;min-width:0;display:flex;align-items:center;gap:9px;background:transparent;border:none;cursor:pointer;text-align:left;padding:0">
        <span style="font-size:15px;flex-shrink:0">${r.type==='recipe'?'🍲':'⭐'}</span>
        <span style="flex:1;min-width:0">
          <span style="display:block;font-size:13.5px;font-weight:700;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.name)}</span>
          <span style="display:block;font-size:11px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.type==='recipe' ? (r.per100?('100g = '+r.per100.kcal+' kcal'):'tencere ağırlığı girilmedi') : esc(r.items.map(i=>i.name).join(' + '))}</span>
        </span>
        <span style="font-size:12px;color:var(--text2);flex-shrink:0">${kcal} kcal</span>
      </button>
      <button onclick="closeModal('modal-routine-picker');openRoutineEdit('${r.id}')" title="Düzenle" style="flex-shrink:0;background:transparent;border:none;color:var(--text3);font-size:16px;cursor:pointer;padding:4px 6px">✎</button>
      <button onclick="silRutinListeden('${r.id}')" title="Sil" style="flex-shrink:0;background:transparent;border:none;color:var(--danger);font-size:15px;cursor:pointer;padding:4px 6px">🗑</button>
    </div>`;
  }).join('')
  : `<div style="font-size:13px;color:var(--text3);padding:18px 0;text-align:center">${q?'Eşleşen rutin yok.':'Henüz rutin yok.'}</div>`;

  const el=document.getElementById('routine-pick-list');
  if(listOnly && el){ el.innerHTML=rows; return; }
  document.getElementById('routine-picker-content').innerHTML=`
    <button class="btn btn-primary btn-full" style="margin-bottom:12px"
      onclick="document.getElementById('yeni-tarif-adi').value='';openModal('modal-yeni-tarif')">🍲 Kendi tarifini ekle</button>
    <input id="routine-pick-search" class="form-input" placeholder="Rutin ara..." autocomplete="off"
           style="font-size:14px;padding:10px 12px;margin-bottom:12px" oninput="onRoutinePickSearch(this.value)">
    <div id="routine-pick-list" style="display:flex;flex-direction:column;gap:6px;max-height:54vh;overflow-y:auto">${rows}</div>`;
}

// Listeden doğrudan silme: bozuk kayıtlar düzenleme ekranını açamadığı
// için silinemez hâlde kalıyordu.
async function silRutinListeden(id){
  const r=ST.mealRoutines.find(x=>x.id===id);
  showConfirm('🗑️','Rutini sil', (r?.name||'Bu rutin')+' silinsin mi? Geçmiş öğünlerin etkilenmez.', async()=>{
    closeModal('modal-alert');
    await deleteMealRoutine(id);
    _renderRoutinePicker();
  });
}

async function applyRoutineFromPicker(id){
  closeModal('modal-routine-picker');
  await applyRoutineFromChip(id);
}

// Çipe basınca rutini uygula (geri alma seçenekli)
async function applyRoutineFromChip(id){
  const r=ST.mealRoutines.find(x=>x.id===id); if(!r) return;
  // Tarifte ne kadar yediğini bilmiyoruz: öğrenilmiş porsiyon varsa onu
  // kullan, yoksa sor. Rutin sabit porsiyon taşıdığı için doğrudan eklenir.
  if(r.type==='recipe'){
    if(!r.per100){ showToast('Önce tencere ağırlığını gir',true); openRoutineEdit(id); return; }
    const kap=Object.keys(r.portions||{})[0];
    if(!kap){ sorPorsiyon(id,'porsiyon',''); return; }
    const res=await applyMealRecipe(id, r.portions[kap]);
    if(res) showActionToast('📐 '+res.routine.name+' eklendi ('+Math.round(r.portions[kap])+'g)','Geri al',
      ()=>_undoRoutineApply(res.added,res.routine.id));
    return;
  }
  const res=await applyMealRoutine(id);
  if(!res) return;
  showActionToast('⭐ '+res.routine.name+' eklendi','Geri al',
    ()=>_undoRoutineApply(res.added,res.routine.id));
}
