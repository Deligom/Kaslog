// ---- Öğün listesi çizimi ---------------------------------------
// Tek satırda yazılan çok kalemli öğün ayrı kayıtlar olarak saklanır ama
// ortak groupId ile TEK satır gibi görünür; dokununca kalemler açılır.
let _expandedNutGroups = new Set();

function toggleNutGroup(gid){
  if(_expandedNutGroups.has(gid)) _expandedNutGroups.delete(gid);
  else _expandedNutGroups.add(gid);
  renderBeslenme();
}

function _nutMacroHTML(e){
  if(e.pending) return '<span class="nut-entry-macro" style="color:var(--text3);font-style:italic">⏳ AI analiz ediyor...</span>';
  if(e.error)   return '<span class="nut-entry-macro" style="color:var(--danger)">⚠️ '+esc(e.errMsg||'Analiz başarısız — tekrar dene')+'</span>';
  return '<span class="nut-entry-macro">🥩 '+Math.round(e.protein||0)+'g protein</span>'
       + '<span class="nut-entry-macro">🌾 '+Math.round(e.carbs||0)+'g karb</span>'
       + '<span class="nut-entry-macro">🧈 '+Math.round(e.fat||0)+'g yağ</span>';
}

const _svgEdit = '<svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
const _svgDel  = '<svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>';

// Öğünün saati — "ne zaman yedim" bilgisi listede hiç yoktu
function _hhmm(ts){
  if(!ts) return '';
  const d=new Date(ts);
  return String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');
}

// Seçim kutusu AYRI bir öğe. Eskiden yiyecek ikonunun YERİNE konuyordu ve
// seçim modunda hangi satırın ne olduğu görsel olarak kayboluyordu.
function _checkBox(picked){
  return `<div style="flex-shrink:0;font-size:17px;line-height:1">${picked?'✅':'⬜'}</div>`;
}

function _nutEntryRowHTML(e, nested){
  const selectable=_routineSelectMode && !e.pending && !e.error;
  const picked=_routineSelected.has(e.id);
  const nameHTML=e.pending?'<span class="nut-entry-queue-dot"></span>'+esc(e.name):esc(e.name);
  const attrs = selectable
    ? `onclick="toggleRoutineSelection('${e.id}')" style="cursor:pointer${nested?';margin-left:16px':''}${picked?';border-color:var(--accent);background:var(--accent-dim)':''}"`
    : (nested?'style="margin-left:16px"':'');
  const saat=_hhmm(e.createdAt);
  const saatHTML=(saat&&!e.pending&&!e.error)
    ? `<span class="nut-entry-macro" style="color:var(--text3)">🕒 ${saat}</span>` : '';
  return `<div class="nut-entry${e.pending?' pending':''}${e.error?' error':''}" ${attrs}>
    ${selectable?_checkBox(picked):''}
    <div class="nut-entry-icon">${e.pending?'⏳':esc(e.emoji||'🍽️')}</div>
    <div class="nut-entry-info">
      <div class="nut-entry-name">${nameHTML}</div>
      <div class="nut-entry-macros">${_nutMacroHTML(e)}${saatHTML}</div>
    </div>
    ${(e.error || (e.pending && Date.now()-(e.createdAt||0) > 90000))
      ? `<button class="nut-retry-btn" onclick="retryNutritionEntry('${e.id}')">🔄 Tekrar</button>`
      : `<div class="nut-entry-kcal">${e.pending?'—':Math.round(e.calories||0)}</div>`}
    ${_routineSelectMode?'':`
      ${!e.pending&&!e.error?`<button class="nut-del-btn" onclick="openNutPicker('${e.id}')" title="Bu değil — kayıtlılardan seç" style="font-size:17px;letter-spacing:1px">⋯</button>
      <button class="nut-del-btn" onclick="openNutEdit('${e.id}')" title="Düzenle">${_svgEdit}</button>`:''}
      <button class="nut-del-btn" onclick="deleteNutritionEntry('${e.id}')" title="Sil">${_svgDel}</button>`}
  </div>`;
}

function _nutGroupRowHTML(items){
  const gid=items[0].groupId;
  // Seçim modunda kalemler tek tek işaretlenebilmeli — grubu hep açık göster
  const open=_expandedNutGroups.has(gid) || _routineSelectMode;
  const kcal=Math.round(items.reduce((a,e)=>a+(e.calories||0),0));
  const sum=k=>Math.round(items.reduce((a,e)=>a+(e[k]||0),0));
  const name=items[0].groupName||items.map(i=>i.name).join(' + ');
  const anyPending=items.some(e=>e.pending);
  const secilebilir=_routineSelectMode && !anyPending;
  const hepsiSecili=secilebilir && items.every(e=>_routineSelected.has(e.id));
  const ts=Math.min(...items.map(e=>e.createdAt||Infinity));
  const saat=Number.isFinite(ts)?_hhmm(ts):'';
  const saatHTML=(saat&&!anyPending)
    ? `<span class="nut-entry-macro" style="color:var(--text3)">🕒 ${saat}</span>` : '';
  // Seçim modunda başlığa basmak TÜM kalemleri işaretler. Eskiden ana kart
  // hiç seçilemiyordu, kullanıcı alt kalemleri tek tek işaretlemek zorundaydı.
  const tik=secilebilir
    ? `onclick="toggleRoutineSelectionGroup('${gid}')"`
    : `onclick="toggleNutGroup('${gid}')"`;
  const head=`<div class="nut-entry" ${tik} style="cursor:pointer${hepsiSecili?';border-color:var(--accent);background:var(--accent-dim)':''}">
    ${secilebilir?_checkBox(hepsiSecili):''}
    <div class="nut-entry-icon">${esc(items[0].groupEmoji||items[0].emoji||'🍽️')}</div>
    <div class="nut-entry-info">
      <div class="nut-entry-name">${esc(name)} <span style="color:var(--text3);font-weight:500;font-size:12px">· ${items.length} kalem</span></div>
      <div class="nut-entry-macros">
        <span class="nut-entry-macro">🥩 ${sum('protein')}g protein</span>
        <span class="nut-entry-macro">🌾 ${sum('carbs')}g karb</span>
        <span class="nut-entry-macro">🧈 ${sum('fat')}g yağ</span>
        ${saatHTML}
      </div>
    </div>
    <div class="nut-entry-kcal">${anyPending?'—':kcal}</div>
    ${_routineSelectMode?'':`
    <button class="nut-del-btn" onclick="event.stopPropagation();openNutPicker('${items[0].id}')" title="Bu değil — kayıtlılardan seç" style="font-size:17px;letter-spacing:1px">⋯</button>
    <button class="nut-del-btn" onclick="event.stopPropagation();deleteNutGroup('${gid}')" title="Öğünü sil">${_svgDel}</button>
    <button class="nut-del-btn" style="transform:rotate(${open?90:0}deg);transition:transform .2s" aria-label="${open?'Kalemleri gizle':'Kalemleri göster'}" aria-expanded="${open}">
      <svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
    </button>`}
  </div>`;
  if(!open) return head;
  return head + items.map(e=>_nutEntryRowHTML(e,true)).join('');
}

function _nutListHTML(entries){
  if(!entries.length) return `
    <div class="nut-empty">
      <div class="nut-empty-icon">🥗</div>
      <div class="nut-empty-text">Henüz öğün girilmedi.<br>Yukarıya ne yediğini yaz.</div>
    </div>`;
  const out=[]; const seen=new Set();
  for(const e of entries){
    if(e.groupId){
      if(seen.has(e.groupId)) continue;
      seen.add(e.groupId);
      out.push(_nutGroupRowHTML(entries.filter(x=>x.groupId===e.groupId)));
    } else out.push(_nutEntryRowHTML(e,false));
  }
  return out.join('');
}

// ---- "Bu değil" seçicisi (⋯) -----------------------------------
// Kullanıcı sistemin bulduğunu beğenmezse kayıtlılardan kendi seçer.
let _pickerForId=null, _pickerSort='freq';

function openNutPicker(entryId){
  _pickerForId=entryId;
  _renderNutPicker();
  openModal('modal-nut-picker');
}

function setNutPickerSort(s){ _pickerSort=s; _renderNutPicker(); }

function _renderNutPicker(){
  const e=ST.nutritionLogs.find(x=>x.id===_pickerForId);
  const freq=_foodFrequency();
  const routines=[...(ST.mealRoutines||[])].map(r=>({
    kind:'routine', id:r.id, name:r.name,
    kcal:Math.round(r.items.reduce((a,i)=>a+(i.calories||0),0)),
    sub:r.items.map(i=>i.name).join(' + '),
    score:(r.useCount||0)+(r.samples||0),
  }));
  const foods=[...(ST.foodDb||[])].map(f=>({
    kind:'food', id:f.id, name:f.name,
    kcal:Math.round(f.per100?.kcal||0),
    sub:'100g başına',
    score:freq[f.id]||0,
  }));
  let list=[...routines,...foods];
  if(_pickerSort==='alpha') list.sort((a,b)=>a.name.localeCompare(b.name,'tr'));
  else list.sort((a,b)=>b.score-a.score || a.name.localeCompare(b.name,'tr'));
  list=list.slice(0,80);

  const btn=(s,label)=>`<button onclick="setNutPickerSort('${s}')" style="flex:1;padding:7px;border-radius:9px;font-size:12px;font-weight:700;cursor:pointer;background:${_pickerSort===s?'var(--accent)':'var(--surface2)'};color:${_pickerSort===s?'#fff':'var(--text2)'};border:1.5px solid ${_pickerSort===s?'var(--accent)':'var(--border)'}">${label}</button>`;

  document.getElementById('nut-picker-content').innerHTML=`
    <div style="font-size:12px;color:var(--text2);margin-bottom:10px;line-height:1.5">
      Şu an: <b style="color:var(--text)">${esc(e?e.name:'—')}</b><br>Doğrusunu seç, kayıt bununla değiştirilsin.
    </div>
    <div style="display:flex;gap:6px;margin-bottom:12px">${btn('freq','⭐ En çok kullanılan')}${btn('alpha','🔤 Alfabetik')}</div>
    ${list.length?`<div style="display:flex;flex-direction:column;gap:6px;max-height:52vh;overflow-y:auto">
      ${list.map(it=>`<button onclick="applyNutPick('${it.kind}','${it.id}')" style="display:flex;align-items:center;gap:10px;padding:10px 11px;border-radius:10px;background:var(--surface2);border:1.5px solid ${it.kind==='routine'?'var(--accent)':'var(--border)'};cursor:pointer;text-align:left;width:100%">
        <span style="font-size:15px;flex-shrink:0">${it.kind==='routine'?'⭐':'📗'}</span>
        <span style="flex:1;min-width:0">
          <span style="display:block;font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(it.name)}</span>
          <span style="display:block;font-size:11px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(it.sub)}</span>
        </span>
        <span style="font-size:12px;color:var(--text2);flex-shrink:0">${it.kcal} kcal</span>
      </button>`).join('')}
    </div>`:`<div style="font-size:13px;color:var(--text3);padding:16px 0;text-align:center">Henüz kayıtlı rutin veya ürün yok.</div>`}
  `;
}

async function applyNutPick(kind, id){
  const e=ST.nutritionLogs.find(x=>x.id===_pickerForId);
  if(!e){ closeModal('modal-nut-picker'); return; }
  const raw=e.raw||e.name;
  // Yanlış kaydı (grubun tamamını) kaldır
  const doomed=e.groupId ? ST.nutritionLogs.filter(x=>x.groupId===e.groupId) : [e];
  for(const d of doomed){ await DB.del('nutritionLogs',d.id); ST.nutritionLogs=ST.nutritionLogs.filter(x=>x.id!==d.id); }
  closeModal('modal-nut-picker');

  if(kind==='routine'){
    const res=await applyMealRoutine(id);
    if(res){
      // Kullanıcının yazdığı ifadeyi bu rutine tetik olarak öğret —
      // bir dahakine kendisi bulsun.
      await _learnRoutineTrigger(id, raw);
      showToast('⭐ '+res.routine.name+' uygulandı');
    }
    return;
  }
  const food=ST.foodDb.find(f=>f.id===id);
  if(!food){ renderBeslenme(); return; }
  const {qty,grams}=_parseFoodText(raw);
  const mac=_foodToMacros(food,qty,grams);
  const entry={ id:'n_'+Date.now()+'_'+Math.random().toString(36).slice(2,6), date:todayDateKey(),
    name:food.name+(qty!==1?' ×'+qty:''), calories:mac.calories, protein:mac.protein,
    carbs:mac.carbs, fat:mac.fat, emoji:'📗', portionNote:mac.portionNote,
    matchSource:'manual', foodId:food.id, raw, pending:false, createdAt:Date.now() };
  await DB.put('nutritionLogs',entry); ST.nutritionLogs.push(entry);
  renderBeslenme();
  showToast('📗 '+food.name);
}

// HIZLI TEKRAR: geçmiş girişin kopyasını bugüne ekle (AI/API'siz, anında)
async function quickRepeatEntry(srcId){
  const src=ST.nutritionLogs.find(e=>e.id===srcId); if(!src) return;
  const entry={
    id:'n_'+Date.now()+'_'+Math.random().toString(36).slice(2,6),
    date:todayDateKey(),
    name:src.name, calories:src.calories, protein:src.protein,
    carbs:src.carbs, fat:src.fat, emoji:src.emoji||'🍽️',
    portionNote:src.portionNote||'', matchSource:'repeat',
    foodId:src.foodId||null, pending:false, createdAt:Date.now(),
  };
  await DB.put('nutritionLogs',entry);
  ST.nutritionLogs.push(entry);
  renderBeslenme();
  showToast('⚡ Eklendi: '+entry.name);
}

// ÖĞÜN DÜZENLE: yanlış eşleşmeleri düzelt, foodDb'den yanlış öğrenmeyi sil
let _editNutId=null, _editNutDateKey=null;
// dateKey verilirse düzenleme İstatistik > gün detayından açılmıştır; kaydedince
// o ekran da tazelenir. Tek form, tek id: ikisi ayrı formdaydı ve çakışıyordu.
function openNutEdit(id, dateKey=null){
  const e=ST.nutritionLogs.find(x=>x.id===id); if(!e||e.pending) return;
  _editNutId=id; _editNutDateKey=dateKey;
  document.getElementById('ne-name').value=e.name||'';
  document.getElementById('ne-kcal').value=Math.round(e.calories||0);
  document.getElementById('ne-protein').value=e.protein||0;
  document.getElementById('ne-carbs').value=e.carbs||0;
  document.getElementById('ne-fat').value=e.fat||0;
  // Yanlış eşleşme butonu: sadece otomatik eşleşmiş (öğrenilmiş) girişlerde
  const wrongBtn=document.getElementById('ne-wrong-btn');
  wrongBtn.style.display=(e.foodId&&ST.foodDb.some(f=>f.id===e.foodId))?'block':'none';
  openModal('modal-nut-edit');
}
async function saveNutEdit(){
  const idx=ST.nutritionLogs.findIndex(x=>x.id===_editNutId); if(idx===-1) return;
  const g=id=>document.getElementById(id);
  const updated={...ST.nutritionLogs[idx],
    name:g('ne-name').value.trim()||ST.nutritionLogs[idx].name,
    calories:Math.round(parseFloat(g('ne-kcal').value)||0),
    protein:Math.round((parseFloat(g('ne-protein').value)||0)*10)/10,
    carbs:Math.round((parseFloat(g('ne-carbs').value)||0)*10)/10,
    fat:Math.round((parseFloat(g('ne-fat').value)||0)*10)/10,
    edited:true,
  };
  ST.nutritionLogs[idx]=updated;
  await DB.put('nutritionLogs',updated);
  closeModal('modal-nut-edit');
  renderBeslenme();
  if(_editNutDateKey){
    renderNutDayContent(_editNutDateKey);
    if(ST.activeTab==='istatistik') renderStatsInner();
  }
  showToast('✏️ Güncellendi');
}
// Yanlış eşleşme: öğrenilmiş ürünü DB'den sil + girişi AI ile yeniden analiz et
async function nutEditWrongMatch(){
  const e=ST.nutritionLogs.find(x=>x.id===_editNutId); if(!e) return;
  if(e.foodId){
    await DB.del('foodDb',e.foodId);
    ST.foodDb=ST.foodDb.filter(f=>f.id!==e.foodId);
  }
  closeModal('modal-nut-edit');
  showToast('🗑️ Yanlış eşleşme silindi, AI ile tekrar analiz ediliyor...');
  await retryNutritionEntry(e.id);
}

// Çok kalemli öğünün tamamını sil. Eskiden ana kartı silmenin tek yolu
// alt kalemleri tek tek silmekti.
async function deleteNutGroup(gid){
  const ids=ST.nutritionLogs.filter(e=>e.groupId===gid).map(e=>e.id);
  for(const id of ids){ await DB.del('nutritionLogs',id); _routineSelected.delete(id); }
  ST.nutritionLogs=ST.nutritionLogs.filter(e=>e.groupId!==gid);
  _expandedNutGroups.delete(gid);
  renderBeslenme();
  showToast('🗑️ Öğün silindi ('+ids.length+' kalem)');
}

async function deleteNutritionEntry(id) {
  await DB.del('nutritionLogs', id);
  ST.nutritionLogs = ST.nutritionLogs.filter(e => e.id !== id);
  renderBeslenme();
}

// ---- Günlük Detay Modal (İstatistik sekmesinden) ----
function openNutDayDetail(dateKey) {
  const MONTHS = ['Oca','Şub','Mar','Nis','May','Haz','Tem','Ağu','Eyl','Eki','Kas','Ara'];
  const DAY_NAMES = ['Paz','Pzt','Sal','Çar','Per','Cum','Cmt'];
  const d = new Date(dateKey + 'T00:00:00');
  const title = `${DAY_NAMES[d.getDay()]} ${d.getDate()} ${MONTHS[d.getMonth()]}`;
  document.getElementById('nut-day-title').textContent = '🍽️ ' + title;
  renderNutDayContent(dateKey);
  openModal('modal-nut-day');
}

function renderNutDayContent(dateKey) {
  const entries = ST.nutritionLogs.filter(e => e.date === dateKey);
  const el = document.getElementById('nut-day-content');
  if (!entries.length) {
    el.innerHTML = `<div style="text-align:center;padding:40px 20px;color:var(--text3)"><div style="font-size:36px;margin-bottom:10px">🥗</div><div style="font-size:14px">Bu gün için kayıt yok</div></div>`;
    return;
  }
  const totKcal = Math.round(entries.reduce((a,e) => a+(e.calories||0), 0));
  const totProt = Math.round(entries.reduce((a,e) => a+(e.protein||0), 0));
  const totCarbs = Math.round(entries.reduce((a,e) => a+(e.carbs||0), 0));
  const totFat = Math.round(entries.reduce((a,e) => a+(e.fat||0), 0));

  el.innerHTML = `
    <div style="padding:14px 20px;background:var(--surface2);border-bottom:1px solid var(--border);display:flex;gap:16px;justify-content:space-around">
      <div style="text-align:center">
        <div style="font-family:'Barlow Condensed',sans-serif;font-size:22px;font-weight:800;color:var(--accent-text)">${totKcal}</div>
        <div style="font-size:10px;color:var(--text2);font-weight:600">KCALORİ</div>
      </div>
      <div style="text-align:center">
        <div style="font-family:'Barlow Condensed',sans-serif;font-size:22px;font-weight:800;color:#3b82f6">${totProt}g</div>
        <div style="font-size:10px;color:var(--text2);font-weight:600">PROTEİN</div>
      </div>
      <div style="text-align:center">
        <div style="font-family:'Barlow Condensed',sans-serif;font-size:22px;font-weight:800;color:var(--warning)">${totCarbs}g</div>
        <div style="font-size:10px;color:var(--text2);font-weight:600">KARB</div>
      </div>
      <div style="text-align:center">
        <div style="font-family:'Barlow Condensed',sans-serif;font-size:22px;font-weight:800;color:var(--text2)">${totFat}g</div>
        <div style="font-size:10px;color:var(--text2);font-weight:600">YAĞ</div>
      </div>
    </div>
    <div style="padding:12px 16px 20px">
      ${entries.map(e => `
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:12px 14px;margin-bottom:8px;display:flex;align-items:center;gap:10px" data-nut-id="${e.id}">
          <div style="font-size:22px;flex-shrink:0">${esc(e.emoji||'🍽️')}</div>
          <div style="flex:1;min-width:0">
            <div style="font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(e.name)}</div>
            <div style="display:flex;gap:8px;margin-top:3px;flex-wrap:wrap">
              <span style="font-size:11px;color:var(--text2)">⚡ ${Math.round(e.calories||0)} kcal</span>
              <span style="font-size:11px;color:var(--text2)">🥩 ${Math.round(e.protein||0)}g</span>
              <span style="font-size:11px;color:var(--text2)">🌾 ${Math.round(e.carbs||0)}g</span>
              <span style="font-size:11px;color:var(--text2)">🧈 ${Math.round(e.fat||0)}g</span>
            </div>
          </div>
          <div style="display:flex;gap:6px;flex-shrink:0">
            <button onclick="openNutEntryEdit('${e.id}','${dateKey}')" style="width:32px;height:32px;border-radius:8px;background:var(--surface2);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:var(--transition)" title="Düzenle">
              <svg viewBox="0 0 24 24" style="width:14px;height:14px;stroke:var(--text2);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            </button>
            <button onclick="deleteNutDayEntry('${e.id}','${dateKey}')" style="width:32px;height:32px;border-radius:8px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:var(--transition)" title="Sil">
              <svg viewBox="0 0 24 24" style="width:14px;height:14px;stroke:var(--danger);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
            </button>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

async function deleteNutDayEntry(id, dateKey) {
  await DB.del('nutritionLogs', id);
  ST.nutritionLogs = ST.nutritionLogs.filter(e => e.id !== id);
  renderNutDayContent(dateKey);
  renderBeslenme();
  if (ST.activeTab === 'istatistik') renderStatsInner();
  showToast('Öğün silindi');
}

function openNutEntryEdit(id, dateKey) { openNutEdit(id, dateKey); }
