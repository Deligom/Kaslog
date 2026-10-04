// ============================================================
// BUGÜN
// ============================================================
function renderBugun() {
  const el=document.getElementById('bugun-content');
  const s=ST.settings;
  const routine=ST.routines.find(r=>r.id===s.activeRoutineId);
  let todayHTML='', breakHTML='';
  const info=routine?getTodayDayInfo(routine):null;
  if(info){
    const len=routine.days.length;
    const pos=info.pos;
    const day=info.day;
    const bn=s.breakNotice;
    if(bn&&!bn.dismissed){
      const prev=routine.days[normPos(bn.prevPos,len)];
      breakHTML=`<div class="card card-pad" style="margin:0 20px 12px;border:1px solid rgba(59,130,246,0.32);background:linear-gradient(135deg,rgba(59,130,246,0.13),rgba(59,130,246,0.03))"><div style="display:flex;align-items:flex-start;gap:12px"><div style="font-size:26px;line-height:1">👋</div><div style="flex:1"><div style="font-weight:700;font-size:15px;margin-bottom:2px">${T('break_title')}</div><div style="font-size:13px;color:var(--text2);line-height:1.5"><strong>${bn.days}</strong> ${T('break_days')} ${T('break_rewound')}</div></div></div><div style="display:flex;gap:8px;margin-top:12px"><button class="btn btn-ghost" style="flex:1;height:36px;font-size:12px" onclick="undoBreakRewind()">↩️ ${prev.isRest?'😴':esc(prev.emoji)} ${T('break_continue')}</button><button class="btn btn-ghost" style="flex:0 0 auto;height:36px;font-size:12px;padding:0 14px" onclick="dismissBreakNotice()">${T('break_dismiss')}</button></div></div>`;
    }
    if(info.done){
      const dVol=info.logs.reduce((a,l)=>a+(l.totalVolume||0),0);
      const dMin=info.logs.reduce((a,l)=>a+(l.duration||0),0);
      const dSets=info.logs.reduce((a,l)=>a+(l.exercises||[]).reduce((x,e)=>x+(e.sets||[]).filter(st=>!st.isWarmup).length,0),0);
      const next=routine.days[(pos+1)%len];
      const chip=(v,lbl)=>`<div style="flex:1"><div style="font-family:'Barlow Condensed',sans-serif;font-size:26px;font-weight:700;color:var(--success);line-height:1.1">${v}</div><div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">${lbl}</div></div>`;
      todayHTML=`<div class="rest-day-card" style="border-color:rgba(34,197,94,0.35);background:linear-gradient(180deg,rgba(34,197,94,0.08),transparent)"><div class="rest-day-icon">✅</div><div class="rest-day-title">${T('done_today')}</div><div class="rest-day-sub" style="margin-bottom:4px">${esc(day.emoji)} <strong>${translateDayNameH(day.name)}</strong> — ${T('done_today_sub')}</div><div style="display:flex;gap:8px;margin:18px 0 4px">${chip(dVol>999?Math.round(dVol/1000)+'k':dVol,'kg '+T('done_stat_vol'))}${chip(dSets,T('done_stat_set'))}${chip(dMin,T('done_stat_min'))}</div><div class="rest-day-sub" style="margin-top:14px">${T('tomorrow')}: <strong>${next.isRest?'😴':esc(next.emoji)} ${translateDayNameH(next.name)}</strong></div><button class="btn btn-ghost btn-full" style="margin-top:16px" onclick="startTrainingFrom(${(pos+1)%len})">${T('train_again')}</button></div>`;
    } else if(day.isRest){
      const next=peekDayAfter(routine,pos);
      todayHTML=`<div class="rest-day-card"><div class="rest-day-icon">😴</div><div class="rest-day-title">${T('rest_day')}</div><div class="rest-day-sub">${T('rest_day_sub')}<br>${T('tomorrow')}: <strong>${next.isRest?'😴':esc(next.emoji)} ${translateDayNameH(next.name)}</strong></div><button class="btn btn-ghost btn-full" style="margin-top:20px" onclick="skipRestDay()">${T('train_anyway')}</button></div>`;
    } else {
      const activeExs=day.exercises.filter(e=>!e.disabled);
      const items=day.exercises.map((de,i)=>{
        const ex=getExercise(de.exId); if(!ex)return'';
        const ts=ex.type==='time'?`${de.sets}×${de.reps}s`:`${de.sets}×${de.reps}`;
        return `<div class="today-ex-item"><div class="ex-num" style="${de.disabled?'opacity:0.35':''}">${i+1}</div><div class="ex-name-wrap"><div class="ex-name" style="${de.disabled?'text-decoration:line-through;opacity:0.35':''}">${esc(ex.name)}</div><div class="ex-meta">${esc(ex.equipment)} • ${esc(ex.muscle)}</div></div><span class="badge ${de.disabled?'badge-muted':'badge-accent'}">${ts}</span></div>`;
      }).join('');
      const est=Math.round(activeExs.length*(s.restTime+45)/60);
      todayHTML=`<div class="today-workout-card"><div class="today-header"><div class="today-day-label">${esc(routine.name)} · ${T('day_prefix')} ${routine.days.filter(d=>!d.isRest).indexOf(day)+1}</div><div class="today-day-name">${esc(day.emoji)} ${translateDayNameH(day.name)}</div><div class="today-day-meta">${activeExs.length} ${T('exercises_count')} · ~${est} min</div></div><div class="today-exercises">${items}</div><div class="today-footer"><button class="btn btn-primary btn-full btn-start-pulse" onclick="startWorkout('${routine.id}','${day.id}')"><svg style="width:18px;height:18px;stroke:#fff;fill:none;stroke-width:2.5;stroke-linecap:round" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>${T('start_workout')}</button></div></div>`;
    }
  } else {
    todayHTML=`<div class="rest-day-card"><div class="rest-day-icon">📋</div><div class="rest-day-title">${T('no_routine')}</div><div class="rest-day-sub">${T('no_routine_sub')}</div></div>`;
  }
  const total=ST.workoutLogs.length; const streak=calcStreak(); const vol=ST.workoutLogs.reduce((a,l)=>a+(l.totalVolume||0),0);
  el.innerHTML=`<div class="greeting-block"><div class="greeting-name">Hey, ${esc(s.name||'Sporcu')} 👋</div><div class="greeting-sub">${getTodayGreeting()}</div></div><div class="stats-row"><div class="stat-card"><div class="stat-num"><span class="streak-fire">🔥</span>${streak}</div><div class="stat-label">${T('streak')}</div></div><div class="stat-card"><div class="stat-num">${total}</div><div class="stat-label">📅 ${T('sessions')}</div></div><div class="stat-card"><div class="stat-num">${vol>999?Math.round(vol/1000)+'k':vol}</div><div class="stat-label">⚡ kg ${T('volume')}</div></div></div><div style="padding:0 20px 12px"><div class="section-title">${T('today_workout')}</div></div>${breakHTML}${todayHTML}`;
}
function updateNavLabels(){
  document.querySelectorAll('.nav-item').forEach(n=>{
    const tab=n.dataset.tab;
    const map={bugun:'nav_today',program:'nav_program',istatistik:'nav_stats',ayarlar:'nav_settings'};
    if(map[tab])n.querySelector('.nav-label').textContent=T(map[tab]);
  });
}

function getTodayGreeting(){const h=new Date().getHours();if(h<6)return T('g0');if(h<12)return T('g1');if(h<17)return T('g2');if(h<21)return T('g3');return T('g4');}

function calcStreak(){
  if(!ST.workoutLogs.length)return 0;
  // Find max consecutive rest days in active routine
  const routine=ST.routines.find(r=>r.id===ST.settings.activeRoutineId);
  let maxRestGap=1;
  if(routine){
    let cur=0,best=0;
    routine.days.forEach(d=>{if(d.isRest){cur++;best=Math.max(best,cur);}else cur=0;});
    maxRestGap=best+1; // allow workout gap = consecutive rest days + 1
  }
  const allowedGap=Math.max(2,maxRestGap+1); // at least 2 days tolerance
  const dates=[...new Set(ST.workoutLogs.map(l=>new Date(l.date).toDateString()))];
  dates.sort((a,b)=>new Date(b)-new Date(a));
  let s=0,prev=new Date();prev.setHours(0,0,0,0);
  const today=new Date();today.setHours(0,0,0,0);
  const daysSinceLast=(today-new Date(dates[0]))/86400000;
  if(daysSinceLast>allowedGap)return 0;
  for(const d of dates){const dt=new Date(d);const diff=(prev-dt)/86400000;if(diff<=allowedGap){s++;prev=dt;}else break;}
  return s;
}
function skipRestDay(){
  const routine=activeRoutine(); if(!routine)return;
  startTrainingFrom(resolveCyclePos(routine,dayKey()));
}

// ============================================================
// PROGRAM
// ============================================================
function renderProgram() {
  const el=document.getElementById('program-content');
  const cards=ST.routines.map(r=>{
    const isActive=r.id===ST.settings.activeRoutineId;
    const pills=r.days.map(d=>`<div class="day-pill${d.isRest?' rest':''}">${d.isRest?'😴':esc(d.emoji)} ${translateDayNameH(d.name)}</div>`).join('');
    return `<div class="routine-card ${isActive?'active-routine':''}" onclick="openRoutineDetail('${r.id}')"><div class="routine-header"><div class="routine-icon">${esc(r.emoji||'💪')}</div><div style="flex:1"><div class="routine-name">${esc(r.name)}</div><div class="routine-meta">${r.type==='cyclic'?T('cyclic'):T('fixed')} · ${r.days.filter(d=>!d.isRest).length} ${T('training_days')}</div></div>${isActive?`<span class="badge badge-success">${T('active')}</span>`:''}</div><div class="routine-days-strip">${pills}</div></div>`;
  }).join('');
  const groups=[{id:'push',label:T('group_push')},{id:'pull',label:T('group_pull')},{id:'legs',label:T('group_legs')},{id:'core',label:T('group_core')},{id:'custom',label:T('group_custom')}];
  const allEx=getAllExercises();
  const libHTML=groups.map(g=>{
    const exs=allEx.filter(e=>e.group===g.id); if(!exs.length)return'';
    return `<div style="padding:8px 16px 4px;font-size:11px;font-weight:700;color:var(--text3);letter-spacing:1px;text-transform:uppercase">${g.label}</div>`+exs.map(ex=>{
      const isCustom=ST.customExercises.some(c=>c.id===ex.id);
      const right=isCustom
        ? `<button onclick="deleteLibExercise('${ex.id}')" style="width:30px;height:30px;border-radius:8px;display:flex;align-items:center;justify-content:center;color:var(--text3);background:transparent;border:none;cursor:pointer;transition:var(--transition);flex-shrink:0" onmouseenter="this.style.color='var(--danger)';this.style.background='rgba(239,68,68,0.1)'" onmouseleave="this.style.color='var(--text3)';this.style.background='transparent'" ontouchstart="this.style.color='var(--danger)';this.style.background='rgba(239,68,68,0.1)'" ontouchend="this.style.color='var(--text3)';this.style.background='transparent'"><svg viewBox="0 0 24 24" style="width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg></button>`
        : `<span class="badge badge-muted">${ex.type==='time'?T('time_label'):T('reps')}</span>`;
      return `<div class="lib-item"><div class="muscle-dot md-${ex.group}"></div><div style="flex:1"><div style="font-size:14px;font-weight:600">${esc(ex.name)}${isCustom?' <span style="font-size:10px;color:var(--accent-text);font-weight:700;background:var(--accent-dim);padding:1px 6px;border-radius:6px">ÖZEL</span>':''}</div><div style="font-size:12px;color:var(--text2)">${esc(ex.muscle)} · ${esc(ex.equipment)}</div></div>${right}</div>`;
    }).join('');
  }).join('');
  el.innerHTML=`<div class="page-pad" style="padding-bottom:12px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px"><div class="section-title" style="margin-bottom:0">${T('my_routines')}</div><button class="btn btn-ghost" style="height:36px;font-size:13px" onclick="openNewRoutineBuilder()">${T('new_routine')}</button></div></div>${cards||`<div class="empty-state"><div class="empty-icon">📋</div><div class="empty-title">${T('no_routines')}</div><div class="empty-sub">${T('no_routines_sub')}</div></div>`}<div class="page-pad" style="padding-top:24px;padding-bottom:8px"><div class="section-title">${T('exercise_lib')}</div></div><div class="card" style="margin:0 20px 20px;overflow:hidden">${libHTML}</div>`;
}

// ============================================================
// ROUTINE DETAIL
// ============================================================
function openRoutineDetail(routineId) {
  const routine=ST.routines.find(r=>r.id===routineId); if(!routine)return;
  document.getElementById('routine-builder-title').textContent=routine.name;
  renderRoutineDetail(routineId);
  openModal('modal-routine-builder');
}

function renderRoutineDetail(routineId) {
  const routine=ST.routines.find(r=>r.id===routineId); if(!routine)return;
  const isActive=routine.id===ST.settings.activeRoutineId;
  const daysHTML=routine.days.map((day,di)=>{
    if(day.isRest){
      return `<div class="card card-pad" style="margin-bottom:10px;display:flex;align-items:center;gap:12px"><div style="font-size:24px">😴</div><div style="flex:1"><div style="font-weight:600">${esc(day.name)}</div><div style="font-size:12px;color:var(--text2)">${T('rest_day_label')}</div></div><button onclick="removeRoutineDay('${routineId}',${di})" style="font-size:12px;color:var(--danger);font-weight:600">${T('remove')}</button></div>`;
    }
    const exItems=day.exercises.map(de=>{const ex=getExercise(de.exId);if(!ex)return'';return `<div style="padding:6px 0;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border)"><div class="muscle-dot md-${ex.group}"></div><div style="flex:1;font-size:13px;${de.disabled?'text-decoration:line-through;opacity:0.4':''}">${esc(ex.name)}</div><span style="font-size:12px;color:var(--text2)">${de.sets}×${de.reps}${ex.type==='time'?'s':''}</span></div>`;}).join('');
    return `<div class="card" style="margin-bottom:10px;overflow:hidden"><div style="padding:12px 16px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border)"><div style="font-size:20px">${esc(day.emoji)}</div><div style="flex:1;font-family:'Barlow Condensed',sans-serif;font-size:18px;font-weight:700">${translateDayNameH(day.name)}</div><span style="font-size:12px;color:var(--text2)">${day.exercises.filter(e=>!e.disabled).length} ${T('exercises_count')}</span><button class="btn btn-ghost" style="height:30px;font-size:12px;padding:0 10px;margin-left:6px" onclick="openDayEditor('${routineId}','${day.id}')">${T('edit')}</button></div><div style="padding:4px 16px 10px">${exItems||`<div style="color:var(--text3);font-size:13px;padding-top:8px">${T('no_exercises')}</div>`}</div></div>`;
  }).join('');
  document.getElementById('routine-builder-content').innerHTML=`
    <div style="margin-bottom:16px">${!isActive?`<button class="btn btn-primary btn-full" onclick="setActiveRoutine('${routine.id}')">${T('set_active')}</button>`:`<div class="badge badge-success" style="display:inline-flex">✓ ${T('active')}</div>`}</div>
    ${daysHTML}
    <div style="display:flex;gap:8px;margin-top:8px">
      <button class="btn btn-ghost" style="flex:1" onclick="addRoutineDay('${routineId}',false)">${T('training_day')}</button>
      <button class="btn btn-ghost" style="flex:1" onclick="addRoutineDay('${routineId}',true)">${T('rest_day_btn')}</button>
    </div>
    <button class="btn btn-danger btn-full" style="margin-top:16px" onclick="deleteRoutine('${routineId}')">${T('delete_routine')}</button>
  `;
}

async function addRoutineDay(routineId,isRest) {
  const routine=ST.routines.find(r=>r.id===routineId); if(!routine)return;
  const num=routine.days.filter(d=>!d.isRest).length+1;
  const restName=T('rest_day'); const dayName=T('day_prefix')+' '+num;
  routine.days.push(isRest?{id:'day_r_'+Date.now(),name:restName,emoji:'😴',isRest:true,exercises:[]}:{id:'day_'+Date.now(),name:dayName,emoji:'💪',isRest:false,exercises:[]});
  await DB.put('routines',routine);
  renderRoutineDetail(routineId);
  if(!isRest)setTimeout(()=>openDayEditor(routineId,routine.days[routine.days.length-1].id),100);
}

async function removeRoutineDay(routineId,idx) {
  const routine=ST.routines.find(r=>r.id===routineId); if(!routine)return;
  routine.days.splice(idx,1);
  await DB.put('routines',routine);
  renderRoutineDetail(routineId);
}

async function setActiveRoutine(routineId) {
  ST.settings.activeRoutineId=routineId; ST.settings.cyclePosition=0;
  ST.settings.cycleDate=dayKey(); ST.settings.breakNotice=null;
  await DB.put('settings',{id:'main',...ST.settings});
  closeModal('modal-routine-builder'); renderProgram(); renderBugun();
}

async function deleteRoutine(routineId) {
  showConfirm('🗑️',T('delete_routine_title'),T('delete_routine_msg'),async()=>{
    await DB.del('routines',routineId); ST.routines=ST.routines.filter(r=>r.id!==routineId);
    if(ST.settings.activeRoutineId===routineId){ST.settings.activeRoutineId=ST.routines[0]?.id||null;await DB.put('settings',{id:'main',...ST.settings});}
    closeModal('modal-routine-builder'); closeModal('modal-alert'); renderProgram(); renderBugun();
  });
}

// New routine builder
let _newRType='cyclic',_newREmoji='💪';
function openNewRoutineBuilder() {
  _newRType='cyclic'; _newREmoji='💪';
  document.getElementById('routine-builder-title').textContent=T('new_routine_title');
  document.getElementById('routine-builder-content').innerHTML=`
    <div class="form-group"><label class="form-label">${T('routine_name')}</label><input class="form-input" id="new-routine-name" placeholder="e.g. Push Pull Legs"></div>
    <div class="form-group"><label class="form-label">${T('routine_type')}</label>
      <div class="pill-row">
        <div class="pill active" id="rt-cyclic" onclick="selRT('cyclic')">${T('cyclic_label')}</div>
        <div class="pill" id="rt-fixed" onclick="selRT('fixed')">${T('fixed_label')}</div>
      </div>
    </div>
    <div class="form-group"><label class="form-label">${T('emoji_label')}</label>
      <div class="pill-row">${['💪','🔥','⚡','🏠','🦁','🎯','🏋️','🌊','🧲','⛰️'].map(e=>`<div class="pill" onclick="selRE(this,'${e}')">${e}</div>`).join('')}</div>
    </div>
    <button class="btn btn-primary btn-full" onclick="createNewRoutine()">${T('create_routine')}</button>
  `;
  openModal('modal-routine-builder');
}
function selRT(t){_newRType=t;document.querySelectorAll('[id^="rt-"]').forEach(p=>p.classList.toggle('active',p.id==='rt-'+t));}
function selRE(el,e){_newREmoji=e;el.closest('.pill-row').querySelectorAll('.pill').forEach(p=>p.classList.remove('active'));el.classList.add('active');}
async function createNewRoutine() {
  const name=document.getElementById('new-routine-name')?.value.trim(); if(!name)return;
  const r={id:'routine_'+Date.now(),name,emoji:_newREmoji,type:_newRType,days:[],active:false,createdAt:Date.now()};
  await DB.put('routines',r); ST.routines.push(r);
  renderRoutineDetail(r.id); renderProgram();
}

// ============================================================
// DAY EDITOR — Freestyle with drag reorder + search
// ============================================================
let DE = { routineId:null, dayId:null };
let _dragSrcIdx = null;

function openDayEditor(routineId, dayId) {
  DE={routineId,dayId};
  const routine=ST.routines.find(r=>r.id===routineId);
  const day=routine?.days.find(d=>d.id===dayId);
  document.getElementById('day-editor-title').textContent=day?day.name:'Edit Day';
  renderDayEditor();
  openModal('modal-day-editor');
}

function renderDayEditor() {
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId);
  if(!day)return;
  const el=document.getElementById('day-editor-content');
  el.innerHTML=`
    <div class="form-group">
      <label class="form-label">${T('day_name')}</label>
      <div style="display:flex;gap:8px">
        <input class="form-input" id="de-day-name" value="${esc(day.name)}" placeholder="e.g. PUSH" style="flex:1" oninput="updateDayName(this.value)">
        <input class="form-input" id="de-day-emoji" value="${esc(day.emoji||'💪')}" placeholder="Emoji" style="width:64px;text-align:center;font-size:20px" oninput="updateDayEmoji(this.value)">
      </div>
    </div>
    <div class="section-title">${T('exercises_title')}</div>
    <div class="dex-list" id="dex-list">${renderDexItems(day.exercises)}</div>
    <div class="dex-add-row" style="position:relative">
      <svg class="dex-search-icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input class="dex-search-input" id="dex-search" placeholder="${T('search_placeholder')}" autocomplete="off"
        oninput="onDexSearch(this.value)"
        onfocus="onDexSearchFocus(this)">
      <div class="dex-dropdown" id="dex-dropdown"></div>
    </div>
    <div id="dex-create-form" style="display:none"></div>
    <div style="margin-top:16px">
      <button class="btn btn-primary btn-full" onclick="closeDayEditor()">${T('done')}</button>
    </div>
  `;
  initDragHandlers();
  // Keyboard resize → scroll search into view
  window.addEventListener('resize', _onKeyboardResize);
  document.addEventListener('click', closeDexDropdownOutside);
}

function _onKeyboardResize() {
  const inp = document.getElementById('dex-search');
  if (document.activeElement === inp) {
    setTimeout(() => inp.scrollIntoView({behavior:'smooth', block:'center'}), 80);
  }
}

function onDexSearchFocus(inp) {
  onDexSearch(inp.value);
  setTimeout(() => inp.scrollIntoView({behavior:'smooth', block:'center'}), 350);
}

// ============================================================
// ANIMATED GHOST DRAG
// ============================================================
let DRAG = {active:false, idx:null, ghostEl:null, ghostOffsetY:0, targetIdx:null, itemH:0};

function initDragHandlers() {
  const list = document.getElementById('dex-list');
  if (!list) return;

  list.addEventListener('touchstart', _dragTouchStart, {passive:false});
  list.addEventListener('touchmove', _dragTouchMove, {passive:false});
  list.addEventListener('touchend', _dragTouchEnd, {passive:false});
}

function _dragTouchStart(e) {
  const handle = e.target.closest('[data-drag]');
  if (!handle) return;
  e.preventDefault();
  const item = handle.closest('.dex-item');
  if (!item) return;
  const idx = parseInt(item.dataset.idx);
  const rect = item.getBoundingClientRect();
  const touch = e.touches[0];

  // Create floating ghost
  const ghost = item.cloneNode(true);
  ghost.removeAttribute('id');
  ghost.style.cssText = [
    `position:fixed`,`left:${rect.left}px`,`top:${rect.top}px`,
    `width:${rect.width}px`,`height:${rect.height}px`,
    `z-index:9999`,`pointer-events:none`,
    `border-radius:12px`,`border:1.5px solid var(--accent)`,
    `background:var(--surface)`,
    `box-shadow:0 12px 40px rgba(0,0,0,0.35)`,
    `transform:scale(1.03)`,
    `transition:transform 0.1s ease`,
    `opacity:0.97`,
  ].join(';');
  document.body.appendChild(ghost);

  DRAG = {
    active: true,
    idx,
    ghostEl: ghost,
    ghostOffsetY: touch.clientY - rect.top,
    targetIdx: idx,
    itemH: rect.height + 4,
  };

  // Dim original
  item.style.opacity = '0.25';
  item.style.pointerEvents = 'none';
}

function _dragTouchMove(e) {
  if (!DRAG.active) return;
  e.preventDefault();
  const touch = e.touches[0];

  // Move ghost
  DRAG.ghostEl.style.top = (touch.clientY - DRAG.ghostOffsetY) + 'px';

  // Find target index
  const list = document.getElementById('dex-list');
  if (!list) return;
  const items = [...list.querySelectorAll('.dex-item:not([style*="pointer-events: none"])')];
  // Include the dragged item placeholder
  const allItems = [...list.querySelectorAll('.dex-item')];
  let newTarget = DRAG.idx;

  for (let i = 0; i < allItems.length; i++) {
    const el = allItems[i];
    const r = el.getBoundingClientRect();
    const mid = r.top + r.height / 2;
    // Use ghost top center
    const ghostMid = touch.clientY - DRAG.ghostOffsetY + DRAG.itemH / 2;
    if (ghostMid < mid) { newTarget = i; break; }
    newTarget = i;
  }

  if (newTarget !== DRAG.targetIdx) {
    DRAG.targetIdx = newTarget;
    _animateDragShift(allItems, DRAG.idx, newTarget);
  }
}

function _animateDragShift(items, fromIdx, toIdx) {
  items.forEach((item, i) => {
    if (i === fromIdx) { item.style.transform=''; return; }
    let shift = 0;
    if (fromIdx < toIdx && i > fromIdx && i <= toIdx) shift = -DRAG.itemH;
    else if (fromIdx > toIdx && i >= toIdx && i < fromIdx) shift = DRAG.itemH;
    item.style.transition = 'transform 0.18s cubic-bezier(0.4,0,0.2,1)';
    item.style.transform = shift ? `translateY(${shift}px)` : '';
  });
}

async function _dragTouchEnd() {
  if (!DRAG.active) return;
  DRAG.active = false;

  // Remove ghost with fade
  if (DRAG.ghostEl) {
    DRAG.ghostEl.style.transition = 'opacity 0.15s, transform 0.15s';
    DRAG.ghostEl.style.opacity = '0';
    DRAG.ghostEl.style.transform = 'scale(0.97)';
    setTimeout(() => { DRAG.ghostEl?.remove(); DRAG.ghostEl = null; }, 150);
  }

  const list = document.getElementById('dex-list');
  if (list) {
    list.querySelectorAll('.dex-item').forEach(item => {
      item.style.opacity = '';
      item.style.pointerEvents = '';
      item.style.transform = '';
      item.style.transition = '';
    });
  }

  if (DRAG.targetIdx !== null && DRAG.targetIdx !== DRAG.idx) {
    await moveDexItem(DRAG.idx, DRAG.targetIdx);
  }

  DRAG = {active:false,idx:null,ghostEl:null,ghostOffsetY:0,targetIdx:null,itemH:0};
}

function attachDragHandlers() { initDragHandlers(); } // alias

function renderDexItems(exercises) {
  if (!exercises.length) return `<div style="color:var(--text3);font-size:14px;padding:12px 0">${T('no_exercises')}</div>`;
  return exercises.map((de,i)=>{
    const ex=getExercise(de.exId); if(!ex)return'';
    return `<div class="dex-item" data-idx="${i}">
      <div class="dex-drag-handle" data-drag="${i}"><div class="dex-drag-icon"><span></span><span></span><span></span></div></div>
      <div class="dex-info">
        <div class="dex-name${de.disabled?' disabled-ex':''}">${esc(ex.name)}</div>
        <div class="dex-sub">${esc(ex.muscle)} · ${esc(ex.equipment)}</div>
      </div>
      <div class="dex-params">
        <input type="number" class="dex-num-input" value="${de.sets}" min="1" max="20" onchange="updateDexParam(${i},'sets',this.value)" title="Set sayısı" aria-label="Set sayısı">
        <span class="dex-x">×</span>
        <input type="number" class="dex-num-input" value="${de.reps}" min="1" onchange="updateDexParam(${i},'reps',this.value)" aria-label="${ex.type==='time'?'Süre (saniye)':'Tekrar sayısı'}">
        <span class="dex-unit">${ex.type==='time'?'s':'r'}</span>
      </div>
      <div class="dex-actions">
        <button class="dex-btn dex-btn-toggle ${de.disabled?'disabled':''}" onclick="toggleDexDisabled(${i})">${de.disabled?'👁':'🚫'}</button>
        <button class="dex-btn dex-btn-remove" onclick="removeDexItem(${i})">✕</button>
      </div>
    </div>`;
  }).join('');
}

async function moveDexItem(from, to) {
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId); if(!day)return;
  const arr=day.exercises;
  const [item]=arr.splice(from,1); arr.splice(to,0,item);
  await DB.put('routines',routine);
  document.getElementById('dex-list').innerHTML=renderDexItems(day.exercises);
  attachDragHandlers();
}

async function updateDexParam(idx, field, val) {
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId); if(!day)return;
  day.exercises[idx][field]=parseInt(val)||0;
  await DB.put('routines',routine);
}

async function toggleDexDisabled(idx) {
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId); if(!day)return;
  day.exercises[idx].disabled=!day.exercises[idx].disabled;
  await DB.put('routines',routine);
  document.getElementById('dex-list').innerHTML=renderDexItems(day.exercises);
  attachDragHandlers();
}

async function removeDexItem(idx) {
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId); if(!day)return;
  day.exercises.splice(idx,1);
  await DB.put('routines',routine);
  document.getElementById('dex-list').innerHTML=renderDexItems(day.exercises);
  attachDragHandlers();
}

async function updateDayName(val) {
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId); if(!day)return;
  day.name=val; await DB.put('routines',routine);
}
async function updateDayEmoji(val) {
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId); if(!day)return;
  day.emoji=val||'💪'; await DB.put('routines',routine);
}

async function closeDayEditor() {
  closeModal('modal-day-editor');
  window.removeEventListener('resize', _onKeyboardResize);
  document.removeEventListener('click',closeDexDropdownOutside);
  renderRoutineDetail(DE.routineId);
  renderBugun(); renderProgram();
}

// Exercise search dropdown
let _showingCreate=false;
function normTR(s){return s.toLowerCase().replace(/ş/g,'s').replace(/ğ/g,'g').replace(/ü/g,'u').replace(/ö/g,'o').replace(/ç/g,'c').replace(/ı/g,'i').replace(/İ/g,'i').replace(/Ş/g,'s').replace(/Ğ/g,'g').replace(/Ü/g,'u').replace(/Ö/g,'o').replace(/Ç/g,'c');}
function onDexSearch(q) {
  const dd=document.getElementById('dex-dropdown'); if(!dd)return;
  const all=getAllExercises();
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId);
  const existing=new Set((day?.exercises||[]).map(e=>e.exId));
  const trimQ=normTR(q.trim());
  if(!trimQ){dd.classList.remove('open');return;}
  const results=all.filter(e=>normTR(e.name).includes(trimQ)||normTR(e.muscle).includes(trimQ)||normTR(e.equipment).includes(trimQ)||normTR(e.tip||'').includes(trimQ)||(e.tip_tr&&normTR(e.tip_tr).includes(trimQ)));
  const items=results.slice(0,8).map(ex=>`<div class="dex-dd-item" onclick="addExToDay('${ex.id}')"><div class="muscle-dot md-${ex.group}"></div><div><div class="dex-dd-name">${esc(ex.name)}${existing.has(ex.id)?' ✓':''}</div><div class="dex-dd-meta">${esc(ex.muscle)} · ${esc(ex.equipment)}</div></div></div>`).join('');
  const noRes=results.length===0?`<div style="padding:10px 14px;color:var(--text3);font-size:13px">${T('no_results')}</div>`:'';
  const createBtn=`<div class="dex-dd-item dex-dd-item-create" data-q="${esc(q.trim())}" onclick="showCreateExForm(this.dataset.q)"><div style="font-size:18px">✨</div><div><div class="dex-dd-name">${T('create_custom').replace('Exercise','')} "${esc(q.trim())}"</div><div class="dex-dd-meta">${T('add_as_custom')}</div></div></div>`;
  dd.innerHTML=noRes+items+createBtn;
  dd.classList.add('open');
}

function closeDexDropdownOutside(e) {
  if(!e.target.closest('.dex-add-row')){const dd=document.getElementById('dex-dropdown');if(dd)dd.classList.remove('open');}
}

async function addExToDay(exId) {
  const routine=ST.routines.find(r=>r.id===DE.routineId);
  const day=routine?.days.find(d=>d.id===DE.dayId); if(!day)return;
  const ex=getExercise(exId); if(!ex)return;
  if(!day.exercises.find(e=>e.exId===exId)) {
    day.exercises.push({exId,sets:getDefaultSets(ex,ST.settings.level),reps:getDefaultReps(ex,ST.settings.level),disabled:false});
    await DB.put('routines',routine);
  }
  document.getElementById('dex-list').innerHTML=renderDexItems(day.exercises);
  initDragHandlers();
  const dd=document.getElementById('dex-dropdown'); if(dd)dd.classList.remove('open');
  const inp=document.getElementById('dex-search'); if(inp)inp.value='';
}

function showCreateExForm(prefill='') {
  _showingCreate=true;
  const dd=document.getElementById('dex-dropdown'); if(dd)dd.classList.remove('open');
  const cf=document.getElementById('dex-create-form'); if(!cf)return;
  cf.style.display='block';
  cf.innerHTML=`<div class="create-ex-form">
    <div style="font-family:'Barlow Condensed',sans-serif;font-size:16px;font-weight:700;margin-bottom:12px;color:var(--accent-text)">${T('cex_title')}</div>
    <div class="form-group"><label class="form-label">${T('cex_name')}</label><input class="form-input" id="cex-name" value="${esc(prefill)}" placeholder="e.g. Cable Fly"></div>
    <div class="form-row">
      <div class="form-group"><label class="form-label">${T('cex_muscle')}</label><input class="form-input" id="cex-muscle" placeholder="e.g. Chest"></div>
      <div class="form-group"><label class="form-label">${T('cex_equip')}</label><input class="form-input" id="cex-equip" placeholder="e.g. Cable"></div>
    </div>
    <div class="form-group"><label class="form-label">${T('cex_type')}</label>
      <div class="pill-row">
        <div class="pill active" id="cex-type-reps" onclick="selCexType('reps')">Reps</div>
        <div class="pill" id="cex-type-time" onclick="selCexType('time')">Time</div>
      </div>
    </div>
    <div class="form-group"><label class="form-label">${T('cex_group')}</label>
      <div class="pill-row">
        <div class="pill" id="cex-g-push" onclick="selCexGroup('push')">Push</div>
        <div class="pill" id="cex-g-pull" onclick="selCexGroup('pull')">Pull</div>
        <div class="pill" id="cex-g-legs" onclick="selCexGroup('legs')">Legs</div>
        <div class="pill" id="cex-g-core" onclick="selCexGroup('core')">Core</div>
        <div class="pill active" id="cex-g-custom" onclick="selCexGroup('custom')">Custom</div>
      </div>
    </div>
    <div class="form-group"><label class="form-label">${T('cex_tip')}</label><input class="form-input" id="cex-tip" placeholder="Form cues, notes..."></div>
    <div style="display:flex;gap:8px">
      <button class="btn btn-ghost" style="flex:1" onclick="cancelCreateEx()">${T('cex_cancel')}</button>
      <button class="btn btn-primary" style="flex:1" onclick="saveCreateEx()">${T('cex_save')}</button>
    </div>
  </div>`;
}
let _cexType='reps',_cexGroup='custom';
function selCexType(t){_cexType=t;['reps','time'].forEach(x=>{const el=document.getElementById('cex-type-'+x);if(el)el.classList.toggle('active',x===t);});}
function selCexGroup(g){_cexGroup=g;['push','pull','legs','core','custom'].forEach(x=>{const el=document.getElementById('cex-g-'+x);if(el)el.classList.toggle('active',x===g);});}
function cancelCreateEx(){const cf=document.getElementById('dex-create-form');if(cf){cf.style.display='none';cf.innerHTML='';}}
async function saveCreateEx(){
  const name=document.getElementById('cex-name')?.value.trim(); if(!name)return;
  const muscle=document.getElementById('cex-muscle')?.value.trim()||'Custom';
  const equip=document.getElementById('cex-equip')?.value.trim()||'Bodyweight';
  const tip=document.getElementById('cex-tip')?.value.trim()||'';
  const ex={
    id:'cex_'+Date.now(), name, muscle, equipment:equip, group:_cexGroup, type:_cexType,
    sets:{b:3,i:3,a:4,e:4}, reps:{b:10,i:12,a:15,e:15}, dur:{b:30,i:45,a:60,e:60}, tip,
    isCustom:true
  };
  await DB.put('customExercises',ex); ST.customExercises.push(ex);
  cancelCreateEx();
  await addExToDay(ex.id);
  renderProgram();
}

async function deleteLibExercise(exId) {
  const ex = ST.customExercises.find(e => e.id === exId);
  if (!ex) return;
  showConfirm('🗑️', 'Egzersizi Sil', `"${ex.name}" kütüphaneden silinecek. Rutinlerdeki bu harekete dokunulmaz.`, async () => {
    await DB.del('customExercises', exId);
    ST.customExercises = ST.customExercises.filter(e => e.id !== exId);
    closeModal('modal-alert');
    renderProgram();
    showToast('✓ Egzersiz silindi');
  });
}
