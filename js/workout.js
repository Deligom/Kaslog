// ============================================================
// ACTIVE WORKOUT
// ============================================================
let woTimer=null, woRestTimer=null, woStartTime=null, woElapsed=0;
let _restRemaining=0, _restDuration=0, _restEndsAt=null;
const restC=2*Math.PI*88;

function startWorkout(routineId,dayId) {
  const routine=ST.routines.find(r=>r.id===routineId);
  const day=routine?.days.find(d=>d.id===dayId); if(!day)return;
  const activeExs=day.exercises.filter(e=>!e.disabled);
  const allExs=day.exercises; // disabled dahil hepsini al
  if(!allExs.length){showConfirm('💪',translateDayName(day.name),T('day_empty'),()=>{closeModal('modal-alert');navTo('program');});return;}
  ST.workout={
    routineId,dayId,dayName:day.name,
    exercises:allExs.map(de=>{const ex=getExercise(de.exId);return{exId:de.exId,exData:ex,totalSets:de.sets,targetReps:de.reps,completedSets:[],skipped:de.disabled,prevPerf:getLastPerformance(de.exId),prevSets:getLastSetsPerformance(de.exId)};}).filter(e=>e.exData),
    exIndex:0,setIndex:0,startTime:Date.now(),phase:'exercise'
  };
  woStartTime=Date.now();
  startWoTimer();
  // Seans başı durum: hedefleri o günkü haline göre yumuşatmak için.
  // Atlanabilir; atlanınca sistem eskisi gibi sadece performansa bakar.
  openModal('modal-readiness');
  // Başlangıçta disabled/skipped olanları atla
  while(ST.workout.exIndex<ST.workout.exercises.length&&ST.workout.exercises[ST.workout.exIndex].skipped)ST.workout.exIndex++;
  if(ST.workout.exIndex>=ST.workout.exercises.length){showSummary();}
  else renderWoExercise();
  // Show Bitir button, hide on summary
  document.getElementById('wo-end-btn').style.display='';
  document.getElementById('workout-overlay').classList.add('open');
  updateWoHeader();
  saveWorkoutDraft();
}

function startWoTimer(){
  if(woTimer)clearInterval(woTimer);
  woTimer=setInterval(()=>{
    woElapsed=Math.floor((Date.now()-woStartTime)/1000);
    const m=Math.floor(woElapsed/60).toString().padStart(2,'0');
    const s=(woElapsed%60).toString().padStart(2,'0');
    const el=document.getElementById('wo-elapsed');
    if(el)el.textContent=m+':'+s;
  },1000);
}

function updateWoHeader(){
  const w=ST.workout; if(!w)return;
  const pi=document.getElementById('wo-progress-info');
  const pf=document.getElementById('wo-progress-fill');
  const dn=document.getElementById('wo-day-name');
  if(pi)pi.textContent=`${T('ex_label')} ${w.exIndex+1} ${T('of_label')}${w.exercises.length}`;
  if(pf)pf.style.width=((w.exIndex)/w.exercises.length*100)+'%';
  if(dn)dn.textContent=translateDayName(w.dayName);
}

function renderWoExercise(){
  const w=ST.workout; if(!w)return;
  const se=w.exercises[w.exIndex]; const ex=se.exData;
  setWoPhase('exercise'); updateWoHeader();
  // Animate name in
  const nameEl=document.getElementById('wo-ex-name');
  nameEl.textContent=ex.name;
  nameEl.style.animation='none'; void nameEl.offsetWidth; nameEl.style.animation='exNameIn 0.3s ease';
  document.getElementById('wo-muscle-badge').innerHTML=`<span class="badge badge-accent">${esc(ex.muscle)}</span>`;
  document.getElementById('wo-ex-equipment').textContent=ex.equipment;
  let dots='';
  const warmupCount=(se.warmupSets||[]).length;
  for(let i=0;i<se.totalSets;i++){let c='set-dot';if(i<se.completedSets.length)c+=' done';else if(i===se.completedSets.length)c+=' current';dots+=`<div class="${c}"></div>`;}
  if(warmupCount>0)dots+=`<div class="set-dot warmup" title="Isınma seti"></div>`.repeat(warmupCount);
  document.getElementById('wo-set-dots').innerHTML=dots;
  const pEl=document.getElementById('wo-prev-hint');
  if(se.prevPerf){
    pEl.style.display='flex';
    // Son antrenmandaki o egzersizin tüm set sayısını göster
    const lastLog = ST.workoutLogs.slice().reverse().find(l=>l.exercises?.some(e=>e.exId===se.exId));
    const lastExLog = lastLog?.exercises?.find(e=>e.exId===se.exId);
    const workSets = (lastExLog?.sets||[]).filter(s=>!s.isWarmup);
    // Başlıkta en iyi seti (en ağır, eşitse en çok tekrar) göster — son/zayıf seti değil.
    const topSet = workSets.length
      ? workSets.reduce((b,s)=>(s.weight>b.weight||(s.weight===b.weight&&s.reps>b.reps))?s:b)
      : se.prevPerf;
    // Vücut ağırlığı hareketlerinde "0kg × 12" yazmak anlamsız
    let prevText = (+topSet.weight||0)>0
      ? `${topSet.weight}kg × ${topSet.reps}${ex.type==='time'?'s':'rep'}`
      : `${topSet.reps}${ex.type==='time'?'s':' tekrar'}`;
    if(workSets.length>1) prevText += ` (${workSets.length} set)`;
    document.getElementById('wo-prev-text').textContent = prevText;
  } else pEl.style.display='none';
  // Progressive overload badge
  const sug=getProgressiveOverloadSuggestion(se.exId, se.targetReps);
  const badge=document.getElementById('wo-overload-badge');
  if(badge){
    if(sug){badge.style.display='inline';badge.textContent=sug.msg||`${sug.workW}kg · ${sug.target} tekrar hedefle`;}
    else badge.style.display='none';
  }
  const last=se.completedSets[se.completedSets.length-1];
  // Şu an girilecek setin sırası (0 tabanlı). Geçen antrenmanın AYNI sıradaki setini referans al.
  const setIdx=se.completedSets.length;
  const prevSet=(se.prevSets&&se.prevSets.length)
    ? (se.prevSets[setIdx]??se.prevSets[se.prevSets.length-1])
    : se.prevPerf;
  const weightSug=(sug?.type==='increase'||sug?.type==='deload'||sug?.type==='layoff');
  let prefillWeight=last?.weight??(weightSug?sug.suggestedWeight:(prevSet?.weight??0));
  document.getElementById('wo-weight').value=prefillWeight;
  // Vücut ağırlığı hareketlerinde ilerleme tekrardan gelir — hedefi oraya yaz
  document.getElementById('wo-reps').value=last?.reps??(sug?.nextReps??(prevSet?.reps??se.targetReps));
  // i18n labels
  const rl=document.getElementById('wo-reps-label'), ru=document.getElementById('wo-reps-unit');
  const wl=document.getElementById('wo-weight-label');
  if(wl)wl.textContent=T('weight');
  if(rl)rl.textContent=ex.type==='time'?T('time_label'):T('reps');
  if(ru)ru.textContent=ex.type==='time'?T('sec_unit'):T('rep_unit');
  // Reset chips/note
  _isWarmupSet=false;
  _setRir=null; _paintRirChips();
  const chip=document.getElementById('wo-warmup-chip'); if(chip)chip.classList.remove('wo-chip-active');
  const noteEl=document.getElementById('wo-set-note'); if(noteEl){noteEl.style.display='none';noteEl.value='';}
  // Btn labels
  const cLabel=document.getElementById('wo-complete-label'); if(cLabel)cLabel.textContent=T('complete_set');
  const sBtn=document.getElementById('wo-skip-btn'); if(sBtn)sBtn.textContent=T('skip_exercise');
  // Tip
  const tipText=ex.tip_tr||ex.tip;
  const tipWrap=document.getElementById('wo-tip-wrap');
  const tipPreview=document.getElementById('wo-tip-preview');
  const tipBody=document.getElementById('wo-tip-body');
  const tipToggleBtn=document.getElementById('wo-tip-toggle-btn');
  if(tipText&&tipWrap&&tipPreview&&tipBody){
    tipWrap.style.display='block';
    const short=tipText.length>48?tipText.slice(0,46)+'…':tipText;
    tipPreview.textContent='💡 '+short;
    tipBody.textContent=tipText;
    tipBody.classList.remove('open');
    if(tipToggleBtn)tipToggleBtn.classList.remove('open');
  }else if(tipWrap){tipWrap.style.display='none';}
}

function completeSet(){
  const w=ST.workout; if(!w)return;
  const se=w.exercises[w.exIndex];
  const weight=parseFloat(document.getElementById('wo-weight').value)||0;
  const reps=parseInt(document.getElementById('wo-reps').value)||0;
  const note=document.getElementById('wo-set-note')?.value.trim()||'';
  const isWarmup=_isWarmupSet;
  const setData={weight,reps,time:Date.now(),...(note?{note}:{}),...(isWarmup?{isWarmup:true}:{}),
    ...(!isWarmup&&_setRir!==null?{rir:_setRir}:{})};
  // Cevap SETE aittir. Burada sıfırlanmazsa sonraki setler bu cevabı miras
  // alır ve kullanıcının hiç vermediği bir veri uydurulmuş olur.
  _setRir=null; _paintRirChips();

  if(isWarmup){
    if(!se.warmupSets)se.warmupSets=[];
    se.warmupSets.push(setData);
    _isWarmupSet=false;
    const chip=document.getElementById('wo-warmup-chip');
    if(chip)chip.classList.remove('wo-chip-active');
    const noteEl=document.getElementById('wo-set-note');
    if(noteEl)noteEl.value='';
    showToast('☀️ Isınma seti kaydedildi');
    SFX.warmup();
    animateSetComplete(true);
    renderWoExercise();
    saveWorkoutDraft();
    return;
  }

  // Check PR mid-workout — kıyas e1RM üzerinden (vücut ağırlığı da sayılır)
  const pr=getPersonalRecord(se.exId);
  const score=setPRScore(setData,se.exData);
  if(score>0&&(!pr||score>(pr.e1rm??e1RM(effectiveLoad(pr,se.exData),pr.reps)))){
    showMidWorkoutPR(se.exData?.name||se.exId, weight>0?weight:reps, weight>0);
    SFX.pr();
  }

  SFX.setDone();
  animateSetComplete(false);
  se.completedSets.push(setData);
  saveWorkoutDraft();
  if(se.completedSets.length>=se.totalSets){advanceExercise();}
  else{w.setIndex=se.completedSets.length;startRestTimer(ST.settings.restTime,w.exercises[w.exIndex]);}
}

function advanceExercise(){
  const w=ST.workout; if(!w)return;
  w.exIndex++; w.setIndex=0;
  while(w.exIndex<w.exercises.length&&w.exercises[w.exIndex].skipped)w.exIndex++;
  saveWorkoutDraft();
  if(w.exIndex>=w.exercises.length)showSummary();
  else{const nextEx=w.exercises[w.exIndex];startRestTimer(ST.settings.restTime,nextEx);}
}

function skipExercise(){
  const w=ST.workout; if(!w)return;
  w.exercises[w.exIndex].skipped=true; advanceExercise();
}

function startRestTimer(duration,nextEx){
  const d=duration??ST.settings.restTime;
  _restDuration=d; _restRemaining=d;
  // Sayaç TİK saymaz, GEÇEN ZAMANI ölçer. Tarayıcı arka plandaki sekmenin
  // zamanlayıcılarını ~60 sn sonra donduruyor; eskiden 60 saniye sayıp
  // duruyordu ve uygulama açılınca kaldığı yerden devam ediyordu.
  // Bitiş anını mutlak zaman olarak tutunca kapalıyken geçen süre de sayılır.
  _restEndsAt=Date.now()+d*1000;
  setWoPhase('rest');
  const lbl=document.getElementById('rest-phase-label');
  if(lbl)lbl.textContent=T('rest_title');
  const circle=document.getElementById('rest-circle');
  const countdown=document.getElementById('rest-countdown');
  const nextExEl=document.getElementById('rest-next-ex');
  // Reset colors
  circle.style.stroke='var(--accent)';
  countdown.style.color='var(--text)';
  countdown.style.animation='';
  circle.style.strokeDasharray=restC; circle.style.strokeDashoffset=0;
  nextExEl.textContent=nextEx?nextEx.exData.name:'—';
  countdown.textContent=_restRemaining;
  if(woRestTimer)clearInterval(woRestTimer);
  woRestTimer=setInterval(_tickRest,250); // 250ms: geri dönüşte ekran hemen düzelsin
  _tickRest();
}

// Kalan süreyi mutlak bitiş anından hesaplar. Kaç kez çağrıldığı önemsiz.
function _tickRest(){
  if(!_restEndsAt) return;
  const circle=document.getElementById('rest-circle');
  const countdown=document.getElementById('rest-countdown');
  if(!circle||!countdown) return;
  _restRemaining=Math.max(0,Math.ceil((_restEndsAt-Date.now())/1000));
  const frac=Math.max(0,_restRemaining/_restDuration);
  circle.style.strokeDashoffset=restC*(1-frac);
  countdown.textContent=_restRemaining;
  // Color warning: yellow at 30%, red at 10%
  if(_restRemaining<=Math.ceil(_restDuration*0.1)){
    circle.style.stroke='var(--danger)';
    countdown.style.color='var(--danger)';
    countdown.style.animation='restPulse 0.5s ease-in-out infinite';
  } else if(_restRemaining<=Math.ceil(_restDuration*0.3)){
    circle.style.stroke='var(--warning)';
    countdown.style.color='var(--warning)';
    countdown.style.animation='';
  } else {
    circle.style.stroke='var(--accent)';
    countdown.style.color='var(--text)';
    countdown.style.animation='';
  }
  if(_restRemaining<=0){
    clearInterval(woRestTimer); woRestTimer=null; _restEndsAt=null;
    SFX.restEnd(); skipRest();
  }
}

// Uygulamaya dönüldüğünde ekranı anında tazele — donmuş sayı görünmesin
document.addEventListener('visibilitychange',()=>{
  if(!document.hidden && _restEndsAt && ST.workout?.phase==='rest') _tickRest();
});

function adjRestTimer(delta){
  _restRemaining=Math.max(5,_restRemaining+delta);
  _restDuration=Math.max(_restDuration,_restRemaining);
  // Bitiş anını da kaydır, yoksa bir sonraki tikte eski değere geri döner
  _restEndsAt=Date.now()+_restRemaining*1000;
  const countdown=document.getElementById('rest-countdown');
  if(countdown)countdown.textContent=_restRemaining;
  showToast((delta>0?'+':'')+delta+'s');
}

function skipRest(){
  if(woRestTimer)clearInterval(woRestTimer);
  woRestTimer=null; _restEndsAt=null;
  const w=ST.workout; if(!w)return;
  if(w.exIndex>=w.exercises.length){showSummary();return;}
  setWoPhase('exercise'); renderWoExercise();
}

function setWoPhase(phase){
  document.querySelectorAll('.wo-phase').forEach(p=>p.classList.remove('active'));
  document.getElementById('wo-phase-'+phase).classList.add('active');
  if(ST.workout)ST.workout.phase=phase;
  // Hide "Bitir" button on summary, stop timer
  const endBtn=document.getElementById('wo-end-btn');
  if(phase==='summary'){
    if(endBtn)endBtn.style.display='none';
    // Stop elapsed timer — freeze display
    if(woTimer){clearInterval(woTimer);woTimer=null;}
  } else {
    if(endBtn)endBtn.style.display='';
  }
}

function showSummary(){
  if(woRestTimer)clearInterval(woRestTimer);
  woRestTimer=null; _restEndsAt=null;
  setWoPhase('summary');
  const w=ST.workout;
  const duration=Math.floor((Date.now()-w.startTime)/60000);
  let totalVol=0,totalSets=0,prs=[];
  const exList=w.exercises.filter(e=>!e.skipped&&e.completedSets.length).map(se=>{
    const ex=se.exData; let vol=0;
    const workSets=se.completedSets.filter(s=>!s.isWarmup);
    const warmupSetsCount=(se.warmupSets||[]).length;
    workSets.forEach(s=>{vol+=setVolume(s,ex);totalSets++;});totalVol+=vol;
    const prevPR=getPersonalRecord(se.exId);
    const prevScore=prevPR?(prevPR.e1rm??e1RM(effectiveLoad(prevPR,ex),prevPR.reps)):0;
    const best=workSets.reduce((b,s)=>setPRScore(s,ex)>setPRScore(b,ex)?s:b,{weight:0,reps:0});
    const isPR=setPRScore(best,ex)>prevScore && setPRScore(best,ex)>0;
    if(isPR)prs.push({exId:se.exId,name:ex.name,...best});
    const setsStr=workSets.map(s=>`${(+s.weight||0)>0?s.weight+'kg×':''}${s.reps}${(+s.weight||0)>0?'':' tekrar'}${s.note?` (${esc(s.note)})`:''}`).join(', ');
    const warmupStr=warmupSetsCount?`<div style="font-size:11px;color:var(--warning);margin-top:2px">☀️ ${warmupSetsCount} ısınma seti</div>`:'';
    return `<div class="summary-ex-row"><div><div class="summary-ex-name">${esc(ex.name)}${isPR?'<span class="pr-badge">🏆 PR</span>':''}</div><div class="summary-ex-sets">${setsStr}</div>${warmupStr}</div></div>`;
  }).join('');
  document.getElementById('summary-sub').textContent=prs.length?`${prs.length} ${T('new_prs')}! 🏆`:T('great_session');
  // Stats with count-up
  const statsGrid=document.getElementById('summary-stats-grid');
  statsGrid.innerHTML=`<div class="summary-stat"><div class="summary-stat-num" id="sum-dur">0</div><div class="summary-stat-label">⏱ ${T('minutes')}</div></div><div class="summary-stat"><div class="summary-stat-num" id="sum-sets">0</div><div class="summary-stat-label">✅ ${T('sets')}</div></div><div class="summary-stat"><div class="summary-stat-num" id="sum-vol">0</div><div class="summary-stat-label">⚡ kg Vol</div></div>`;
  document.getElementById('summary-ex-list').innerHTML=exList;
  // Animate count-up
  setTimeout(()=>{
    animateCount(document.getElementById('sum-dur'),duration,1200);
    animateCount(document.getElementById('sum-sets'),totalSets,1400);
    animateCount(document.getElementById('sum-vol'),Math.round(totalVol),1600);
    if(prs.length)launchConfetti();
  SFX.finish();
  },300);
}

// ============================================================
// PLATE CALCULATOR
// ============================================================
const PLATE_COLORS={25:'#ef4444',20:'#3b82f6',15:'#eab308',10:'#22c55e',5:'#d1d5db',2.5:'#f97316',2:'#8b5cf6',1.25:'#9ca3af',1:'#6b7280',0.5:'#4b5563'};
const PLATE_SIZES=[25,20,15,10,5,2.5,2,1.25,1,0.5];
const BAR_KG=20;
let _plateW=20,_plateMode='barbell';

function openPlateCalc(){
  const cur=parseFloat(document.getElementById('wo-weight')?.value)||0;
  _plateW=cur>0?cur:20;
  _plateMode='barbell';
  document.getElementById('pmode-barbell')?.classList.add('active');
  document.getElementById('pmode-dumbbell')?.classList.remove('active');
  renderPlateCalc();
  openModal('modal-plates');
}

function setPlateMode(m){
  _plateMode=m;
  document.getElementById('pmode-barbell')?.classList.toggle('active',m==='barbell');
  document.getElementById('pmode-dumbbell')?.classList.toggle('active',m==='dumbbell');
  renderPlateCalc();
}

function adjPlateWeight(d){
  _plateW=Math.max(0,parseFloat((_plateW+d).toFixed(1)));
  renderPlateCalc();
}

function calcPlatesGreedy(target){
  let rem=target; const out=[];
  for(const p of PLATE_SIZES){while(rem>=p-0.001){out.push(p);rem=parseFloat((rem-p).toFixed(3));}}
  return out;
}

function renderPlateCalc(){
  const dispEl=document.getElementById('plate-weight-disp');
  const hintEl=document.getElementById('plate-mode-hint');
  const visualEl=document.getElementById('plate-visual');
  const listEl=document.getElementById('plate-list');
  const errEl=document.getElementById('plate-error');
  if(dispEl)dispEl.textContent=_plateW;

  let loadPerSide=0,errMsg='',isBarbell=_plateMode==='barbell';
  if(isBarbell){
    if(hintEl)hintEl.textContent=`Bar (${BAR_KG}kg) dahil`;
    const net=parseFloat((_plateW-BAR_KG).toFixed(3));
    if(net<0){errMsg=`Minimum ağırlık ${BAR_KG}kg (bar).`;loadPerSide=0;}
    else{loadPerSide=parseFloat((net/2).toFixed(3));}
  }else{
    if(hintEl)hintEl.textContent='Tek dumbbell toplam';
    loadPerSide=_plateW;
  }

  if(errEl){errEl.style.display=errMsg?'block':'none';errEl.textContent=errMsg;}
  if(errMsg){if(visualEl)visualEl.innerHTML='';if(listEl)listEl.innerHTML='';return;}

  const plates=calcPlatesGreedy(loadPerSide);
  const countMap={};
  plates.forEach(p=>{countMap[p]=(countMap[p]||0)+1;});

  // Visual barbell/dumbbell
  function makeDisc(p){
    const c=PLATE_COLORS[p]||'#888';
    const h=Math.min(70,Math.max(22,18+p*2));
    const w=p>=10?14:p>=2.5?10:7;
    return `<div style="width:${w}px;height:${h}px;background:${c};border-radius:3px;display:flex;align-items:center;justify-content:center;writing-mode:vertical-rl;font-size:8px;font-weight:800;color:#fff;flex-shrink:0">${p>=2.5?p:''}</div>`;
  }

  let visualHTML='';
  if(isBarbell){
    const leftDiscs=[...plates].reverse().map(makeDisc).join('');
    const rightDiscs=plates.map(makeDisc).join('');
    visualHTML=`
      <div class="plate-bar-sleeve" style="width:22px"></div>
      ${leftDiscs}
      <div class="plate-bar-center" style="width:60px"></div>
      ${rightDiscs}
      <div class="plate-bar-sleeve" style="width:22px"></div>`;
  }else{
    const discs=plates.map(makeDisc).join('');
    visualHTML=`
      <div class="plate-bar-sleeve" style="width:14px;height:8px"></div>
      ${discs}
      <div class="plate-bar-sleeve" style="width:14px;height:8px"></div>`;
  }
  if(visualEl)visualEl.innerHTML=plates.length?visualHTML:`<div style="color:var(--success);font-size:13px;text-align:center;width:100%">${isBarbell?'Sadece bar ('+BAR_KG+'kg)':'0 kg'}</div>`;

  // List
  const listHTML=Object.entries(countMap).sort((a,b)=>b[0]-a[0]).map(([p,cnt])=>{
    const c=PLATE_COLORS[p]||'#888';
    const total=isBarbell?cnt*2:cnt;
    const note=isBarbell?` (her taraf: ${cnt} adet)`:'';
    return `<div class="plate-item-row">
      <div class="plate-swatch" style="background:${c}"></div>
      <div style="flex:1;margin:0 10px;font-size:14px;font-weight:600">${p} kg</div>
      <div style="font-size:13px;color:var(--text2)">${total} adet${note}</div>
    </div>`;
  }).join('');
  if(listEl)listEl.innerHTML=listHTML||`<div style="text-align:center;color:var(--text3);font-size:13px;padding:4px 0">Plaka yok</div>`;
}

async function finishWorkout(){
  const w=ST.workout; if(!w||w._saving)return;
  // Kaydet düğmesine ardışık iki dokunuş iki ayrı seans yazıyordu (hacim, seri
  // ve geçmiş ikiye katlanıyordu). İlk çağrı bitene kadar kilitle.
  w._saving=true;
  const woNote=document.getElementById('wo-workout-note')?.value.trim()||'';
  const duration=Math.floor((Date.now()-w.startTime)/60000);
  let totalVol=0;
  const exerciseLogs=w.exercises.map(se=>{
    let v=0;
    se.completedSets.forEach(s=>{if(!s.isWarmup)v+=setVolume(s,se.exData);});
    totalVol+=v;
    const allSets=[...(se.warmupSets||[]),...se.completedSets];
    return{exId:se.exId,sets:allSets,skipped:se.skipped};
  });
  const log={id:'log_'+Date.now(),date:new Date().toISOString(),routineId:w.routineId,dayId:w.dayId,dayName:w.dayName,exercises:exerciseLogs,duration,totalVolume:Math.round(totalVol),...(woNote?{note:woNote}:{}),...(typeof w.readiness==='number'?{readiness:w.readiness}:{})};
  try{
    await DB.put('workoutLogs',log); ST.workoutLogs.push(log);
    const routine=ST.routines.find(r=>r.id===w.routineId);
    ST.settings.lastWorkoutDate=new Date().toISOString();
    ST.settings.breakNotice=null;
    if(routine&&routine.days&&routine.days.length&&routine.id===ST.settings.activeRoutineId){
      // Sirayi calisilan gunun kendisinden ilerlet (dinlenmeyi atlayip antrenman yapildiysa da dogru).
      const trainedIdx=routine.days.findIndex(d=>d.id===w.dayId);
      const base=trainedIdx>=0?trainedIdx:normPos(ST.settings.cyclePosition,routine.days.length);
      ST.settings.cyclePosition=(base+1)%routine.days.length;
      // Yeni pozisyon YARINDAN itibaren gecerli: bugun zaten calisildi, bugunku dinlenme yanmasin.
      ST.settings.cycleDate=shiftKey(dayKey(),1);
    }
    await DB.put('settings',{id:'main',...ST.settings});
    // Save PRs to dedicated prs store
    for(const se of w.exercises.filter(e=>!e.skipped)){
      const workSets=se.completedSets.filter(s=>!s.isWarmup);
      const exD=se.exData;
      const best=workSets.reduce((b,s)=>setPRScore(s,exD)>setPRScore(b,exD)?s:b,{weight:0,reps:0});
      const score=setPRScore(best,exD);
      if(score>0){
        const prev=getPersonalRecord(se.exId);
        const prevScore=prev?(prev.e1rm??e1RM(effectiveLoad(prev,exD),prev.reps)):0;
        if(score>prevScore){
          const prRec={id:'pr_'+se.exId,exId:se.exId,weight:+best.weight||0,reps:best.reps,
            e1rm:score,date:new Date().toISOString()};
          await DB.put('prs',prRec); ST.prs[se.exId]=prRec;
        }
      }
    }
    closeWorkout(); renderBugun();
  }catch(err){
    w._saving=false;
    console.error('finishWorkout error:',err);
    showToast('❌ Kaydedilemedi, tekrar dene',true);
  }
}

function discardWorkout(){
  showConfirm('⚠️',T('discard_title'),T('discard_msg'),()=>{closeWorkout();closeModal('modal-alert');});
}

function closeWorkout(){
  if(woTimer)clearInterval(woTimer);
  if(woRestTimer)clearInterval(woRestTimer);
  woTimer=null; woRestTimer=null; _restEndsAt=null; ST.workout=null; woElapsed=0;
  document.getElementById('workout-overlay').classList.remove('open');
  clearWorkoutDraft();
}

// ── YARIM KALAN ANTRENMAN ───────────────────────────────────
// Antrenman yalnızca bellekteydi: PWA'yı işletim sistemi arka planda öldürürse
// (veya yanlışlıkla kapatılırsa) tamamlanan tüm setler kayboluyordu. Her
// değişiklikte küçük bir anlık görüntü IndexedDB'ye yazılır; açılışta devam
// etmek istenip istenmediği sorulur. Egzersiz verisi (exData) yazılmaz, id'den
// yeniden kurulur — özel egzersiz silindiyse o kalem sessizce düşer.
const WO_DRAFT_ID = 'workoutDraft';
const WO_DRAFT_MAX_AGE_MS = 12 * 3600 * 1000;

function _workoutDraftSnapshot(){
  const w=ST.workout; if(!w||w._saving) return null;
  return {
    id:WO_DRAFT_ID, savedAt:Date.now(),
    routineId:w.routineId, dayId:w.dayId, dayName:w.dayName,
    // Kapalı kaldığı süre antrenman süresine girmesin: geçen ETKİN süreyi sakla
    activeMs:Date.now()-w.startTime,
    readiness:typeof w.readiness==='number'?w.readiness:null,
    exIndex:w.exIndex,
    exercises:w.exercises.map(e=>({exId:e.exId,totalSets:e.totalSets,targetReps:e.targetReps,
      completedSets:e.completedSets,warmupSets:e.warmupSets||[],skipped:!!e.skipped})),
  };
}
function saveWorkoutDraft(){
  const d=_workoutDraftSnapshot(); if(!d) return;
  DB.put('settings',d).catch(()=>{});
}
function clearWorkoutDraft(){ return DB.del('settings',WO_DRAFT_ID).catch(()=>{}); }

async function offerWorkoutResume(){
  let d=null;
  try{ d=await DB.get('settings',WO_DRAFT_ID); }catch{ return; }
  if(!d) return;
  const routine=ST.routines.find(r=>r.id===d.routineId);
  const done=(d.exercises||[]).reduce((a,e)=>a+(e.completedSets||[]).length,0);
  if(!routine || Date.now()-(d.savedAt||0)>WO_DRAFT_MAX_AGE_MS || (!done && !(d.exercises||[]).some(e=>e.skipped))){
    await clearWorkoutDraft(); return;
  }
  showConfirm('🏋️','Yarım kalan antrenman',
    `${translateDayName(d.dayName||'')} — ${done} set kayıtlıydı. Kaldığın yerden devam edelim mi? `
    +`"Vazgeç" dersen bu antrenman silinir.`,
    ()=>{ closeModal('modal-alert'); resumeWorkoutDraft(d); }, 'primary');
  const cancel=document.getElementById('alert-cancel');
  if(cancel) cancel.onclick=()=>{ closeModal('modal-alert'); clearWorkoutDraft(); };
}

function resumeWorkoutDraft(d){
  if(ST.workout) return;
  const exercises=(d.exercises||[]).map(e=>({
    exId:e.exId, exData:getExercise(e.exId), totalSets:e.totalSets, targetReps:e.targetReps,
    completedSets:e.completedSets||[], warmupSets:e.warmupSets||[], skipped:!!e.skipped,
    prevPerf:getLastPerformance(e.exId), prevSets:getLastSetsPerformance(e.exId),
  }));
  // Silinmiş egzersizler düşer; imleç doğru kalemde kalsın diye indeksi yeniden hesapla
  const keep=exercises.map(e=>!!e.exData);
  let newIndex=0;
  for(let i=0;i<Math.min(d.exIndex,exercises.length);i++) if(keep[i]) newIndex++;
  const list=exercises.filter(e=>e.exData);
  if(!list.length){ clearWorkoutDraft(); return; }
  const startTime=Date.now()-(d.activeMs||0);
  ST.workout={ routineId:d.routineId, dayId:d.dayId, dayName:d.dayName, exercises:list,
    exIndex:newIndex, setIndex:0, startTime, phase:'exercise',
    ...(typeof d.readiness==='number'?{readiness:d.readiness}:{}) };
  woStartTime=startTime; startWoTimer();
  while(ST.workout.exIndex<list.length && list[ST.workout.exIndex].skipped) ST.workout.exIndex++;
  document.getElementById('workout-overlay').classList.add('open');
  if(ST.workout.exIndex>=list.length) showSummary(); else renderWoExercise();
  updateWoHeader();
}

function showEndWorkoutConfirm(){
  showConfirm('🏁',T('finish_title'),T('finish_msg'),()=>{closeModal('modal-alert');showSummary();});
}

function toggleTipExpand(){
  const tipEl=document.getElementById('wo-tip');
  const btn=document.getElementById('wo-tip-toggle');
  const span=document.getElementById('wo-tip-text');
  if(!tipEl||!btn||!span)return;
  tipEl._expanded=!tipEl._expanded;
  span.textContent=tipEl._expanded?tipEl._full:(tipEl._full.slice(0,78)+'…');
  btn.textContent=tipEl._expanded?'kapat':'daha fazla';
}
function adjInput(id,delta){const el=document.getElementById(id);if(!el)return;let v=parseFloat(el.value)||0;v=Math.max(0,parseFloat((v+delta).toFixed(1)));el.value=v;haptic('light');SFX.tick();}

// Long-press weight buttons: kısa basış 0.5kg, uzun basış (380ms+) 2.5kg
const _wadj={timer:null,fired:false,btn:null,short:0};
function startWAdj(btn,shortD,longD){
  _wadj.fired=false;_wadj.short=shortD;_wadj.btn=btn;
  btn.classList.add('lp-active');
  _wadj.timer=setTimeout(()=>{
    _wadj.fired=true;
    adjInput('wo-weight',longD);
    haptic('medium');
    showToast((longD>0?'+':'')+longD+'kg');
    btn.classList.remove('lp-active');
  },380);
}
function endWAdj(){
  if(_wadj.timer)clearTimeout(_wadj.timer);
  if(_wadj.btn)_wadj.btn.classList.remove('lp-active');
  if(!_wadj.fired){adjInput('wo-weight',_wadj.short);_wadj.fired=true;}
  _wadj.btn=null;
}

// ============================================================
// HAPTIC + SOUND ENGINE
// ============================================================
const haptic = (type='light') => {
  if (!navigator.vibrate || ST.settings.hapticEnabled === false) return;
  const patterns = { light:10, medium:25, heavy:[20,30,20], success:[10,40,60], error:[40,30,40] };
  navigator.vibrate(patterns[type] || 10);
};

const SFX = (() => {
  let ctx = null;
  const getCtx = () => { if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)(); return ctx; };

  function beep({ freq=440, type='sine', gain=0.18, dur=0.08, ramp=true } = {}) {
    if (ST.settings.soundEnabled === false) return;
    try {
      const ac = getCtx();
      // Tarayıcı AudioContext'i askıya alıyor — her seste resume et
      const play = () => {
        const osc = ac.createOscillator();
        const g = ac.createGain();
        osc.connect(g); g.connect(ac.destination);
        osc.type = type; osc.frequency.setValueAtTime(freq, ac.currentTime);
        g.gain.setValueAtTime(gain, ac.currentTime);
        if (ramp) g.gain.exponentialRampToValueAtTime(0.001, ac.currentTime + dur);
        osc.start(ac.currentTime); osc.stop(ac.currentTime + dur);
      };
      if (ac.state === 'suspended') { ac.resume().then(play); } else { play(); }
    } catch(e) {}
  }

  return {
    tick()    { beep({ freq:880, type:'sine',     gain:0.07, dur:0.05 }); },
    setDone() { haptic('medium'); beep({ freq:523, type:'triangle', gain:0.22, dur:0.12 }); setTimeout(()=>beep({ freq:659, type:'triangle', gain:0.18, dur:0.10 }),100); },
    pr()      { haptic('success'); [523,659,784,1047].forEach((f,i)=>setTimeout(()=>beep({ freq:f, type:'triangle', gain:0.2, dur:0.15 }),i*90)); },
    finish()  { haptic('success'); [392,523,659,784,1047].forEach((f,i)=>setTimeout(()=>beep({ freq:f, type:'sine', gain:0.18, dur:0.2 }),i*110)); },
    restEnd() { haptic('heavy');   beep({ freq:880, type:'square', gain:0.15, dur:0.12 }); setTimeout(()=>beep({ freq:1100, type:'square', gain:0.12, dur:0.18 }),130); },
    warmup()  { haptic('light');   beep({ freq:660, type:'sine', gain:0.14, dur:0.09 }); }
  };
})();

function getLastPerformance(exId){
  for(let i=ST.workoutLogs.length-1;i>=0;i--){
    const log=ST.workoutLogs[i];
    const ex=log.exercises?.find(e=>e.exId===exId);
    if(ex&&ex.sets?.length){
      // Warmup olmayan son work set'i döndür (kilo 0 olabilir: vücut ağırlığı)
      const workSets=ex.sets.filter(s=>!s.isWarmup);
      if(workSets.length) return workSets[workSets.length-1];
      // Sadece warmup varsa da göster
      return ex.sets[ex.sets.length-1];
    }
  }
  return null;
}
// Önceki antrenmanın o egzersizdeki TÜM work setlerini (sırasıyla) döndürür.
// Böylece yeni antrenmanda 1. set -> geçen seferki 1. set ile eşleşir.
function getLastSetsPerformance(exId){
  for(let i=ST.workoutLogs.length-1;i>=0;i--){
    const log=ST.workoutLogs[i];
    const ex=log.exercises?.find(e=>e.exId===exId);
    if(ex&&ex.sets?.length){
      // Vücut ağırlığı hareketlerinde kilo 0'dır; `weight>0` süzgeci bunları
      // eleyip ısınma setlerine düşürüyordu. Isınma dışı her set çalışma setidir.
      const workSets=ex.sets.filter(s=>!s.isWarmup);
      if(workSets.length) return workSets;
      return ex.sets;
    }
  }
  return null;
}
function getPersonalRecord(exId){
  // Önce kayıtlı PR'a bak (date bilgisi var)
  if(ST.prs[exId]) return ST.prs[exId];
  // Yoksa loglardan hesapla — kıyas e1RM üzerinden, böylece vücut ağırlığı
  // hareketleri de rekor kaydedebiliyor.
  const exData=getExercise(exId);
  let best=null,bestScore=0;
  for(const log of ST.workoutLogs){
    const ex=log.exercises?.find(e=>e.exId===exId); if(!ex) continue;
    for(const s of (ex.sets||[])){
      if(s.isWarmup) continue;
      const sc=setPRScore(s,exData);
      if(sc>bestScore){bestScore=sc;best={weight:+s.weight||0,reps:s.reps,e1rm:sc,date:log.date};}
    }
  }
  return best;
}
