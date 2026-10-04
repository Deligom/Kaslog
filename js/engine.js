// ============================================================
// ADAPTİF ANTRENMAN MOTORU
//
// Eski mantık iki yerden aksıyordu:
//   1. `weight > 0` filtresi yüzünden vücut ağırlığı hareketleri (şınav,
//      barfiks, dips…) sistemde HİÇ görünmüyordu — ne öneri, ne rekor,
//      ne hacim, ne grafik.
//   2. Sadece en iyi set bakılıyordu: 12/11/9 ile 12/5/5 aynı sayılıyordu.
//      Yorgun bir gün ile gerçek gerileme ayırt edilemiyordu.
//
// Yeni yaklaşım üç katman:
//   a) ORTAK PARA BİRİMİ — her set e1RM'e (tahmini 1 tekrar maksimum)
//      çevrilir. Ağırlık ve tekrar tek sayıya iner; 45kg×8 ile 40kg×12
//      karşılaştırılabilir olur. Vücut ağırlığı hareketlerinde yük,
//      kilonun hareket katsayısıyla çarpımıdır — şınav da bu sayede girer.
//   b) TREND — tek seans değil, üssel hareketli ortalama izlenir. Kötü bir
//      gün ortalamayı birkaç yüzde oynatır, yönü değiştirmez.
//   c) EFOR — sette "kaç tekrar daha yapabilirdin" (RIR) ve seans başında
//      1-5 durum sorulur. 9 tekrar iki farklı şeydir: RIR 0 ise gerçek
//      limitin, RIR 3 ise bugün zorlamamışsın. Sistem ikincisini gerileme
//      saymaz; düşük durumda hedefi kendiliğinden yumuşatır.
// ============================================================

// Vücut ağırlığının ne kadarını kaldırdığın. Kaba ama tutarlı tahminler:
// amaç mutlak doğruluk değil, aynı hareketi zaman içinde kıyaslayabilmek.
const BW_COEF = {
  pushup:0.64, diamond_pushup:0.64, pike_pushup:0.70, weighted_pushup:0.64,
  dips:0.50, pullup:1.00,
  squat:0.65, lunge:0.65, bulgarian_split_squat:0.85, calf_raise:0.90,
  crunches:0.30,
};

// Artış adımı: squat'ta +0,5 kg komik, lateral raise'de fazla.
// Çalışma ağırlığının yüzdesi olarak ilerlemek ikisini de doğru ölçekler.
const INC_PCT = {
  squat:0.05, lunge:0.05, bulgarian_split_squat:0.05, calf_raise:0.05,
  deadlift:0.05, romanian_deadlift:0.05, hip_thrust:0.05,
  bent_row:0.025, overhead_press:0.025, floor_press:0.025, pullup:0.025,
  pushup:0.025, weighted_pushup:0.025, diamond_pushup:0.025, pike_pushup:0.025,
  dips:0.025,
};
const INC_PCT_DEFAULT = 0.02;   // izolasyon hareketleri
const MIN_INCREMENT    = 0.5;   // elindeki en küçük plaka

function _bodyWeight(){
  const ms=(ST.measurements||[]).filter(m=>+m.weight>0)
    .sort((a,b)=>new Date(b.date)-new Date(a.date));
  if(ms.length) return +ms[0].weight;
  const s=+ST.settings.bodyWeight;
  return s>0?s:null;
}

// Hareket vücut ağırlığıyla mı yapılıyor? Katsayısını döner, değilse null.
function _bwCoef(exData){
  if(!exData) return null;
  if(exData.type==='time') return null;   // süre bazlı harekette e1RM anlamsız
  if(BW_COEF[exData.id]!=null) return BW_COEF[exData.id];
  // Kullanıcının eklediği özel hareketler: ekipmanında "Bodyweight" geçiyorsa
  // makul bir varsayılan ver, yoksa bunlar da görünmez kalır.
  if(/bodyweight/i.test(exData.equipment||'')) return 0.65;
  return null;
}

/**
 * Setin GERÇEK yükü. Vücut ağırlığı hareketlerinde girilen kilo EK yüktür
 * (sırt çantası, dambıl); taban vücut ağırlığından gelir.
 * Kilo bilinmiyorsa eski davranışa döner — yanlış sayı üretmektense
 * hiç üretmemek yeğdir.
 */
function effectiveLoad(set, exData){
  const w=+set?.weight||0;
  const coef=_bwCoef(exData);
  if(coef==null) return w;
  const bw=_bodyWeight();
  if(!bw) return w;
  return Math.round((bw*coef + w)*10)/10;
}

// Epley formülü — ağırlık ve tekrarı tek karşılaştırılabilir sayıya indirger
function e1RM(load, reps){
  if(!(load>0)||!(reps>0)) return 0;
  if(reps===1) return load;
  return Math.round(load*(1+reps/30)*10)/10;
}

/**
 * Bir hareketin seans geçmişi (eskiden yeniye).
 * Seans başına: en iyi e1RM, hacim, ortalama RIR, o günkü durum.
 */
function exerciseSessions(exId){
  const exData=getExercise(exId);
  const out=[];
  // Trend ve grafik zaman sırasına dayanıyor; kayıt sırasına güvenme.
  const logs=[...ST.workoutLogs].sort((a,b)=>new Date(a.date)-new Date(b.date));
  for(const log of logs){
    const ex=log.exercises?.find(e=>e.exId===exId);
    if(!ex) continue;
    const scored=(ex.sets||[])
      .filter(s=>!s.isWarmup)
      .map(s=>{ const load=effectiveLoad(s,exData); return {...s, load, est:e1RM(load,s.reps)}; })
      .filter(s=>s.est>0);
    if(!scored.length) continue;
    const best=scored.reduce((a,b)=>b.est>a.est?b:a);
    const rirs=scored.filter(s=>typeof s.rir==='number').map(s=>s.rir);
    out.push({
      ts:new Date(log.date).getTime(),
      sets:scored, best, bestE1rm:best.est,
      volume:Math.round(scored.reduce((a,s)=>a+s.load*s.reps,0)),
      avgRir:rirs.length ? rirs.reduce((a,b)=>a+b,0)/rirs.length : null,
      readiness:log.readiness ?? null,
    });
  }
  return out;
}

/**
 * Yumuşatılmış güç trendi + kişisel ilerleme hızı.
 * Kitaptaki "her hafta +2,5 kg" dayatılmaz; SENİN son haftalardaki gerçek
 * eğimin ölçülür ve hedef ona göre konur.
 */
function e1rmTrend(exId){
  const s=exerciseSessions(exId);
  if(!s.length) return null;
  const ALPHA=0.35;                    // yeni seansın ağırlığı
  let ewma=s[0].bestE1rm;
  let ewmaPrev=ewma;                   // SON seans hariç ortalama
  for(let i=1;i<s.length;i++){
    if(i===s.length-1) ewmaPrev=ewma;  // son adımdan önceki değeri sakla
    ewma=ALPHA*s[i].bestE1rm+(1-ALPHA)*ewma;
  }

  // Son 8 seansın haftalık eğimi (en küçük kareler)
  const recent=s.slice(-8);
  let slopePerWeek=0;
  if(recent.length>=3){
    const t0=recent[0].ts;
    const xs=recent.map(r=>(r.ts-t0)/(7*86400000));  // hafta
    const ys=recent.map(r=>r.bestE1rm);
    const n=xs.length;
    const mx=xs.reduce((a,b)=>a+b,0)/n, my=ys.reduce((a,b)=>a+b,0)/n;
    let num=0,den=0;
    for(let i=0;i<n;i++){ num+=(xs[i]-mx)*(ys[i]-my); den+=(xs[i]-mx)**2; }
    if(den>0) slopePerWeek=Math.round((num/den)*100)/100;
  }

  const last=s[s.length-1];
  const daysSince=Math.floor((Date.now()-last.ts)/86400000);
  return {
    sessions:s, ewma:Math.round(ewma*10)/10,
    last, lastE1rm:last.bestE1rm, slopePerWeek,
    daysSince, sessionCount:s.length,
    // Son seansı ÖNCEKİ ortalamayla kıyasla. Tam ortalamayı kullanmak hatalı:
    // kötü seans ortalamayı kendine doğru çeker ve kendini gizler.
    lastWasOff: s.length>=2 && last.bestE1rm < ewmaPrev*0.95,
  };
}

// Setin hacme katkısı — vücut ağırlığı dahil
function setVolume(set, exData){ return effectiveLoad(set, exData) * (+set?.reps || 0); }

// Bir setin rekor değeri e1RM'dir: hem şınav rekor kırabilir, hem de aynı
// kiloda tekrar artışı rekor sayılabilir — 40kg×14 (58,7) gerçekten
// 45kg×8'i (57) geçer. Eskiden sadece kiloya bakıldığı için görünmezdi.
function setPRScore(set, exData){ return e1RM(effectiveLoad(set, exData), set?.reps); }

// PR kaydını okunur metne çevir. Vücut ağırlığında "0kg" yazmak anlamsız.
function formatPR(pr){
  if(!pr) return '';
  return (+pr.weight||0) > 0 ? `${pr.weight}kg × ${pr.reps}` : `${pr.reps} tekrar`;
}

// Bu harekete uygun kilo artışı — yüzde bazlı, en küçük plakaya yuvarlanır
function incrementFor(exData, workLoad){
  const pct=INC_PCT[exData?.id] ?? INC_PCT_DEFAULT;
  const raw=workLoad*pct;
  return Math.max(MIN_INCREMENT, Math.round(raw/MIN_INCREMENT)*MIN_INCREMENT);
}

// FEATURE 1: Progressive Overload
// ============================================================
// Seans başı durum (1-5). null = yanıtlanmadı, sistem sadece performansa bakar.
function setReadiness(v){
  if(ST.workout){ ST.workout.readiness = v; saveWorkoutDraft(); }
  closeModal('modal-readiness');
  // Durum, önerileri etkiliyor — ekranı tazele
  if(ST.workout) renderWoExercise();
}

// Bu set için seçilen RIR (kaç tekrar daha yapabilirdin). null = yanıtlanmadı.
let _setRir = null;
function setSetRir(v){
  _setRir = (_setRir === v) ? null : v;   // aynısına basınca seçimi kaldır
  _paintRirChips();
}
function _paintRirChips(){
  document.querySelectorAll('.wo-rir-chip').forEach(b=>{
    const on = _setRir !== null && +b.dataset.rir === _setRir;
    b.style.background = on ? 'var(--accent)' : 'var(--surface2)';
    b.style.color      = on ? '#fff' : 'var(--text2)';
    b.style.borderColor= on ? 'var(--accent)' : 'var(--border)';
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

let _isWarmupSet = false;
function toggleWarmup() {
  _isWarmupSet = !_isWarmupSet;
  const chip = document.getElementById('wo-warmup-chip');
  if (chip) chip.classList.toggle('wo-chip-active', _isWarmupSet);
}

function toggleNoteInput() {
  const n = document.getElementById('wo-set-note');
  if (!n) return;
  const show = n.style.display === 'none' || !n.style.display;
  n.style.display = show ? 'block' : 'none';
  if (show) setTimeout(() => n.focus(), 50);
}

function toggleTipWrap() {
  const body = document.getElementById('wo-tip-body');
  const btn = document.getElementById('wo-tip-toggle-btn');
  if (!body) return;
  const isOpen = body.classList.toggle('open');
  if (btn) btn.classList.toggle('open', isOpen);
}

// Çift ilerleme (double progression): çalışma ağırlığında ÜST setinde hedef
// tekrarı tutturduysan → kiloyu artır. Tutturamadıysan (yorgun gün dahil) →
// aynı kiloda kal, tekrarı büyütmeye çalış. Tek kötü gün seni asla geriletmez.
function getProgressiveOverloadSuggestion(exId, targetReps) {
  const exData = getExercise(exId);
  const tr = e1rmTrend(exId);
  if (!tr) return null;

  const target  = targetReps || 10;
  const last    = tr.last;
  const isBW    = _bwCoef(exData) != null;

  // Öneri kullanıcının GİRDİĞİ birimde olmalı: vücut ağırlığı hareketinde
  // girilen kilo EK yüktür ve çoğu zaman 0'dır.
  const workW   = Math.max(...last.sets.map(s => +s.weight || 0));
  const setsAtW = last.sets.filter(s => (+s.weight || 0) === workW);
  const topReps = Math.max(...setsAtW.map(s => s.reps));
  const rir     = last.avgRir;
  const ready   = last.readiness;
  const inc     = incrementFor(exData, last.best.load || workW);
  const bwOnly  = isBW && workW === 0;   // ek yük yok → tekrarla ilerlenir

  // ── 1. Uzun ara: son seansın yükünü dayatma ────────────────
  if (tr.daysSince >= 14) {
    const back = bwOnly ? 0 : Math.max(MIN_INCREMENT, Math.round((workW*0.9)/MIN_INCREMENT)*MIN_INCREMENT);
    return { type:'layoff', suggestedWeight: back, workW, target, topReps,
      msg: `⏸️ ${tr.daysSince} gün ara — ${bwOnly ? `${Math.max(1,topReps-2)} tekrarla ısın` : `${back}kg ile dön`}` };
  }

  // ── 2. Hedefi tutturduysan artır ───────────────────────────
  if (topReps >= target) {
    // BUGÜN kötü hissediyorsan yeni yük dayatma. Geçen seans hak ettiğin
    // artışı kaybetmezsin — bir sonraki iyi güne saklanır.
    const todayReady = ST.workout?.readiness;
    if (typeof todayReady === 'number' && todayReady <= 2) {
      return { type:'maintain', suggestedWeight: workW, workW, target, topReps,
        msg: `😴 Bugün ağır — aynı yükte kal, artışı sonraya sakla` };
    }
    // RIR biliniyorsa adımı ona göre ölçekle: hâlâ 3+ yedeğin varsa cesur,
    // son tekrar zor geldiyse (RIR 0) temkinli davran.
    let step = inc;
    if (typeof rir === 'number') {
      if (rir >= 3)      step = inc * 2;
      else if (rir <= 0) step = inc * 0.5;
    }
    step = Math.max(MIN_INCREMENT, Math.round(step/MIN_INCREMENT)*MIN_INCREMENT);

    if (bwOnly) {
      const nextReps = target + (typeof rir === 'number' && rir >= 3 ? 2 : 1);
      return { type:'increase_reps', suggestedWeight: 0, workW, target, topReps, nextReps,
        msg: `🔼 ${nextReps} tekrar hedefle` };
    }
    const w = +(workW + step).toFixed(1);
    return { type:'increase', suggestedWeight: w, workW, target, topReps,
      msg: `🔼 ${w}kg dene` };
  }

  // ── 3. Tutturamadın — sebebini ayırt et ────────────────────
  // a) Yedeğin vardı ya da bitkin bir gündü: bu gerileme değil, bugün
  //    zorlamamışsın. Sistem seni geriletmez.
  if (typeof rir === 'number' && rir >= 2) {
    return { type:'maintain', suggestedWeight: workW, workW, target, topReps,
      msg: `💪 Yedeğin vardı — ${target} tekrarı zorla` };
  }
  if (typeof ready === 'number' && ready <= 2) {
    return { type:'maintain', suggestedWeight: workW, workW, target, topReps,
      msg: `😴 Yorgun gündün — aynı yükte kal` };
  }

  // b) Trend hâlâ yukarı: tek seansa bakıp deload etme.
  if (tr.slopePerWeek > 0.2) {
    return { type:'maintain', suggestedWeight: workW, workW, target, topReps,
      msg: `📈 Trend yukarı — ${target} tekrar hedefle` };
  }

  // c) Trend durdu/düştü, son seans da aykırı değil → gerçek plato.
  if (tr.sessionCount >= 3 && tr.slopePerWeek <= 0 && !tr.lastWasOff) {
    if (bwOnly) {
      const easier = Math.max(1, Math.round(topReps * 0.8));
      return { type:'deload', suggestedWeight: 0, workW, target, topReps, nextReps: easier,
        msg: `🔻 Plato — ${easier} tekrara düş, temiz formla tırman` };
    }
    const deloadW = Math.max(MIN_INCREMENT, Math.round((workW*0.9)/MIN_INCREMENT)*MIN_INCREMENT);
    return { type:'deload', suggestedWeight: deloadW, workW, target, topReps,
      msg: `🔻 Plato — ${deloadW}kg'a düş, 2 hafta sonra tırman` };
  }

  return { type:'maintain', suggestedWeight: workW, workW, target, topReps,
    msg: bwOnly ? `${target} tekrar hedefle` : `${workW}kg · ${target} tekrar hedefle` };
}
// ============================================================
// FEATURE 2: Exercise Progress Chart
// ============================================================
function openExProgress(exId) {
  const ex = getExercise(exId); if (!ex) return;
  document.getElementById('exp-title').textContent = ex.name;
  document.getElementById('exp-muscle').textContent = ex.muscle + ' · ' + ex.equipment;

  // Seans başına en iyi performans. Grafik artık ham kiloyu değil e1RM'i
  // (tahmini güç) çiziyor: hem vücut ağırlığı hareketleri görünür oluyor,
  // hem de "aynı kiloda 8→12 tekrar" gerçek bir ilerleme olarak okunuyor.
  const sessions = exerciseSessions(exId).map(s => ({
    date: new Date(s.ts).toISOString(),
    weight: +s.best.weight || 0,
    reps: s.best.reps,
    e1rm: s.bestE1rm,
    vol: s.volume,
  }));

  const pr = getPersonalRecord(exId);
  const totalSessions = sessions.length;
  const firstE = sessions[0]?.e1rm || 0;
  const lastE = sessions[sessions.length-1]?.e1rm || 0;
  const gain = firstE > 0 ? +(lastE - firstE).toFixed(1) : 0;

  document.getElementById('exp-stats').innerHTML = `
    <div class="ex-prog-stat"><div class="ex-prog-stat-num" style="font-size:${(pr&&(+pr.weight||0)===0)?'20px':''}">${pr ? formatPR(pr) : '—'}</div><div class="ex-prog-stat-lbl">🏆 PR</div></div>
    <div class="ex-prog-stat"><div class="ex-prog-stat-num">${totalSessions}</div><div class="ex-prog-stat-lbl">📅 Seans</div></div>
    <div class="ex-prog-stat"><div class="ex-prog-stat-num">${gain>0?'+':''}${gain}kg</div><div class="ex-prog-stat-lbl">📈 Güç kazanımı</div></div>
  `;

  if (sessions.length < 2) {
    document.getElementById('exp-history').innerHTML = '<div style="color:var(--text3);font-size:13px;padding:8px 0">Grafik için en az 2 seans gerekli.</div>';
    document.querySelector('.ex-prog-canvas').style.display = 'none';
  } else {
    document.querySelector('.ex-prog-canvas').style.display = 'block';
    // Recent session log
    const recentHTML = sessions.slice(-5).reverse().map(s => {
      const d = new Date(s.date);
      return `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
        <div style="font-size:13px;color:var(--text2)">${d.getDate()}/${d.getMonth()+1}/${d.getFullYear()}</div>
        <div style="font-size:14px;font-weight:600">${s.weight>0?`${s.weight}kg × ${s.reps}rep`:`${s.reps} tekrar`}</div>
        <div style="font-size:12px;color:var(--text3)">${s.vol}kg vol</div>
      </div>`;
    }).join('');
    document.getElementById('exp-history').innerHTML = `<div style="font-size:11px;font-weight:700;letter-spacing:1px;color:var(--text2);text-transform:uppercase;margin-bottom:8px">Son Seanslar</div>${recentHTML}`;
    setTimeout(() => drawExerciseProgressChart(sessions), 60);
  }

  openModal('modal-ex-progress');
}

function drawExerciseProgressChart(sessions) {
  const canvas = document.getElementById('exp-canvas'); if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width) return;
  canvas.width = rect.width * dpr; canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);
  const W = rect.width, H = rect.height;
  const data = sessions.map(s => s.e1rm ?? s.weight);
  const labels = sessions.map(s => { const d = new Date(s.date); return (d.getDate()+'/'+(d.getMonth()+1)); });
  chartLabel(canvas, 'Tahmini güç grafiği, seans başına: ' + data.slice(-10).map((v, i, a) => labels[labels.length - a.length + i] + ' ' + v + ' kg').join(', '));
  const max = Math.max(...data); const min = Math.min(...data);
  const range = max - min || 1;
  const pad = {top:16, right:16, bottom:32, left:44};
  const cW = W - pad.left - pad.right, cH = H - pad.top - pad.bottom;
  const step = data.length > 1 ? cW / (data.length - 1) : cW;

  // Grid
  const gridColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim();
  const text2Color = getComputedStyle(document.documentElement).getPropertyValue('--text2').trim();
  ctx.strokeStyle = gridColor; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + cH * (1 - i/4);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left+cW, y); ctx.stroke();
    ctx.fillStyle = text2Color; ctx.font = '10px DM Sans'; ctx.textAlign = 'right';
    ctx.fillText((min + range*i/4).toFixed(1)+'kg', pad.left-4, y+4);
  }

  const pts = data.map((v, i) => ({ x: pad.left + i * step, y: pad.top + cH * (1 - (v - min) / range) }));

  // Area
  ctx.beginPath();
  pts.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
  ctx.lineTo(pts[pts.length-1].x, pad.top+cH); ctx.lineTo(pts[0].x, pad.top+cH); ctx.closePath();
  const g = ctx.createLinearGradient(0, pad.top, 0, pad.top+cH);
  g.addColorStop(0, 'rgba(240,90,34,0.35)'); g.addColorStop(1, 'rgba(240,90,34,0.02)');
  ctx.fillStyle = g; ctx.fill();

  // Line
  ctx.beginPath();
  pts.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
  ctx.strokeStyle = '#f05a22'; ctx.lineWidth = 2.5; ctx.lineJoin = 'round'; ctx.stroke();

  // Dots + labels
  const showLabels = data.length <= 10;
  pts.forEach((p, i) => {
    ctx.beginPath(); ctx.arc(p.x, p.y, 4, 0, Math.PI*2);
    ctx.fillStyle = '#f05a22'; ctx.fill();
    ctx.fillStyle = text2Color; ctx.font = '9px DM Sans'; ctx.textAlign = 'center';
    ctx.fillText(labels[i], p.x, H - pad.bottom + 16);
    if (showLabels) { ctx.fillText(data[i]+'kg', p.x, p.y - 7); }
  });
}

// ============================================================
// FEATURE 3: Heatmap
// ============================================================
function renderHeatmap(el) {
  const WEEKS = 14; // ~3.5 months, fits well on mobile
  const DAYS = 7;
  const today = new Date(); today.setHours(0,0,0,0);

  // Build set of workout dates
  const workoutDates = new Set();
  ST.workoutLogs.forEach(l => {
    const d = new Date(l.date); d.setHours(0,0,0,0);
    workoutDates.add(d.getTime());
  });

  // Calculate stats
  const streak = calcStreak();
  const totalDays = workoutDates.size;

  // Find start Monday
  const startDate = new Date(today);
  const dow = today.getDay() === 0 ? 6 : today.getDay() - 1; // Monday = 0
  startDate.setDate(startDate.getDate() - dow - (WEEKS-1)*7);

  el.innerHTML = `
    <div class="heatmap-wrap">
      <div class="heatmap-title">📅 ${T('heatmap_title')}</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px">
        <div class="ex-prog-stat"><div class="ex-prog-stat-num">${streak}</div><div class="ex-prog-stat-lbl">🔥 ${T('streak_label')}</div></div>
        <div class="ex-prog-stat"><div class="ex-prog-stat-num">${totalDays}</div><div class="ex-prog-stat-lbl">📅 ${T('workout_days')}</div></div>
        <div class="ex-prog-stat"><div class="ex-prog-stat-num">${ST.workoutLogs.length}</div><div class="ex-prog-stat-lbl">🏋️ ${T('total_sessions')}</div></div>
      </div>
      <canvas id="heatmap-canvas" style="display:block;width:100%"></canvas>
      <div class="heatmap-legend">
        <span>${T('heatmap_less')}</span>
        <div class="heatmap-legend-cell" style="background:var(--surface3)"></div>
        <div class="heatmap-legend-cell" style="background:rgba(240,90,34,0.3)"></div>
        <div class="heatmap-legend-cell" style="background:rgba(240,90,34,0.6)"></div>
        <div class="heatmap-legend-cell" style="background:#f05a22"></div>
        <span>${T('heatmap_more')}</span>
      </div>
    </div>
  `;

  setTimeout(() => drawHeatmap(startDate, today, workoutDates, WEEKS, DAYS), 50);
}

function drawHeatmap(startDate, today, workoutDates, WEEKS, DAYS) {
  const canvas = document.getElementById('heatmap-canvas'); if (!canvas) return;
  chartLabel(canvas, 'Son ' + WEEKS + ' haftanın antrenman takvimi: ' + [...workoutDates].filter(ts => ts >= startDate.getTime()).length + ' gün antrenman yapıldı');
  const dpr = window.devicePixelRatio || 1;
  // Fit exactly to container — subtract heatmap-wrap padding (16px each side)
  const wrapW = canvas.parentElement.clientWidth || 320;
  const containerW = Math.max(200, wrapW); // already inside padded wrap
  const padLeft = 22, padTop = 20;
  const gap = 2;
  const cellSize = Math.max(8, Math.floor((containerW - padLeft - gap * (WEEKS - 1)) / WEEKS));
  const totalW = containerW; // always exact container width
  const totalH = padTop + DAYS * (cellSize + gap) + 6;

  canvas.style.width = '100%';
  canvas.style.height = totalH + 'px';
  canvas.width = Math.round(containerW * dpr);
  canvas.height = Math.round(totalH * dpr);
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);

  const bgColor = getComputedStyle(document.documentElement).getPropertyValue('--surface3').trim() || '#242430';
  const text3 = getComputedStyle(document.documentElement).getPropertyValue('--text3').trim() || '#4a4a62';
  const text2 = getComputedStyle(document.documentElement).getPropertyValue('--text2').trim() || '#8888a0';

  const dayLabels = ['M','','W','','F','','S'];

  // Day labels
  dayLabels.forEach((lbl, i) => {
    if (!lbl) return;
    ctx.fillStyle = text3; ctx.font = `bold 9px DM Sans`; ctx.textAlign = 'right';
    ctx.fillText(lbl, padLeft - 3, padTop + i*(cellSize+gap) + cellSize - 2);
  });

  // Count workouts per day (for intensity)
  const counts = {};
  ST.workoutLogs.forEach(l => {
    const d = new Date(l.date); d.setHours(0,0,0,0);
    const key = d.getTime();
    counts[key] = (counts[key] || 0) + 1;
  });

  let prevMonth = -1;
  for (let w = 0; w < WEEKS; w++) {
    for (let d = 0; d < DAYS; d++) {
      const cellDate = new Date(startDate);
      cellDate.setDate(startDate.getDate() + w*7 + d);
      cellDate.setHours(0,0,0,0);
      const ts = cellDate.getTime();
      const isFuture = cellDate > today;
      const isToday = ts === today.getTime();
      const cnt = counts[ts] || 0;

      let color;
      if (isFuture) { color = 'rgba(0,0,0,0)'; }
      else if (cnt === 0) { color = bgColor; }
      else if (cnt === 1) { color = 'rgba(240,90,34,0.45)'; }
      else if (cnt === 2) { color = 'rgba(240,90,34,0.7)'; }
      else { color = '#f05a22'; }

      const availW = containerW - padLeft;
      const step = availW / WEEKS;
      const x = padLeft + w * step;
      const drawCell = step - gap;
      const y = padTop + d * (drawCell + gap);
      const r = 3;

      ctx.beginPath();
      ctx.roundRect ? ctx.roundRect(x, y, drawCell, drawCell, r) : (ctx.rect(x, y, drawCell, drawCell));
      ctx.fillStyle = color;
      ctx.fill();

      if (isToday) {
        ctx.strokeStyle = '#f05a22'; ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.roundRect ? ctx.roundRect(x, y, drawCell, drawCell, r) : ctx.rect(x, y, drawCell, drawCell);
        ctx.stroke();
      }

      // Month label: show once per month, only on first week day of that month
      if (d === 0 && cellDate.getMonth() !== prevMonth) {
        prevMonth = cellDate.getMonth();
        const mTR = ['Oca','Şub','Mar','Nis','May','Haz','Tem','Ağu','Eyl','Eki','Kas','Ara'];
        const mNames = mTR;
        ctx.fillStyle = text2; ctx.font = `bold 9px DM Sans`; ctx.textAlign = 'left';
        ctx.fillText(mNames[cellDate.getMonth()], Math.round(x), padTop - 5);
      }
    }
  }
}
