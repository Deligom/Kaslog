// ============================================================
// İSTATİSTİK
// ============================================================
let statsTab='gecmis';
function renderIstatistik(){
  const el=document.getElementById('istatistik-content');
  el.innerHTML=`<div class="sticky-tabs"><div class="sticky-tab ${statsTab==='gecmis'?'active':''}" onclick="setStatsTab('gecmis')">${T('history')}</div><div class="sticky-tab ${statsTab==='pr'?'active':''}" onclick="setStatsTab('pr')">${T('prs')}</div><div class="sticky-tab ${statsTab==='olcum'?'active':''}" onclick="setStatsTab('olcum')">${T('body')}</div><div class="sticky-tab ${statsTab==='hacim'?'active':''}" onclick="setStatsTab('hacim')">${T('vol_tab')}</div><div class="sticky-tab ${statsTab==='takvim'?'active':''}" onclick="setStatsTab('takvim')">📅 ${T('tab_calendar')}</div><div class="sticky-tab ${statsTab==='beslenme_stats'?'active':''}" onclick="setStatsTab('beslenme_stats')">🍽️ Beslenme</div></div><div id="stats-inner"></div>`;
  renderStatsInner();
}
function setStatsTab(t){statsTab=t;document.querySelectorAll('.sticky-tab').forEach((s,i)=>s.classList.toggle('active',['gecmis','pr','olcum','hacim','takvim','beslenme_stats'][i]===t));renderStatsInner();}
function renderStatsInner(){
  const el=document.getElementById('stats-inner'); if(!el)return;
  if(statsTab==='gecmis'){
    if(!ST.workoutLogs.length){el.innerHTML=`<div class="empty-state"><div class="empty-icon">📅</div><div class="empty-title">${T('no_workouts')}</div><div class="empty-sub">${T('no_workouts_sub')}</div></div>`;return;}
    const sorted=[...ST.workoutLogs].sort((a,b)=>new Date(b.date)-new Date(a.date));
    const MONTHS=['Oca','Şub','Mar','Nis','May','Haz','Tem','Ağu','Eyl','Eki','Kas','Ara'];
    el.innerHTML=`<div class="card" style="margin:0 20px 20px;overflow:hidden">`+sorted.map(log=>{const d=new Date(log.date);return`<div class="history-item" style="cursor:pointer" onclick="openHistoryDetail('${log.id}')"><div class="history-date-block"><div class="history-day">${d.getDate()}</div><div class="history-month">${MONTHS[d.getMonth()]}</div></div><div class="history-info"><div class="history-name">${translateDayNameH(log.dayName||'Workout')}</div><div class="history-meta">${log.duration}min · ${log.exercises?.filter(e=>!e.skipped).length||0} ${T('exercises_count')}</div></div><div style="text-align:right"><div class="history-day" style="font-size:18px">${log.totalVolume||0}</div><div style="font-size:10px;color:var(--text3)">kg</div><svg viewBox="0 0 24 24" style="width:14px;height:14px;stroke:var(--text3);fill:none;stroke-width:2;margin-top:6px"><polyline points="9 18 15 12 9 6"/></svg></div></div>`;}).join('')+`</div>`;
  }else if(statsTab==='pr'){
    // Sıralama e1RM'e göre: vücut ağırlığı rekorları da listeye girsin ve
    // 40kg×12, 45kg×8'in üstünde yer alabilsin.
    const _prScore=p=>p.pr.e1rm??e1RM(effectiveLoad(p.pr,p.ex),p.pr.reps);
    const prs=getAllExercises().map(ex=>({ex,pr:getPersonalRecord(ex.id)})).filter(p=>p.pr).sort((a,b)=>_prScore(b)-_prScore(a));
    if(!prs.length){el.innerHTML=`<div class="empty-state"><div class="empty-icon">🏆</div><div class="empty-title">${T('no_prs')}</div><div class="empty-sub">${T('no_prs_sub')}</div></div>`;return;}
    const medals=['🥇','🥈','🥉'];
    el.innerHTML=`<div class="pr-list" style="margin:0 20px 20px">`+prs.slice(0,30).map((p,i)=>{
      const dateStr=p.pr.date?new Date(p.pr.date).toLocaleDateString('tr-TR',{day:'numeric',month:'short',year:'numeric'}):'';
      return`<div class="pr-row" style="cursor:pointer" onclick="openExProgress('${p.ex.id}')"><div class="pr-medal">${medals[i]||'🏅'}</div><div style="flex:1"><div class="pr-ex-name">${esc(p.ex.name)}</div><div style="font-size:12px;color:var(--text2)">${esc(p.ex.muscle)}</div>${dateStr?`<div style="font-size:11px;color:var(--text3);margin-top:2px">📅 ${T('pr_date_label')}: ${dateStr}</div>`:''}</div><div style="text-align:right"><div class="pr-value">${(+p.pr.weight||0)>0?p.pr.weight+'kg':p.pr.reps}</div><div class="pr-date">${(+p.pr.weight||0)>0?'× '+p.pr.reps+(p.ex.type==='time'?'s':'rep'):'tekrar · vücut ağırlığı'}</div><div style="font-size:11px;color:var(--accent-text);margin-top:4px">📈 Graf</div></div></div>`;
    }).join('')+`</div>`;
  }else if(statsTab==='olcum'){
    renderMeasurements(el);
  }else if(statsTab==='hacim'){
    renderVolumeChart(el);
  }else if(statsTab==='takvim'){
    renderHeatmap(el);
  }else if(statsTab==='beslenme_stats'){
    renderBeslenmeStats(el);
  }
}
function renderMeasurements(el){
  const sorted=[...ST.measurements].sort((a,b)=>new Date(a.date)-new Date(b.date));
  const latest=sorted[sorted.length-1];
  const oldest=sorted[0];
  const fields=[
    {id:'weight',lk:'weight_field',unit:'kg',icon:'⚖️',good:'down'},
    {id:'height',lk:'height_field',unit:'cm',icon:'📏',good:'none'},
    {id:'bicep', lk:'bicep_field', unit:'cm',icon:'💪',good:'up'},
    {id:'chest', lk:'chest_field', unit:'cm',icon:'🫁',good:'up'},
    {id:'waist', lk:'waist_field', unit:'cm',icon:'〰️',good:'down'},
    {id:'shoulder',lk:'shoulder_field',unit:'cm',icon:'🏋️',good:'up'},
    {id:'hip',   lk:'hip_field',   unit:'cm',icon:'🍑',good:'none'},
    {id:'thigh', lk:'thigh_field', unit:'cm',icon:'🦵',good:'up'},
  ];

  // Header summary card
  let summaryHTML='';
  if(latest){
    const daysDiff = oldest && oldest.id!==latest.id ? Math.round((new Date(latest.date)-new Date(oldest.date))/(1000*60*60*24)) : 0;
    const monthsDiff = daysDiff/30.4;
    summaryHTML=`
    <div style="margin:0 20px 16px;background:linear-gradient(135deg,var(--accent) 0%,#c43a10 100%);border-radius:var(--radius);padding:18px 20px;position:relative;overflow:hidden">
      <div style="position:absolute;top:-16px;right:-16px;width:80px;height:80px;border-radius:50%;background:rgba(255,255,255,0.08)"></div>
      <div style="font-size:11px;font-weight:700;letter-spacing:1.5px;color:rgba(255,255,255,0.7);text-transform:uppercase;margin-bottom:4px">${T('body_measurements')}</div>
      <div style="font-size:13px;color:rgba(255,255,255,0.85)">
        ${sorted.length} ${T('measure_entries')} · ${daysDiff>0?Math.round(daysDiff)+' '+T('days_tracked'):''}
      </div>
      <button onclick="openMeasurementModal()" style="margin-top:12px;background:rgba(255,255,255,0.2);color:#fff;border-radius:10px;padding:8px 16px;font-size:13px;font-weight:600;border:none;cursor:pointer">+ ${T('add_measure_btn')}</button>
    </div>`;
  } else {
    summaryHTML=`
    <div style="margin:0 20px 16px">
      <button class="btn btn-primary btn-full" onclick="openMeasurementModal()">+ ${T('add_measure_btn')}</button>
    </div>`;
  }

  if(!latest){
    el.innerHTML=summaryHTML+`<div class="empty-state"><div class="empty-icon">📏</div><div class="empty-title">${T('no_measure_title')}</div><div class="empty-sub">${T('no_measure_sub')}</div></div>`;
    return;
  }

  // Each field card with mini sparkline + change indicator
  const fieldCards=fields.map(f=>{
    const pts=sorted.filter(m=>m[f.id]!=null).map(m=>({v:m[f.id],date:m.date}));
    if(!pts.length) return '';
    const cur=pts[pts.length-1].v;
    const first=pts[0].v;
    const prev=pts.length>1?pts[pts.length-2].v:null;
    const delta=prev!==null?(cur-prev):null;
    const totalDelta=pts.length>1?(cur-first):null;
    const daySpan=pts.length>1?Math.round((new Date(pts[pts.length-1].date)-new Date(pts[0].date))/(86400000)):0;
    const monthRate=daySpan>5&&totalDelta!==null?(totalDelta/(daySpan/30.4)):null;

    // Change badge
    let changeHTML='';
    if(delta!==null){
      const sign=delta>0?'+':'';
      const isGood=(f.good==='up'&&delta>=0)||(f.good==='down'&&delta<=0)||(f.good==='none');
      const isNeutral=delta===0||f.good==='none';
      const color=isNeutral?'var(--text3)':isGood?'var(--success)':'var(--danger)';
      const arrow=delta>0?'↑':delta<0?'↓':'→';
      changeHTML=`<span style="font-size:13px;font-weight:700;color:${color}">${arrow} ${sign}${Math.abs(delta).toFixed(1)}</span>`;
    }

    // Monthly rate badge
    let rateHTML='';
    if(monthRate!==null&&Math.abs(monthRate)>0.01){
      const sign=monthRate>0?'+':'';
      const isGood=(f.good==='up'&&monthRate>=0)||(f.good==='down'&&monthRate<=0)||(f.good==='none');
      const color=f.good==='none'?'var(--text3)':isGood?'var(--success)':'var(--warning)';
      rateHTML=`<div style="font-size:11px;color:${color};margin-top:3px">${sign}${monthRate.toFixed(2)} ${f.unit}/ay</div>`;

      // Warning if rate is suspiciously low for muscle metrics
      if(f.id==='bicep'&&monthRate<0.1&&monthRate>0&&daySpan>60){
        rateHTML+=`<div style="font-size:11px;color:var(--warning);margin-top:2px">⚠️ ${T('slow_progress')}</div>`;
      }
    }

    // Mini sparkline canvas id
    const cid='spark_'+f.id;

    return `<div style="background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px 16px;margin-bottom:10px">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px">
        <div>
          <div style="font-size:11px;font-weight:700;letter-spacing:0.8px;color:var(--text2);text-transform:uppercase;margin-bottom:4px">${f.icon} ${T(f.lk)}</div>
          <div style="display:flex;align-items:baseline;gap:6px">
            <span style="font-family:'Barlow Condensed',sans-serif;font-size:36px;font-weight:800;line-height:1;color:var(--text)">${cur}</span>
            <span style="font-size:13px;color:var(--text2)">${f.unit}</span>
          </div>
          ${rateHTML}
        </div>
        <div style="text-align:right">
          ${changeHTML}
          ${pts.length>1?`<div style="font-size:11px;color:var(--text3);margin-top:4px">${pts.length} ölçüm</div>`:''}
          ${totalDelta!==null&&pts.length>2?`<div style="font-size:11px;color:var(--text2);margin-top:2px">Toplam: ${totalDelta>0?'+':''}${totalDelta.toFixed(1)}${f.unit}</div>`:''}
        </div>
      </div>
      ${pts.length>1?`<canvas id="${cid}" style="width:100%;height:52px;display:block"></canvas>`:'<div style="font-size:12px;color:var(--text3)">İkinci ölçüm eklenince grafik görünecek.</div>'}
    </div>`;
  }).join('');

  // Measurement history list
  const histRows = [...ST.measurements]
    .sort((a,b)=>new Date(b.date)-new Date(a.date))
    .map(m => {
      const d = new Date(m.date);
      const dateStr = d.toLocaleDateString('tr-TR',{day:'numeric',month:'short',year:'numeric'});
      const vals = ['weight','height','bicep','chest','waist','shoulder','hip','thigh']
        .filter(f=>m[f]!=null).map(f=>`${f}:${m[f]}`).join(' · ');
      return `<div style="display:flex;align-items:center;gap:8px;padding:10px 0;border-bottom:1px solid var(--border)">
        <div style="flex:1">
          <div style="font-size:13px;font-weight:600">${dateStr}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">${vals}</div>
        </div>
        <button onclick="editMeasurement('${m.id}')" style="font-size:12px;font-weight:600;color:var(--accent-text);padding:4px 10px;border-radius:8px;background:var(--accent-dim);border:none;cursor:pointer">${T('edit_entry')}</button>
        <button onclick="deleteMeasurement('${m.id}')" style="font-size:12px;font-weight:600;color:var(--danger);padding:4px 10px;border-radius:8px;background:rgba(239,68,68,0.1);border:none;cursor:pointer">${T('delete_entry')}</button>
      </div>`;
    }).join('');
  const histHTML = ST.measurements.length ? `<div style="padding:0 20px 20px"><div class="section-title" style="margin-bottom:12px">${T('measure_history')}</div>${histRows}</div>` : '';
  el.innerHTML=summaryHTML+`<div style="padding:0 20px 20px">${fieldCards}</div>`+histHTML;

  // Draw sparklines after render
  setTimeout(()=>{
    fields.forEach(f=>{
      const pts=sorted.filter(m=>m[f.id]!=null).map(m=>m[f.id]);
      if(pts.length<2)return;
      const canvas=document.getElementById('spark_'+f.id);
      if(!canvas)return;
      drawSparkline(canvas,pts,f.good);
    });
  },60);
}

function drawSparkline(canvas,data,good){
  chartLabel(canvas,'Değişim: '+data[0]+' → '+data[data.length-1]+' ('+data.length+' ölçüm)');
  const dpr=window.devicePixelRatio||1;
  const rect=canvas.getBoundingClientRect();
  if(!rect.width)return;
  canvas.width=rect.width*dpr; canvas.height=rect.height*dpr;
  const ctx=canvas.getContext('2d'); ctx.scale(dpr,dpr);
  const W=rect.width, H=rect.height;
  const min=Math.min(...data), max=Math.max(...data);
  const range=max-min||1;
  const pad={top:6,bottom:6,left:4,right:4};
  const cW=W-pad.left-pad.right, cH=H-pad.top-pad.bottom;
  const step=cW/(data.length-1);

  const pts=data.map((v,i)=>({x:pad.left+i*step, y:pad.top+cH*(1-(v-min)/range)}));

  // Area fill
  const last=pts[pts.length-1], first2=pts[0];
  const trend=last.y<first2.y; // going up visually = value increased
  const isGoodTrend=(good==='up'&&trend)||(good==='down'&&!trend)||(good==='none');
  const color=good==='none'?'#6366f1':isGoodTrend?'#22c55e':'#ef4444';

  ctx.beginPath();
  pts.forEach((p,i)=>i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y));
  ctx.lineTo(pts[pts.length-1].x,H); ctx.lineTo(pts[0].x,H); ctx.closePath();
  const g=ctx.createLinearGradient(0,0,0,H);
  g.addColorStop(0,color+'44'); g.addColorStop(1,color+'08');
  ctx.fillStyle=g; ctx.fill();

  // Line
  ctx.beginPath();
  pts.forEach((p,i)=>i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y));
  ctx.strokeStyle=color; ctx.lineWidth=2; ctx.lineJoin='round'; ctx.stroke();

  // Dots
  pts.forEach(p=>{
    ctx.beginPath(); ctx.arc(p.x,p.y,3,0,Math.PI*2);
    ctx.fillStyle=color; ctx.fill();
  });

  // Value labels on first and last
  ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text2').trim()||'#888';
  ctx.font=`bold ${10*dpr/dpr}px DM Sans`; ctx.textAlign='left';
  ctx.fillText(data[0],pts[0].x,H-1);
  ctx.textAlign='right';
  ctx.fillText(data[data.length-1],pts[pts.length-1].x,H-1);
}
let _volFilter='30d';
function renderVolumeChart(el){
  const allLogs=[...ST.workoutLogs].sort((a,b)=>new Date(a.date)-new Date(b.date));
  if(allLogs.length<2){el.innerHTML=`<div class="empty-state"><div class="empty-icon">📈</div><div class="empty-title">${T('not_enough')}</div><div class="empty-sub">${T('not_enough_sub')}</div></div>`;return;}
  const filters=[{k:'10s',label:'Son 10'},{k:'30d',label:'30 gün'},{k:'90d',label:'3 ay'},{k:'all',label:'Tümü'}];
  const filterHTML=filters.map(f=>`<button onclick="setVolFilter('${f.k}')" id="vf-${f.k}" style="padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600;border:1.5px solid ${_volFilter===f.k?'var(--accent)':'var(--border)'};background:${_volFilter===f.k?'var(--accent-dim)':'var(--surface2)'};color:${_volFilter===f.k?'var(--accent)':'var(--text2)'};cursor:pointer">${f.label}</button>`).join('');
  el.innerHTML=`<div style="padding:16px 20px 8px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px"><div class="chart-title" style="font-family:'Barlow Condensed',sans-serif;font-size:16px;font-weight:700">${T('session_vol')}</div></div><div style="display:flex;gap:6px;flex-wrap:wrap">${filterHTML}</div></div><div class="chart-card" style="margin:0 20px"><div class="chart-canvas-wrap"><canvas id="volume-chart"></canvas></div></div>`;
  const logs=_filterLogs(allLogs,_volFilter);
  setTimeout(()=>drawVolumeChart(logs),50);
}
function setVolFilter(k){_volFilter=k;renderVolumeChart(document.getElementById('stats-inner'));}
function _filterLogs(logs,filter){
  if(filter==='all')return logs;
  if(filter==='10s')return logs.slice(-10);
  const days=filter==='30d'?30:90;
  const cutoff=new Date(); cutoff.setDate(cutoff.getDate()-days);
  return logs.filter(l=>new Date(l.date)>=cutoff);
}
function drawVolumeChart(logs){
  const canvas=document.getElementById('volume-chart'); if(!canvas)return;
  const ctx=canvas.getContext('2d'); const dpr=window.devicePixelRatio||1;
  const rect=canvas.getBoundingClientRect(); canvas.width=rect.width*dpr; canvas.height=rect.height*dpr; ctx.scale(dpr,dpr);
  const W=rect.width,H=rect.height;
  const data=logs.slice(-10).map(l=>l.totalVolume||0);
  const labels=logs.slice(-10).map(l=>{const d=new Date(l.date);return(d.getDate()+'/'+(d.getMonth()+1));});
  chartLabel(canvas,'Seans hacmi grafiği (kg): '+data.map((v,i)=>labels[i]+' '+v).join(', '));
  const max=Math.max(...data,1); const pad={top:20,right:16,bottom:30,left:44};
  const cW=W-pad.left-pad.right,cH=H-pad.top-pad.bottom; const step=cW/(data.length-1||1);
  ctx.strokeStyle=getComputedStyle(document.documentElement).getPropertyValue('--border').trim(); ctx.lineWidth=1;
  for(let i=0;i<=4;i++){const y=pad.top+cH*(1-i/4);ctx.beginPath();ctx.moveTo(pad.left,y);ctx.lineTo(pad.left+cW,y);ctx.stroke();ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text2').trim();ctx.font='10px DM Sans';ctx.textAlign='right';ctx.fillText(Math.round(max*i/4)+'kg',pad.left-4,y+4);}
  ctx.beginPath(); data.forEach((v,i)=>{const x=pad.left+i*step,y=pad.top+cH*(1-v/max);if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);}); ctx.lineTo(pad.left+(data.length-1)*step,pad.top+cH); ctx.lineTo(pad.left,pad.top+cH); ctx.closePath();
  const g=ctx.createLinearGradient(0,pad.top,0,pad.top+cH); g.addColorStop(0,'rgba(240,90,34,0.3)'); g.addColorStop(1,'rgba(240,90,34,0)'); ctx.fillStyle=g; ctx.fill();
  ctx.beginPath(); data.forEach((v,i)=>{const x=pad.left+i*step,y=pad.top+cH*(1-v/max);if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);}); ctx.strokeStyle='#f05a22'; ctx.lineWidth=2.5; ctx.stroke();
  data.forEach((v,i)=>{const x=pad.left+i*step,y=pad.top+cH*(1-v/max);ctx.beginPath();ctx.arc(x,y,4,0,Math.PI*2);ctx.fillStyle='#f05a22';ctx.fill();ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text2').trim();ctx.font='9px DM Sans';ctx.textAlign='center';ctx.fillText(labels[i],x,H-pad.bottom+18);});
}
function openMeasurementModal(){_editMeasureId=null;
  const fields=[
    {id:'weight',lk:'weight_field',unit:'kg',ph:'70.5'},
    {id:'height',lk:'height_field',unit:'cm',ph:'175'},
    {id:'bicep', lk:'bicep_field', unit:'cm',ph:'35'},
    {id:'chest', lk:'chest_field', unit:'cm',ph:'95'},
    {id:'waist', lk:'waist_field', unit:'cm',ph:'80'},
    {id:'shoulder',lk:'shoulder_field',unit:'cm',ph:'48'},
    {id:'hip',   lk:'hip_field',   unit:'cm',ph:'95'},
    {id:'thigh', lk:'thigh_field', unit:'cm',ph:'55'},
  ];
  const today=new Date().toLocaleDateString('tr-TR',{day:'numeric',month:'long',year:'numeric'});
  // Get last entry for reference hints
  const sorted=[...ST.measurements].sort((a,b)=>new Date(a.date)-new Date(b.date));
  const prev=sorted[sorted.length-1];
  document.getElementById('measurements-content').innerHTML=`
    <div style="background:var(--surface2);border-radius:10px;padding:10px 14px;margin-bottom:16px;font-size:13px;color:var(--text2)">
      📅 ${today}
    </div>
    <div class="form-row">${fields.map(f=>{
      const prevVal=prev?.[f.id];
      return `<div class="form-group">
        <label class="form-label">${T(f.lk)} (${f.unit})</label>
        <input class="form-input" id="m-${f.id}" type="number" step="0.1" placeholder="${f.ph}" inputmode="decimal">
        ${prevVal?`<div style="font-size:11px;color:var(--text3);margin-top:3px">${T('prev_val')}: ${prevVal}${f.unit}</div>`:''}
      </div>`;
    }).join('')}</div>
    <div style="font-size:12px;color:var(--text2);margin-bottom:12px;line-height:1.5">
      💡 ${T('measure_hint')}
    </div>
    <button class="btn btn-primary btn-full" onclick="saveMeasurement()">${T('save')}</button>
  `;
  openModal('modal-measurements');
}
let _editMeasureId = null;
async function saveMeasurement(){
  const fields=['weight','height','chest','waist','bicep','hip','thigh','shoulder'];
  if(_editMeasureId){
    // Edit existing
    const idx=ST.measurements.findIndex(m=>m.id===_editMeasureId);
    if(idx>-1){
      const m=ST.measurements[idx];
      fields.forEach(f=>{const el=document.getElementById('m-'+f);const v=parseFloat(el?.value);if(el?.value!=='')m[f]=v||undefined;});
      // clean undefined
      fields.forEach(f=>{if(m[f]==null)delete m[f];});
      await DB.put('measurements',m);
    }
    _editMeasureId=null;
  } else {
    const m={id:'m_'+Date.now(),date:new Date().toISOString()};
    fields.forEach(f=>{const v=parseFloat(document.getElementById('m-'+f)?.value);if(v)m[f]=v;});
    await DB.put('measurements',m); ST.measurements.push(m);
  }
  closeModal('modal-measurements'); renderStatsInner();
}
function editMeasurement(id){
  const m=ST.measurements.find(x=>x.id===id); if(!m)return;
  _editMeasureId=id;
  const fields=[
    {id:'weight',lk:'weight_field',unit:'kg',ph:'70.5'},
    {id:'height',lk:'height_field',unit:'cm',ph:'175'},
    {id:'bicep', lk:'bicep_field', unit:'cm',ph:'35'},
    {id:'chest', lk:'chest_field', unit:'cm',ph:'95'},
    {id:'waist', lk:'waist_field', unit:'cm',ph:'80'},
    {id:'shoulder',lk:'shoulder_field',unit:'cm',ph:'48'},
    {id:'hip',   lk:'hip_field',   unit:'cm',ph:'95'},
    {id:'thigh', lk:'thigh_field', unit:'cm',ph:'55'},
  ];
  const d=new Date(m.date);
  const dateStr=d.toLocaleDateString('tr-TR',{day:'numeric',month:'long',year:'numeric'});
  document.getElementById('measurements-content').innerHTML=`
    <div style="background:var(--surface2);border-radius:10px;padding:10px 14px;margin-bottom:16px;font-size:13px;color:var(--text2)">
      📅 ${dateStr}
    </div>
    <div class="form-row">${fields.map(f=>`<div class="form-group">
      <label class="form-label">${T(f.lk)} (${f.unit})</label>
      <input class="form-input" id="m-${f.id}" type="number" step="0.1" placeholder="${f.ph}" inputmode="decimal" value="${m[f.id]!=null?m[f.id]:''}">
    </div>`).join('')}</div>
    <button class="btn btn-primary btn-full" onclick="saveMeasurement()">${T('save')}</button>
  `;
  openModal('modal-measurements');
}
async function deleteMeasurement(id){
  showConfirm('🗑️',T('delete_entry'),T('confirm_delete_measure'),async()=>{
    await DB.del('measurements',id);
    ST.measurements=ST.measurements.filter(m=>m.id!==id);
    closeModal('modal-alert'); renderStatsInner();
  });
}
