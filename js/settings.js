// ============================================================
// AYARLAR
// ============================================================
function renderAyarlar(){
  const s=ST.settings;
  const lvlMap={beginner:T('level_beginner'),intermediate:T('level_intermediate'),advanced:T('level_advanced'),expert:T('level_expert')};
  const goalMap={strength:T('goal_strength'),hypertrophy:T('goal_hypertrophy'),both:T('goal_both')};
  const isDark=document.documentElement.getAttribute('data-theme')==='dark';
  const cycleInfo=getCycleInfo();
  document.getElementById('ayarlar-content').innerHTML=`
    <div class="page-pad" style="padding-bottom:12px;padding-top:20px"><div class="section-title">${T('profile')}</div></div>
    <div class="settings-section"><div class="settings-block">
      <div class="settings-row" onclick="editSetting('name')"><div class="settings-row-left"><div class="settings-icon si-orange">👤</div><div><div class="settings-row-title">${T('name_label')}</div></div></div><div class="settings-row-value">${esc(s.name||'—')}<svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div></div>
      <div class="settings-row" onclick="editSetting('level')"><div class="settings-row-left"><div class="settings-icon si-blue">⚡</div><div><div class="settings-row-title">${T('level_label')}</div></div></div><div class="settings-row-value">${esc(lvlMap[s.level]||s.level)}<svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div></div>
      <div class="settings-row" onclick="editSetting('goal')"><div class="settings-row-left"><div class="settings-icon si-green">🎯</div><div><div class="settings-row-title">${T('goal_label')}</div></div></div><div class="settings-row-value">${esc(goalMap[s.goal]||s.goal)}<svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div></div>
    </div></div>
    <div class="page-pad" style="padding-bottom:12px;padding-top:4px"><div class="section-title">${T('workout_sec')}</div></div>
    <div class="settings-section"><div class="settings-block">
      <div class="settings-row" onclick="editSetting('rest')"><div class="settings-row-left"><div class="settings-icon si-orange">⏱</div><div><div class="settings-row-title">${T('rest_label')}</div><div class="settings-row-sub">${T('rest_sub')}</div></div></div><div class="settings-row-value">${s.restTime}s<svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div></div>
    </div></div>
    <div class="page-pad" style="padding-bottom:12px;padding-top:4px"><div class="section-title">${T('cycle_sec')}</div></div>
    <div class="settings-section"><div class="settings-block">
      <div class="settings-row" style="cursor:default">
        <div class="settings-row-left"><div class="settings-icon si-blue">🔄</div><div><div class="settings-row-title">${T('current_pos')}</div><div class="settings-row-sub">${cycleInfo}</div></div></div>
        <button onclick="resetCyclePos()" style="font-size:12px;font-weight:600;color:var(--accent-text);padding:6px 12px;border-radius:8px;background:var(--accent-dim)">${T('cycle_reset')}</button>
      </div>
    </div></div>
    <div class="page-pad" style="padding-bottom:12px;padding-top:4px"><div class="section-title">${T('appearance')}</div></div>
    <div class="settings-section"><div class="settings-block">
      <div class="settings-row">
        <div class="settings-row-left"><div class="settings-icon si-purple">${isDark?'🌙':'☀️'}</div><div><div class="settings-row-title">${T('dark_mode')}</div></div></div>
        <div class="toggle ${isDark?'on':''}" onclick="toggleTheme()"><div class="toggle-thumb"></div></div>
      </div>
      <div class="settings-row" style="flex-direction:column;align-items:stretch;gap:8px;cursor:default">
        <div class="settings-row-left"><div class="settings-icon si-green">⚖️</div><div><div class="settings-row-title">Vücut Ağırlığın</div><div class="settings-row-sub">${_bodyWeight() ? _bodyWeight()+' kg kullanılıyor' : 'Şınav/barfiks istatistikleri için gerekli'}</div></div></div>
        <div style="font-size:11px;padding:7px 10px;border-radius:8px;background:var(--surface2);border:1px solid var(--border);color:var(--text2);line-height:1.5">Şınav, barfiks, dips gibi hareketlerde kaldırdığın yük vücut ağırlığından gelir. Bunu bilmeden o hareketler hacme, rekora ve grafiğe giremez. Ölçüm eklediysen oradan otomatik alınır.</div>
        <input class="form-input" type="number" inputmode="decimal" step="0.1" min="0" placeholder="örn. 78" value="${+s.bodyWeight>0?s.bodyWeight:''}" style="font-size:13px;padding:10px 12px" onchange="saveBodyWeight(this.value)">
      </div>
    </div></div>
    <div class="page-pad" style="padding-bottom:12px;padding-top:4px"><div class="section-title">🍽️ BESLENME</div></div>
    <div class="settings-section"><div class="settings-block">
      <div class="settings-row" style="flex-direction:column;align-items:stretch;gap:8px;cursor:default">
        <div class="settings-row-left"><div class="settings-icon si-orange">🤖</div><div><div class="settings-row-title">Gemini API Key</div><div class="settings-row-sub">${s.geminiKey?.trim() ? 'Kendi key\'in kullanılıyor — sınır yok' : 'Opsiyonel — boş bırakırsan ortak kota kullanılır'}</div></div></div>
        ${s.geminiKey?.trim()
          ? `<div style="font-size:11px;padding:7px 10px;border-radius:8px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:var(--success)">🔑 Kendi key'in aktif — istekler doğrudan Google'a gidiyor, ortak kotadan düşmüyor</div>`
          : `<div style="font-size:11px;padding:7px 10px;border-radius:8px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:var(--success)">🔒 Ortak kota aktif — key girmeden AI analizi çalışıyor</div>
             <div style="font-size:11px;padding:7px 10px;border-radius:8px;background:var(--surface2);border:1px solid var(--border);color:var(--text2);line-height:1.5">Ortak kota herkesle paylaşılıyor; yoğun günlerde dolabilir veya yavaşlayabilir. Kendi <b>ücretsiz</b> key'ini girersen bu sınırlar sana işlemez.<br><a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer" style="color:var(--accent-text);font-weight:600">aistudio.google.com/apikey →</a></div>`}
        <!-- type="password" DEĞİL: Chrome sayfada parola alanı görünce bunu bir
             giriş formu sanıp "kaydedilen şifre kullanılsın mı?" panelini
             açıyordu. Maskelemeyi CSS yapıyor, davranış aynı kalıyor. -->
        <input class="form-input masked-input" id="gemini-key-input" type="text"
               autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"
               name="kaslog-ai-token" data-form-type="other" inputmode="text"
               placeholder="Kendi key'ini girmek istersen: AIza..." value="${esc(s.geminiKey||'')}"
               style="font-size:13px;padding:10px 12px;" onchange="saveGeminiKey(this.value)">
      </div>
      <div class="settings-row" style="flex-direction:column;align-items:stretch;gap:8px;cursor:default">
        <div class="settings-row-left"><div class="settings-icon si-blue">🧠</div><div><div class="settings-row-title">Gemini Model</div><div class="settings-row-sub">Besin analizi için kullanılır</div></div></div>
        <div style="display:flex;flex-direction:column;gap:6px">
          ${[
            {id:'gemini-3.1-pro-preview',label:'3.1 Pro Preview',desc:'En akıllı, yavaş'},
            {id:'gemini-3-flash-preview',label:'3 Flash Preview',desc:'Hızlı & güçlü ✓'},
            {id:'gemini-3.1-flash-lite-preview',label:'3.1 Flash Lite',desc:'En hızlı, ekonomik'}
          ].map(m=>`
            <div onclick="saveGeminiModel('${m.id}')" style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;border-radius:10px;border:1.5px solid ${(s.geminiModel||'gemini-3-flash-preview')===m.id?'var(--accent)':'var(--border)'};background:${(s.geminiModel||'gemini-3-flash-preview')===m.id?'var(--accent-dim)':'var(--surface2)'};cursor:pointer;transition:var(--transition)">
              <div>
                <div style="font-size:13px;font-weight:600;font-family:monospace;color:${(s.geminiModel||'gemini-3-flash-preview')===m.id?'var(--accent)':'var(--text)'}">${m.id}</div>
                <div style="font-size:11px;color:var(--text2);margin-top:2px">${m.desc}</div>
              </div>
              ${(s.geminiModel||'gemini-3-flash-preview')===m.id?'<span style="color:var(--accent-text);font-size:16px">✓</span>':''}
            </div>
          `).join('')}
        </div>
      </div>
      <div class="settings-row" style="cursor:default">
        <div class="settings-row-left"><div class="settings-icon si-blue">👤</div><div><div class="settings-row-title">Cinsiyet</div><div class="settings-row-sub">Kalori hesabı için</div></div></div>
        <div style="display:flex;gap:6px">
          <button onclick="saveGender('male')" style="padding:5px 14px;border-radius:20px;font-size:13px;font-weight:600;transition:var(--transition);background:${(s.gender||'male')==='male'?'var(--accent)':'var(--surface2)'};color:${(s.gender||'male')==='male'?'#fff':'var(--text2)'};border:1.5px solid ${(s.gender||'male')==='male'?'var(--accent)':'var(--border)'}">Erkek</button>
          <button onclick="saveGender('female')" style="padding:5px 14px;border-radius:20px;font-size:13px;font-weight:600;transition:var(--transition);background:${s.gender==='female'?'var(--accent)':'var(--surface2)'};color:${s.gender==='female'?'#fff':'var(--text2)'};border:1.5px solid ${s.gender==='female'?'var(--accent)':'var(--border)'}">Kadın</button>
        </div>
      </div>
      <div class="settings-row" onclick="editNutritionGoals()" style="cursor:pointer">
        <div class="settings-row-left"><div class="settings-icon si-green">🎯</div><div><div class="settings-row-title">Kalori Hedefi (Ant.)</div><div class="settings-row-sub">0 = otomatik hesapla</div></div></div>
        <div class="settings-row-value">${s.nutritionGoalKcal||'Otomatik'}<svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div>
      </div>
    </div></div>
    <div class="page-pad" style="padding-bottom:12px;padding-top:4px"><div class="section-title">🔔 SES & TİTREŞİM</div></div>
    <div class="settings-section"><div class="settings-block">
      <div class="settings-row">
        <div class="settings-row-left"><div class="settings-icon si-orange">🔊</div><div><div class="settings-row-title">Ses Efektleri</div><div class="settings-row-sub">Set, PR, dinlenme bildirimleri</div></div></div>
        <div class="toggle ${s.soundEnabled!==false?'on':''}" onclick="toggleSoundSetting()"><div class="toggle-thumb"></div></div>
      </div>
      <div class="settings-row">
        <div class="settings-row-left"><div class="settings-icon si-blue">📳</div><div><div class="settings-row-title">Titreşim (Haptic)</div><div class="settings-row-sub">Buton geri bildirimi</div></div></div>
        <div class="toggle ${s.hapticEnabled!==false?'on':''}" onclick="toggleHapticSetting()"><div class="toggle-thumb"></div></div>
      </div>
      <div class="settings-row" onclick="debugAudioHaptic()" style="cursor:pointer">
        <div class="settings-row-left"><div class="settings-icon si-green">🔬</div><div><div class="settings-row-title">Ses & Titreşim Testi</div><div class="settings-row-sub">Çalışıp çalışmadığını kontrol et</div></div></div>
        <div class="settings-row-value"><svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div>
      </div>
    </div></div>
    <div class="page-pad" style="padding-bottom:12px;padding-top:4px"><div class="section-title">${T('data_sec')}</div></div>
    <div class="settings-section"><div class="settings-block">
      <div class="settings-row" onclick="openExportModal()"><div class="settings-row-left"><div class="settings-icon si-green">📤</div><div><div class="settings-row-title">${T('export_data')}</div><div class="settings-row-sub">${T('export_desc')}</div></div></div><div class="settings-row-value"><svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div></div>
      <div class="settings-row" onclick="openImportModal()"><div class="settings-row-left"><div class="settings-icon si-blue">📥</div><div><div class="settings-row-title">${T('import_data')}</div><div class="settings-row-sub">${T('import_desc')}</div></div></div><div class="settings-row-value"><svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div></div>
      <div class="settings-row" onclick="openAILogModal()"><div class="settings-row-left"><div class="settings-icon si-orange">🤖</div><div><div class="settings-row-title">AI Antrenman Analizi</div><div class="settings-row-sub">Gelişim tablosu, öneriler, PR analizi</div></div></div><div class="settings-row-value"><svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div></div>
      <div class="settings-row" onclick="clearData()"><div class="settings-row-left"><div class="settings-icon si-red">🗑️</div><div><div class="settings-row-title" style="color:var(--danger)">${T('delete_data')}</div><div class="settings-row-sub">${T('delete_sub')}</div></div></div><div class="settings-row-value"><svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div></div>
    </div></div>
    <div style="text-align:center;padding:20px 20px 8px;color:var(--text3);font-size:12px">
      KASLOG v${APP_VERSION} · Home Workout Tracker<br>
      <span style="font-size:10.5px;opacity:0.75">build ${APP_BUILD}</span>
    </div>
    <div style="text-align:center;padding:0 20px 24px">
      <button onclick="openModal('modal-changelog')" style="background:none;border:none;color:var(--accent-text);font-size:12px;font-weight:600;cursor:pointer;padding:4px 8px">📋 Neler yeni?</button>
    </div>
  `;
}

function debugAudioHaptic() {
  const lines = [];

  // Vibration test
  const vibSupport = 'vibrate' in navigator;
  lines.push('📳 vibrate API: ' + (vibSupport ? 'VAR' : 'YOK'));
  if (vibSupport) {
    const result = navigator.vibrate(200);
    lines.push('📳 vibrate(200): ' + (result ? 'ÇALIŞTI ✓' : 'BAŞARISIZ ✗'));
  }

  // AudioContext test
  const acSupport = !!(window.AudioContext || window.webkitAudioContext);
  lines.push('🔊 AudioContext: ' + (acSupport ? 'VAR' : 'YOK'));
  if (acSupport) {
    try {
      const ac = new (window.AudioContext || window.webkitAudioContext)();
      lines.push('🔊 AC state: ' + ac.state);
      ac.resume().then(() => {
        lines.push('🔊 resume sonrası: ' + ac.state);
        // play a beep
        const osc = ac.createOscillator();
        const g = ac.createGain();
        osc.connect(g); g.connect(ac.destination);
        osc.type = 'sine'; osc.frequency.value = 880;
        g.gain.setValueAtTime(0.3, ac.currentTime);
        g.gain.exponentialRampToValueAtTime(0.001, ac.currentTime + 0.3);
        osc.start(); osc.stop(ac.currentTime + 0.3);
        showToast(lines.join(' | '));
      });
      return; // toast will show after resume
    } catch(e) {
      lines.push('🔊 HATA: ' + e.message);
    }
  }

  showToast(lines.join(' | '));
}

async function toggleSoundSetting() {
  ST.settings.soundEnabled = ST.settings.soundEnabled === false ? true : false;
  await DB.put('settings',{id:'main',...ST.settings});
  if (ST.settings.soundEnabled) SFX.setDone(); // açıldığında örnek ses çal
  renderAyarlar();
}
async function toggleHapticSetting() {
  ST.settings.hapticEnabled = ST.settings.hapticEnabled === false ? true : false;
  await DB.put('settings',{id:'main',...ST.settings});
  if (ST.settings.hapticEnabled) haptic('success'); // açıldığında örnek titreşim
  renderAyarlar();
}

async function saveGeminiKey(val) {
  ST.settings.geminiKey = val.trim();
  await DB.put('settings',{id:'main',...ST.settings});
}

async function saveBodyWeight(val) {
  const n = parseFloat(String(val).replace(',','.'));
  ST.settings.bodyWeight = Number.isFinite(n) && n > 0 ? n : 0;
  await DB.put('settings',{id:'main',...ST.settings});
  renderAyarlar();
}

async function saveGeminiModel(model) {
  ST.settings.geminiModel = model;
  await DB.put('settings',{id:'main',...ST.settings});
  renderAyarlar();
}

async function saveGender(g) {
  ST.settings.gender = g;
  await DB.put('settings',{id:'main',...ST.settings});
  renderAyarlar();
}

function editNutritionGoals() {
  const s = ST.settings;
  document.getElementById('se-title').textContent = 'Beslenme Hedefleri';
  document.getElementById('se-content').innerHTML = `
    <div class="form-group">
      <label class="form-label">Antrenman Günü Kalori (kcal)</label>
      <input class="form-input" id="se-kcal" type="number" placeholder="0 = otomatik" value="${s.nutritionGoalKcal||''}" inputmode="numeric">
    </div>
    <div class="form-group">
      <label class="form-label">Antrenman Günü Protein (g)</label>
      <input class="form-input" id="se-protein" type="number" placeholder="0 = otomatik" value="${s.nutritionGoalProtein||''}" inputmode="numeric">
    </div>
    <div style="font-size:12px;color:var(--text2);margin-bottom:16px;line-height:1.6">Dinlenme günü hedefleri otomatik olarak %85 kaloriye ve %90 proteine indirilir.<br>0 girilirse ağırlık × katsayı ile otomatik hesaplanır.</div>
    <button class="btn btn-primary btn-full" onclick="saveNutritionGoals()">Kaydet</button>
  `;
  openModal('modal-setting-edit');
}

async function saveNutritionGoals() {
  ST.settings.nutritionGoalKcal = parseInt(document.getElementById('se-kcal').value)||0;
  ST.settings.nutritionGoalProtein = parseInt(document.getElementById('se-protein').value)||0;
  await DB.put('settings',{id:'main',...ST.settings});
  closeModal('modal-setting-edit');
  renderAyarlar();
  showToast('Hedefler kaydedildi ✓');
}

// ============================================================
// HISTORY DETAIL
// ============================================================
function openHistoryDetail(logId){
  const log=ST.workoutLogs.find(l=>l.id===logId); if(!log)return;
  const d=new Date(log.date);
  const dateStr=d.toLocaleDateString('tr-TR',{weekday:'long',day:'numeric',month:'long',year:'numeric'});
  const MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  document.getElementById('hd-title').textContent=translateDayName(log.dayName||'Workout');
  const exHTML=log.exercises.map(ex=>{
    const allEx=getAllExercises(); const exData=allEx.find(e=>e.id===ex.exId)||{name:ex.exId,muscle:'',equipment:''};
    if(ex.skipped) return `<div style="padding:12px 16px;border-bottom:1px solid var(--border);opacity:0.45"><div style="font-size:14px;font-weight:600;text-decoration:line-through">${esc(exData.name)}</div><div style="font-size:12px;color:var(--text3)">${T('skipped')}</div></div>`;
    const sets=(ex.sets||[]).map((s,i)=>{const warmupBadge=s.isWarmup?`<span style="font-size:10px;color:var(--warning);margin-left:4px">☀️ ısınma</span>`:'';const noteStr=s.note?`<div style="font-size:11px;color:var(--text3);margin-top:2px">📝 ${esc(s.note)}</div>`:'';return`<div style="padding:4px 0;border-bottom:1px solid var(--border)"><div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:${s.isWarmup?'var(--warning)':'var(--text2)'}">Set ${i+1}${warmupBadge}</span><span style="font-weight:600;${s.isWarmup?'opacity:0.6':''}">${s.weight}kg × ${s.reps}rep</span></div>${noteStr}</div>`}).join('');
    const vol=(ex.sets||[]).filter(s=>!s.isWarmup).reduce((a,s)=>a+setVolume(s,exData),0);
    const pr=getPersonalRecord(ex.exId);
    const prScore=pr?(pr.e1rm??e1RM(effectiveLoad(pr,exData),pr.reps)):0;
    const isPR=prScore>0&&(ex.sets||[]).some(s=>!s.isWarmup&&setPRScore(s,exData)>=prScore);
    return `<div style="padding:12px 16px;border-bottom:1px solid var(--border)"><div style="display:flex;justify-content:space-between;margin-bottom:8px"><div><div style="font-size:14px;font-weight:600">${esc(exData.name)}${isPR?'<span class="pr-badge">🏆 PR</span>':''}</div><div style="font-size:11px;color:var(--text2)">${esc(exData.muscle)}</div></div><div style="text-align:right;font-size:12px;color:var(--text2)">${Math.round(vol)}kg ${T('total_volume')}</div></div>${sets}</div>`;
  }).join('');
  document.getElementById('hd-content').innerHTML=`
    <div style="background:var(--surface2);border-radius:10px;padding:12px 16px;margin-bottom:16px">
      <div style="font-size:12px;color:var(--text2)">📅 ${dateStr}</div>
      <div style="display:flex;gap:20px;margin-top:8px">
        <div><div style="font-family:'Barlow Condensed',sans-serif;font-size:22px;font-weight:700">${log.duration}</div><div style="font-size:11px;color:var(--text2)">${T('minutes')}</div></div>
        <div><div style="font-family:'Barlow Condensed',sans-serif;font-size:22px;font-weight:700">${log.exercises?.filter(e=>!e.skipped).length||0}</div><div style="font-size:11px;color:var(--text2)">${T('exercises_count')}</div></div>
        <div><div style="font-family:'Barlow Condensed',sans-serif;font-size:22px;font-weight:700">${log.totalVolume||0}</div><div style="font-size:11px;color:var(--text2)">kg ${T('volume')}</div></div>
      </div>
    </div>
    <div class="card" style="margin-bottom:16px;overflow:hidden">${exHTML}</div>
    ${log.note?`<div style="margin:0 0 16px;background:var(--surface2);border-radius:10px;padding:12px 14px"><div style="font-size:11px;font-weight:700;letter-spacing:0.8px;color:var(--text2);text-transform:uppercase;margin-bottom:4px">📝 Antrenman Notu</div><div style="font-size:13px;color:var(--text)">${esc(log.note)}</div></div>`:''}
    <div class="ai-export-row" style="margin-bottom:8px">
      <button class="ai-export-btn" onclick="exportSingleLogCSV('${log.id}')">📊 CSV İndir<br><span style="font-size:11px;font-weight:400;color:var(--text2)">Bu seans</span></button>
      <button class="ai-export-btn" onclick="closeModal('modal-history-detail');openAILogModal()">🤖 AI Analizi<br><span style="font-size:11px;font-weight:400;color:var(--text2)">Tüm geçmiş</span></button>
    </div>`;
  openModal('modal-history-detail');
}

// ============================================================
// EXPORT / IMPORT
// ============================================================
function openExportModal(){
  document.getElementById('data-modal-title').textContent=T('export_data');
  // Toplam set sayısını hesapla
  const totalSets = ST.workoutLogs.reduce((acc, log) => {
    return acc + (log.exercises||[]).reduce((a, ex) => a + (ex.sets||[]).length, 0);
  }, 0);
  document.getElementById('data-modal-content').innerHTML=`
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:16px">
      <div style="text-align:center;background:var(--surface2);border-radius:12px;padding:14px 8px"><div style="font-family:'Barlow Condensed',sans-serif;font-size:28px;font-weight:800;color:var(--accent-text)">${ST.workoutLogs.length}</div><div style="font-size:11px;color:var(--text2)">Seans</div></div>
      <div style="text-align:center;background:var(--surface2);border-radius:12px;padding:14px 8px"><div style="font-family:'Barlow Condensed',sans-serif;font-size:28px;font-weight:800;color:var(--accent-text)">${totalSets}</div><div style="font-size:11px;color:var(--text2)">Toplam Set</div></div>
      <div style="text-align:center;background:var(--surface2);border-radius:12px;padding:14px 8px"><div style="font-family:'Barlow Condensed',sans-serif;font-size:28px;font-weight:800;color:var(--accent-text)">${ST.measurements.length}</div><div style="font-size:11px;color:var(--text2)">Ölçüm</div></div>
    </div>
    <div style="font-size:12px;font-weight:700;letter-spacing:1px;color:var(--text2);text-transform:uppercase;margin-bottom:10px">📤 Dışa Aktar</div>
    <div class="ai-export-row">
      <button class="ai-export-btn" onclick="exportData()">💾 JSON Yedek<br><span style="font-size:11px;font-weight:400;color:var(--text2)">Tam veri yedeği</span></button>
      <button class="ai-export-btn" onclick="exportCSV()">📊 CSV (Excel)<br><span style="font-size:11px;font-weight:400;color:var(--text2)">Set bazlı log</span></button>
    </div>
    <div style="font-size:12px;font-weight:700;letter-spacing:1px;color:var(--text2);text-transform:uppercase;margin-bottom:10px">🤖 AI Analizi</div>
    <button class="btn btn-primary btn-full" onclick="closeModal('modal-data');openAILogModal()" style="margin-bottom:10px">
      🤖 AI'a Sor — Gelişim & Tablo Analizi
    </button>
    <div style="font-size:11px;color:var(--text3);text-align:center;line-height:1.5">Tüm antrenman geçmişin Gemini'ye gönderilir.<br>Tablo, gelişim analizi, öneriler alabilirsin.</div>`;
  openModal('modal-data');
}

function exportData(){
  const {geminiKey:_gizli,...ayarlar}=ST.settings;   // kişisel API anahtarı yedek dosyasına SIZMASIN (dosya paylaşılabilir)
  const backup={version:'kaslog_v2',exportDate:new Date().toISOString(),settings:ayarlar,routines:ST.routines,workoutLogs:ST.workoutLogs,measurements:ST.measurements,customExercises:ST.customExercises,prs:Object.values(ST.prs),nutritionLogs:ST.nutritionLogs,foodDb:ST.foodDb,mealRoutines:ST.mealRoutines};
  const json=JSON.stringify(backup,null,2);
  const blob=new Blob([json],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  const date=new Date().toISOString().slice(0,10);
  a.href=url; a.download=`kaslog-backup-${date}.json`; a.click();
  URL.revokeObjectURL(url);
  closeModal('modal-data');
  setTimeout(()=>showToast(T('export_success')),400);
}

// CSV hücresi: çift tırnak ikiye katlanır (aksi halde not/ad içindeki " satırı
// bozuyordu) ve =,+,-,@ ile başlayan METİN hücreler formül olarak çalışmasın
// diye önüne ' konur (CSV enjeksiyonu: Excel açılışta formülü çalıştırır).
function _csvCell(v) {
  let t = String(v ?? '');
  if (typeof v === 'string' && /^[=+\-@\t\r]/.test(t)) t = "'" + t;
  return '"' + t.replace(/"/g, '""') + '"';
}
function _csvText(rows) { return rows.map(r => r.map(_csvCell).join(',')).join('\n'); }

function exportCSV() {
  const allEx = getAllExercises();
  const rows = [['Tarih','Gün','Egzersiz','Kas Grubu','Set No','Isınma?','Ağırlık (kg)','Tekrar','Hacim (kg)','Not']];
  const sorted = [...ST.workoutLogs].sort((a,b)=>new Date(a.date)-new Date(b.date));
  for (const log of sorted) {
    const dateStr = new Date(log.date).toLocaleDateString('tr-TR');
    const dayName = translateDayName(log.dayName||'Workout');
    for (const ex of (log.exercises||[])) {
      if (ex.skipped) continue;
      const exData = allEx.find(e=>e.id===ex.exId)||{name:ex.exId,muscle:''};
      let setNo = 0;
      for (const s of (ex.sets||[])) {
        if (!s.isWarmup) setNo++;
        const vol = (s.weight||0)*(s.reps||0);
        rows.push([
          dateStr, dayName, exData.name, exData.muscle,
          s.isWarmup ? 'ısınma' : setNo,
          s.isWarmup ? 'Evet' : 'Hayır',
          s.weight||0, s.reps||0, vol,
          s.note||''
        ]);
      }
    }
  }
  const csv = _csvText(rows);
  const bom = '\uFEFF'; // UTF-8 BOM for Excel
  const blob = new Blob([bom+csv],{type:'text/csv;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const date = new Date().toISOString().slice(0,10);
  a.href=url; a.download=`kaslog-log-${date}.csv`; a.click();
  URL.revokeObjectURL(url);
  closeModal('modal-data');
  setTimeout(()=>showToast('📊 CSV indirildi'),400);
}

// ============================================================
// AI LOG ANALİZİ
// ============================================================
function _buildWorkoutLogText() {
  const allEx = getAllExercises();
  const sorted = [...ST.workoutLogs].sort((a,b)=>new Date(a.date)-new Date(b.date));
  const lines = [];
  lines.push(`Kullanıcı: ${ST.settings.name || 'Sporcu'}`);
  lines.push(`Seviye: ${ST.settings.level || '-'}, Hedef: ${ST.settings.goal || '-'}`);
  lines.push(`Toplam seans: ${sorted.length}`);
  lines.push('---');
  for (const log of sorted) {
    const d = new Date(log.date).toLocaleDateString('tr-TR');
    const dayName = translateDayName(log.dayName||'Workout');
    lines.push(`\n📅 ${d} — ${dayName} (${log.duration || 0} dk, toplam hacim: ${log.totalVolume || 0}kg)`);
    if (log.note) lines.push(`   Not: ${log.note}`);
    for (const ex of (log.exercises||[])) {
      if (ex.skipped) continue;
      const exData = allEx.find(e=>e.id===ex.exId)||{name:ex.exId,muscle:''};
      const workSets = (ex.sets||[]).filter(s=>!s.isWarmup);
      const warmSets = (ex.sets||[]).filter(s=>s.isWarmup);
      if (!workSets.length) continue;
      const setStr = workSets.map((s,i)=>`Set${i+1}: ${s.weight}kg×${s.reps}rep${s.note?` [${s.note}]`:''}`).join(', ');
      const warmStr = warmSets.length ? ` | Isınma: ${warmSets.map(s=>`${s.weight}kg×${s.reps}`).join(', ')}` : '';
      const vol = workSets.reduce((a,s)=>a+(s.weight||0)*(s.reps||0),0);
      lines.push(`   • ${exData.name} (${exData.muscle}) — ${setStr}${warmStr} = ${Math.round(vol)}kg hacim`);
    }
  }
  // PRs
  const prList = Object.values(ST.prs);
  if (prList.length) {
    lines.push('\n🏆 KİŞİSEL REKORLAR:');
    for (const pr of prList) {
      const exData = allEx.find(e=>e.id===pr.exId)||{name:pr.exId};
      const d = pr.date ? new Date(pr.date).toLocaleDateString('tr-TR') : '';
      lines.push(`   • ${exData.name}: ${pr.weight}kg × ${pr.reps}rep ${d?'('+d+')':''}`);
    }
  }
  return lines.join('\n');
}

function openAILogModal() {
  const body = document.getElementById('ai-log-body');
  body.innerHTML = `
    <div style="font-size:13px;color:var(--text2);line-height:1.6;margin-bottom:14px;background:var(--surface2);border-radius:10px;padding:12px 14px">
      📋 <strong style="color:var(--text)">${ST.workoutLogs.length} seans</strong> verimle AI'a ne sormak istiyorsun?
    </div>
    <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px">
      <button class="ai-preset-btn" onclick="runAILog('Antrenman verilerimi analiz et. Son 4 haftanın haftalık özet tablosunu çıkar: haftada kaç seans yaptım, toplam antrenman süresi ve toplam hacim (kg).')">📊 Haftalık özet tablo</button>
      <button class="ai-preset-btn" onclick="runAILog('Her egzersiz için zaman içindeki ağırlık gelişimimi göster. Başlangıç ağırlığım ile şimdiki ağırlığımı karşılaştır, kaç kg ilerleme kaydettiğimi ve yüzde gelişimimi belirt.')">📈 Egzersiz bazlı gelişim</button>
      <button class="ai-preset-btn" onclick="runAILog('Kas gruplarına göre antrenman dağılımımı analiz et. Hangi kas gruplarını ne sıklıkla çalıştırıyorum? Baskın ve ihmal edilen kas grupları hangileri? Denge önerileri ver.')">💪 Kas grubu dengesi</button>
      <button class="ai-preset-btn" onclick="runAILog('PR kayıtlarımı ve en iyi performanslarımı listele. Her egzersizde en yüksek ağırlık, tekrar ve toplam hacim nedir? Hangi egzersizlerde en çok gelişim var?')">🏆 PR ve en iyi performanslar</button>
      <button class="ai-preset-btn" onclick="runAILog('Antrenman tutarlılığımı değerlendir. Haftada ortalama kaç seans yapıyorum, seans başına ortalama süre ve hacim nedir? Son 1 ay ile öncesini karşılaştır.')">🔥 Tutarlılık & trend analizi</button>
      <button class="ai-preset-btn" onclick="runAILog('Tüm antrenman verilerime göre gelişimim için somut öneriler ver: hangi egzersizlerde ağırlık artırma zamanı geldi, hangi kas grupları daha fazla çalışmalı, program düzeni nasıl iyileştirilebilir?')">🎯 Genel öneriler & program analizi</button>
    </div>
    <div style="font-size:12px;font-weight:700;letter-spacing:1px;color:var(--text2);text-transform:uppercase;margin-bottom:8px">Özel soru sor</div>
    <div class="ai-custom-wrap">
      <input class="ai-custom-input" id="ai-custom-q" placeholder="Örn: Squat gelişimimi göster..." onkeydown="if(event.key==='Enter')runAILogCustom()">
      <div class="ai-custom-send" onclick="runAILogCustom()" aria-label="Soruyu gönder">
        <svg viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
      </div>
    </div>
  `;
  openModal('modal-ai-log');
}

function runAILogCustom() {
  const q = document.getElementById('ai-custom-q')?.value?.trim();
  if (!q) return;
  runAILog(q);
}

async function runAILog(question) {
  const body = document.getElementById('ai-log-body');
  const logText = _buildWorkoutLogText();

  // Loading UI
  body.innerHTML = `
    <div style="margin-bottom:16px;font-size:13px;color:var(--text2);background:var(--surface2);border-radius:10px;padding:10px 14px;line-height:1.5">
      🤖 <em>"${esc(question.slice(0,80))}${question.length>80?'…':''}"</em>
    </div>
    <div class="ai-thinking">
      <div class="ai-dot"></div><div class="ai-dot"></div><div class="ai-dot"></div>
      <span style="margin-left:4px">Analiz ediliyor...</span>
    </div>
  `;

  const prompt = `Sen bir fitness koçu ve veri analistisin. Kullanıcının KASLOG uygulamasından aldığı gerçek antrenman verisi aşağıda verilmiştir.

ANTRENMAN VERİSİ:
${logText}

KULLANICI SORUSU: ${question}

Talimatlar:
- Türkçe yanıt ver.
- Sayısal verilerden tablo veya liste oluşturduğunda Markdown formatını kullan (| başlıklı tablo, **kalın** önemli değerler).
- Gerçek sayılara dayan, yorum yaparken veriye sadık kal.
- Eğer veri yetersizse bunu belirt ama elimdekilerle analiz yap.
- Maksimum 600 kelime.`;

  try {
    const data = await callGemini([{ parts: [{ text: prompt }] }]);
    if (data.error) throw new Error(data.error.message);
    const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || 'Yanıt alınamadı.';
    const html = _markdownToHTML(raw);

    body.innerHTML = `
      <div style="margin-bottom:12px;font-size:12px;color:var(--text3);background:var(--surface2);border-radius:8px;padding:8px 12px">
        🤖 <em>"${esc(question.slice(0,70))}${question.length>70?'…':''}"</em>
      </div>
      <div class="ai-result-wrap">
        <div class="ai-result-text">${html}</div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="btn btn-ghost" style="flex:1;font-size:13px" onclick="openAILogModal()">← Geri</button>
        <button class="btn btn-ghost" style="flex:1;font-size:13px" onclick="copyAIResult()">📋 Kopyala</button>
      </div>
    `;
    // store for copy
    window._lastAIResult = raw;
  } catch(err) {
    body.innerHTML = `
      <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:10px;padding:14px;margin-bottom:16px;font-size:13px;color:var(--danger)">
        ❌ Hata: ${esc(err.message || 'API yanıt vermedi')}
      </div>
      <button class="btn btn-ghost btn-full" onclick="openAILogModal()">← Geri dön</button>
    `;
  }
}

function copyAIResult() {
  const text = window._lastAIResult || '';
  if (!text) return;
  navigator.clipboard?.writeText(text).then(()=>showToast('📋 Kopyalandı')).catch(()=>showToast('Kopyalanamadı',true));
}

function exportSingleLogCSV(logId) {
  const log = ST.workoutLogs.find(l=>l.id===logId); if(!log) return;
  const allEx = getAllExercises();
  const dateStr = new Date(log.date).toLocaleDateString('tr-TR');
  const dayName = translateDayName(log.dayName||'Workout');
  const rows = [['Tarih','Gün','Egzersiz','Kas Grubu','Set No','Isınma?','Ağırlık (kg)','Tekrar','Hacim (kg)','Not']];
  for (const ex of (log.exercises||[])) {
    if (ex.skipped) continue;
    const exData = allEx.find(e=>e.id===ex.exId)||{name:ex.exId,muscle:''};
    let setNo = 0;
    for (const s of (ex.sets||[])) {
      if (!s.isWarmup) setNo++;
      rows.push([
        dateStr, dayName, exData.name, exData.muscle,
        s.isWarmup ? 'ısınma' : setNo,
        s.isWarmup ? 'Evet' : 'Hayır',
        s.weight||0, s.reps||0, (s.weight||0)*(s.reps||0),
        s.note||''
      ]);
    }
  }
  const csv = _csvText(rows);
  const blob = new Blob(['\uFEFF'+csv],{type:'text/csv;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const d = new Date(log.date).toISOString().slice(0,10);
  a.href=url; a.download=`kaslog-seans-${d}.csv`; a.click();
  URL.revokeObjectURL(url);
  showToast('📊 CSV indirildi');
}

function _markdownToHTML(md) {
  // Minimal markdown → HTML (tablo, bold, liste)
  let html = md
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    // Tables
    .replace(/\|(.+)\|\n\|[-| :]+\|\n((?:\|.+\|\n?)+)/g, (_, header, rows) => {
      const ths = header.split('|').filter(s=>s.trim()).map(h=>`<th>${h.trim()}</th>`).join('');
      const trs = rows.trim().split('\n').map(row=>{
        const tds = row.split('|').filter(s=>s.trim()).map(d=>`<td>${d.trim()}</td>`).join('');
        return `<tr>${tds}</tr>`;
      }).join('');
      return `<table><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
    })
    // Bold
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    // Headers
    .replace(/^### (.+)$/gm,'<div style="font-family:\'Barlow Condensed\',sans-serif;font-size:17px;font-weight:700;margin:14px 0 6px;color:var(--text)">$1</div>')
    .replace(/^## (.+)$/gm,'<div style="font-family:\'Barlow Condensed\',sans-serif;font-size:19px;font-weight:700;margin:16px 0 6px;color:var(--accent-text)">$1</div>')
    .replace(/^# (.+)$/gm,'<div style="font-family:\'Barlow Condensed\',sans-serif;font-size:22px;font-weight:800;margin:16px 0 8px;color:var(--accent-text)">$1</div>')
    // Bullets
    .replace(/^[-•] (.+)$/gm,'<div style="padding:2px 0 2px 16px;position:relative"><span style="position:absolute;left:0;color:var(--accent-text)">•</span>$1</div>')
    // Line breaks
    .replace(/\n\n/g,'<br><br>')
    .replace(/\n/g,'<br>');
  return html;
}

function openImportModal(){
  document.getElementById('data-modal-title').textContent=T('import_data');
  document.getElementById('data-modal-content').innerHTML=`
    <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);border-radius:10px;padding:14px 16px;margin-bottom:20px;font-size:13px;color:var(--danger);line-height:1.6">⚠️ ${T('import_warning')}</div>
    <div style="background:var(--surface2);border-radius:10px;padding:14px 16px;margin-bottom:20px;font-size:13px;color:var(--text2);line-height:1.6">${T('import_desc')}</div>
    <input type="file" id="import-file-input" accept=".json" style="display:none" onchange="handleImportFile(this)">
    <button class="btn btn-primary btn-full" onclick="document.getElementById('import-file-input').click()">📥 ${T('import_btn')}</button>`;
  openModal('modal-data');
}

// ── Yedek doğrulama ─────────────────────────────────────────
// Yedek dosyası güvenilmeyen girdidir: paylaşılmış/değiştirilmiş olabilir. İçeri
// alınan her kayıt (1) güvenli bir id taşımalı — id'ler onclick özniteliklerine
// gömülüyor, (2) listelerin liste, sayıların sayı olması gerekir — yoksa render
// çöker. Geçersiz kayıtlar sessizce atlanır; geri kalanı yüklenir.
const _BACKUP_ID_RE = /^[A-Za-z0-9_.:\-]{1,120}$/;
const _okId  = v => typeof v === 'string' && _BACKUP_ID_RE.test(v);
const _bNum  = (v, d = 0) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
const _bStr  = (v, d = '') => v == null ? d : String(v);
const _bArr  = v => Array.isArray(v) ? v : [];
const _bDate = v => !isNaN(new Date(v).getTime());
const _MEASURE_FIELDS = ['weight','height','chest','waist','bicep','hip','thigh','shoulder'];

const BACKUP_CLEANERS = {
  routines: r => {
    if (!_okId(r.id)) return null;
    return { ...r, name:_bStr(r.name,'Rutin'), emoji:_bStr(r.emoji,'💪'),
      type: r.type === 'fixed' ? 'fixed' : 'cyclic',
      days: _bArr(r.days).filter(d => d && _okId(d.id)).map(d => ({ ...d,
        name:_bStr(d.name), emoji:_bStr(d.emoji,'💪'), isRest:!!d.isRest,
        exercises: _bArr(d.exercises).filter(e => e && _okId(e.exId))
          .map(e => ({ ...e, sets:_bNum(e.sets,3), reps:_bNum(e.reps,10), disabled:!!e.disabled })) })) };
  },
  workoutLogs: l => {
    if (!_okId(l.id) || !_bDate(l.date)) return null;
    return { ...l, dayName:_bStr(l.dayName), duration:_bNum(l.duration), totalVolume:_bNum(l.totalVolume),
      exercises: _bArr(l.exercises).filter(e => e && _okId(e.exId)).map(e => ({ ...e, skipped:!!e.skipped,
        sets: _bArr(e.sets).filter(Boolean).map(x => ({ ...x, weight:_bNum(x.weight), reps:_bNum(x.reps) })) })) };
  },
  measurements: m => {
    if (!_okId(m.id) || !_bDate(m.date)) return null;
    const out = { ...m };
    for (const f of _MEASURE_FIELDS) if (out[f] != null) { const n = Number(out[f]); if (Number.isFinite(n)) out[f] = n; else delete out[f]; }
    return out;
  },
  customExercises: c => {
    if (!_okId(c.id)) return null;
    return { ...c, name:_bStr(c.name,'Egzersiz'), muscle:_bStr(c.muscle,'Custom'), equipment:_bStr(c.equipment,'Bodyweight'),
      group: ['push','pull','legs','core','custom'].includes(c.group) ? c.group : 'custom',
      type: c.type === 'time' ? 'time' : 'reps', tip:_bStr(c.tip) };
  },
  prs: p => (_okId(p.id) && _okId(p.exId)) ? { ...p, weight:_bNum(p.weight), reps:_bNum(p.reps) } : null,
  nutritionLogs: n => {
    if (!_okId(n.id) || typeof n.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(n.date)) return null;
    const out = { ...n, name:_bStr(n.name), emoji:_bStr(n.emoji,'🍽️'),
      calories:_bNum(n.calories), protein:_bNum(n.protein), carbs:_bNum(n.carbs), fat:_bNum(n.fat) };
    if (out.groupId != null && !_okId(out.groupId)) delete out.groupId;   // onclick'e gömülüyor
    return out;
  },
  foodDb: f => {
    if (!_okId(f.id) || !f.per100 || typeof f.per100 !== 'object') return null;
    return { ...f, name:_bStr(f.name),
      per100:{ kcal:_bNum(f.per100.kcal), protein:_bNum(f.per100.protein), carbs:_bNum(f.per100.carbs), fat:_bNum(f.per100.fat) } };
  },
  mealRoutines: r => {
    if (!_okId(r.id)) return null;
    // Tarif alanları (100 g değerleri, tencere ağırlığı, porsiyonlar) düzenleme
    // ekranında HAM yazdırılıyor: sayıya indirilmezse metin olarak içeri girebilir.
    const per100 = (r.per100 && typeof r.per100 === 'object')
      ? { kcal:_bNum(r.per100.kcal), protein:_bNum(r.per100.protein), carbs:_bNum(r.per100.carbs), fat:_bNum(r.per100.fat) } : null;
    const portions = {};
    if (r.portions && typeof r.portions === 'object' && !Array.isArray(r.portions))
      for (const [k, v] of Object.entries(r.portions)) if (/^[a-z]{2,20}$/.test(k) && Number(v) > 0) portions[k] = Number(v);
    return { ...r, name:_bStr(r.name,'Rutin'), emoji:_bStr(r.emoji,'⭐'),
      ...(r.type === 'recipe' ? { type:'recipe' } : { type:undefined }),
      per100, portions, yieldG:_bNum(r.yieldG), useCount:_bNum(r.useCount), samples:_bNum(r.samples,1),
      triggers:_bArr(r.triggers).map(t => _bStr(t)),
      items: _bArr(r.items).filter(i => i && typeof i === 'object').map(i => ({ ...i,
        name:_bStr(i.name), calories:_bNum(i.calories), protein:_bNum(i.protein), carbs:_bNum(i.carbs), fat:_bNum(i.fat) })) };
  },
};

/** Ayarlar: yalnızca bilinen anahtarlar; API anahtarı dosyadan ASLA alınmaz. */
function _cleanBackupSettings(raw, defaults) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const k of Object.keys(defaults)) {
    if (k === 'geminiKey' || !(k in raw)) continue;
    const v = raw[k], d = defaults[k];
    if (typeof d === 'number')       { const n = Number(v); if (Number.isFinite(n)) out[k] = n; }
    else if (typeof d === 'boolean') out[k] = !!v;
    else if (typeof d === 'string')  out[k] = _bStr(v, d);
    else if (Array.isArray(d))       out[k] = _bArr(v).map(x => _bStr(x));
    else                             out[k] = v;   // null/nesne alanlar (cycleDate, breakNotice)
  }
  if (!['dark','light'].includes(out.theme))   delete out.theme;
  if (out.geminiModel !== undefined && !/^[\w.\-]+$/.test(out.geminiModel)) delete out.geminiModel;
  if (out.activeRoutineId != null && !_okId(out.activeRoutineId)) delete out.activeRoutineId;
  if ('dishPortions' in out) {              // { yemekAnahtarı: { kap: gram } } — yalnızca güvenli anahtar + pozitif sayı
    const dp = {};
    if (raw.dishPortions && typeof raw.dishPortions === 'object' && !Array.isArray(raw.dishPortions))
      for (const [k, v] of Object.entries(raw.dishPortions)) {
        if (!/^[a-z0-9 _-]{1,60}$/.test(k) || !v || typeof v !== 'object') continue;
        const kaplar = {};
        for (const [kap, g] of Object.entries(v)) if (/^[a-z]{2,20}$/.test(kap) && Number(g) > 0) kaplar[kap] = Number(g);
        if (Object.keys(kaplar).length) dp[k] = kaplar;
      }
    out.dishPortions = dp;
  }
  if (out.restTime !== undefined) out.restTime = Math.min(600, Math.max(15, Math.round(out.restTime)));
  if (out.breakNotice) out.breakNotice = (typeof out.breakNotice === 'object')
    ? { days:_bNum(out.breakNotice.days), prevPos:_bNum(out.breakNotice.prevPos), dismissed:!!out.breakNotice.dismissed } : null;
  if (out.cycleDate != null && !/^\d{4}-\d{2}-\d{2}$/.test(String(out.cycleDate))) out.cycleDate = null;
  if (out.lastWorkoutDate != null && !_bDate(out.lastWorkoutDate)) out.lastWorkoutDate = null;
  return out;
}

/** Geçersiz kayıtları ayıklanmış, depo başına temiz kayıt listesi döner. */
function sanitizeBackup(b, defaultSettings) {
  const out = { settings: _cleanBackupSettings(b.settings, defaultSettings) };
  let dropped = 0;
  for (const [store, clean] of Object.entries(BACKUP_CLEANERS)) {
    if (!Array.isArray(b[store])) continue;       // yedekte yoksa o depoya dokunma
    out[store] = [];
    for (const rec of b[store]) {
      const c = (rec && typeof rec === 'object' && !Array.isArray(rec)) ? clean({ ...rec }) : null;
      if (c) out[store].push(c); else dropped++;
    }
  }
  out._dropped = dropped;
  return out;
}

// Depoyu yedekle BİREBİR aynı yap: önce yedekteki kayıtlar yazılır, sonra
// yedekte olmayanlar silinir. (Eski kod yalnızca üzerine yazıyordu: bellekte
// yedek vardı ama veritabanında eski kayıtlar kalıyor, yeniden açınca geri geliyordu.)
async function _replaceStore(store, records) {
  const keep = new Set(records.map(r => r.id));
  const existing = await DB.getAll(store);
  for (const r of records) await DB.put(store, r);
  for (const e of existing) if (!keep.has(e.id)) await DB.del(store, e.id);
}

async function handleImportFile(input){
  const file=input.files[0]; if(!file)return;
  input.value='';
  let backup;
  try{ backup=JSON.parse(await file.text()); }catch(e){ showToast(T('import_error'),true); return; }
  if(!backup||typeof backup!=='object'||typeof backup.version!=='string'||!backup.version.startsWith('kaslog')){ showToast(T('import_error'),true); return; }
  const clean=sanitizeBackup(backup, _DEFAULT_SETTINGS);
  showConfirm('📥',T('import_data'),T('import_warning'),async()=>{
    closeModal('modal-alert');
    try{
      if(Object.keys(clean.settings).length){
        ST.settings={...ST.settings,...clean.settings};
        await DB.put('settings',{id:'main',...ST.settings});
      }
      for(const k of ['routines','workoutLogs','measurements','customExercises','nutritionLogs','foodDb','mealRoutines']){
        if(!clean[k]) continue;
        await _replaceStore(k,clean[k]);
        ST[k]=clean[k];
      }
      if(clean.prs){
        await _replaceStore('prs',clean.prs);
        ST.prs={}; clean.prs.forEach(p=>{ST.prs[p.exId]=p;});
      }
      await syncCycle();
      applyTheme(ST.settings.theme||'dark');
      closeModal('modal-data');
      renderAll();
      _recoverPendingMeals();   // yedekte yarım kalmış analiz varsa takılı kalmasın
      setTimeout(()=>showToast(clean._dropped?`${T('import_success')} (${clean._dropped} geçersiz kayıt atlandı)`:T('import_success')),300);
    }catch(err){
      console.error('import error:',err);
      showToast('❌ İçe aktarma yarıda kaldı: '+(err?.message||'bilinmeyen hata'),true);
    }
  });
}

// ============================================================
// TOAST
// ============================================================
function showToast(msg,isError=false){
  const t=document.getElementById('toast-el');
  t.textContent=msg;
  t.style.background=isError?'var(--danger)':'var(--success)';
  t.style.whiteSpace=isError?'normal':'nowrap';
  t.style.maxWidth=isError?'88vw':'none';
  t.style.textAlign=isError?'center':'left';
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), isError?4200:2800);
}


function getCycleInfo(){
  const routine=activeRoutine();
  if(!routine)return T('no_routine');
  const info=getTodayDayInfo(routine); const total=routine.days.length;
  if(info.done){
    const n=routine.days[(info.pos+1)%total];
    return`${T('tomorrow')}: ${n.isRest?'😴':esc(n.emoji)} ${translateDayNameH(n.name)} (${((info.pos+1)%total)+1}/${total} ${T('in_cycle')})`;
  }
  const day=info.day;
  return`${T('next_label')}: ${day.isRest?'😴':esc(day.emoji)} ${translateDayNameH(day.name)} (${info.pos+1}/${total} ${T('in_cycle')})`;
}

function editSetting(key){
  const sc=document.getElementById('se-content');
  if(key==='name'){
    document.getElementById('se-title').textContent=T('edit_name_title');
    sc.innerHTML=`<div class="form-group"><label class="form-label">${T('name_label')}</label><input class="form-input" id="se-name-input" value="${esc(ST.settings.name||'')}" maxlength="20" style="font-size:18px;padding:14px" autofocus></div><button class="btn btn-primary btn-full" onclick="saveSetting('name')">${T('save')}</button>`;
    openModal('modal-setting-edit');
    setTimeout(()=>document.getElementById('se-name-input')?.focus(),300);
  } else if(key==='level'){
    document.getElementById('se-title').textContent=T('edit_level_title');
    const levels=[{v:'beginner',lk:'level_beginner',icon:'🌱',desc:'0–6 ay'},{v:'intermediate',lk:'level_intermediate',icon:'⚡',desc:'6ay–2yıl'},{v:'advanced',lk:'level_advanced',icon:'🔥',desc:'2–4 yıl'},{v:'expert',lk:'level_expert',icon:'🏆',desc:'4+ yıl'}];
    sc.innerHTML=`<div style="display:flex;flex-direction:column;gap:10px" id="se-level-grid">`+levels.map(l=>`<div onclick="saveSetting('level','${l.v}')" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:12px;border:1.5px solid ${ST.settings.level===l.v?'var(--accent)':'var(--border)'};background:${ST.settings.level===l.v?'var(--accent-dim)':'var(--surface2)'};cursor:pointer;transition:var(--transition)"><div style="font-size:24px">${l.icon}</div><div><div style="font-weight:600">${T(l.lk)}</div><div style="font-size:12px;color:var(--text2)">${l.desc}</div></div>${ST.settings.level===l.v?'<div style="margin-left:auto;color:var(--accent-text);font-weight:700">✓</div>':''}</div>`).join('')+`</div>`;
    openModal('modal-setting-edit');
  } else if(key==='goal'){
    document.getElementById('se-title').textContent=T('edit_goal_title');
    const goals=[{v:'strength',lk:'goal_strength',icon:'💪',desc:'Az tekrar, yüksek ağırlık. 3–5 dk dinlenme.'},{v:'hypertrophy',lk:'goal_hypertrophy',icon:'🔥',desc:'Orta tekrar, orta ağırlık. 60–90sn dinlenme.'},{v:'both',lk:'goal_both',icon:'⚡',desc:'Karma program. 90–120sn dinlenme.'}];
    sc.innerHTML=`<div style="display:flex;flex-direction:column;gap:10px">`+goals.map(g=>`<div onclick="saveSetting('goal','${g.v}')" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:12px;border:1.5px solid ${ST.settings.goal===g.v?'var(--accent)':'var(--border)'};background:${ST.settings.goal===g.v?'var(--accent-dim)':'var(--surface2)'};cursor:pointer;transition:var(--transition)"><div style="font-size:24px">${g.icon}</div><div><div style="font-weight:600">${T(g.lk)}</div><div style="font-size:12px;color:var(--text2)">${g.desc}</div></div>${ST.settings.goal===g.v?'<div style="margin-left:auto;color:var(--accent-text);font-weight:700">✓</div>':''}</div>`).join('')+`</div>`;
    openModal('modal-setting-edit');
  } else if(key==='rest'){
    document.getElementById('se-title').textContent=T('edit_rest_title');
    sc.innerHTML=`<div class="form-group"><label class="form-label">${T('rest_label')} (s)</label><input class="form-input" id="se-rest-input" type="number" value="${ST.settings.restTime}" min="15" max="600" style="font-size:24px;text-align:center;padding:14px" autofocus><div style="font-size:12px;color:var(--text2);margin-top:6px;text-align:center">${T('rest_hint')}</div></div><button class="btn btn-primary btn-full" onclick="saveSetting('rest')">${T('save')}</button>`;
    openModal('modal-setting-edit');
    setTimeout(()=>document.getElementById('se-rest-input')?.focus(),300);
  }
}
async function saveSetting(key,val){
  if(key==='name'){const v=document.getElementById('se-name-input').value.trim();if(!v)return;ST.settings.name=v;}
  else if(key==='level'){ST.settings.level=val;}
  else if(key==='goal'){const rt={strength:180,hypertrophy:75,both:105};ST.settings.goal=val;ST.settings.restTime=rt[val];}
  else if(key==='rest'){const t=parseInt(document.getElementById('se-rest-input').value);if(t<15||t>600)return;ST.settings.restTime=t;}
  await DB.put('settings',{id:'main',...ST.settings});
  closeModal('modal-setting-edit');
  renderAyarlar(); renderBugun();
}

async function resetCyclePos(){ST.settings.cyclePosition=0;ST.settings.cycleDate=dayKey();ST.settings.breakNotice=null;await DB.put('settings',{id:'main',...ST.settings});renderAyarlar();renderBugun();}

function clearData(){showConfirm('⚠️',T('delete_data_title'),T('delete_data_msg'),async()=>{
  closeModal('modal-alert');
  // Açık bağlantı silmeyi bekletir (başta kendi bağlantımız): önce kapat, sonra
  // sil, silme BİTİNCE yenile. Eskiden silme beklerken sayfa hemen yenileniyordu.
  DB.close();
  const done=()=>location.reload();
  const r=indexedDB.deleteDatabase('KaslogDB2');
  r.onsuccess=done; r.onerror=done;
  r.onblocked=()=>setTimeout(done,1500);   // başka bağlam tutuyorsa yine de yenile; silme sıraya girmiştir
});}

// ============================================================
// THEME
// ============================================================
function toggleTheme(){
  const cur=document.documentElement.getAttribute('data-theme');
  applyTheme(cur==='dark'?'light':'dark');
  ST.settings.theme=document.documentElement.getAttribute('data-theme');
  DB.put('settings',{id:'main',...ST.settings});
}
function applyTheme(t){
  document.documentElement.setAttribute('data-theme',t);
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content',t==='dark'?'#0a0a0c':'#f0f0f5');
  document.getElementById('theme-icon-dark').style.display=t==='dark'?'block':'none';
  document.getElementById('theme-icon-light').style.display=t==='light'?'block':'none';
  if(ST.activeTab==='ayarlar')renderAyarlar();
}

// ============================================================
// MODALS
// ============================================================
function openModal(id){document.getElementById(id).classList.add('open');}
function closeModal(id){document.getElementById(id).classList.remove('open');}
// tone: 'danger' (yıkıcı işlem, varsayılan) | 'primary' (olumlu eylem). Düğme rengi
// her açılışta yeniden atanır; önceki diyaloğun rengi sızmasın.
function showConfirm(icon,title,msg,onConfirm,tone='danger'){
  document.getElementById('alert-icon').textContent=icon;
  document.getElementById('alert-title').textContent=title;
  document.getElementById('alert-msg').textContent=msg;
  const ok=document.getElementById('alert-confirm');
  ok.onclick=onConfirm; ok.className='btn btn-'+tone;
  // Çağıranlar "Vazgeç"e özel işleyici bağlayabiliyor (bkz. _maybeOfferRoutine).
  // Her açılışta varsayılana döndür, yoksa önceki işleyici sonraki diyaloğa sızar.
  const cancel=document.getElementById('alert-cancel');
  if(cancel) cancel.onclick=()=>closeModal('modal-alert');
  openModal('modal-alert');
}
document.querySelectorAll('.modal-backdrop').forEach(bd=>{
  bd.addEventListener('click',e=>{if(e.target===bd&&bd.id!=='modal-alert')closeModal(bd.id);});
});

