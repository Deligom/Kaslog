// ============================================================
// BESLENME İSTATİSTİKLERİ (Haftalık Grafik)
// ============================================================
function renderBeslenmeStats(el) {
  const dayLabelArr = ['Paz','Pzt','Sal','Çar','Per','Cum','Cmt'];
  const todayD = new Date(); todayD.setHours(0,0,0,0);

  // Grafik için her zaman sabit 7 gün
  const chartDays = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(todayD); d.setDate(todayD.getDate() - i);
    const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    const entries = ST.nutritionLogs.filter(e => e.date === key);
    const kcal = Math.round(entries.reduce((a,e) => a+(e.calories||0), 0));
    const protein = Math.round(entries.reduce((a,e) => a+(e.protein||0), 0));
    chartDays.push({ key, kcal, protein, label: dayLabelArr[d.getDay()], dayNum: d.getDate() });
  }

  // Günlük Detay: AY BAZLI SAYFALAMA (her ay 1 sayfa, 28-31 gün otomatik)
  const allNutLogsForDays = ST.nutritionLogs;
  // İlk log ayı = geriye gidilebilecek sınır
  let minMonthKey = `${todayD.getFullYear()}-${String(todayD.getMonth()+1).padStart(2,'0')}`;
  if (allNutLogsForDays.length > 0) {
    minMonthKey = allNutLogsForDays.map(e => e.date.slice(0,7)).sort()[0];
  }
  const curMonthKey = `${todayD.getFullYear()}-${String(todayD.getMonth()+1).padStart(2,'0')}`;
  // Seçili ay yoksa veya sınır dışındaysa bu aya dön
  if (!window._nutStatMonth || window._nutStatMonth > curMonthKey || window._nutStatMonth < minMonthKey)
    window._nutStatMonth = curMonthKey;
  const [selY, selM] = window._nutStatMonth.split('-').map(Number);
  const daysInMonth = new Date(selY, selM, 0).getDate(); // 28/29/30/31 otomatik
  const isCurMonth = window._nutStatMonth === curMonthKey;
  const lastDay = isCurMonth ? todayD.getDate() : daysInMonth; // bu ayda geleceği gösterme
  const MONTH_NAMES = ['Ocak','Şubat','Mart','Nisan','Mayıs','Haziran','Temmuz','Ağustos','Eylül','Ekim','Kasım','Aralık'];
  const days = [];
  for (let dn = 1; dn <= lastDay; dn++) {
    const d = new Date(selY, selM - 1, dn);
    const key = `${selY}-${String(selM).padStart(2,'0')}-${String(dn).padStart(2,'0')}`;
    const entries = ST.nutritionLogs.filter(e => e.date === key);
    const kcal = Math.round(entries.reduce((a,e) => a+(e.calories||0), 0));
    const protein = Math.round(entries.reduce((a,e) => a+(e.protein||0), 0));
    days.push({ key, kcal, protein, label: dayLabelArr[d.getDay()], dayNum: dn });
  }
  const canPrev = window._nutStatMonth > minMonthKey;
  const canNext = window._nutStatMonth < curMonthKey;
  // Ay özeti (kayıtlı günlerin ortalaması)
  const monthDaysWithData = days.filter(d => d.kcal > 0);
  const monthAvgKcal = monthDaysWithData.length ? Math.round(monthDaysWithData.reduce((a,d)=>a+d.kcal,0)/monthDaysWithData.length) : 0;

  // Tüm zamanların ortalaması: ilk log gününden bugüne kaç gün
  const allNutLogs = ST.nutritionLogs;
  let daysActive = 7; // fallback
  if (allNutLogs.length > 0) {
    const allDates = allNutLogs.map(e => e.date).sort();
    const firstDate = new Date(allDates[0] + 'T00:00:00');
    const todayD = new Date(); todayD.setHours(0,0,0,0);
    daysActive = Math.max(1, Math.round((todayD - firstDate) / 86400000) + 1);
  }
  // Tüm zamanlardaki toplamlar (son 7 gün değil, tüm loglar)
  const allTimeKcal = allNutLogs.reduce((a, e) => a + (e.calories || 0), 0);
  const allTimeProtein = allNutLogs.reduce((a, e) => a + (e.protein || 0), 0);
  const allTimeDaysWithData = new Set(allNutLogs.map(e => e.date)).size;

  const totalKcal = days.reduce((a,d) => a+d.kcal, 0);
  const totalProtein = days.reduce((a,d) => a+d.protein, 0);
  // Ortalama KAYITLI günler üzerinden: kaydı hiç girilmeyen günleri 0 kcal
  // saymak (eskiden böyleydi) "ilk hafta 3 gün girdim" diyen kullanıcıya %20'lik
  // sahte bir ortalama gösteriyordu. Aylık özet de zaten kayıtlı günlerle hesaplanıyor.
  const avgKcal = Math.round(allTimeKcal / Math.max(1, allTimeDaysWithData));
  const avgProtein = Math.round(allTimeProtein / Math.max(1, allTimeDaysWithData));
  const daysWithData = days.filter(d => d.kcal > 0).length;

  const isWorkout = _nutWorkoutMode !== null ? _nutWorkoutMode : isTodayWorkoutDay();
  const goals = calcNutritionGoals(isWorkout);
  const avgKcalPct = goals.kcal > 0 ? Math.round(avgKcal / goals.kcal * 100) : 0;
  const avgProtPct = goals.protein > 0 ? Math.round(avgProtein / goals.protein * 100) : 0;


  // ---- GERÇEK TDEE TAHMİNİ (kilo değişimi + kalori verisi) ----
  // Son ~35 günde: ≥2 kilo ölçümü (≥14 gün arayla) + ≥10 kayıtlı beslenme günü gerek
  let tdeeCard = '';
  {
    const wMs = ST.measurements.filter(m => m.weight).sort((a,b) => new Date(a.date) - new Date(b.date));
    const cut = new Date(); cut.setDate(cut.getDate() - 35);
    const recent = wMs.filter(m => new Date(m.date) >= cut);
    if (recent.length >= 2) {
      const first = recent[0], last = recent[recent.length - 1];
      const spanDays = Math.round((new Date(last.date) - new Date(first.date)) / 86400000);
      if (spanDays >= 14) {
        // Beslenme kayıtları YEREL gün anahtarı taşıyor; toISOString() UTC verir ve
        // UTC+3'te gece yarısından sonra girilen ölçümde bir gün kayardı.
        const fKey = dayKey(new Date(first.date));
        const lKey = dayKey(new Date(last.date));
        const periodLogs = ST.nutritionLogs.filter(e => e.date >= fKey && e.date <= lKey && e.calories > 0);
        const loggedDays = new Set(periodLogs.map(e => e.date)).size;
        if (loggedDays >= 10) {
          const avgIntake = Math.round(periodLogs.reduce((a,e) => a + e.calories, 0) / loggedDays);
          const dWeight = last.weight - first.weight; // kg
          // 1 kg yağ ≈ 7700 kcal → günlük enerji açığı/fazlası
          const dailySurplus = (dWeight * 7700) / spanDays;
          const tdee = Math.round(avgIntake - dailySurplus);
          const trend = dWeight > 0.2 ? `+${dWeight.toFixed(1)}kg` : dWeight < -0.2 ? `${dWeight.toFixed(1)}kg` : 'sabit';
          const cover = Math.round(loggedDays / (spanDays + 1) * 100);
          tdeeCard = `
          <div style="background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:20px">
            <div style="font-size:11px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px">⚖️ Gerçek Bakım Kalorin (TDEE)</div>
            <div style="display:flex;align-items:baseline;gap:8px">
              <div style="font-family:'Barlow Condensed',sans-serif;font-size:30px;font-weight:800;color:var(--accent-text)">~${tdee}</div>
              <div style="font-size:13px;color:var(--text2)">kcal/gün</div>
            </div>
            <div style="font-size:11.5px;color:var(--text3);margin-top:4px;line-height:1.5">Son ${spanDays} günde ort. ${avgIntake} kcal yedin, kilon ${trend} (${first.weight}→${last.weight}kg). Formül değil, kendi vücudunun ölçümü.${cover < 70 ? ' ⚠️ Sadece günlerin %' + cover + String.fromCharCode(39) + 'i kayıtlı — doğruluk düşük olabilir.' : ''}</div>
          </div>`;
        }
      }
    }
    if (!tdeeCard) {
      tdeeCard = `<div style="background:var(--surface2);border:1px dashed var(--border);border-radius:12px;padding:12px;margin-bottom:20px;font-size:12px;color:var(--text3);line-height:1.5">⚖️ <b style="color:var(--text2)">Gerçek TDEE tahmini</b> için en az 14 gün arayla 2 kilo ölçümü + o aralıkta 10 gün beslenme kaydı gerekiyor. Veri biriktikçe burada bakım kalorin görünecek.</div>`;
    }
  }
  el.innerHTML = `
    <div style="padding:16px 20px 8px">
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px">
        <div class="ex-prog-stat"><div class="ex-prog-stat-num">${avgKcal}</div><div class="ex-prog-stat-lbl">⚡ Ort. Kcal</div></div>
        <div class="ex-prog-stat"><div class="ex-prog-stat-num">${avgProtein}g</div><div class="ex-prog-stat-lbl">🥩 Ort. Protein</div></div>
        <div class="ex-prog-stat"><div class="ex-prog-stat-num">${allTimeDaysWithData}/${daysActive}</div><div class="ex-prog-stat-lbl">📅 Kayıtlı Gün</div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:20px">
        <div style="background:var(--surface2);border-radius:12px;padding:12px;border:1px solid var(--border)">
          <div style="font-size:11px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px">Kalori Hedefi</div>
          <div style="height:6px;background:var(--surface3);border-radius:3px;overflow:hidden"><div style="height:100%;width:${Math.min(100,avgKcalPct)}%;background:${avgKcalPct>=100?'var(--danger)':avgKcalPct>=50?'#3b82f6':'var(--accent)'};border-radius:3px;transition:width 0.6s ease"></div></div>
          <div style="font-size:12px;color:var(--text2);margin-top:4px">${avgKcalPct}% ortalama</div>
        </div>
        <div style="background:var(--surface2);border-radius:12px;padding:12px;border:1px solid var(--border)">
          <div style="font-size:11px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px">Protein Hedefi</div>
          <div style="height:6px;background:var(--surface3);border-radius:3px;overflow:hidden"><div style="height:100%;width:${Math.min(100,avgProtPct)}%;background:${avgProtPct>=100?'#f59e0b':avgProtPct>=50?'#3b82f6':'var(--accent)'};border-radius:3px;transition:width 0.6s ease"></div></div>
          <div style="font-size:12px;color:var(--text2);margin-top:4px">${avgProtPct}% ortalama</div>
        </div>
      </div>
      ${tdeeCard}
    </div>

    <div style="padding:0 20px 8px">
      <div class="section-title" style="margin-bottom:8px">📊 SON 7 GÜN — KALORİ</div>
      <div class="chart-card"><div class="chart-canvas-wrap"><canvas id="nut-kcal-chart" style="height:160px"></canvas></div></div>
    </div>
    <div style="padding:12px 20px 8px">
      <div class="section-title" style="margin-bottom:8px">🥩 SON 7 GÜN — PROTEİN</div>
      <div class="chart-card"><div class="chart-canvas-wrap"><canvas id="nut-prot-chart" style="height:140px"></canvas></div></div>
    </div>
    <div style="padding:12px 20px 20px">
      <div class="section-title" style="margin-bottom:8px">GÜNLÜK DETAY</div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:6px 8px">
        <button onclick="nutStatMonthNav(-1)" aria-label="Önceki ay" ${canPrev?'':'disabled'} style="width:34px;height:34px;border-radius:10px;border:none;background:${canPrev?'var(--surface3)':'transparent'};color:${canPrev?'var(--text)':'var(--text3)'};font-size:16px;cursor:${canPrev?'pointer':'default'};opacity:${canPrev?1:0.35}">‹</button>
        <div style="text-align:center">
          <div style="font-family:'Barlow Condensed',sans-serif;font-size:17px;font-weight:700">${MONTH_NAMES[selM-1]} ${selY}</div>
          <div style="font-size:10px;color:var(--text3)">${monthDaysWithData.length} kayıtlı gün${monthAvgKcal?` · ort. ${monthAvgKcal} kcal`:''}</div>
        </div>
        <button onclick="nutStatMonthNav(1)" aria-label="Sonraki ay" ${canNext?'':'disabled'} style="width:34px;height:34px;border-radius:10px;border:none;background:${canNext?'var(--surface3)':'transparent'};color:${canNext?'var(--text)':'var(--text3)'};font-size:16px;cursor:${canNext?'pointer':'default'};opacity:${canNext?1:0.35}">›</button>
      </div>
      <div class="card" style="overflow:hidden">
        ${days.map(d => {
          const pctK = goals.kcal > 0 ? Math.min(100, Math.round(d.kcal/goals.kcal*100)) : 0;
          const pctP = goals.protein > 0 ? Math.min(100, Math.round(d.protein/goals.protein*100)) : 0;
          const isEmpty = d.kcal === 0;
          const entryCount = ST.nutritionLogs.filter(e => e.date === d.key).length;
          return `<div style="padding:10px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px${isEmpty?';opacity:0.38':''};cursor:${isEmpty?'default':'pointer'};transition:background 0.15s" onclick="${isEmpty?'':'openNutDayDetail(\''+d.key+'\')'}" ${isEmpty?'':'onmousedown="this.style.background=\'var(--surface2)\'" onmouseup="this.style.background=\'\'"'}>
            <div style="text-align:center;width:36px;flex-shrink:0">
              <div style="font-family:'Barlow Condensed',sans-serif;font-size:18px;font-weight:700">${d.dayNum}</div>
              <div style="font-size:10px;color:var(--text3);font-weight:600">${d.label}</div>
            </div>
            <div style="flex:1;min-width:0">
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px">
                <span style="color:var(--text2)">⚡ ${d.kcal} kcal</span>
                <span style="color:var(--text3)">${pctK}%</span>
              </div>
              <div style="height:4px;background:var(--surface3);border-radius:2px;margin-bottom:4px"><div style="height:100%;width:${pctK}%;background:${pctK>=100?'var(--danger)':pctK>=50?'#3b82f6':'var(--accent)'};border-radius:2px"></div></div>
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px">
                <span style="color:var(--text2)">🥩 ${d.protein}g protein</span>
                <span style="color:var(--text3)">${pctP}%</span>
              </div>
              <div style="height:4px;background:var(--surface3);border-radius:2px"><div style="height:100%;width:${pctP}%;background:${pctP>=100?'#f59e0b':pctP>=50?'#3b82f6':'var(--accent)'};border-radius:2px"></div></div>
            </div>
            ${!isEmpty ? `<div style="color:var(--text3);flex-shrink:0;display:flex;align-items:center;gap:3px"><span style="font-size:10px">${entryCount}</span><svg viewBox="0 0 24 24" style="width:12px;height:12px;stroke:var(--text3);fill:none;stroke-width:2"><polyline points="9 18 15 12 9 6"/></svg></div>` : ''}
          </div>`;
        }).join('')}
      </div>
    </div>
  `;

  setTimeout(() => {
    drawNutChart('nut-kcal-chart', chartDays.map(d=>d.kcal), chartDays.map(d=>d.label+'\n'+d.dayNum), goals.kcal, '#f05a22', 'kcal');
    drawNutChart('nut-prot-chart', chartDays.map(d=>d.protein), chartDays.map(d=>d.label+'\n'+d.dayNum), goals.protein, '#3b82f6', 'g');
  }, 60);
}

// Ay değiştir ve istatistik sekmesini yeniden çiz
function nutStatMonthNav(delta){
  const [y,m]=(window._nutStatMonth||'').split('-').map(Number);
  const d=new Date(y,m-1+delta,1);
  window._nutStatMonth=`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
  const el=document.getElementById('stats-inner');
  if(el) renderBeslenmeStats(el);
}

function drawNutChart(canvasId, data, labels, goalLine, color, unit) {  const canvas = document.getElementById(canvasId); if (!canvas) return;
  chartLabel(canvas, 'Son 7 gün ' + (unit === 'kcal' ? 'kalori' : 'protein') + ': ' + labels.map((l, i) => l.split('\n')[0] + ' ' + data[i] + ' ' + unit).join(', ') + (goalLine > 0 ? '. Hedef ' + goalLine + ' ' + unit : ''));
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width) return;
  canvas.width = rect.width * dpr; canvas.height = rect.height * dpr;
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
  const W = rect.width, H = rect.height;
  const pad = {top:22, right:14, bottom:28, left:44};
  const cW = W - pad.left - pad.right, cH = H - pad.top - pad.bottom;
  const max = Math.max(...data, goalLine, 1);
  const step = data.length > 1 ? cW / (data.length - 1) : cW;
  const gridColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim();
  const text2 = getComputedStyle(document.documentElement).getPropertyValue('--text2').trim();
  const text3 = getComputedStyle(document.documentElement).getPropertyValue('--text3').trim();

  // Grid lines
  ctx.strokeStyle = gridColor; ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = pad.top + cH * (1 - i/3);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left+cW, y); ctx.stroke();
    ctx.fillStyle = text2; ctx.font = '9px DM Sans'; ctx.textAlign = 'right';
    ctx.fillText(Math.round(max*i/3), pad.left-4, y+3);
  }

  // Goal line
  if (goalLine > 0) {
    const gy = pad.top + cH * (1 - goalLine/max);
    ctx.setLineDash([4,3]); ctx.strokeStyle = 'rgba(255,255,255,0.2)'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pad.left, gy); ctx.lineTo(pad.left+cW, gy); ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = 'rgba(255,255,255,0.35)'; ctx.font = 'bold 9px DM Sans'; ctx.textAlign = 'left';
    ctx.fillText('Hedef', pad.left+2, gy-3);
  }

  // Bar chart
  const barW = Math.max(4, cW / data.length * 0.55);
  data.forEach((v, i) => {
    const x = pad.left + i * step;
    const barH = v > 0 ? cH * (v/max) : 0;
    const y = pad.top + cH - barH;
    const pct = goalLine > 0 ? v/goalLine : 0;
    const barColor = pct >= 1 ? (unit==='g'?'#f59e0b':'var(--danger)') : pct >= 0.5 ? '#3b82f6' : color;
    ctx.fillStyle = barColor + 'cc';
    const r = Math.min(4, barW/2);
    ctx.beginPath();
    ctx.moveTo(x - barW/2 + r, y);
    ctx.lineTo(x + barW/2 - r, y);
    ctx.quadraticCurveTo(x + barW/2, y, x + barW/2, y + r);
    ctx.lineTo(x + barW/2, pad.top + cH);
    ctx.lineTo(x - barW/2, pad.top + cH);
    ctx.lineTo(x - barW/2, y + r);
    ctx.quadraticCurveTo(x - barW/2, y, x - barW/2 + r, y);
    ctx.closePath(); ctx.fill();
    // Value label on top of bar
    if (v > 0) {
      ctx.fillStyle = text2; ctx.font = 'bold 8px DM Sans'; ctx.textAlign = 'center';
      ctx.fillText(v, x, y - 3);
    }
    // Day label
    const parts = labels[i].split('\n');
    ctx.fillStyle = text3; ctx.font = '8px DM Sans'; ctx.textAlign = 'center';
    ctx.fillText(parts[0], x, H - pad.bottom + 10);
    ctx.fillText(parts[1]||'', x, H - pad.bottom + 19);
  });
}


function animateSetComplete(isWarmup) {
  const btn = document.getElementById('wo-complete-btn');
  if (!btn) return;
  btn.classList.remove('set-flash', 'warmup-flash');
  void btn.offsetWidth;
  btn.classList.add(isWarmup ? 'warmup-flash' : 'set-flash');
  setTimeout(() => btn.classList.remove('set-flash', 'warmup-flash'), 500);
}

function animateCount(el, target, duration) {
  if (!el) return;
  const start = performance.now();
  const tick = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const ease = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(ease * target);
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

let _prBannerTimer = null;
function showMidWorkoutPR(exName, value, isWeight = true) {
  const banner = document.getElementById('pr-banner-inner');
  if (!banner) return;
  banner.textContent = `🏆 REKOR! ${value}${isWeight ? 'kg' : ' tekrar'}`;
  banner.classList.add('show');
  if (_prBannerTimer) clearTimeout(_prBannerTimer);
  _prBannerTimer = setTimeout(() => banner.classList.remove('show'), 2800);
}

function launchConfetti() {
  const colors = ['#f05a22','#f59e0b','#22c55e','#3b82f6','#a855f7','#ec4899','#ffffff'];
  for (let i = 0; i < 72; i++) {
    const el = document.createElement('div');
    el.className = 'confetti-piece';
    const hue = colors[Math.floor(Math.random() * colors.length)];
    const x = Math.random() * 100;
    const delay = Math.random() * 0.7;
    const dur = 1.6 + Math.random() * 1.2;
    const size = 6 + Math.random() * 8;
    el.style.cssText = `left:${x}vw;width:${size}px;height:${size}px;background:${hue};animation-duration:${dur}s;animation-delay:${delay}s;border-radius:${Math.random()>0.5?'50%':'2px'}`;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), (dur + delay + 0.3) * 1000);
  }
}

// ============================================================
// BESLENME (NUTRITION)
// ============================================================

function todayDateKey() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}

function getTodayNutrition() {
  const key = todayDateKey();
  return ST.nutritionLogs.filter(e => e.date === key);
}

function calcNutritionGoals(isWorkoutDay) {
  // Kullanıcının girdiği hedef varsa o, yoksa kiloya göre otomatik. Her hedef
  // AYRI değerlendirilir: yalnızca kaloriyi girmiş biri eskiden ikisi de yok
  // sayılıp sessizce otomatik değerlere dönüyordu.
  const s = ST.settings;
  // Kilo: son ölçüm → Ayarlar'daki vücut ağırlığı → 75. (Eskiden Ayarlar'a girilen
  // kilo burada hiç kullanılmıyordu; ölçüm eklemeyen herkes 75 kg sanılıyordu.)
  const weight = _bodyWeight() || 75;
  const isMale = (s.gender || 'male') === 'male';
  const autoKcal = isWorkoutDay
    ? (isMale ? Math.round(weight * 36) : Math.round(weight * 34))
    : (isMale ? Math.round(weight * 30) : Math.round(weight * 28));
  const autoProtein = Math.round(weight * 2);

  const customKcal = +s.nutritionGoalKcal > 0, customProt = +s.nutritionGoalProtein > 0;
  const kcal = customKcal
    ? (isWorkoutDay ? s.nutritionGoalKcal : Math.round(s.nutritionGoalKcal * 0.85))
    : autoKcal;
  const protein = customProt
    ? (isWorkoutDay ? s.nutritionGoalProtein : Math.round(s.nutritionGoalProtein * 0.9))
    : autoProtein;
  // Makro oranları kalori kaynağına göre: elle girilen hedefte %40/%25, otomatikte %42/%28
  const cR = customKcal ? 0.40 : 0.42, fR = customKcal ? 0.25 : 0.28;
  return {kcal, protein, carbs: Math.round((kcal * cR) / 4), fat: Math.round((kcal * fR) / 9)};
}

function getScheduledDayType() {
  // Takvimle ilerletilmiş döngü pozisyonuna göre bugün antrenman mı dinlenme mi?
  const routine = activeRoutine();
  if (!routine) return null;
  const info = getTodayDayInfo(routine);
  if (!info || !info.day) return null;
  if (info.done) return 'workout';
  const day = info.day;
  const isRest = day.isRest || !day.exercises || day.exercises.filter(e => !e.disabled).length === 0;
  return isRest ? 'rest' : 'workout';
}

function isTodayWorkoutDay() {
  // 1. Bugün antrenman logu var mı? (workout tamamlandıysa kesin antrenman günü)
  if (todaysLogs().length) return true;
  // 2. Döngü programına bak (antrenman tamamlanmadan da doğru hedefleri göster)
  const scheduled = getScheduledDayType();
  if (scheduled !== null) return scheduled === 'workout';
  return false;
}

let _nutWorkoutMode = null; // null = auto-detect

function renderBeslenme() {
  // Kullanıcı yazıyorsa sıfırlanmasın
  const savedInput = document.getElementById('nut-input')?.value || '';

  const el = document.getElementById('beslenme-content');
  const s = ST.settings;
  const hasKey = !!s.geminiKey?.trim();
  const entries = getTodayNutrition();
  const isWorkout = _nutWorkoutMode !== null ? _nutWorkoutMode : isTodayWorkoutDay();
  const goals = calcNutritionGoals(isWorkout);

  const totals = entries.reduce((acc, e) => {
    acc.kcal += e.calories || 0;
    acc.protein += e.protein || 0;
    acc.carbs += e.carbs || 0;
    acc.fat += e.fat || 0;
    return acc;
  }, {kcal:0, protein:0, carbs:0, fat:0});

  const pct = (v,g) => Math.min(150, g > 0 ? Math.round(v/g*100) : 0);
  const kcalPct = pct(totals.kcal, goals.kcal);
  const proteinPct = pct(totals.protein, goals.protein);
  const carbsPct = pct(totals.carbs, goals.carbs);

  // Dinamik renk: 0-50% turuncu, 50-90% mavi, 100%+ yeşil; kalori 100%+ tehlike
  const barColor = (p, isProtein=false, isKcal=false) => {
    if (isKcal && p >= 100) return 'var(--danger)';
    if (p >= 100) return isProtein ? '#f59e0b' : 'var(--success)';
    if (p >= 50) return '#3b82f6';
    return 'var(--accent)';
  };
  const kcalColor = barColor(kcalPct, false, true);
  const proteinColor = barColor(proteinPct, true);
  const carbsColor = barColor(carbsPct);

  // AKILLI KÖPRÜ: Bugünkü antrenman programını analiz et
  let bridgeBanner = '';
  const _activeRoutine = activeRoutine();
  if (_activeRoutine) {
    const _info = getTodayDayInfo(_activeRoutine);
    const _todayDay = _info && _info.day;
    if (_todayDay && !_todayDay.isRest && _todayDay.exercises && _todayDay.exercises.length > 0) {
      const _groups = [...new Set(_todayDay.exercises.map(de => { const ex = getExercise(de.exId); return ex ? ex.group : ''; }).filter(Boolean))];
      const _hasLegs = _groups.includes('legs');
      const _hasPush = _groups.includes('push');
      const _hasPull = _groups.includes('pull');
      let _icon = '🏋️', _msg = '';
      if (_hasLegs) { _icon = '🦵'; _msg = 'Bacak günü! Yıkım büyük — protein hedefine sadık kal, karbonhidratı ihmal etme.'; }
      else if (_hasPush && _hasPull) { _icon = '💥'; _msg = 'Tam üst vücut günü! Kas onarımı için proteine odaklan.'; }
      else if (_hasPush) { _icon = '🫸'; _msg = 'İtiş günü! Göğüs & omuz için protein kritik.'; }
      else if (_hasPull) { _icon = '🫷'; _msg = 'Çekiş günü! Sırt & bicep onarımı için proteini tamamla.'; }
      else { _icon = '💪'; _msg = 'Antrenman günü! Kalori ve protein hedeflerini tut.'; }
      const _proteinWarn = proteinPct < 60 ? ' <span style="color:#f59e0b;font-weight:700">⚠ Protein düşük!</span>' : '';
      bridgeBanner = `<div style="margin:0 20px 12px;background:linear-gradient(135deg,rgba(59,130,246,0.13),rgba(59,130,246,0.04));border:1px solid rgba(59,130,246,0.28);border-radius:14px;padding:12px 14px;display:flex;align-items:flex-start;gap:10px"><div style="font-size:20px;flex-shrink:0;margin-top:1px">${_icon}</div><div><div style="font-size:12px;font-weight:700;color:#3b82f6;margin-bottom:2px">${esc(_todayDay.emoji)} ${translateDayNameH(_todayDay.name)}</div><div style="font-size:12px;color:var(--text2);line-height:1.5">${_msg}${_proteinWarn}</div></div></div>`;
    }
  }

  const d = new Date();
  const dateStr = d.toLocaleDateString('tr-TR',{weekday:'long',day:'numeric',month:'long'});

  el.innerHTML = `
    <div class="greeting-block" style="padding-bottom:4px">
      <div class="greeting-name">🍽️ Beslenme</div>
      <div class="greeting-sub">${dateStr}</div>
    </div>

    <div style="height:12px"></div>

    ${bridgeBanner}

    <div class="nut-day-type">
      <div class="nut-day-btn ${isWorkout ? 'active' : ''}" onclick="setNutDayType(true)">💪 Antrenman Günü</div>
      <div class="nut-day-btn ${!isWorkout ? 'active' : ''}" onclick="setNutDayType(false)">😴 Dinlenme Günü</div>
    </div>
    ${_nutWorkoutMode !== null
      ? `<div style="text-align:center;margin:-4px 20px 4px"><button onclick="_nutWorkoutMode=null;renderBeslenme()" style="font-size:11px;color:var(--text3);background:none;border:none;cursor:pointer;padding:4px 8px">🔄 Otomatik algılamaya dön</button></div>`
      : `<div style="text-align:center;margin:-4px 20px 4px;font-size:11px;color:var(--text3)">🤖 Program döngüsünden otomatik algılandı</div>`
    }

    <div class="nut-goal-card">
      <div class="nut-macros-row">
        <div class="nut-macro">
          <div class="nut-macro-val" style="color:${kcalColor}">${totals.kcal}</div>
          <div class="nut-macro-bar-wrap"><div class="nut-macro-bar nut-bar-kcal" style="width:${Math.min(100,kcalPct)}%;background:${kcalColor}"></div></div>
          <div class="nut-macro-lbl">KKALORİ</div>
          <div class="nut-macro-goal">/ ${goals.kcal} kcal</div>
        </div>
        <div class="nut-macro">
          <div class="nut-macro-val" style="color:${proteinColor}">${Math.round(totals.protein)}</div>
          <div class="nut-macro-bar-wrap"><div class="nut-macro-bar" style="width:${Math.min(100,proteinPct)}%;background:${proteinColor}"></div></div>
          <div class="nut-macro-lbl">PROTEİN</div>
          <div class="nut-macro-goal">/ ${goals.protein}g</div>
        </div>
        <div class="nut-macro">
          <div class="nut-macro-val" style="color:var(--warning)">${Math.round(totals.carbs)}</div>
          <div class="nut-macro-bar-wrap"><div class="nut-macro-bar" style="width:${Math.min(100,carbsPct)}%;background:${carbsColor}"></div></div>
          <div class="nut-macro-lbl">KARBONHİDRAT</div>
          <div class="nut-macro-goal">/ ${goals.carbs}g</div>
        </div>
      </div>
    </div>

    <div class="nut-add-wrap${(ST.mealRoutines||[]).length?' has-star':''}">
      <input class="nut-add-input" id="nut-input" placeholder='Örn: "200gr tavuk göğsü" veya fotoğraf seçince açıklama ekle...' onkeydown="if(event.key===\'Enter\')addNutritionEntry()" autocomplete="off">
      ${(ST.mealRoutines||[]).length
        ? `<button class="nut-star-btn" onclick="openRoutinePicker()" title="Rutinlerim">⭐</button>` : ''}
      ${_nutSelectedPhotos.length > 0
        ? `<button class="nut-cam-btn" id="nut-cam-btn" onclick="clearNutPhotos()" title="Fotoğrafları temizle" style="background:rgba(239,68,68,0.15);border-color:rgba(239,68,68,0.4)"><svg viewBox="0 0 24 24" style="stroke:var(--danger)"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`
        : `<button class="nut-cam-btn" id="nut-cam-btn" onclick="document.getElementById(\'nut-photo-input\').click()" title="Fotoğraftan analiz et"><svg viewBox="0 0 24 24"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg></button>`
      }
      <button class="nut-add-btn" id="nut-add-btn" onclick="addNutritionEntry()" aria-label="Öğünü ekle">
        ${_nutSelectedPhotos.length > 0
          ? `<svg viewBox="0 0 24 24"><path d="M22 2L11 13"/><path d="M22 2L15 22 11 13 2 9l20-7z"/></svg>`
          : `<svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`
        }
      </button>
    </div>
    ${(() => {
      // HIZLI TEKRAR: son 14 günün en sık girilen öğeleri (hatasız, kalorili)
      const cutoff = new Date(); cutoff.setDate(cutoff.getDate() - 14);
      const cutKey = `${cutoff.getFullYear()}-${String(cutoff.getMonth()+1).padStart(2,'0')}-${String(cutoff.getDate()).padStart(2,'0')}`;
      const freq = {};
      for (const e of ST.nutritionLogs) {
        if (e.date < cutKey || e.error || e.pending || !e.calories) continue;
        const k = _foodNorm(e.name);
        if (!k) continue;
        if (!freq[k]) freq[k] = { count: 0, latest: e };
        freq[k].count++;
        if ((e.createdAt||0) > (freq[k].latest.createdAt||0)) freq[k].latest = e;
      }
      const chips = Object.values(freq)
        .filter(f => f.count >= 2)
        .sort((a,b) => b.count - a.count).slice(0,5);

      // ÖĞRENİLMİŞ RUTİNLER önce gelir: en sık ve en yakın zamanda kullanılan
      // başta. Tek dokunuşla tüm öğün eklenir.
      const routines = [...(ST.mealRoutines||[])]
        .sort((a,b) => (b.useCount||0)-(a.useCount||0) || (b.lastUsedAt||0)-(a.lastUsedAt||0))
        .slice(0,4);

      if (!chips.length && !routines.length) return '';
      return `<div style="display:flex;gap:6px;overflow-x:auto;padding:2px 20px 6px;-webkit-overflow-scrolling:touch;scrollbar-width:none">
        ${routines.map(r => {
          // Tarifte kalem toplamı değil 100 g başına değer anlamlı
          const kcal = r.type==='recipe'
            ? (r.per100 ? r.per100.kcal : 0)
            : Math.round(r.items.reduce((a,i)=>a+(i.calories||0),0));
          return `<span style="flex-shrink:0;display:inline-flex;align-items:center;border-radius:20px;background:var(--accent-dim);border:1.5px solid var(--accent);white-space:nowrap;overflow:hidden">
            <button onclick="applyRoutineFromChip('${r.id}')" style="display:inline-flex;align-items:center;gap:5px;padding:7px 4px 7px 12px;background:transparent;border:none;color:var(--accent-text);font-size:12.5px;font-weight:700;cursor:pointer;white-space:nowrap">${r.type==='recipe'?'🍲':'⭐'} ${esc(r.name)}<span style="opacity:.75;font-weight:500">${kcal}${r.type==='recipe'?'/100g':''}</span></button>
            <button onclick="openRoutineEdit('${r.id}')" title="Düzenle" style="padding:7px 10px 7px 6px;background:transparent;border:none;color:var(--accent-text);opacity:.7;font-size:13px;cursor:pointer">⋯</button>
          </span>`;
        }).join('')}
        ${chips.map(c => `<button onclick="quickRepeatEntry('${c.latest.id}')" style="flex-shrink:0;display:inline-flex;align-items:center;gap:5px;padding:7px 12px;border-radius:20px;background:var(--surface2);border:1.5px solid var(--border);color:var(--text);font-size:12.5px;font-weight:600;cursor:pointer;white-space:nowrap">${esc(c.latest.emoji||'🍽️')} ${esc(c.latest.name)}<span style="color:var(--text3);font-weight:500">${Math.round(c.latest.calories)}</span></button>`).join('')}
      </div>`;
    })()}
    ${_nutSelectedPhotos.length > 0 ? `
    <div class="nut-photo-strip" id="nut-photo-strip">
      ${_nutSelectedPhotos.map((p,i) => `
        <div class="nut-photo-thumb">
          <img src="${p.dataUrl}" alt="Fotoğraf ${i+1}">
          <button class="nut-photo-thumb-del" onclick="removeNutPhoto(${i})">✕</button>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:0 20px;margin-bottom:12px">
      <div class="section-title" style="padding:0;margin:0">BUGÜNKÜ ÖĞÜNLER</div>
      ${entries.filter(e=>!e.pending&&!e.error).length >= 1 ? `
        <button onclick="toggleRoutineSelectMode()" style="flex-shrink:0;padding:5px 11px;border-radius:20px;font-size:11.5px;font-weight:700;cursor:pointer;background:${_routineSelectMode?'var(--accent)':'var(--surface2)'};color:${_routineSelectMode?'#fff':'var(--text2)'};border:1.5px solid ${_routineSelectMode?'var(--accent)':'var(--border)'}">${_routineSelectMode?'Vazgeç':'⭐ Rutin yap'}</button>
      ` : ''}
    </div>
    ${_routineSelectMode ? `
      <div style="margin:0 20px 12px;padding:11px 13px;border-radius:12px;background:var(--accent-dim);border:1px solid var(--accent);font-size:12.5px;color:var(--text);line-height:1.5">
        Rutine girecek öğeleri seç, sonra kaydet. Bir daha yazdığında hepsi birden eklenir.
        <button onclick="createRoutineFromSelection()" style="display:block;width:100%;margin-top:10px;padding:9px;border-radius:10px;background:var(--accent);color:#fff;border:none;font-size:13px;font-weight:700;cursor:pointer">${_routineSelected.size} öğeyi rutin yap</button>
      </div>
    ` : ''}
    <div class="nut-entry-list">${_nutListHTML(entries)}</div>
    <div style="height:20px"></div>
  `;

  // Input değerini geri yükle (AI analiz beklerken yazı sıfırlanmasın)
  if (savedInput) {
    const inputEl = document.getElementById('nut-input');
    if (inputEl) { inputEl.value = savedInput; inputEl.setSelectionRange(savedInput.length, savedInput.length); }
  }

  // Rutin tekrarı kontrolü. Her yeniden çizim zamanlayıcıyı ileri atar, yani
  // kullanıcı öğününü yazmayı BİTİRDİKTEN sonra bir kez çalışır.
  _scheduleRoutineCheck();
}

function setNutDayType(isWorkout) {
  _nutWorkoutMode = isWorkout;
  renderBeslenme();
}


