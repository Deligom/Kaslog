// ============================================================
// GÜN TAKİBİ (DÖNGÜ MOTORU)
// Kural: dinlenme günleri takvimle tükenir, antrenman günleri seni bekler.
// cyclePosition = "cycleDate gününün planı". Takvim ilerledikçe sadece
// dinlenme günleri otomatik yanar; kaçırılan antrenman günü yerinde kalır.
// ============================================================
const LONG_BREAK_DAYS = 7;

function dayKey(d){const x=d||new Date();return `${x.getFullYear()}-${String(x.getMonth()+1).padStart(2,'0')}-${String(x.getDate()).padStart(2,'0')}`;}
function keyToDate(k){const p=String(k||'').split('-').map(Number);return (p.length===3&&p.every(n=>!isNaN(n)))?new Date(p[0],p[1]-1,p[2]):null;}
function daysBetween(fromKey,toKey){const a=keyToDate(fromKey),b=keyToDate(toKey);if(!a||!b)return 0;return Math.round((b-a)/86400000);}
function shiftKey(k,delta){const d=keyToDate(k)||new Date();d.setDate(d.getDate()+delta);return dayKey(d);}
function activeRoutine(){const r=ST.routines.find(x=>x.id===ST.settings.activeRoutineId);return (r&&r.days&&r.days.length)?r:null;}
function normPos(p,len){len=len||1;return ((p|0)%len+len)%len;}

// Takvim ilerlemesini uygulayıp verilen günün döngü pozisyonunu bulur (yan etkisiz).
function resolveCyclePos(routine,atKey){
  if(!routine||!routine.days||!routine.days.length)return 0;
  const len=routine.days.length;
  let pos=normPos(ST.settings.cyclePosition,len);
  if(!ST.settings.cycleDate)return pos;
  let elapsed=daysBetween(ST.settings.cycleDate,atKey||dayKey());
  if(elapsed<=0)return pos;                        // aynı gün ya da çapa ileri tarihli
  if(routine.days.every(d=>d.isRest))return pos;   // tamamı dinlenme → sonsuz döngüye girme
  let guard=0;
  while(elapsed>0&&routine.days[pos].isRest&&guard++<len*2){pos=(pos+1)%len;elapsed--;}
  return pos;                                       // antrenman gününe gelince durur
}

// Bugünün pozisyonunu takvime göre ilerlet ve kalıcı yaz. Gün dönümünde de çağrılır.
async function syncCycle(){
  const routine=activeRoutine(); if(!routine)return false;
  const s=ST.settings, today=dayKey();
  let changed=false;
  if(!s.cycleDate){s.cycleDate=today;changed=true;}
  if(daysBetween(s.cycleDate,today)>0){
    const pos=resolveCyclePos(routine,today);
    if(pos!==normPos(s.cyclePosition,routine.days.length)){s.cyclePosition=pos;changed=true;}
    s.cycleDate=today;changed=true;
  }
  if(applyBreakRewind(routine))changed=true;
  if(changed)await DB.put('settings',{id:'main',...s});
  return changed;
}

function logDayKey(l){const d=l&&l.date?new Date(l.date):null;return (d&&!isNaN(d))?dayKey(d):'';}

function daysSinceLastWorkout(){
  let latest='';
  for(const l of ST.workoutLogs){const k=logDayKey(l);if(k>latest)latest=k;}
  if(!latest)return null;
  return Math.max(0,daysBetween(latest,dayKey()));
}

// Uzun ara: 7+ gün antrenman yoksa döngüyü ilk antrenman gününe sar (geri alınabilir).
function applyBreakRewind(routine){
  const s=ST.settings, gap=daysSinceLastWorkout();
  if(gap===null||gap<LONG_BREAK_DAYS){
    if(s.breakNotice){s.breakNotice=null;return true;}
    return false;
  }
  if(s.breakNotice){
    if(s.breakNotice.days!==gap){s.breakNotice={...s.breakNotice,days:gap};return true;}
    return false;
  }
  const first=routine.days.findIndex(d=>!d.isRest);
  if(first<0)return false;
  s.breakNotice={days:gap,prevPos:normPos(s.cyclePosition,routine.days.length),dismissed:false};
  s.cyclePosition=first; s.cycleDate=dayKey();
  return true;
}

async function undoBreakRewind(){
  const routine=activeRoutine(); const bn=ST.settings.breakNotice;
  if(!routine||!bn)return;
  ST.settings.cyclePosition=normPos(bn.prevPos,routine.days.length);
  ST.settings.cycleDate=dayKey();
  ST.settings.breakNotice={...bn,dismissed:true};
  await DB.put('settings',{id:'main',...ST.settings});
  renderBugun();
}

async function dismissBreakNotice(){
  if(!ST.settings.breakNotice)return;
  ST.settings.breakNotice={...ST.settings.breakNotice,dismissed:true};
  await DB.put('settings',{id:'main',...ST.settings});
  renderBugun();
}

function todaysLogs(routineId){
  const key=dayKey();
  return ST.workoutLogs.filter(l=>logDayKey(l)===key&&(!routineId||l.routineId===routineId));
}

// Bugün gerçekten ne yapıldı/yapılacak? Log varsa gerçek kazanır, yoksa döngü konuşur.
function getTodayDayInfo(routine){
  if(!routine||!routine.days||!routine.days.length)return null;
  const logs=todaysLogs(routine.id).filter(l=>l.dayId);
  if(logs.length){
    const last=logs.reduce((a,b)=>new Date(b.date)>new Date(a.date)?b:a);
    const idx=routine.days.findIndex(d=>d.id===last.dayId);
    if(idx>=0)return{pos:idx,day:routine.days[idx],done:true,logs};
  }
  const pos=resolveCyclePos(routine,dayKey());
  return{pos,day:routine.days[pos],done:false,logs:[]};
}

// pos bugünün planıysa yarın hangi gün? (dinlenme tükenir, antrenman bekler)
function peekDayAfter(routine,pos){
  const len=routine.days.length;
  if(routine.days.every(d=>d.isRest))return routine.days[(pos+1)%len];
  return routine.days[routine.days[pos].isRest?(pos+1)%len:pos];
}

// Uygulama gece boyu açık kalırsa gün dönümünü yakala.
let _lastSeenDay=null;
async function checkDayRollover(){
  const today=dayKey();
  if(_lastSeenDay===today)return;
  _lastSeenDay=today;
  await syncCycle();
  renderAll();
}

// startPos'tan itibaren ilk antrenman gününü başlat (dinlenmeleri atlar).
function startTrainingFrom(startPos){
  const routine=activeRoutine(); if(!routine)return;
  const len=routine.days.length;
  for(let i=0;i<len;i++){
    const d=routine.days[(startPos+i)%len];
    if(d.isRest)continue;
    if(!d.exercises||!d.exercises.length){
      showConfirm('📋',translateDayName(d.name),T('day_empty_sub'),()=>{closeModal('modal-alert');navTo('program');});
      return;
    }
    startWorkout(routine.id,d.id); return;
  }
}
