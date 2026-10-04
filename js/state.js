// ============================================================
// STATE
// ============================================================
let ST = {
  settings:{name:'',level:'intermediate',goal:'both',restTime:90,theme:'dark',cyclePosition:0,cycleDate:null,breakNotice:null,lastWorkoutDate:null,activeRoutineId:'routine_default',geminiKey:'',geminiModel:'gemini-3-flash-preview',gender:'male',nutritionGoalKcal:0,nutritionGoalProtein:0,soundEnabled:true,hapticEnabled:true,dismissedMealSigs:[],bodyWeight:0,dishPortions:{}},
  routines:[],
  workoutLogs:[],
  measurements:[],
  customExercises:[],
  nutritionLogs:[],
  foodDb:[],
  mealRoutines:[],
  activeTab:'bugun', prs:{},
  workout:null,
};
const _DEFAULT_SETTINGS = JSON.parse(JSON.stringify(ST.settings));   // yedekten ayar süzmek için şema

// ============================================================
// ONBOARDING
// ============================================================
let onboardData = {name:'',level:'',goal:''};
function nextStep(id) {
  if (id==='step-level') { const n=document.getElementById('onboard-name').value.trim(); if(!n){document.getElementById('onboard-name').focus();return;} onboardData.name=n; }
  if (id==='step-goal' && !onboardData.level) { return; }
  document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}
function selectLevel(el) { document.querySelectorAll('.level-card').forEach(c=>c.classList.remove('selected')); el.classList.add('selected'); onboardData.level=el.dataset.level; }
function selectGoal(el) { document.querySelectorAll('.goal-card').forEach(c=>c.classList.remove('selected')); el.classList.add('selected'); onboardData.goal=el.dataset.goal; }
async function finishOnboarding() {
  if (!onboardData.goal) return;
  ST.settings.name=onboardData.name; ST.settings.level=onboardData.level; ST.settings.goal=onboardData.goal;
  ST.settings.restTime={strength:180,hypertrophy:75,both:105}[onboardData.goal]||90;
  await DB.put('settings',{id:'main',...ST.settings});
  const routines=getDefaultRoutines(ST.settings.level);
  for(const r of routines) await DB.put('routines',r);
  ST.routines=routines;
  document.getElementById('splash').classList.add('hidden');
  document.getElementById('main').style.display='flex';
  applyTheme(ST.settings.theme);
  renderAll();
}

// ============================================================
// NAV
// ============================================================
function navTo(tab) {
  if(ST.activeTab===tab)return;
  // Bounce animation on nav icon
  document.querySelectorAll('.nav-item').forEach(n=>{
    if(n.dataset.tab===tab){n.classList.add('nav-tapped');setTimeout(()=>n.classList.remove('nav-tapped'),400);}
  });
  ST.activeTab=tab;
  document.querySelectorAll('.tab-section').forEach(s=>s.classList.remove('active'));
  document.getElementById('tab-'+tab).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.tab===tab));
  renderTab(tab);
}
function renderTab(tab) {
  if(tab==='bugun')renderBugun();
  else if(tab==='program')renderProgram();
  else if(tab==='beslenme')renderBeslenme();
  else if(tab==='istatistik')renderIstatistik();
  else if(tab==='ayarlar')renderAyarlar();
}
function renderAll(){renderTab(ST.activeTab);updateNavLabels();}

