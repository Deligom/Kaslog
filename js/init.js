// ============================================================
// INIT
// ============================================================
async function init(){
  await DB.open();
  const savedSettings=await DB.get('settings','main');
  if(savedSettings){ST.settings={...ST.settings,...savedSettings};delete ST.settings.id;delete ST.settings.lang;}   // dil seçeneği kaldırıldı

  // URL key artık kullanılmıyor — proxy ile güvenli erişim sağlanıyor
  ST.routines=await DB.getAll('routines');
  ST.workoutLogs=await DB.getAll('workoutLogs');
  ST.measurements=await DB.getAll('measurements');
  ST.customExercises=await DB.getAll('customExercises');
  ST.nutritionLogs=await DB.getAll('nutritionLogs');
  ST.foodDb=await DB.getAll('foodDb');
  ST.mealRoutines=await DB.getAll('mealRoutines');

  // Uygulama kapalıyken tamamlanmış AI analizleri varsa hemen sonuçlandır;
  // geriye kalan yarım işleri yeniden başlat.
  _drainBgJobs().then(_recoverPendingMeals);
  loadDishTable();                 // data/yemekler.json (yoksa kademe atlanır)
  navigator.serviceWorker?.addEventListener('message', e => {
    if(e.data?.type==='nut-queue-flushed') _drainBgJobs();
  });
  document.addEventListener('visibilitychange',()=>{
    if(document.hidden) _registerNutSync();   // arka plana geçti → devri SW'ye ver
    else { _drainBgJobs(); checkDayRollover(); } // geri döndü → biten işleri yaz + gün değiştiyse döngüyü tazele
  });
  window.addEventListener('pagehide',()=>{ _registerNutSync(); });
  const allPrs=await DB.getAll('prs');
  allPrs.forEach(p=>{ST.prs[p.exId]=p;});
  // Migrate old PRs from settings store to prs store
  const allSettings=await DB.getAll('settings');
  for(const s of allSettings.filter(s=>s.id&&s.id.startsWith('pr_'))){
    if(!ST.prs[s.exId]){ST.prs[s.exId]=s;await DB.put('prs',s);}
    await DB.del('settings',s.id);
  }
  // Takvim ilerlemesini uygula: geçen dinlenme günleri yansın, uzun ara yakalansın.
  await syncCycle();
  _lastSeenDay=dayKey();
  setInterval(checkDayRollover,60000);
  window.addEventListener('focus',checkDayRollover);

  const circle=document.getElementById('rest-circle');
  if(circle){circle.style.strokeDasharray=restC;circle.style.strokeDashoffset=0;}
  if(savedSettings?.name){
    document.getElementById('splash').classList.add('hidden');
    document.getElementById('main').style.display='flex';
    applyTheme(ST.settings.theme||'dark');
    renderAll();
    offerWorkoutResume();
  }else{applyTheme('dark');}
}
init().catch(err=>{
  console.error('[kaslog] başlatma hatası:',err);
  // Başarısız açılışta sessizce onboarding'e düşmek yeni kullanıcıyı yanıltır
  // ve mevcut veriyle çakışabilir: nedenini söyle.
  const sp=document.getElementById('splash');
  if(sp) sp.innerHTML='<div class="splash-logo">KASLOG</div><div class="splash-sub" style="max-width:300px;line-height:1.5">Veritabanı açılamadı. Gizli sekme veya tarayıcı depolama kısıtı olabilir. Sayfayı yenile; sürerse tarayıcı verilerine izin ver.</div><button class="btn btn-primary" style="margin-top:20px" onclick="location.reload()">Yenile</button>';
});
// Tarayıcı depolamayı kalıcı işaretler: iOS/Android depolama baskısında ya da
// uzun kullanılmayan sitelerde IndexedDB'yi sessizce silebiliyor. Tüm antrenman
// geçmişi orada duruyor, bu yüzden izin istemek ucuz bir sigorta.
try{ navigator.storage?.persist?.().catch(()=>{}); }catch{}

if('serviceWorker' in navigator){
  window.addEventListener('load',()=>{
    navigator.serviceWorker.register('sw.js').catch(()=>{});
  });
}
