// ============================================================
// EXERCISE LIBRARY
// ============================================================
const EXERCISES = [
  {id:'overhead_press',name:'Standing Overhead Press',muscle:'Front Delt',group:'push',equipment:'Z-Bar / Dumbbell',type:'reps',sets:{b:4,i:4,a:4,e:5},reps:{b:6,i:8,a:10,e:12},tip:'Brace your core tight, avoid arching lower back. This is the king of overhead movements.',tip_tr:'Koru sıkı tut, bel yaylanmasını engelle. Baş üstü hareketlerin kralı.'},
  {id:'weighted_pushup',name:'Weighted Push-Up',muscle:'Chest',group:'push',equipment:'Backpack / Bodyweight',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:8,i:12,a:15,e:20},tip:'Load a backpack on your back to increase difficulty. Best bench-free chest builder.',tip_tr:'Sırtına sırt çantası takarak zorluk artır. Bench olmadan en iyi göğüs egzersizi.'},
  {id:'pushup',name:'Push-Up',muscle:'Chest',group:'push',equipment:'Bodyweight',type:'reps',sets:{b:3,i:3,a:4,e:5},reps:{b:10,i:15,a:20,e:30},tip:'Elbows at 45°. Chest touches the floor, explosive on the way up.',tip_tr:'Dirsekler 45° açıyla. Göğüs yere değsin, yukarı patlayarak çık.'},
  {id:'diamond_pushup',name:'Diamond Push-Up',muscle:'Triceps / Chest',group:'push',equipment:'Bodyweight',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:8,i:12,a:18,e:25},tip:'Thumbs touch. Best bodyweight triceps exercise.',tip_tr:'Başparmaklar birbirine değsin. En iyi vücut ağırlıklı triceps egzersizi.'},
  {id:'floor_press',name:'Dumbbell Floor Press',muscle:'Chest / Triceps',group:'push',equipment:'Dumbbell',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:10,i:12,a:15,e:15},tip:'Lie on your back. Pause when elbows touch floor, then explode up.',tip_tr:'Sırt üstü yat. Dirsekler yere değince dur, sonra patlayarak it.'},
  {id:'pike_pushup',name:'Pike Push-Up',muscle:'Front Delt',group:'push',equipment:'Bodyweight',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:8,i:12,a:15,e:20},tip:'Hips high in a V shape. Head goes toward the floor. Handstand prep.',tip_tr:'Kalçaları yükseğe kaldır, V şekli yap. Kafa yere doğru iner. El duruşu hazırlığı.'},
  {id:'lateral_raise',name:'Lateral Raise',muscle:'Lateral Delt',group:'push',equipment:'Dumbbell',type:'reps',sets:{b:4,i:4,a:4,e:4},reps:{b:10,i:12,a:15,e:20},tip:'Slight bend in elbows, lead with elbows not hands. Most important shoulder width exercise.',tip_tr:'Dirseği hafif kır, elleri değil dirseği öne çek. Omuz genişliği için en kritik egzersiz.'},
  {id:'rear_delt_fly',name:'Rear Delt Fly',muscle:'Rear Delt',group:'pull',equipment:'Dumbbell',type:'reps',sets:{b:3,i:3,a:3,e:4},reps:{b:12,i:15,a:15,e:20},tip:'Torso parallel to floor. Sweep arms back like wings. This is a pulling muscle!',tip_tr:'Gövde yere paralel. Kolları kanat gibi geriye süpür. Arka omuz anatomik olarak çekiş kasıdır!'},
  {id:'skullcrusher',name:'Skullcrusher',muscle:'Triceps',group:'push',equipment:'Z-Bar',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:10,i:12,a:12,e:15},tip:'Lower bar to forehead while lying. Keep elbows pinned and stationary.',tip_tr:'Bar uzanırken alna doğru iner. Dirsekler sabit ve hareketsiz kalmalı.'},
  {id:'dips',name:'Chair Dips',muscle:'Triceps / Chest',group:'push',equipment:'Chair / Bench',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:8,i:12,a:15,e:20},tip:'Keep elbows close to body for triceps focus.',tip_tr:'Triceps odağı için dirsekleri gövdeye yakın tut.'},
  {id:'wall_handstand',name:'Wall Handstand Hold',muscle:'Shoulder / Core',group:'push',equipment:'Wall',type:'time',sets:{b:3,i:3,a:3,e:4},dur:{b:20,i:30,a:45,e:60},tip:'Back to wall, hands shoulder width. Hollow body — belly button faces up not out.',tip_tr:'Sırt duvara yaslan, eller omuz genişliğinde. Hollow body — göbek deliği dışarı değil yukarı bakmalı.'},
  {id:'pullup',name:'Pull-Up',muscle:'Lats (Width)',group:'pull',equipment:'Pull-Up Bar',type:'reps',sets:{b:4,i:4,a:4,e:5},reps:{b:3,i:6,a:10,e:15},tip:'Get chin above bar. Use resistance band or do negatives if needed.',tip_tr:'Çeneyi barın üzerine çıkar. Gerekirse direnç bandı kullan ya da negatif tekrarlar yap.'},
  {id:'bent_row',name:'Bent Over Row',muscle:'Back (Thickness)',group:'pull',equipment:'Z-Bar',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:8,i:10,a:12,e:15},tip:'Keep back flat, pull bar to belly button. Squeeze shoulder blades together.',tip_tr:'Sırtı düz tut, barı göbek deliğine doğru çek. Kürek kemiklerini birbirine yaklaştır.'},
  {id:'single_row',name:'Single Arm Dumbbell Row',muscle:'Lats',group:'pull',equipment:'Dumbbell',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:10,i:12,a:12,e:15},tip:'Plant one hand on bench, pull dumbbell toward hip. Elbow skims body.',tip_tr:'Bir elin banka yaslan, dambıl kalçaya doğru çek. Dirsek gövdeye yakın kayar.'},
  {id:'shrug',name:'Shrug',muscle:'Trapezius',group:'pull',equipment:'Z-Bar / Dumbbell',type:'reps',sets:{b:3,i:3,a:3,e:4},reps:{b:12,i:15,a:15,e:20},tip:'Elevate shoulders toward ears without bending elbows. Safer than upright row.',tip_tr:'Omuzları kulaklara doğru kaldır, dirsekler bükülmez. Barbell çekişinden daha güvenli.'},
  {id:'zbar_curl',name:'Z-Bar Curl',muscle:'Biceps',group:'pull',equipment:'Z-Bar',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:8,i:10,a:12,e:15},tip:'Elbows glued to sides, no swinging.',tip_tr:'Dirsekler yanlara yapışık, sallanma yok.'},
  {id:'hammer_curl',name:'Hammer Curl',muscle:'Brachialis / Forearm',group:'pull',equipment:'Dumbbell',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:10,i:12,a:12,e:15},tip:'Grip dumbbells like hammer handles. Adds thickness and arm size.',tip_tr:'Dambılları çekiç gibi tut. Kol kalınlığı ve underarm boyutu için idealdir.'},
  {id:'wrist_curl',name:'Wrist Curl',muscle:'Forearm Flexors',group:'pull',equipment:'Z-Bar / Dumbbell',type:'reps',sets:{b:3,i:3,a:3,e:3},reps:{b:15,i:15,a:20,e:20},tip:'Forearms rest on thighs, palms up. Only the wrist moves. For handstand grip.',tip_tr:'Kollar uyluğa yaslanır, avuç içi yukarı. Sadece bilek hareket eder. El duruşu kavraması için.'},
  {id:'reverse_wrist_curl',name:'Reverse Wrist Curl',muscle:'Forearm Extensors',group:'pull',equipment:'Z-Bar / Dumbbell',type:'reps',sets:{b:3,i:3,a:3,e:3},reps:{b:15,i:15,a:20,e:20},tip:'Forearms on thighs, palms down. Critical for handstand wrist balance.',tip_tr:'Kollar uyluğa yaslanır, avuç içi aşağı. El duruşu bilek dengesi için kritik.'},
  {id:'hollow_body',name:'Hollow Body Hold',muscle:'Core',group:'core',equipment:'Bodyweight',type:'time',sets:{b:3,i:3,a:3,e:4},dur:{b:20,i:30,a:45,e:60},tip:'Lie on back, arms overhead. Lower back pressed to floor. Everything slightly lifted.',tip_tr:'Sırt üstü yat, kollar başın üzerinde. Bel yere bastırılmış. Her şey hafifçe havada.'},
  {id:'plank',name:'Plank',muscle:'Core',group:'core',equipment:'Bodyweight',type:'time',sets:{b:3,i:3,a:4,e:4},dur:{b:30,i:45,a:60,e:90},tip:'Hips level. Breathe. Neutral spine.',tip_tr:'Kalçalar düz. Nefes al. Nötr omurga.'},
  {id:'crunches',name:'Crunches',muscle:'Abs',group:'core',equipment:'Bodyweight',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:15,i:20,a:25,e:30},tip:'Lift with upper back, not neck. Control the negative.',tip_tr:'Boyun değil, üst sırtla kaldır. Negatifi kontrollü yap.'},
  {id:'squat',name:'Bodyweight Squat',muscle:'Legs / Glutes',group:'legs',equipment:'Bodyweight',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:15,i:20,a:25,e:30},tip:'Knees track over toes. Push hips back and down.',tip_tr:'Dizler ayak parmak hizasında ilerlesin. Kalçaları geriye ve aşağıya it.'},
  {id:'lunge',name:'Walking Lunge',muscle:'Legs',group:'legs',equipment:'Bodyweight / Dumbbell',type:'reps',sets:{b:3,i:3,a:4,e:4},reps:{b:10,i:12,a:15,e:20},tip:'Front knee at 90°. Rear knee hovers above floor.',tip_tr:'Ön diz 90°. Arka diz yere değmeden hover etmeli.'},
  {id:'goblet_squat',name:'Goblet Squat',muscle:'Legs / Core',group:'legs',equipment:'Dumbbell',type:'reps',sets:{b:3,i:3,a:3,e:4},reps:{b:12,i:15,a:15,e:20},tip:'Hold a heavy dumbbell at chest height with both hands. Squat deep, elbows inside knees.',tip_tr:'Tek ağır dambıl göğüs hizasında iki elinle tut. Kalçanı iyice aşağı indir, dirsekler dizlerin içinde.'},
  {id:'bulgarian_split_squat',name:'Bulgarian Split Squat',muscle:'Quads / Glutes',group:'legs',equipment:'Dumbbell / Bodyweight',type:'reps',sets:{b:3,i:3,a:3,e:4},reps:{b:8,i:10,a:10,e:12},tip:'Rear foot on chair/bench, front foot forward. Dumbbells in hands double the feel. Most effective unilateral leg exercise.',tip_tr:'Arka ayağı koltuğa/sandalyeye yasla, ön ayak ileride. Elinde dambıllarla ağırlığı iki kat hissettir. Günün en önemli hareketi!'},
  {id:'romanian_deadlift',name:'Romanian Deadlift',muscle:'Hamstrings / Glutes',group:'legs',equipment:'Z-Bar / Dumbbell',type:'reps',sets:{b:3,i:3,a:3,e:4},reps:{b:10,i:12,a:12,e:15},tip:'Slight knee bend, bar/dumbbells stay close to legs. Hinge at hips, feel the stretch in hamstrings.',tip_tr:'Dizler hafifçe kırık, bar/dambıl bacaklara yakın kal. Kalçadan eğil, arka bacaktaki gerilimi hisset. Bel için kritik!'},
  {id:'dumbbell_lunge',name:'Dumbbell Lunge',muscle:'Legs / Glutes',group:'legs',equipment:'Dumbbell',type:'reps',sets:{b:3,i:3,a:3,e:4},reps:{b:12,i:12,a:12,e:15},tip:'Dumbbells in both hands, step forward and lunge down. Front knee at 90°. 12 reps = 24 total steps.',tip_tr:'İki elinde dambıllarla ileriye adım atarak çök. Ön diz 90°. 12 tekrar = 24 toplam adım.'},
  {id:'calf_raise',name:'Standing Calf Raise',muscle:'Calves',group:'legs',equipment:'Dumbbell / Bodyweight',type:'reps',sets:{b:3,i:3,a:3,e:4},reps:{b:15,i:20,a:20,e:25},tip:'Stand on edge of step for full range of motion. Hold dumbbells for extra load. Slow and controlled.',tip_tr:'Tam hareket aralığı için basamak kenarında dur. Ek yük için elinde dambıl tut. Yavaş ve kontrollü yap.'},
  {id:'wall_sit',name:'Wall Sit',muscle:'Quads / Glutes',group:'legs',equipment:'Wall',type:'time',sets:{b:3,i:3,a:3,e:3},dur:{b:30,i:45,a:60,e:60},tip:'Back flat against wall, thighs parallel to floor at 90°. Great endurance finisher.',tip_tr:'Sırt duvara yapışık, uyluğu yere paralel, 90° açı. Antrenman sonunda dayanıklılık ve yanma hissini maksimuma çıkarır.'},
];

function getExercise(id) {
  const all = [...EXERCISES, ...ST.customExercises];
  return all.find(e => e.id === id);
}

function getAllExercises() {
  return [...EXERCISES, ...ST.customExercises];
}

function getLK(level) {
  return {beginner:'b',intermediate:'i',advanced:'a',expert:'e'}[level] || 'i';
}
function getDefaultSets(ex,level) { return ex.sets?.[getLK(level)] || 3; }
function getDefaultReps(ex,level) {
  if (ex.type === 'time') return ex.dur?.[getLK(level)] || 30;
  return ex.reps?.[getLK(level)] || 10;
}

function getDefaultRoutines(level) {
  // Sets capped at 3 — better recovery management especially for home training
  const mk = (exId) => ({exId, sets:Math.min(getDefaultSets(getExercise(exId),level),3), reps:getDefaultReps(getExercise(exId),level), disabled:false});
  return [{
    id:'routine_default', name:'Push Pull Legs', emoji:'🏠', type:'cyclic', active:true, createdAt:Date.now(),
    days:[
      // Gün 1: İTME — Rear Delt Fly anatomik olarak çekiş kasıdır, Pull gününe alındı
      {id:'day_push',name:'PUSH',emoji:'💪',isRest:false,exercises:['overhead_press','weighted_pushup','floor_press','pike_pushup','lateral_raise','skullcrusher','wall_handstand'].map(mk)},
      // Gün 2: ÇEKİŞ — Rear Delt Fly buraya taşındı (doğru anatomik sınıflandırma)
      {id:'day_pull',name:'PULL',emoji:'🔗',isRest:false,exercises:['pullup',{...mk('bent_row'),disabled:true},'single_row','shrug','zbar_curl','hammer_curl','rear_delt_fly','wrist_curl','reverse_wrist_curl','hollow_body'].map(e=>typeof e==='string'?mk(e):e)},
      // Gün 3: BACAK — Evde dumbbell/z-bar ile tam bacak programı
      {id:'day_legs',name:'LEGS',emoji:'🦵',isRest:false,exercises:['goblet_squat','bulgarian_split_squat','romanian_deadlift','dumbbell_lunge','calf_raise','wall_sit'].map(mk)},
      // Gün 4: DİNLENME
      {id:'day_rest1',name:'Rest',emoji:'😴',isRest:true,exercises:[]},
    ]
  }];
}
