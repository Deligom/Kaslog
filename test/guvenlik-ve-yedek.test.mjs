// ============================================================
// Kaslog güvenlik / yedek / veri bütünlüğü testleri
//
// Çalıştırma (bağımlılık yok, sadece Node 18+):
//   node test/guvenlik-ve-yedek.test.mjs
//
// index.html içindeki GERÇEK kod parçaları söküp çalıştırılır; testin
// kopyaladığı bir taklit değil. Kapsadığı hatalar, denetimde tarayıcıda
// BİREBİR yeniden üretilmiş olanlardır (bkz. her senaryonun açıklaması).
// ============================================================

import { HTML, BODY, JS, CSS, slice } from './_kaynak.mjs';

let pass = 0, fail = 0;
function check(label, actual, expected) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; console.log(`  ✓ ${label}`); }
  else { fail++; console.log(`  ✗ ${label}\n      beklenen: ${e}\n      gelen   : ${a}`); }
}
const scenario = n => console.log(`\n▸ ${n}`);

// ============================================================
scenario('HTML kaçışı (XSS): ad alanları script çalıştıramaz');
{
  const { esc } = new Function(slice('const _ESC_MAP', 'function translateDayNameH', 'esc') + 'return { esc };')();
  check('etiket kaçar', esc('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
  check('çift tırnak öznitelikten çıkaramaz', esc('a"b'), 'a&quot;b');
  check('tek tırnak', esc("a'b"), 'a&#39;b');
  check('& ilk kaçar (çift kaçış yok)', esc('A & B'), 'A &amp; B');
  check('null/undefined boş metin', [esc(null), esc(undefined)], ['', '']);
  check('sayı metne döner', esc(42), '42');
}

// ============================================================
scenario('CSV: tırnak ve formül enjeksiyonu');
{
  const { _csvCell, _csvText } = new Function(
    slice('function _csvCell', 'function exportCSV', 'csv') + 'return { _csvCell, _csvText };')();
  check('iç tırnak ikiye katlanır (satır bozulmaz)', _csvCell('form "iyi"'), '"form ""iyi"""');
  check('= ile başlayan metin formül olmaz', _csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"');
  check('+ - @ ile başlayanlar da', [_csvCell('+1'), _csvCell('-1x'), _csvCell('@SUM')], ['"\'+1"', '"\'-1x"', '"\'@SUM"']);
  check('negatif SAYI değişmez', _csvCell(-5), '"-5"');
  check('virgül hücreyi bölmez', _csvText([['a,b', 'c']]), '"a,b","c"');
}

// ============================================================
scenario('Yedek içe aktarma: geçersiz/kötü niyetli kayıtlar ayıklanır');
{
  const code = slice('const _BACKUP_ID_RE', '// Depoyu yedekle BİREBİR', 'yedek doğrulama');
  const { sanitizeBackup } = new Function(code + 'return { sanitizeBackup };')();
  const defaults = { name:'', theme:'dark', restTime:90, geminiKey:'', geminiModel:'gemini-3-flash-preview',
    activeRoutineId:'routine_default', cycleDate:null, breakNotice:null, soundEnabled:true, dismissedMealSigs:[] };

  const evil = {
    version: 'kaslog_v2',
    settings: { name:'Ali', geminiKey:'ATTACKER', geminiModel:'evil/../x', lang:'xx', theme:'dark',
      restTime:99999, cycleDate:'not-a-date', breakNotice:{ days:'<b>9</b>' }, bogus:1,
      activeRoutineId:"x');alert(1);//" },
    routines: [
      { id:'r_ok', name:'Rutin', days:[{ id:'d1', name:'PUSH', isRest:false, exercises:[{ exId:'pushup', sets:'3', reps:'12' }] }] },
      { id:"x');alert(1);//", name:'kötü id', days:[] },
      'metin', null, [],
    ],
    workoutLogs: [
      { id:'log_ok', date:'2026-01-05T09:00:00Z', duration:'30', totalVolume:'1000', exercises:[{ exId:'pushup', sets:[{ weight:'0', reps:'12' }] }] },
      { id:'log_bad', date:'garbage', exercises:[] },
    ],
    nutritionLogs: [
      { id:'n1', date:'2026-01-05', name:'Yulaf', calories:'300', protein:'10', carbs:'50', fat:'5', groupId:"g');alert(2);//" },
      { id:'n2', date:'dün', name:'x' },
    ],
    foodDb: [{ id:'f1', name:'Süt' }, { id:'f2', name:'Peynir', per100:{ kcal:'264', protein:'17' } }],
    measurements: [{ id:'m1', date:'2026-01-01', weight:'80', waist:'abc' }],
    customExercises: [{ id:'cex_1', name:'Özel', group:'sacma', type:'garip' }],
    mealRoutines: [{ id:'mr_1', name:'Çorba', type:'recipe', yieldG:'<b>3200</b>', per100:{ kcal:'<i>68</i>', protein:'3.4' },
      portions:{ kase:'320', '<img src=x>':'5', tabak:'abc' }, items:[{ name:'Mercimek', calories:'352' }] }],
  };
  const out = sanitizeBackup(evil, defaults);

  check('API anahtarı dosyadan alınmaz', 'geminiKey' in out.settings, false);
  check('bilinmeyen ayar anahtarı atılır', 'bogus' in out.settings, false);
  check('geçersiz model adı atılır', 'geminiModel' in out.settings, false);
  check('artık desteklenmeyen "lang" ayarı alınmaz', 'lang' in out.settings, false);
  check('dinlenme süresi sınırlanır', out.settings.restTime, 600);
  check('bozuk çapa tarihi sıfırlanır', out.settings.cycleDate, null);
  check('tehlikeli aktif rutin id atılır', 'activeRoutineId' in out.settings, false);
  check('mola bildirimi sayıya indirilir', out.settings.breakNotice, { days:0, prevPos:0, dismissed:false });

  check('yalnızca güvenli id\'li rutin kalır', out.routines.map(r => r.id), ['r_ok']);
  check('rutin içindeki sayılar sayıya çevrilir', out.routines[0].days[0].exercises[0], { exId:'pushup', sets:3, reps:12, disabled:false });
  check('tarihi bozuk seans atılır', out.workoutLogs.map(l => l.id), ['log_ok']);
  check('seans sayıları sayı olur', [out.workoutLogs[0].duration, out.workoutLogs[0].exercises[0].sets[0].reps], [30, 12]);
  check('tarihi bozuk öğün atılır', out.nutritionLogs.map(n => n.id), ['n1']);
  check('öğündeki tehlikeli groupId silinir', 'groupId' in out.nutritionLogs[0], false);
  check('öğün kalorisi sayı olur', out.nutritionLogs[0].calories, 300);
  check('per100\'ü olmayan besin atılır', out.foodDb.map(f => f.id), ['f2']);
  check('ölçümde sayı olmayan alan silinir', 'waist' in out.measurements[0], false);
  check('geçersiz grup/tür varsayılana döner', [out.customExercises[0].group, out.customExercises[0].type], ['custom', 'reps']);
  const mr = out.mealRoutines[0];
  check('tarif 100 g değerleri sayıya iner', mr.per100, { kcal:0, protein:3.4, carbs:0, fat:0 });
  check('tencere ağırlığı sayıya iner', mr.yieldG, 0);
  check('tarif porsiyonlarında yalnızca güvenli anahtar + pozitif sayı kalır', mr.portions, { kase:320 });
  check('atlanan kayıt sayısı raporlanır (4 rutin + 1 seans + 1 öğün + 1 besin)', out._dropped, 7);

  const partial = sanitizeBackup({ version:'kaslog_v2', routines:[] }, defaults);
  check('yedekte olmayan depo YOK sayılır (mevcut veri korunur)', Object.keys(partial).filter(k => !k.startsWith('_') && k !== 'settings'), ['routines']);
}

// ============================================================
scenario('Beslenme hedefleri');
{
  const code = slice('function calcNutritionGoals', 'function getScheduledDayType', 'hedefler');
  let ST, BW;
  const calc = new Function('ST', '_bodyWeight', code + 'return calcNutritionGoals;');
  const goals = (settings, bw, isWorkout = true) => { ST = { settings }; return calc(ST, () => bw)(isWorkout); };

  check('Ayarlar\'daki kilo kullanılır (eskiden hep 75 kg)', goals({ gender:'male' }, 90).kcal, 90 * 36);
  check('kilo hiç yoksa 75 kg', goals({ gender:'male' }, null).protein, 150);
  check('yalnızca kalori girildiyse o kullanılır', goals({ nutritionGoalKcal:2500, nutritionGoalProtein:0 }, 80).kcal, 2500);
  check('...protein otomatik kalır (2 g/kg)', goals({ nutritionGoalKcal:2500, nutritionGoalProtein:0 }, 80).protein, 160);
  check('yalnızca protein girildiyse o kullanılır', goals({ nutritionGoalKcal:0, nutritionGoalProtein:170 }, 80).protein, 170);
  check('dinlenme günü kalori %85', goals({ nutritionGoalKcal:2000, nutritionGoalProtein:150 }, 80, false).kcal, 1700);
}

// ============================================================
scenario('Statik kontroller (geçmiş hataların geri gelmemesi için)');
{
  // 1) Aynı id iki kez tanımlanamaz (modal-nut-edit çift tanımlıydı: biri hiç gösterilmeyen
  //    bir formdu ve gün detayından düzenleme YANLIŞ öğünü eziyordu).
  const body = BODY;
  const ids = [...body.matchAll(/\sid="([^"$]+)"/g)].map(m => m[1]);
  const dup = ids.filter((id, i) => ids.indexOf(id) !== i);
  check('statik HTML\'de yinelenen id yok', [...new Set(dup)], []);

  // 2) Tanımsız CSS sınıfı: .modal diye bir kural hiç yoktu → Neler yeni? modalı arka plansız,
  //    kaydırılamaz ve ekrandan taşıyordu.
  check('<div class="modal"> kullanılmıyor (tanımsız sınıf)', /class="modal"/.test(body), false);

  // 3) Kaçış karakteri düşmüş regex: /d+/ ve /s+/ harf siliyordu (/\d+/ ve /\s+/ olmalıydı).
  const script = JS;
  check('replace(/d+/) ve replace(/s+/) gibi kaçışsız regex yok', /\.replace\(\/[ds]\+\//.test(script), false);

  // 4) API anahtarı yedeğe yazılmıyor
  check('exportData geminiKey\'i ayıklıyor', /const\s*\{\s*geminiKey:\s*_gizli\s*,\s*\.\.\.ayarlar\s*\}\s*=\s*ST\.settings/.test(script), true);

  // 5) Bekleyen öğün kurtarma ve çift kayıt koruması yerinde
  check('açılışta bekleyen öğünler yeniden kuyruğa alınıyor', /_drainBgJobs\(\)\.then\(_recoverPendingMeals\)/.test(script), true);
  check('finishWorkout çift çağrıya karşı kilitli', /if\(!w\|\|w\._saving\)return;/.test(script), true);
}

console.log(`\n${fail ? '✗' : '✓'} ${pass}/${pass + fail} kontrol geçti`);
process.exit(fail ? 1 : 0);
