// ============================================================
// Kaslog gün takibi (döngü motoru) testleri
//
// Çalıştırma (bağımlılık yok, sadece Node 18+):
//   node test/gun-takibi.test.mjs
//
// index.html içindeki GERÇEK kod parçaları söküp çalıştırılır; testin
// kopyaladığı bir taklit değil. Takvim sahte bir saatle ileri sarılır.
// ============================================================

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HTML = readFileSync(join(ROOT, 'index.html'), 'utf8');

// ── index.html'den motoru sök ──────────────────────────────
function slice(startMark, endMark, label) {
  const a = HTML.indexOf(startMark);
  if (a < 0) throw new Error(`bulunamadı: ${label} (başlangıç)`);
  const b = HTML.indexOf(endMark, a);
  if (b < 0) throw new Error(`bulunamadı: ${label} (bitiş)`);
  return HTML.slice(a, b);
}

const ENGINE = slice('const LONG_BREAK_DAYS', '// BUGÜN', 'döngü motoru');
// finishWorkout içindeki pozisyon ilerletme bloğu
const ADVANCE = slice(
  'ST.settings.lastWorkoutDate=new Date().toISOString();',
  "await DB.put('settings'",
  'finishWorkout ilerletme'
);

// ── Sahte saat ─────────────────────────────────────────────
const RealDate = Date;
let NOW = new RealDate(2026, 0, 5, 9, 0, 0);
class FakeDate extends RealDate {
  constructor(...a) { if (a.length === 0) super(NOW.getTime()); else super(...a); }
  static now() { return NOW.getTime(); }
}
globalThis.Date = FakeDate;
function advanceDays(n) { NOW = new RealDate(NOW.getTime() + n * 86400000); }

// ── Ortam taklidi ──────────────────────────────────────────
let ST, started;
globalThis.DB = { put: async () => {} };
globalThis.T = k => k;
globalThis.translateDayName = n => n;
globalThis.navTo = () => {};
globalThis.renderBugun = () => {};
globalThis.renderAll = () => {};
globalThis.showConfirm = (i, t) => { started = { empty: t }; };
globalThis.startWorkout = (rid, did) => { started = { rid, did }; };
Object.defineProperty(globalThis, 'ST', { get: () => ST, set: v => { ST = v; }, configurable: true });

const engine = new Function(ENGINE + `
return { resolveCyclePos, syncCycle, getTodayDayInfo, peekDayAfter, startTrainingFrom,
         applyBreakRewind, undoBreakRewind, daysSinceLastWorkout, dayKey, shiftKey,
         normPos, activeRoutine, daysBetween };`)();

const finishAdvance = new Function('w', 'routine', 'normPos', 'shiftKey', 'dayKey', 'ST', ADVANCE);

function finishWorkout(dayId, { volume = 1000, duration = 45 } = {}) {
  const routine = ST.routines.find(r => r.id === ST.settings.activeRoutineId);
  const day = routine.days.find(d => d.id === dayId);
  ST.workoutLogs.push({
    id: 'log_' + ST.workoutLogs.length, date: new Date().toISOString(),
    routineId: routine.id, dayId, dayName: day.name,
    exercises: [{ exId: 'x', sets: [{ weight: 20, reps: 10 }, { weight: 20, reps: 10 }] }],
    duration, totalVolume: volume,
  });
  finishAdvance({ dayId, routineId: routine.id }, routine, engine.normPos, engine.shiftKey, engine.dayKey, ST);
}

function mkRoutine(days) {
  return {
    id: 'r1', name: 'Test', type: 'cyclic',
    days: days.map((n, i) => n === 'REST'
      ? { id: 'd' + i, name: 'REST', emoji: '😴', isRest: true, exercises: [] }
      : { id: 'd' + i, name: n, emoji: '💪', isRest: false, exercises: [{ exId: 'x', sets: 3, reps: 10 }] }),
  };
}

function reset(days) {
  ST = {
    settings: { activeRoutineId: 'r1', cyclePosition: 0, cycleDate: null, breakNotice: null, lastWorkoutDate: null },
    routines: [mkRoutine(days)], workoutLogs: [],
  };
  started = null;
}

// ── Minik test koşucusu ────────────────────────────────────
let pass = 0, fail = 0;
function check(label, actual, expected) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; console.log(`  ✓ ${label}`); }
  else { fail++; console.log(`  ✗ ${label}\n      beklenen: ${e}\n      gelen   : ${a}`); }
}
async function today() {
  await engine.syncCycle();
  const info = engine.getTodayDayInfo(engine.activeRoutine());
  return info.done ? 'DONE:' + info.day.name : info.day.name;
}
function scenario(name) { console.log(`\n▸ ${name}`); }

// ============================================================
scenario('Asıl şikayet: dinlenme gününde takılıp kalma');
reset(['PUSH', 'REST', 'PULL']);
await today();
finishWorkout('d0');                       // 1. gün: itiş yapıldı
check('itiş yapılan gün "tamamlandı" gösterir', await today(), 'DONE:PUSH');
advanceDays(1);
check('2. gün dinlenme', await today(), 'REST');
advanceDays(1);
check('3. gün dinlenme yandı, çekiş geldi', await today(), 'PULL');
advanceDays(1);
check('4. gün (yapılmadı) hâlâ çekiş — antrenman günü bekler', await today(), 'PULL');
advanceDays(3);
check('7. güne kadar bekledi, hâlâ çekiş', await today(), 'PULL');

// ============================================================
scenario('Arka arkaya iki dinlenme günü tek seferde yanmaz');
reset(['PUSH', 'REST', 'REST', 'PULL']);
await today();
finishWorkout('d0');
advanceDays(1); check('2. gün dinlenme', await today(), 'REST');
advanceDays(1); check('3. gün yine dinlenme', await today(), 'REST');
advanceDays(1); check('4. gün çekiş', await today(), 'PULL');

// ============================================================
scenario('Uygulama 3 gün hiç açılmadı (tek seferde toplu ilerleme)');
reset(['PUSH', 'REST', 'REST', 'PULL']);
await today();
finishWorkout('d0');
advanceDays(3);
check('kapalıyken geçen iki dinlenme de yandı', await today(), 'PULL');
check('pozisyon kalıcı yazıldı', ST.settings.cyclePosition, 3);
check('çapa bugüne sabitlendi', ST.settings.cycleDate, engine.dayKey());

// ============================================================
scenario('"Yine de antrenman yap" sonrası sıra kaymıyor');
reset(['PUSH', 'REST', 'PULL', 'LEGS']);
await today();
finishWorkout('d0');
advanceDays(1);
check('2. gün dinlenme', await today(), 'REST');
engine.startTrainingFrom(engine.resolveCyclePos(engine.activeRoutine(), engine.dayKey()));
check('dinlenmeyi atlayınca çekiş başlar', started.did, 'd2');
finishWorkout('d2');
check('o gün "tamamlandı"', await today(), 'DONE:PULL');
advanceDays(1);
check('ertesi gün BACAK (çekiş tekrar gelmiyor)', await today(), 'LEGS');

// ============================================================
scenario('Aynı gün iki antrenman döngüyü iki adım atlamaz');
reset(['PUSH', 'PULL', 'LEGS', 'REST']);
await today();
finishWorkout('d0');
finishWorkout('d1');
check('pozisyon çalışılan son güne göre', ST.settings.cyclePosition, 2);
advanceDays(1);
check('ertesi gün BACAK', await today(), 'LEGS');

// ============================================================
scenario('Uzun ara (7+ gün): döngü başa sarar, geri alınabilir');
reset(['PUSH', 'REST', 'PULL', 'LEGS']);
await today();
finishWorkout('d0');
advanceDays(3);
check('3 gün sonra çekiş bekliyor', await today(), 'PULL');
advanceDays(5);                              // son antrenmandan 8 gün
check('8 gün sonra döngü ilk antrenman gününde', await today(), 'PUSH');
check('karşılama kartı verisi var', ST.settings.breakNotice.days, 8);
check('geri alma için eski pozisyon saklandı', ST.settings.breakNotice.prevPos, 2);
await engine.undoBreakRewind();
check('geri al: kaldığı yere döndü', await today(), 'PULL');
check('kart kapandı', ST.settings.breakNotice.dismissed, true);
finishWorkout('d2');
check('antrenman yapılınca kart verisi silinir', ST.settings.breakNotice, null);

// ============================================================
scenario('Uzun ara kartı tekrar tekrar sarmaz');
reset(['PUSH', 'REST', 'PULL']);
await today();
finishWorkout('d0');
advanceDays(9);
await today();
const posAfterRewind = ST.settings.cyclePosition;
advanceDays(4);
await today();
check('ikinci sarma yok, pozisyon sabit', ST.settings.cyclePosition, posAfterRewind);
check('gün sayısı tazelendi', ST.settings.breakNotice.days, 13);

// ============================================================
scenario('Sınır durumları');
reset(['REST', 'REST']);
await today();
advanceDays(30);
check('tamamı dinlenme olan rutin sonsuz döngüye girmez', await today(), 'REST');

reset(['PUSH', 'REST', 'PULL']);
check('hiç antrenman yokken uzun ara tetiklenmez', engine.daysSinceLastWorkout(), null);
advanceDays(40);
check('yeni kullanıcı 40 gün sonra da 1. günde', await today(), 'PUSH');

reset(['PUSH', 'REST', 'PULL']);
await today();
finishWorkout('d0');
advanceDays(1);
const r = engine.activeRoutine();
check('yarının günü doğru hesaplanıyor',
  engine.peekDayAfter(r, engine.resolveCyclePos(r, engine.dayKey())).name, 'PULL');

// ============================================================
console.log(fail ? `\n✗ ${fail} kontrol başarısız (${pass} geçti)` : `\n✓ ${pass}/${pass} kontrol geçti`);
process.exit(fail ? 1 : 0);
