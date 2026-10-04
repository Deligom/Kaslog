// ============================================================
// i18n
// ============================================================
const STRINGS = {
  tr: {
    // nav
    nav_today:'Bugün', nav_program:'Program', nav_stats:'İstatistik', nav_settings:'Ayarlar',
    // bugün
    today_workout:"Bugünkü Antrenman", start_workout:"Antrenmanı Başlat",
    rest_day:"Dinlenme Günü", rest_day_sub:"Kaslar dinlenirken büyür.",
    tomorrow:"Yarın", train_anyway:"Yine de Antrenman Yap →",
    done_today:"Bugün Tamamlandı", done_today_sub:"Bugünün işi bitti — şimdi sıra toparlanmada.",
    train_again:"Bir antrenman daha yap →", done_stat_vol:"hacim", done_stat_set:"set", done_stat_min:"dk",
    break_title:"Tekrar hoş geldin!", break_days:"gündür ara verdin.",
    break_rewound:"Döngüyü başa sardım — temiz sayfa.", break_continue:"Kaldığım yerden devam et",
    break_dismiss:"Tamam, başlayalım",
    streak:"Seri", sessions:"Antrenman", volume:"Hacim",
    no_routine:"Rutin Yok", no_routine_sub:"Program sekmesinden rutin oluştur.",
    // program
    my_routines:"Rutinlerim", new_routine:"+ Yeni Rutin",
    no_routines:"Rutin Yok", no_routines_sub:"İlk rutinini oluştur.",
    training_days:"antrenman günü", exercise_lib:"Hareket Kütüphanesi",
    cyclic:"Döngüsel", fixed:"Sabit",
    active:"Aktif", set_active:"Aktif Rutine Ayarla",
    training_day:"+ Antrenman Günü", rest_day_btn:"+ Dinlenme Günü",
    delete_routine:"Rutini Sil", edit:"Düzenle", exercises_count:"egzersiz",
    rest_day_label:"Dinlenme günü", remove:"Kaldır",
    // routine builder
    routine_name:"Rutin Adı", routine_type:"Tip",
    cyclic_label:"Döngüsel (tekrar)", fixed_label:"Sabit (Pzt-Paz)",
    emoji_label:"Emoji", create_routine:"Rutin Oluştur",
    new_routine_title:"Yeni Rutin",
    // day editor
    day_name:"Gün Adı", exercises_title:"EGZERSİZLER",
    search_placeholder:"Egzersiz ara veya ekle...",
    done:"Tamam", no_exercises:"Henüz egzersiz eklenmedi.",
    create_custom:"Özel Egzersiz Oluştur",
    add_as_custom:"Özel egzersiz olarak ekle",
    no_results:"Sonuç bulunamadı.",
    // custom ex form
    cex_title:"✨ Yeni Özel Egzersiz",
    cex_name:"İsim *", cex_muscle:"Kas Grubu", cex_equip:"Ekipman",
    cex_type:"Tip", cex_group:"Grup", cex_tip:"Not / İpucu (opsiyonel)",
    cex_cancel:"İptal", cex_save:"Kaydet & Ekle",
    // workout
    exercise:"Egzersiz", weight:"Ağırlık", reps:"Tekrar",
    time_label:"Süre", seconds:"saniye", rep_unit:"tekrar", sec_unit:"sn",
    complete_set:"SET TAMAMLA", skip_exercise:"Hareketi Atla →",
    rest_title:"Dinlenme", next_exercise:"Sıradaki Egzersiz", skip:"Atla →",
    workout_complete:"Antrenman Bitti!", great_session:"Harika bir seans!",
    new_prs:"yeni kişisel rekor", save_finish:"Kaydet ve Bitir", discard:"İptal Et",
    minutes:"Dakika", sets:"Set", finish_btn:"Bitir",
    last_perf:"Geçen:", completed_ex:"Tamamlanan Egzersizler",
    // stats
    history:"Geçmiş", prs:"Rekorlar", body:"Vücut", vol_tab:"Hacim",
    no_workouts:"Henüz Antrenman Yok", no_workouts_sub:"İlk seansını tamamla!",
    no_prs:"Henüz Rekor Yok", no_prs_sub:"PR kurmak için antrenman yap.",
    not_enough:"Yeterli Veri Yok", not_enough_sub:"En az 2 seans gerekli.",
    body_measurements:"Vücut Ölçüleri", add_measure:"+ Ekle",
    last_update:"Son güncelleme:", no_measure:"Henüz ölçüm girilmedi.",
    no_measure_title:"Ölçüm Yok", no_measure_sub:"İlk ölçümünü ekle, ilerlemeyi takip et.",
    measure_entries:"kayıt", days_tracked:"gün takip", add_measure_btn:"Ölçüm Ekle",
    slow_progress:"Beklenenin altında ilerleme — program ve beslenmeyi gözden geçir",
    session_vol:"Seans Hacmi",
    weight_field:"Kilo", height_field:"Boy", chest_field:"Göğüs",
    waist_field:"Bel", bicep_field:"Biceps", hip_field:"Kalça",
    thigh_field:"Uyluk", shoulder_field:"Omuz", save:"Kaydet",
    // settings
    profile:"Profil", workout_sec:"Antrenman", appearance:"Görünüm",
    data_sec:"Veri", cycle_sec:"Rutin Döngüsü",
    name_label:"İsim", level_label:"Seviye", goal_label:"Hedef",
    rest_label:"Dinlenme Süresi", rest_sub:"Setler arası",
    dark_mode:"Koyu Tema",
    current_pos:"Şu Anki Konum", cycle_reset:"Sıfırla",
    delete_data:"Tüm Verileri Sil", delete_sub:"Geri alınamaz!",
    next_label:"Sıradaki",
    // confirms
    delete_routine_title:"Rutini Sil", delete_routine_msg:"Bu rutin kalıcı olarak silinecek.",
    finish_title:"Antrenmanı Bitir", finish_msg:"Tamamlanan setler özete dahil edilecek.",
    discard_title:"Antrenmanı İptal Et", discard_msg:"Bu antrenman kaydedilmeyecek.",
    delete_data_title:"Tüm Verileri Sil", delete_data_msg:"Tüm antrenman geçmişin ve rutinlerin silinecek.",
    cancel:"Vazgeç", yes:"Evet",
    // greetings
    g0:"Gece antrenmanı mı? 🌙 Kararlılık var.",
    g1:"Sabah seansı = en büyük kazanım. ☀️",
    g2:"Öğleden sonra enerjisi, hadi gidelim!",
    g3:"Günü tamamlamak için akşam seansı.",
    g4:"Geç ama buradayken kazanıyorsun! 💪",
    in_cycle:"döngüde",
    day_prefix:"Gün",
    group_push:"İtme 💪", group_pull:"Çekiş 🔗", group_legs:"Bacak 🦵", group_core:"Kor 🧲", group_custom:"Özel ✨",
    day_push:"İTME", day_pull:"ÇEKİŞ", day_legs:"BACAK", day_core:"KOR",
    no_active_ex:"Bu güne henüz egzersiz eklenmemiş.", day_empty_sub:"Program sekmesine gidip bu güne egzersiz ekleyebilirsin.",
    day_empty:"Bu gün boş, egzersiz eklenmemiş. Program sekmesinden ekleyebilirsin.",
    // export/import
    export_data:"Veriyi Dışa Aktar", import_data:"Veriyi İçe Aktar",
    export_desc:"Tüm antrenman geçmişin, rutinlerin ve ölçümlerin JSON dosyası olarak indirilir.",
    import_desc:"Daha önce aldığın yedek dosyasını seç. Mevcut veri yedekteki haliyle değiştirilir.",
    import_btn:"Dosya Seç", export_success:"Veriler başarıyla dışa aktarıldı ✓",
    import_success:"Veriler başarıyla içe aktarıldı ✓", import_error:"Geçersiz yedek dosyası!",
    import_warning:"Mevcut veriler yedekle DEĞİŞTİRİLECEK: yedekte olmayan kayıtlar silinir. Devam?",
    // history detail
    workout_detail:"Antrenman Detayı", sets_done:"set tamamlandı",
    skipped:"Atlandı", total_volume:"Toplam Hacim",
    // settings edit modal
    save:"Kaydet", cancel_btn:"İptal",
    edit_name_title:"İsim Düzenle", edit_rest_title:"Dinlenme Süresi",
    edit_level_title:"Seviye Seç", edit_goal_title:"Hedef Seç",
    level_beginner:"Başlangıç", level_intermediate:"Orta", level_advanced:"İleri", level_expert:"Uzman",
    goal_strength:"Güç", goal_hypertrophy:"Pump / Kas", goal_both:"Her İkisi",
    rest_hint:"15–600 saniye arasında gir",
    // pr
    pr_date_label:"Kırıldı",
    warmup_chip:"☀️ Isınma", note_chip:"📝 Not",
    tab_calendar:"Takvim",
    heatmap_title:"Antrenman Takvimi",
    streak_label:"Mevcut Seri", workout_days:"Antrenman Günü", total_sessions:"Toplam Seans",
    heatmap_less:"Az", heatmap_more:"Çok",
    prev_val:"Önceki", measure_hint:"Sadece ölçtüklerini gir — boş bıraktıklarına dokunulmaz.",
    ex_label:"Egzersiz", of_label:"/ ",
    measure_history:"Ölçüm Geçmişi", edit_entry:"Düzenle", delete_entry:"Sil",
    edit_measure_title:"Ölçümü Düzenle", confirm_delete_measure:"Bu ölçüm silinsin mi?",
    note_placeholder:"Not gir...",
  },
};
// Arayüz dili Türkçe'dir. (İngilizce seçeneği kaldırıldı: onboarding, Beslenme
// sekmesi, AI istemleri ve besin ayrıştırma zaten Türkçeydi; yarım çevrilmiş bir
// mod yeni kullanıcıyı yanıltıyordu. Çok dilli destek istenirse bu sözlük
// dil başına bir dosyaya taşınıp T() dil seçiyormuş gibi genişletilebilir.)
function T(key) {
  return STRINGS.tr[key] || key;
}

// innerHTML şablonlarına gömülen HER kullanıcı/üçüncü taraf metni buradan geçer.
// Besin adları Open Food Facts'ten ve AI'dan geliyor, rutin/egzersiz adlarını
// kullanıcı yazıyor, yedek dosyasından da içeri girebiliyor: kaçışsız yazılırsa
// bunlar sayfada script çalıştırabiliyor (IndexedDB'ye ve API anahtarına erişir).
const _ESC_MAP = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => _ESC_MAP[c]); }

function translateDayNameH(name) { return esc(translateDayName(name)); }

// Varsayılan rutinler İngilizce adlarla (PUSH, Rest…) kaydedilmişti; ekranda
// Türkçe karşılığı gösterilir. Kullanıcının kendi yazdığı adlara dokunulmaz.
const _DAY_NAMES_TR = {
  'PUSH':'İTME','Push':'İTME','push':'İTME',
  'PULL':'ÇEKİŞ','Pull':'ÇEKİŞ','pull':'ÇEKİŞ',
  'LEGS':'BACAK','Legs':'BACAK','legs':'BACAK',
  'CORE':'KOR','Core':'KOR','core':'KOR',
  'REST':'Dinlenme','Rest':'Dinlenme','rest':'Dinlenme','Rest Day':'Dinlenme',
};
function translateDayName(name) {
  name = String(name ?? '');
  if (_DAY_NAMES_TR[name]) return _DAY_NAMES_TR[name];
  // "Day N" → "Gün N"
  return name.replace(/^Day\s+(\d+)$/i, (_, n) => 'Gün ' + n);
}
