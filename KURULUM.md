# Kaslog — Vercel Kurulumu

Bu sürümde (v2.4) proxy güvenliği yeniden yazıldı. Deploy'dan sonra
aşağıdaki adımları uygulaman gerekiyor, aksi halde AI özellikleri çalışmaz.

## 1. Ortam değişkenleri

Vercel Dashboard → Proje → **Settings → Environment Variables**

### Zorunlu

| Değişken | Değer |
|---|---|
| `GEMINI_KEY` | Gemini API anahtarın ([aistudio.google.com/apikey](https://aistudio.google.com/apikey)) |
| `ALLOWED_ORIGINS` | Uygulamanın servis edildiği adres, örn. `https://kaslog19.vercel.app` |

`ALLOWED_ORIGINS` birden fazla adres için virgülle ayrılır. Boş bırakırsan
Vercel'in kendi production/preview URL'leri otomatik kabul edilir — ama özel
alan adın varsa mutlaka yaz.

### Silinmesi gereken

| Değişken | Neden |
|---|---|
| `APP_SECRET` | **SİL.** v2.3'te HMAC imzalama için kullanılıyordu; anahtar istemci kodunda düz metin olduğu için hiçbir koruma sağlamıyordu. v2.4 bu mekanizmayı tamamen kaldırdı. |

### Besin doğruluğu için (önerilen, ücretsiz)

| Değişken | Değer |
|---|---|
| `USDA_KEY` | USDA FoodData Central anahtarı |

Anahtar: [fdc.nal.usda.gov/api-key-signup.html](https://fdc.nal.usda.gov/api-key-signup.html) — e-posta yazıyorsun, anahtar anında geliyor. Onay süreci, IP kısıtı veya ücret yok.

**Neden gerekli:** Open Food Facts paketli/markalı ürünlerde iyi ama ham yiyeceklerde (tavuk göğsü, pilav, süt, yumurta) zayıf. Orada AI tahminine düşülüyordu ve AI besin değerlerinde yanılıyor. USDA resmî laboratuvar verisi veriyor. İş bölümü şöyle: **AI "bu ne ve kaç gram" sorusunu çözüyor, sayılar USDA'dan geliyor.**

Tanımlamazsan uygulama çalışmaya devam eder — `/api/usda` ucu `503` döner, istemci bu kademeyi bir kez deneyip sessizce atlar ve eskisi gibi AI tahminini kullanır.

### Hız sınırı için (önerilen)

Vercel Dashboard → **Storage → Marketplace → Upstash (Redis)** → ücretsiz plan
ile bağla. Entegrasyon şu değişkenleri otomatik ekler:

```
UPSTASH_REDIS_REST_URL
UPSTASH_REDIS_REST_TOKEN
```

(`KV_REST_API_URL` / `KV_REST_API_TOKEN` adlarıyla kurulursa o da desteklenir.)

Upstash bağlamazsan sistem bellek içi sayaca düşer: çalışır ama sayaç
fonksiyon her yeniden başladığında sıfırlanır ve eşzamanlı örnekler
birbirinden habersiz sayar. Yani limit gevşek uygulanır.

### İsteğe bağlı ayarlar

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `RATE_IP_HOUR` | `20` | Tek IP'nin saatlik istek hakkı |
| `RATE_IP_DAY` | `60` | Tek IP'nin günlük istek hakkı |
| `RATE_GLOBAL_DAY` | `1500` | Tüm kullanıcıların toplam günlük hakkı |
| `ALLOW_LOCALHOST` | (kapalı) | `1` yaparsan `http://localhost:*` kabul edilir (yerel geliştirme) |
| `ORIGIN_ENFORCE` | (açık) | `off` yaparsan origin kontrolü devre dışı kalır (acil kaçış kapısı) |

Limitleri değiştirdikten sonra yeniden deploy gerekmez; Vercel env değişikliği
sonrası fonksiyonu kendi yeniler.

## 2. Güvenlik modeli — ne koruyor, ne korumuyor

Uygulama herkese açık olduğu için istemciyle saldırganı ayırt edecek bir sır
yok. Bir sırrı istemciye koyarsan zaten herkes görür. Bu yüzden hedef erişimi
imkânsız kılmak değil, **zarar tavanını sabitlemek**:

- **Origin beyaz listesi** başka sitelerden ve tarayıcı dışı gelişigüzel
  kullanımdan korur. `curl` ile taklit edilebilir — tek başına yeterli değildir.
- **Hız sınırı** asıl korumadır. Tek kişi kotayı süpüremez; toplam günlük tavan
  en kötü senaryoyu sabitler.
- **Model ve `generationConfig` beyaz listesi** pahalı model çağrısını ve
  `maxOutputTokens` şişirmesini engeller.
- **Gövde/parça sınırları** dev payload ile maliyet şişirmeyi engeller.

Kota dolduğunda istemci kullanıcıyı "kendi ücretsiz Gemini key'ini gir"
akışına yönlendirir; o kullanıcının istekleri doğrudan Google'a gider ve
ortak kotadan düşmez.

### Tarayıcı tarafı: kaçış + içerik güvenliği politikası

Besin adları Open Food Facts'ten, AI'dan ve içe aktarılan yedekten geliyor;
hepsi `innerHTML` şablonlarına yazılıyor. Bu yüzden **her kullanıcı/üçüncü taraf
metni `esc()` ile kaçırılır** (`js/i18n.js`) ve yedek dosyası içeri alınmadan
`sanitizeBackup()` ile doğrulanır (`js/settings.js`).

`vercel.json` ayrıca bir **CSP** gönderir. Ne yapar, ne yapmaz:

- `connect-src` yalnızca bilinen adreslere izin verir (kendi proxy'n, Google AI,
  Open Food Facts). Bir XSS açığı bulunsa bile **veriyi başka bir sunucuya
  fetch ile gönderemez**; `img-src` da görüntü işaretçisiyle sızdırmayı kapatır.
- `script-src` içinde `'unsafe-inline'` VAR: arayüz yüzlerce `onclick="..."`
  kullanıyor. Yani CSP, enjekte edilmiş bir script'in çalışmasını **engellemez**;
  zararını sınırlar. Asıl savunma kaçıştır. (`'unsafe-inline'`i kaldırmak tüm
  satır içi işleyicilerin olay yöneticisine taşınmasını gerektirir.)
- Yeni bir dış adres (yeni API, yeni CDN) eklersen **CSP'yi de güncelle**, yoksa
  canlıda sessizce engellenir. `node test/vercel-basliklar.test.mjs` kodun
  `fetch` ettiği her adresin CSP'de olduğunu denetler.

## 3. Testler

Bağımlılık gerekmez, Node 18+ yeterli:

```bash
node test/proxy.test.mjs              # proxy: origin, hız sınırı, USDA
node test/gun-takibi.test.mjs         # rutin döngüsü / dinlenme günü takibi
node test/guvenlik-ve-yedek.test.mjs  # HTML kaçışı, yedek doğrulama, CSV, hedefler
node test/besin-eslesme.test.mjs      # Open Food Facts seçimi + yemek tablosu
node test/vercel-basliklar.test.mjs   # CSP / güvenlik başlıkları
```

Gemini'ye ve Upstash'e gerçek istek atmaz; ikisi de taklit edilir. Gün takibi,
güvenlik ve besin testleri `js/*.js` içindeki gerçek kodu söküp çalıştırır
(kopya değil); dosya sırası `index.html`'deki `<script src>` sırasından okunur.

## 4. Yerel geliştirme

```bash
node tools/yerel-sunucu.mjs        # http://localhost:4173
```

Bu sunucu `vercel.json`'daki başlıkları (CSP dahil) **birebir uygular**:
tarayıcı konsolunda "Refused to…" görürsen politika gerçekten bir şeyi
engelliyordur — canlıda da aynısı olurdu. (`python -m http.server` hiçbir
başlık göndermez, CSP hatası yerelde görünmez.)

AI çağrılarını yerelde denemek istersen Vercel'de `ALLOW_LOCALHOST=1` ayarla.
`/api/*` uçları yerelde çalışmaz (Vercel fonksiyonu); onlar için `vercel dev`.

## 5. Kod yapısı

`index.html` yalnızca iskelet (arayüz kabukları ve modallar). Stil `css/app.css`,
kod `js/` altında **klasik betikler** olarak bölünmüş ve `index.html`'deki sırayla
yüklenir. (ES modülü DEĞİL: arayüz `onclick="fonksiyon()"` ile global işlevleri
çağırıyor; modüle geçmek her işleyicinin yeniden bağlanmasını gerektirirdi.)

| Dosya | İçerik |
|---|---|
| `core.js` | sürüm, Gemini çağrısı, IndexedDB sarmalayıcı |
| `i18n.js` | Türkçe metinler, `esc()`, gün adı çevirisi |
| `exercises.js` | egzersiz kütüphanesi, varsayılan rutinler |
| `state.js`, `cycle.js` | uygulama durumu, onboarding, sekme gezinmesi, gün/döngü motoru |
| `today-program.js` | Bugün, Program, rutin ve gün düzenleyici |
| `workout.js` | aktif antrenman, yarım kalan antrenman taslağı, plaka hesabı |
| `stats.js`, `settings.js` | istatistik, ayarlar, yedek (içe/dışa aktarma), AI analizi |
| `engine.js` | adaptif ilerleme motoru, grafikler, ısı haritası |
| `nutrition.js` | beslenme sekmesi, hedefler, beslenme istatistikleri |
| `nutrition-ai.js` | analiz kuyruğu, besin eşleştirme kademeleri (yerel → OFF → AI/USDA) |
| `meal-routines.js`, `recipes.js`, `nutrition-list.js` | öğün rutinleri, kendi tarifin, liste/düzenleme arayüzü |
| `dishes.js` | kanonik yemek tablosu (aşağıda) |
| `a11y.js` | erişilebilirlik katmanı (aşağıda) |
| `init.js` | açılış, service worker kaydı |

Yeni dosya eklersen: `index.html`'e `<script src>` + `sw.js` içindeki `STATIC`
listesine ekle.

## 6. Besin eşleştirme sırası

1. **Kendi rutinin / tarifin** (kendi ölçümün — her zaman önce)
2. **Kanonik yemek tablosu** (`data/yemekler.json`): "mercimek çorbası", "pilav",
   "menemen" gibi bileşik yemekler. Birkaç tarifin **medyanından** üretilmiş sabit
   100 g değeri; `tools/tarif-derle.mjs` ile yenilenir. Gram yazılmadıysa ("1 kase")
   bir kez sorulur ve hatırlanır. Eşleşme tam olmalı: "mercimek" tek başına ham
   mercimek sayılır, "tavuklu pilav" tablodaki sade pilava eşleşmez.
3. **Kayıtlı ürün** (daha önce öğrenilen / barkodla okunan)
4. **Open Food Facts — yalnızca MARKALI sorgularda** ("Sütaş süzme yoğurt").
   Markasız ham yiyecekte ("tavuk göğsü", "yumurta") paketli ürünün değeri
   rastgele bir marka olurdu; üstelik OFF kullanıcı katkılı ve gürültülü
   (aynı yumurta için 116–143 kcal). Gelen değer kcal ≈ 4P+4K+9Y ile tutarlı
   değilse reddedilir.
5. **AI (Gemini) anlar, USDA sayıyı verir**; ikisi de yoksa AI tahmini.

Tabloyu genişletmek için `tools/tarif-kaynaklari.json`'a yemek + tarif URL'leri ekle,
`node tools/tarif-derle.mjs` çalıştır. Tek tarifle üretilen yemekler arayüzde
"tek tarif — yaklaşık" diye işaretlenir.

## 7. Erişilebilirlik

`js/a11y.js` işaretlemeyi tek noktadan tamamlar: tıklanan `div`'lere `role="button"`
+ klavye (Enter/Boşluk), simge düğmelerine `aria-label`, anahtarlara `role="switch"`,
pencerelere `role="dialog"` + odak yönetimi + arka plan `inert` + Escape. Grafiklere
metin alternatifi `chartLabel()` ile verilir. Metin renkleri WCAG AA (4,5:1)
kontrastı için ayarlıdır (`css/app.css` başındaki not). Bilinen sınır: beyaz yazılı
turuncu düğmeler 3,4:1 (marka rengi; büyük/kalın yazıda geçer, küçükte geçmez).

Arayüz **yalnızca Türkçe**dir. (İngilizce seçeneği kaldırıldı: onboarding, Beslenme
sekmesi ve AI istemleri zaten Türkçeydi.)
