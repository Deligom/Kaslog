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

## 3. Testler

Bağımlılık gerekmez, Node 18+ yeterli:

```bash
node test/proxy.test.mjs
```

Gemini'ye ve Upstash'e gerçek istek atmaz; ikisi de taklit edilir.

## 4. Yerel geliştirme

```bash
python -m http.server 4173
```

Sonra `http://localhost:4173` adresini aç. AI çağrılarını yerelde denemek
istersen Vercel'de `ALLOW_LOCALHOST=1` ayarla.
