# Crimson: public hosting (sandbox) və parol sıfırlama

## Nə qurulur
Public link: hakimlər və başqaları Crimson-u brauzerdə sınaya bilir. **Sandbox rejimi** təhlükəsizdir:
- yalnız demo hesablar (qeydiyyat bağlıdır), demo məlumat;
- real sistemi skan etmək üçün yenə sahiblik sübutu (DNS TXT / fayl) lazımdır;
- private/daxili ünvanlar bloklanıb, yeganə istisna daxili demo klinikadır (`127.0.0.1:8081`);
- işçinin "əl ilə təsdiq" imkanı söndürülüb (yoxsa platforma başqasının saytını skan etmək üçün sui-istifadə oluna bilərdi).

## Render ilə yerləşdirmək (təxminən 15-20 dəqiqə)
Render pulsuz səviyyəsi: 15 dəqiqə trafik olmayanda yatır, oyanması ~1 dəqiqə çəkir, fayl sistemi müvəqqətidir (restartda sıfırlanır, demo məlumat avtomatik yenidən yaranır).

1. **GitHub:** github.com → New repository (`crimson`, Public). "uploading an existing file" ilə `crimson` qovluğunun məzmununu yükləyin. **YÜKLƏMƏYİN:** `.env`, `crimson-data.json`, `dist` qovluğu, `*.exe`. Yükləndikdən sonra repo siyahısında `.env` olmadığını yoxlayın (açar sızmasın).
2. **Render:** render.com → GitHub ilə daxil olun → **New + → Web Service** → `crimson` reposunu seçin.
3. Ayarlar: **Runtime / Language = Docker**, **Instance Type = Free**.
4. **Environment Variables:**
   - `ANTHROPIC_API_KEY` = Anthropic açarınız (AI izahı üçün)
   - `CRIMSON_SANDBOX` = `1` (Dockerfile artıq təyin edir, ehtiyat üçün)
   - istəyə bağlı: SMTP dəyişənləri (aşağıda)
5. **Create Web Service**. Quraşdırma bir neçə dəqiqə çəkir. Bitəndə `https://....onrender.com` linki çıxır.
6. Linki açın (ilk açılış ~1 dəqiqə ola bilər), demo hesabla daxil olun, demo klinikanı skan edin.
7. Təqdimatdan və hakimlərin baxışından **əvvəl** linki açın ki, servis yatmış olmasın.

Dəyişəcək heç nə yoxdur: `PORT` və `RENDER_EXTERNAL_URL` Render tərəfindən avtomatik verilir, Crimson bunları özü oxuyur.

Başqa platformalar: istənilən Docker hostu işləyir (`docker build -t crimson . && docker run -p 8080:8080 -e PORT=8080 crimson`). Docker olmadan: `go build -o crimson . && CRIMSON_SANDBOX=1 PORT=8080 ./crimson serve`.

## Parol sıfırlama e-poçtu (SMTP)
"Forgot password?" → e-poçtla birdəfəlik link (1 saat etibarlı, bir dəfə istifadə olunur, hər e-poçt üçün saatda 3 sorğu).

Mühit dəyişənləri:
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=siz@gmail.com
SMTP_PASS=<Gmail "App password" (2 mərhələli doğrulama lazımdır)>
SMTP_FROM=Crimson <siz@gmail.com>
CRIMSON_BASE_URL=https://sizin-link.onrender.com   (Render-də avtomatikdir)
```
Brevo, Mailgun, Resend (SMTP) və s. də eyni dəyişənlərlə işləyir. Port 587 (STARTTLS) və 465 (TLS) dəstəklənir.

SMTP verilməyibsə, link **server konsoluna** yazılır (lokal demo üçün): `password reset for ... link printed instead: http://...`

Qeyd: sandbox-da qeydiyyat bağlı olduğu üçün demo hesabların real poçtu yoxdur. Parol sıfırlamanı videoda lokal göstərin (qeydiyyatdan keçin, "Forgot password?", konsoldakı linki açın) və ya `CRIMSON_SANDBOX_SIGNUP=1` + SMTP ilə sandbox-da qeydiyyatı açın.

## Təhlükəsizlik qeydləri
- AI izahları hər tapıntı üçün keşlənir, ona görə public sandbox-da kredit sərfi məhduddur. Hackathondan sonra Anthropic Console-da açarı silin.
- Reset linkləri `CRIMSON_BASE_URL`-dən qurulur, `Host` başlığından yox (link zəhərlənməsinin qarşısı).
- Proxy arxasında (Render) `X-Forwarded-For` rate limit üçün yalnız `CRIMSON_TRUST_PROXY=1` (Render-də avtomatik) olduqda istifadə olunur.
