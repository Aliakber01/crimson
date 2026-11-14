# Crimson

Go ilə yazılmış, təhlükəsizlik komandası olmayan təşkilatlar üçün security scanner + dashboard.
Asılılıq yoxdur (yalnız Go stdlib), tək binary.

## Ən asan başlanğıc (Windows)
`start-demo.bat` faylına ikiqat klik edin. Zəif demo sayt + dashboard qalxır və brauzer özü açılır.
Bütün platformalarda: `crimson demo`

Staff hesabda saytı açın: **Apply fixes on demo site** düyməsi düzəlişi simulyasiya edir, sonra müştəri kimi Rescan edin.

## Əl ilə başlanğıc (demo)
    go build -o crimson .
    ./crimson demo-target            # zəif test saytı: 127.0.0.1:8081
    ./crimson serve -demo            # dashboard: http://127.0.0.1:8080

Demo hesablar:
- müştəri: demo@sunriseclinic.example / Demo-Crimson-2026!
- işçi:    staff@crimson.local / Staff-Crimson-2026!

Dashboardda saytı 127.0.0.1:8081 kimi əlavə edin və skan edin.

## CLI skan
    ./crimson scan -sector healthcare 127.0.0.1:8081
    ./crimson scan -authorized -json example.com     # yalnız icazəniz olan sistemlər!

## Real rejim
    CRIMSON_STAFF_EMAIL=you@x.com CRIMSON_STAFF_PASSWORD='...' ./crimson serve
    ANTHROPIC_API_KEY=... (istəyə bağlı AI izahı), TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID (istəyə bağlı bildiriş)

## Əsas xüsusiyyətlər
- Native modullar: portlar (DICOM 11112, HL7 2575 daxil), TLS, security header, cookie, açıq fayllar (.env, .git, backup), admin panelləri
- Sahiblik təsdiqi (DNS TXT / fayl) olmadan skan yoxdur; SSRF qoruması (guard.go)
- Müştəri və işçi girişi, tapıntı statusları: açıq → istənilib → icrada → düzəldilib → yoxlanılıb
- İşçi əl ilə yoxlama siyahısı və əl ilə tapıntı (skanerin girə bilmədiyi yerlər)
- AZ/EN interfeys, çap/PDF hesabatı (/report/{id}), audit jurnalı

## Public hosting və parol sıfırlama
`crimson serve -sandbox` (və ya `CRIMSON_SANDBOX=1`): public sandbox rejimi. Ətraflı: **DEPLOY.md**.
"Forgot password?" e-poçt ilə işləyir (SMTP dəyişənləri DEPLOY.md-də); SMTP yoxdursa link konsola yazılır.
