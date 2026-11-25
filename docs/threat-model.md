# Модель загроз SecureLab, ЛР 6

Рівень: достатній («Задовільно»). Огляд проводиться лише на локальному навчальному стенді зі штучними даними.

| Елемент | Що зафіксувати | Ваш запис |
|---|---|---|
| Версія та середовище | commit початку огляду (review-start), профіль запуску, seed/reset, версія SDK | review-start b41e0ea19ef59f7c86b25cf73d1f7cf83772138b (гілка lab/6-hardening-review від v0.5.0); reset/seed у Development, далі перевірка у production-like профілі; SDK 10.0.*; лише навчальні облікові записи |
| Компоненти в межах огляду | браузерний клієнт, API, PostgreSQL у Docker Compose, конфігурація, журнали | браузерний клієнт (browser-lab), ASP.NET Core API, PostgreSQL у Docker Compose, конфігурація appsettings та infra, журнали API; Redis не використовується |
| Активи | облікові дані, власні записи, привілейовані переходи, дані аудиту, секрети конфігурації | облікові записи й хеші паролів, інциденти (Incident) та їх власник, зміна статусу інциденту, локальні навчальні секрети конфігурації |
| Суб’єкти | анонімний відвідувач, автентифікований користувач, moderator/admin, локальний розробник | анонімний відвідувач; автентифікований користувач (Alice, Bob); Analyst (Morgan); Administrator; локальний розробник |
| Entry points | HTTP-маршрути, login, форми браузера, завантаження конфігурації, restore пакетів, журнали | HTTP-маршрути API (register, login, GET /api/me, GET і POST /api/incidents, GET /api/incidents/{id}, /health), сторінка browser-lab, завантаження конфігурації, restore пакетів, журнали |
| Межі довіри | browser→API, API→PostgreSQL, repository→build, environment→configuration | browser→API (текст і запити користувача недовірені, cookie додається браузером автоматично); API→PostgreSQL; repository→build; environment→configuration |
| Наявні controls | validation, authentication, authorization, безпечна робота з DOM, CORS, CSP, antiforgery тощо — з посиланням на код, тест або конфігурацію | валідація вхідних даних і параметризовані запити (ЛР 2, S-02); автентифікація cookie, ASP.NET Core Identity (ЛР 3); перевірка власника ресурсу, чужий запис дає 404 (ЛР 4, A-03); textContent замість innerHTML (ЛР 5, REG-XSS-01); CORS-policy Lab05BrowserProbe (ЛР 5, REG-CORS-01); antiforgery відсутній, реалізується в ЛР 6; CSP у ЛР 5 не додавалась |
| Виключення | що не перевірялося й чому | зовнішній penetration test не виконувався; немає production-хоста; HTTPS і HSTS не перевірялись (локальний HTTP на localhost); CSP, dependency audit і повний огляд журналів не входять до рівня «Задовільно»; історія Git не скануватиметься |

## Схема меж довіри

    browser client (недовірений ввід, автоматичний cookie автентифікації)
           |  локальний HTTP, localhost:5080
           v
    ASP.NET Core API (валідація, автентифікація, авторизація, antiforgery, журнали)
           |  рядок підключення / EF Core
           v
    PostgreSQL (дані застосунку, Docker Compose)

    репозиторій + джерела пакетів --> збірка (restore, build)
    конфігурація середовища ---------> запуск API

## Очікувані властивості на межах

| Межа | Очікувана властивість (усі рівні) | Конкретний test або перевірка (добрий і відмінний) |
|---|---|---|
| browser→API | змінювальний запит із cookie без валідного antiforgery token відхилено без зміни стану; текст користувача не виконується як код | REG-CSRF-01 (створюється в ЛР 6); REG-XSS-01 (ЛР 5) |
| API→PostgreSQL | параметр пошуку не змінює структуру SQL | S-02 із ЛР 2 |
| repository→build | tracked files не містять реальних credentials; відкриті навчальні значення обмежені локальним стендом | git grep з етапу 1, п. 3 |
| environment→configuration | у Production не діє Development-конфігурація, reset бази заборонений | доказ Hosting environment Production і відмова --reset-database (етап 1, п. 4) |