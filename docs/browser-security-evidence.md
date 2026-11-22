# Докази безпеки браузера (DEL-01)

Рівень: достатній («Задовільно») / добрий («Добре») / відмінний («Відмінно») — оберіть. Рівні накопичувальні; повні критерії й маршрут — на початку практичної частини методички. Заповнюйте лише розділи свого рівня й усі попередні. Не записуйте паролі, cookie/token values чи export browser storage.

## Стенд і Git-стан (Для всіх)

ОС, browser/version, API/probe origins: Windows 11 Pro; Google Chrome 157.0.8103.79; API і клієнт http://localhost:5080, дозволений probe http://localhost:4173, недозволений контрольний probe http://localhost:4174. Release/base_commit/entry_parent з receipt: lab-05-start-v1 / 292e2e91285dadb62979670b13a79d7cb2e61c72 / 292e2e91285dadb62979670b13a79d7cb2e61c72. (entry_parent — commit, від якого встановлено scaffold; збігається з base_commit, якщо після v0.4.0 не було commit політики SDK). Vulnerable/fixed hashes, v0.5.0, main і спосіб передавання: vulnerable 0fd6e10; fixed: виправлення XSS 3076fce, CORS 7bb9b5a; тег v0.5.0 і main вказують на кінцевий коміт гілки lab/5-browser-xss (git show v0.5.0); спосіб передавання: remote origin і lab05.bundle.

Механізм сеансу (Application → Storage → Cookies → http://localhost:5080): назва cookie, Domain, Path, HttpOnly, SameSite, Secure — без Value: назва .AspNetCore.Identity.Application; Domain localhost; Path /; HttpOnly так; SameSite Lax; Secure ні (HTTP на localhost); термін Session (Рисунок 7).

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description: див. docs/source-to-sink.md (поле з textarea → POST /api/incidents → валідація довжини → колонка description → GET /api/incidents/{id} → fetch у browser-lab.js → innerHTML у рядку 10). Гіпотеза source → storage → response → sink/context: якщо в description потрапить HTML, сервер збереже й поверне його без змін, а browser-lab.js:10 через innerHTML розбере його як розмітку; marker виконається в origin http://localhost:5080 і виставить data-lab05-marker=executed на #lab05-marker-target. Контекст: HTML-вміст елемента. Передумови, локальний користувач, Guid запису, marker із resources/lab05-marker.txt, команди reset/start і create/read: локальний користувач Alice (навчальний вхід); Guid запису: seed 20000000-0000-0000-0000-000000000001, а для експерименту створюється новий запис, його Guid фіксується в Етапі 2; marker із resources/lab05-marker.txt; reset: dotnet run --project src/SecureLab.Api -- --reset-database; start: dotnet run --project src/SecureLab.Api; create/read: кнопка «Створити й прочитати» на browser-lab.html (POST /api/incidents, GET /api/incidents/{id}).

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | Рядок з <img ... onerror=...> збережено в БД і повернуто в JSON без змін | Те саме, дані не змінювались (виправлення на клієнті) | Рисунки 12, 13 |
| DOM основного Description | У div#description створено елемент img з onerror | У div#description лише текстовий вузол із рядком | Рисунки 10, 15 |
| Дія marker | На #lab05-marker-target з'явився data-lab05-marker="executed" | Атрибута немає, marker не виконується | Рисунки 10, 15 |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | Не перевірялось | Усе відображається як текст, <b> не стає жирним | Рисунок 16 |
| Довжина за власними правилами ЛР 2 | Не перевірялось | Опис довжиною 4000 символів приймається й відображається як текст | Рисунок 17 |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Не перевірялось | Morgan бачить marker як текст, атрибута немає; Bob отримує GET 404 | Рисунки 28, 29 |

Finding: актив: Incident.Description і IncidentComment.Text на сторінці browser-lab. Передумови: локальний користувач Alice, запис із marker. Першопричина: browser-lab.js:10 і :14 вставляли рядки з API через innerHTML. Safe DOM diff: обидва місця замінено на textContent (коміт 3076fce). Retest: той самий запис із marker тепер показано як текст, атрибута немає (Рисунок 15). Залишковий ризик: інші нові sinks у майбутньому коді, перевіряти інвентаризацією. REG-XSS-01: створити інцидент із marker із resources/lab05-marker.txt у Description і прочитати його на browser-lab.html; очікування: опис показано як текст, на #lab05-marker-target немає data-lab05-marker. Негативний контроль: у вразливому коміті 0fd6e10 атрибут з'являється (executed).

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповніть до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | Той самий origin, CORS не потрібен; діють лише API authentication/authorization |
| simple GET 4173 → API | так, запит дійде | ні | Інший origin (порт), у відповіді ще немає Access-Control-Allow-Origin, тому браузер не віддасть відповідь скрипту (SOP/CORS) |
| simple GET 4174 → API | так, запит дійде | ні | Те саме: інший origin і немає дозволу в відповіді |
| curl/.http → API | так | не застосовується | Це не JavaScript у браузері, SOP/CORS тут не діють; працюють лише серверні перевірки API |
| preflighted 4173 → API («Добре / Відмінно») | | | |

Команди запуску probes: py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe; py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe. Policy — лише Development, один exact origin 4173; 4174 — контроль. Для «Задовільно» без AllowCredentials().

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | Читає відповідь | Читає відповідь, не залежить від CORS | GET 200, ACAO немає; Рисунки 4, 9 |
| Allowed 4173 | CORS error | 200, відповідь читається | ACAO: http://localhost:4173; Рисунки 19, 23 |
| Disallowed 4174 | CORS error | CORS error (запит дійшов, відповідь 200 не віддана скрипту) | ACAO немає; Рисунки 20, 24 |
| Direct HTTP / curl | 200 | 200 | ACAO лише для Origin 4173; Рисунок 25 |

REG-CORS-01: browser evidence і дві actual HTTP-відповіді для Origin 4173/4174: у браузері Рисунки 19–24; curl з Origin 4173 повертає Access-Control-Allow-Origin: http://localhost:4173, з Origin 4174 заголовка немає (Рисунок 25). Перевірка порядку через читання 401 без cross-origin cookie: зі сторінки 4173 GET /api/incidents/{id} без входу дав 401 без помилки CORS (Рисунок 26). Пояснення різниці browser/direct HTTP: same-origin policy і CORS діють лише в браузері, тому curl читає відповідь завжди, але серверні перевірки API однаково діють. Стан: fixed commit 7bb9b5a.

## Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: … Public seed comment Guid/текст, похідні counts за потреби, DOM до/після: … Єдиний safe helper і виклики для обох полів: …

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method: … Cookie-дослід 4173/4174/без AllowCredentials()/401 без входу: … Кінцевий AllowCredentials() — лише Development policy для 4173. Review XSS/CORS/CSRF/authorization — посилання на DEL-03: …

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | | |
| script-src | | |
| style-src | | |
| connect-src | | |
| img-src | | |
| frame-ancestors | | |

Місце зміни middleware: … Enforcement: document 200 і фактичний CSP header; три сторінки flow; кероване порушення new Image() до 4173 — результат: … Для «Добре» докази report-only не обов’язкові.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | | |
| Referrer-Policy | | |
| frame-ancestors | | |

## Додатково для Відмінно

DOM-тест: файл/команда, browser, vulnerable commit і FAIL, fixed commit і PASS: … Comments, повторний render без дублювання та позитивні рядки: … CSP report-only → enforcement: фактичні headers, flow і кероване порушення в обох режимах: … safe-url.js / атрибут: … Пояснення text/attribute/URL/JavaScript та ризик third-party scripts — посилання на DEL-03: …

Додаткових DEL, навчальних демо або нового журналу не подавайте. Перед поданням повторіть чекліст для свого накопичувального рівня.
