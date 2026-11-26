# \# Security review SecureLab, ЛР 6

# 

# Рівень: достатній («Задовільно»). Commit початку огляду (review-start): b41e0ea19ef59f7c86b25cf73d1f7cf83772138b. Хеші прийнятого merge commit і тегу v1.0.0 додає скрипт експорту в PDF. Дата огляду: 26.11.2026. SDK: .NET 10.0.401. Профілі запуску: Development (`http`, http://localhost:5080) і production-like (`--no-launch-profile -c Release`, Hosting environment: Production). Клієнти: Google Chrome (Windows 11), curl.exe, xUnit-тести (`dotnet test`).

# 

# \## 1. Executive summary

# Огляд охоплює браузерний клієнт, API ASP.NET Core, локальну PostgreSQL у Docker і конфігурацію власного проєкту SecureLab (baseline 2-A) від стану v0.5.0. Перевірено відстежувані файли на секрети, безпечну відповідь 500 у production-like профілі, заголовки безпеки та захист змінювальних маршрутів від CSRF. Зафіксовано одну знахідку (F-01: заголовки безпеки зникали на відповіді 500), вона виправлена й повторно перевірена. Для чотирьох змінювальних маршрутів складено периметр: на два маршрути, що довіряють cookie входу (створення інциденту і вихід), додано стандартну перевірку antiforgery (заголовок X-Lab-CSRF) з регресією REG-CSRF-01; вхід і реєстрація не довіряють cookie, і для них прийнято окреме рішення. Мінімальний набір регресії (SQLi, автентифікація, авторизація/IDOR, XSS, CSRF) виконано. Результат фінального прогону на перевіреному коміті наведено в експортованому PDF-звіті. Головні залишкові ризики: login-CSRF, транспорт (немає HTTPS і HSTS на локальному профілі), відсутність CSP і X-Frame-Options.

# 

# \## 2. Scope та exclusions

# У межах огляду: поточні відстежувані Git файли гілки lab/6-hardening-review (код API, клієнт, тести, конфігурація, документи); локальний навчальний стенд зі штучними даними й облікові записи alice, bob, morgan.

# Не входить: зовнішні системи, реальне розгортання, TLS і зворотний проксі, Redis (не використовується), повна історія Git (не перевірялась, лише поточний стан), CORS-розширення, новий rate limiter, аудит залежностей і повний огляд журналів (не входять до обраного рівня).

# 

# \## 3. System overview і trust boundaries

# Схема і таблиця меж: docs/threat-model.md. Основні межі: browser→API (текст користувача недовірений, cookie додається автоматично), API→PostgreSQL (параметри запитів), repository→build (відстежувані файли не містять реальних секретів), environment→configuration (у Production не діє Development-конфігурація, reset заборонено).

# 

# \## 4. Methodology та test environment

# Відомий початковий стан: гілка lab/6-hardening-review від v0.5.0, commit початку огляду b41e0ea. База: локальна PostgreSQL у Docker (infra/compose.yaml, прив'язка до 127.0.0.1:54329), початкове скидання командою `dotnet run --project src/SecureLab.Api -- --reset-database` (лише Development). Пароль seed-користувачів передається змінною середовища SeedUsers\_\_Password поза Git.

# Команди й результати: `git grep` для секретів і периметра; запуск у production-like профілі з `ConnectionStrings\_\_SecureLab` поза Git; `dotnet build SecureLab.sln -c Release`; `dotnet test SecureLab.sln -c Release` (24 тести після адаптації, 26 разом з REG-CSRF-01); ручні перевірки в Chrome і curl.exe. Коди завершення: збірка і тести завершуються кодом 0.

# 

# \## 5. Findings summary

# 

# | ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | ID повторної перевірки |

# |---|---|---|---|---|---|---|

# | F-01 | заголовки X-Content-Type-Options і Referrer-Policy | MIME sniffing, витік Referer | будь-яка необроблена помилка | P3 | Fixed | RT-F01 (curl -i, production-like, POST /api/auth/login при недосяжній базі) |

# 

# \## 6. Detailed findings

# \- docs/findings/F-01-error-path-headers.md

# 

# \## 7. Regression results

# 

# | ID сценарію | Властивість | Тест або команда | Негативний сценарій | Позитивна перевірка | Результат |

# |---|---|---|---|---|---|

# | S-02 (ЛР 2) | запит не змінює структуру SQL | tests/http/lab-02-checks.http (B, C, A, D); SearchMechanicsTests.Search\_ReturnsJson | пошук `zz-no-match' OR TRUE -- ` повертає 0 записів | пошук USB і O'Brien працюють | pass |

# | A01–A07, Login\_AfterFiveFailures (ЛР 3) | життєвий цикл входу | AuthSecurityRegressionTests; LoginFailureTests | анонім 401; невідомий користувач і хибний пароль однакові; 5 хибних спроб → 429 | вхід, /api/me, вихід | pass |

# | A03, A03R, A04 (ЛР 4) | володіння ресурсом і роль на сервері | IncidentAccessTests | чужий запис 404 | власник 200, аналітик 200 | pass |

# | REG-XSS-01 (ЛР 5) | текст не виконується як код | процедура REG-XSS-01; IncidentEndpointTests.ClientScript\_DoesNotUseDangerousInnerHtmlSink | опис `<img onerror>` показано як текст, атрибута немає | складний текст відображається як текст | pass |

# | REG-CSRF-01 (ЛР 6) | потрібна пара токенів | CsrfRegressionTests (2 тести) | без токена і з недійсним токеном 400, стан не змінюється | валідна пара: створення 201, вихід 204 | pass |

# 

# Старі тести T-02 і T-03 адаптовано до токена CSRF, мету збережено. Позначки pass поставлено за реальними запусками.

# 

# \## 8. Hardening controls

# 

# Зв'язок control → ризик → фактична перевірка → межа:

# 

# | Control | Ризик | Перевірка | Межа |

# |---|---|---|---|

# | стандартний antiforgery ASP.NET Core, заголовок X-Lab-CSRF, спільна перевірка `RequireCsrfToken` | підроблений запит з чужого сайту змінює стан | REG-CSRF-01; ручний прохід усіх змінювальних дій клієнта | login і register без токена (див. таблицю периметра) |

# | безпечна 500 (ProblemDetails, UseExceptionHandler) | витік stack trace, SQL, шляхів | production-like профіль, traceId у відповіді і в журналі | лише локальний стенд |

# | заголовки безпеки (OnStarting) | MIME sniffing, Referer | curl -i на 200 і 500, F-01 | CSP і X-Frame-Options відсутні |

# | login limiter (LoginThrottle) | підбір пароля | 5 хибних спроб → 429 з Retry-After: 60; неіснуючий користувач так само; після вікна вхід 204 | пам'ять одного екземпляра API |

# | textContent замість innerHTML | XSS у DOM | REG-XSS-01 | майбутні нові sinks |

# | transport | перехоплення, зниження до HTTP | огляд конфігурації: профіль лише http, немає UseHttpsRedirection, UseHsts | висновків про production немає |

# 

# Транспорт: у launchSettings.json єдиний профіль `http` з адресою http://localhost:5080, у коді немає UseHttpsRedirection, UseHsts, UseForwardedHeaders. Відсутність HSTS на localhost дефектом не вважається. Cookie входу поза Development має прапорець Secure (Lab03Identity.cs, рядки 25–26), тож для такого розгортання потрібен HTTPS на зовнішній межі; реальне розгортання не перевірялось.

# 

# Периметр змінювальних маршрутів (складено за `git grep` серверних маршрутів і змінювальних викликів клієнта; розбіжностей немає):

# 

# | ID | Method + route | Джерело | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |

# |---|---|---|---|---|---|---|---|

# | SC-01 | POST /api/auth/register | ЛР 3; клієнт lab03-scenario.js | створює обліковий запис | ні | так | absent: анонімна дія, ризик створення облікових записів з чужого сайту прийнято | RegistrationContractTests |

# | SC-02 | POST /api/auth/login | ЛР 3; клієнт auth-lab.js, lab03-scenario.js | створює сеанс | ні | так | absent: ризик login-CSRF прийнято, токен до входу потребує окремого анонімного маршруту (поза межами огляду); підбір пароля обмежує LoginThrottle | LoginFailureTests |

# | SC-03 | POST /api/auth/logout | ЛР 3; клієнт auth-lab.js, lab03-scenario.js | завершує сеанс | так | так | explicit: RequireCsrfToken, перевірка до SignOutAsync | REG-CSRF-01 (вихід) |

# | SC-04 | POST /api/incidents | ЛР 2–4; клієнт browser-lab.js, lab03-scenario.js | створює інцидент | так | так | explicit: RequireCsrfToken після RequireAuthorization | REG-CSRF-01 (створення) |

# 

# Маршрути GET (список, деталі, severity-summary, search, /api/me, /health) стан ресурсів не змінюють. `GET /api/auth/csrf-token` лише видає токен і cookie antiforgery і доступний після входу. Контракт між сервером і клієнтом: заголовок запиту X-Lab-CSRF; клієнтський файл Client/csrf.js додає токен до всіх змінювальних запитів на тому самому origin (окрім входу і реєстрації), токен запитується заново перед кожною такою дією.

# 

# \## 9. Dependency and secret audit

# Перевірено поточну відстежувану конфігурацію (`git ls-files`, `git check-ignore`, `git grep -n -I -i -E 'password|passwd|secret|api.?key'`). Кожен збіг класифіковано: поля форм, назви полів Identity, ключ SeedUsers:Password (значення поза Git), ідентифікатори пакетів у packages.lock.json, правила в README і docs не є секретами; навчальні значення (пароль локальної бази в infra/compose.yaml, рядок підключення в appsettings.Development.json) віднесено до accepted, study-only: штучні дані, прив'язка до 127.0.0.1. Реальних секретів у відстежуваному стані немає. У разі реального витоку значення треба відкликати й замінити (rotation), а не просто видалити з поточного файла.

# Історію Git не перевірено. Таблицю рішень щодо залежностей, систематичний пошук і повний огляд журналів не виконувалось: «Не входить до обраного рівня».

# 

# \## 10. Residual risks

# 

# | Ризик | Стан | Відповідальний | Наступна дія |

# |---|---|---|---|

# | login-CSRF (SC-02) і створення облікових записів (SC-01) без токена | прийнято | автор | розробити анонімний маршрут видачі токена до входу |

# | транспорт: лише HTTP на localhost, немає HTTPS і HSTS | не перевірялось | автор | налаштувати HTTPS на зовнішній межі під час розгортання |

# | відсутні CSP і X-Frame-Options | не входить до обраного рівня | автор | додати й перевірити без руйнування клієнта |

# | login limiter працює в пам'яті одного екземпляра | прийнято | автор | спільне сховище, якщо буде кілька екземплярів |

# | нові sinks innerHTML у майбутньому коді | не перевірялось | автор | інвентаризація sinks під час змін клієнта |

# | історія Git і залежності не перевірялись | не входить до обраного рівня | автор | аудит залежностей і пошук у відповідній історії |

# 

# \## 11. Conclusion

# Виконано всі вимоги рівня «Задовільно»: межі огляду і модель загроз; відстежуваний стан без реальних секретів; безпечна 500 у production-like профілі;

