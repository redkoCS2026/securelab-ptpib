# Власна карта source-to-sink

Поле: Incident.Description. Стан/commit: гілка lab/5-browser-xss, 0fd6e10 (vulnerable state). Вхід/Guid запису: навчальний вхід Alice, 20000000-0000-0000-0000-000000000001.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | Поле «Опис нового інциденту» (form#edit, textarea name=description) у browser-lab.html; seed у DbSeeder.cs:67 | Рядок, який вводить користувач | Ненадійний: контролює користувач; Рисунок 6 (DOM) |
| Request | browser-lab.js:22–24, POST /api/incidents | JSON-поле description | Ненадійний: тіло запиту клієнт може змінити будь-як |
| Validation/mapping | Lab02Endpoints.cs:70–74, :91, :96–98 | Обов'язкове, до 4000, Trim, для High/Critical від 40 символів; HTML не кодується й не очищується | Перевірка довжини не є захистом від XSS |
| Storage | Incident.cs:8; SecureLabDbContext.cs:37; запис у Lab02Endpoints.cs:125 | Колонка description (до 4000), значення зберігається як є | Дані з БД лишаються ненадійними |
| Response | IncidentQueries.cs:75 → IncidentResponses.cs:14; GET /api/incidents/{id} | JSON-поле description, application/json, nosniff | Рисунок 5; JSON-екранування не захищає DOM |
| Client transform | browser-lab.js:5–8 | fetch, response.json(), current.description без змін | Рисунки 4–5 |
| Sink/context | browser-lab.js:10 | #description.innerHTML = current.description (HTML-контекст) | Рисунок 6; небезпечний sink, рішення: textContent |

Інвентаризація: browser-lab.js:9 (textContent, title) → текст → безпечно; browser-lab.js:10 (innerHTML, description) → HTML → небезпечно, замінити на textContent; browser-lab.js:14 (innerHTML, comment.text) → HTML → небезпечно, замінити на textContent/createElement; browser-lab.js:17 (.value у textarea) → значення поля → безпечно.