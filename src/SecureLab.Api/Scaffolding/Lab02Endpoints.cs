using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Security.Claims;


namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            // q екрануємо для LIKE й передаємо EF Core параметром, а не склеюємо з SQL
            var pattern = "%" + EscapeLike(q ?? "") + "%";

            var found = db.Incidents.AsNoTracking().Where(item =>
                EF.Functions.ILike(item.Title, pattern, "\\")
                || EF.Functions.ILike(item.Description, pattern, "\\"));

            // allowlist: клієнт лише обирає одну з гілок, написаних на сервері
            IQueryable<Incident>? ordered = sortBy switch
            {
                null or "" or "createdAtUtc" => found
                    .OrderByDescending(item => item.CreatedAtUtc).ThenBy(item => item.Id),
                "severity" => found
                    .OrderBy(item => item.Severity == IncidentSeverity.Critical ? 0
                        : item.Severity == IncidentSeverity.High ? 1
                        : item.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(item => item.Id),
                "status" => found
                    .OrderBy(item => item.Status == IncidentStatus.New ? 0
                        : item.Status == IncidentStatus.Triaged ? 1
                        : item.Status == IncidentStatus.InProgress ? 2
                        : item.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(item => item.Id),
                _ => null
            };

            if (ordered is null)
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });

            var rows = await ordered.Take(50).ToListAsync(ct);
            return Results.Ok(rows.Select(row => new
            {
                row.Id,
                row.Title,
                row.Description,
                Severity = row.Severity.ToString(),
                Status = row.Status.ToString(),
                row.CreatedAtUtc
            }));
        });
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, HttpContext httpContext, SecureLabDbContext db, CancellationToken ct) =>
        {
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            // 1. title: обов'язковий, довжина до 160 (до Trim)
            if (string.IsNullOrWhiteSpace(request.Title))
                errors["title"] = ["Заголовок обов'язковий."];
            else if (request.Title.Length > 160)
                errors["title"] = ["Заголовок не довший за 160 символів."];

            // 2. description: обов'язковий, довжина до 4000 (до Trim)
            if (string.IsNullOrWhiteSpace(request.Description))
                errors["description"] = ["Опис обов'язковий."];
            else if (request.Description.Length > 4000)
                errors["description"] = ["Опис не довший за 4000 символів."];

            // 3. severity: і TryParse, і IsDefined (інакше "7" проходить)
            var severityIsValid =
                Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
                && Enum.IsDefined(severity);
            if (!severityIsValid)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

            // 4. дата: обов'язкова, не пізніше ніж на 5 хвилин уперед
            if (request.OccurredAtUtc is null)
                errors["occurredAtUtc"] = ["Час події обов'язковий."];
            else if (request.OccurredAtUtc > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["Час події не може бути пізніше ніж на 5 хвилин у майбутньому."];

            // 5. Trim один раз; далі працюємо лише з цими змінними
            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            // 6. взаємозалежні поля: для High/Critical опис від 40 символів
            if (severityIsValid
                && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && description.Length < 40)
                errors["description"] = ["Для High і Critical опис має містити щонайменше 40 символів."];

            // 7. усі помилки формату: одна відповідь 400, до звернення до бази
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // 8. предметний конфлікт: такий самий title уже є і не Closed
            var duplicateExists = await db.Incidents.AnyAsync(
                item => item.Title == title && item.Status != IncidentStatus.Closed, ct);
            if (duplicateExists)
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Інцидент уже існує",
                    detail: "Активний інцидент з таким заголовком уже є.");


            // власник береться з verified principal, а не з тіла запиту
            var ownerIdText = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(ownerIdText, out var ownerId))
                return Results.Unauthorized();

            // 9. entity: id, власника, статус і часи задає лише сервер
            var incident = new Incident
            {
                Id = Guid.NewGuid(),
            OwnerUserId = ownerId,
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };
            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            // 10. response DTO замість анонімного об'єкта
            return Results.Created($"/api/incidents/{incident.Id}", new CreatedIncidentResponse(
                incident.Id, incident.Title, incident.Description,
                incident.Severity.ToString(), incident.Status.ToString(),
                incident.OccurredAtUtc, incident.CreatedAtUtc));
        }).RequireAuthorization();
    }

    // Екранування спецсимволів LIKE: спершу сам \, потім % і _
    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id, string Title, string Description, string Severity, string Status,
    DateTimeOffset OccurredAtUtc, DateTimeOffset CreatedAtUtc);