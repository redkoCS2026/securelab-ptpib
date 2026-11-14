using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Net.Mail;
using System.Security.Claims;


namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<LoginThrottle>();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (SignUpRequest request, UserManager<ApplicationUser> users) =>
        {
            // ЛР 03: DTO validation та перевірки довірчої межі.
            var login = request.UserName?.Trim();
            var mail = request.Email?.Trim();
            var shownName = request.DisplayName?.Trim();
            if (!IsSignUpDataValid(login, mail, shownName, request.Password))
                return Results.BadRequest(new { message = "Registration failed" });
            var newUser = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = login,
                Email = mail,
                DisplayName = shownName!
            };
            var created = await users.CreateAsync(newUser, request.Password!);
            if (!created.Succeeded)
            {
                var isDuplicate = created.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail");
                return isDuplicate
                    ? Results.Conflict(new { message = "Registration failed" })
                    : Results.BadRequest(new { message = "Registration failed" });
            }
            var roleResult = await users.AddToRoleAsync(newUser, DbSeeder.ReporterRole);
            if (!roleResult.Succeeded) throw new InvalidOperationException("Default role assignment failed.");
            return Results.Created("/api/me", new SignUpResponse(newUser.Id, newUser.UserName!, newUser.DisplayName));
        });
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn,
     HttpContext http, LoginThrottle throttle, ILoggerFactory loggers) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
                return Results.Unauthorized();

            var audit = loggers.CreateLogger("AuthEvents");
            var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var key = ip + "|" + input.UserName.Trim().ToUpperInvariant();

            if (throttle.IsBlocked(key, out var waitSeconds))
            {
                audit.LogWarning("AuthEvent LoginThrottled ip={Ip}", ip);
                http.Response.Headers.RetryAfter = waitSeconds.ToString();
                return Results.StatusCode(StatusCodes.Status429TooManyRequests);
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            if (result.Succeeded)
            {
                throttle.Reset(key);
                audit.LogInformation("AuthEvent LoginSucceeded ip={Ip}", ip);
                return Results.NoContent();
            }

            throttle.RegisterFailure(key);
            audit.LogWarning("AuthEvent LoginFailed ip={Ip}", ip);
            return Results.Unauthorized();
        });


        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.NoContent();
        });

        // Навмисно хибна навчальна довіра: ЛР 03 замінює заявлений id на verified principal.
        // Особа береться лише з verified principal, а не з заголовка клієнта.
        app.MapGet("/api/me", async (HttpContext context, SecureLabDbContext db) =>
        {
            var idText = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(idText, out var currentId))
                return Results.Unauthorized();
            var user = await db.Users.FindAsync(currentId);
            return user is null
                ? Results.Unauthorized()
                : Results.Ok(new { user.Id, user.UserName, user.DisplayName });
        }).RequireAuthorization();
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
    private static bool IsSignUpDataValid(string? login, string? mail, string? shownName, string? password)
    {
        if (string.IsNullOrEmpty(login) || login.Length < 3 || login.Length > 64) return false;
        if (!login.All(c => char.IsAsciiLetterOrDigit(c) || "-._@+".Contains(c))) return false;
        if (string.IsNullOrEmpty(mail) || mail.Length > 254) return false;
        if (!MailAddress.TryCreate(mail, out var address) || address.Address != mail) return false;
        if (string.IsNullOrEmpty(shownName) || shownName.Length > 120) return false;
        return !string.IsNullOrEmpty(password) && password.Length <= 128;
    }

}

public sealed record SignUpRequest(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record SignUpResponse(Guid Id, string UserName, string DisplayName);


public sealed class LoginThrottle
{
    private const int MaxFailures = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);
    private readonly Dictionary<string, (int Count, DateTime Start)> _entries = new();
    private readonly object _lock = new();

    public bool IsBlocked(string key, out int retryAfterSeconds)
    {
        lock (_lock)
        {
            retryAfterSeconds = 0;
            if (!_entries.TryGetValue(key, out var entry)) return false;
            var left = entry.Start + Window - DateTime.UtcNow;
            if (left <= TimeSpan.Zero)
            {
                _entries.Remove(key);
                return false;
            }
            if (entry.Count < MaxFailures) return false;
            retryAfterSeconds = (int)Math.Ceiling(left.TotalSeconds);
            return true;
        }
    }

    public void RegisterFailure(string key)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            if (_entries.Count > 10_000)
            {
                foreach (var stale in _entries.Where(p => now - p.Value.Start >= Window)
                                              .Select(p => p.Key).ToList())
                    _entries.Remove(stale);
            }
            if (_entries.TryGetValue(key, out var entry) && now - entry.Start < Window)
                _entries[key] = (entry.Count + 1, entry.Start);
            else
                _entries[key] = (1, now);
        }
    }

    public void Reset(string key)
    {
        lock (_lock) _entries.Remove(key);
    }
}

public sealed record LoginInput(string? UserName, string? Password);
