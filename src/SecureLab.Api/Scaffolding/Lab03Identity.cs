using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Net.Mail;

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
            if (!created.Succeeded) return Results.BadRequest(new { message = "Registration failed" });
            var roleResult = await users.AddToRoleAsync(newUser, DbSeeder.ReporterRole);
            if (!roleResult.Succeeded) throw new InvalidOperationException("Default role assignment failed.");
            return Results.Created("/api/me", new SignUpResponse(newUser.Id, newUser.UserName!, newUser.DisplayName));
        });
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
                return Results.Unauthorized();
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        });
        app.MapPost("/api/auth/logout", () => Results.StatusCode(StatusCodes.Status501NotImplemented));
        // Навмисно хибна навчальна довіра: ЛР 03 замінює заявлений id на verified principal.
        app.MapGet("/api/me", async (HttpContext context, SecureLabDbContext db) =>
        {
            if (!Guid.TryParse(context.Request.Headers["X-Demo-UserId"], out var claimedId))
                return Results.StatusCode(StatusCodes.Status501NotImplemented);
            var user = await db.Users.FindAsync(claimedId);
            return user is null ? Results.NotFound() : Results.Ok(new { user.Id, user.UserName, user.DisplayName });
        });
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

public sealed record LoginInput(string? UserName, string? Password);
