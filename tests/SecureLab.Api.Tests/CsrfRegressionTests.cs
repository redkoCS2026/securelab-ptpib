using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// REG-CSRF-01: без токена і з недійсним токеном стан не змінюється, з валідною парою дія виконується.
public sealed class CsrfRegressionTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task RegCsrf01_CreateIncident_WithoutToken_IsRejected_AndStateUnchanged_ThenValidPairSucceeds()
    {
        var title = $"CSRF-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Перевірка захисту від CSRF: стан не має змінитись без токена.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
        using var client = await factory.LoginAsync("alice", StudyPassword);
        try
        {
            Assert.Equal(0, await CountByTitleAsync(title));

            // 1. без токена: 400, стан не змінився
            using var withoutToken = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.BadRequest, withoutToken.StatusCode);
            Assert.Equal("application/problem+json", withoutToken.Content.Headers.ContentType?.MediaType);
            Assert.Equal(0, await CountByTitleAsync(title));

            // 2. з недійсним значенням токена: той самий код, стан не змінився
            using var invalidRequest = new HttpRequestMessage(HttpMethod.Post, "/api/incidents")
            {
                Content = JsonContent.Create(body)
            };
            invalidRequest.Headers.Add("X-Lab-CSRF", "invalid-test-value");
            using var withInvalidToken = await client.SendAsync(invalidRequest);
            Assert.Equal(HttpStatusCode.BadRequest, withInvalidToken.StatusCode);
            Assert.Equal(0, await CountByTitleAsync(title));

            // 3. валідна пара (cookie antiforgery + токен із того самого сеансу): успіх, стан змінився
            using var withValidPair = await client.PostJsonWithCsrfAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, withValidPair.StatusCode);
            Assert.Equal(1, await CountByTitleAsync(title));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    [Fact]
    public async Task RegCsrf01_Logout_WithoutToken_IsRejected_AndSessionStays_ThenValidPairSucceeds()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        // без токена: 400, сеанс лишається чинним
        using var rejected = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        var stillLoggedIn = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, stillLoggedIn.StatusCode);

        // з валідною парою: вихід виконано, сеанс завершено
        using var accepted = await client.PostWithCsrfAsync("/api/auth/logout");
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
        var afterLogout = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, afterLogout.StatusCode);
    }

    private async Task<int> CountByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.CountAsync(item => item.Title == title);
    }

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }
}