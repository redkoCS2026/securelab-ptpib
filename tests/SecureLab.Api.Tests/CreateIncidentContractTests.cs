using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class CreateIncidentContractTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
     Environment.GetEnvironmentVariable("SeedUsers__Password")
     ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // T-02: severity "7" має дати 400 з ключем severity
    [Fact]
    public async Task Post_WithUnknownSeverity_Returns400WithSeverityKey()
    {
        var title = $"T02-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Опис",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
        using var client = await factory.LoginAsync("alice", StudyPassword);
        try
        {
            using var response = await client.PostAsJsonAsync("/api/incidents", body);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("application/problem+json",
                response.Content.Headers.ContentType?.MediaType);

            var json = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(json);
            var errors = document.RootElement.GetProperty("errors");
            Assert.True(errors.TryGetProperty("severity", out _));
            Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // T-03: повторний title активного інциденту має дати 409
    [Fact]
    public async Task Post_WithDuplicateActiveTitle_Returns409()
    {
        var title = $"T03-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Опис для перевірки конфлікту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
        using var client = await factory.LoginAsync("alice", StudyPassword);
        try
        {
            using var first = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            Assert.Equal("application/problem+json",
                second.Content.Headers.ContentType?.MediaType);

            var json = await second.Content.ReadAsStringAsync();
            Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }
}

