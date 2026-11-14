using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public class AuthSecurityRegressionTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task A01_AnonymousCreate_Returns401_NotRedirect()
    {
        using var anon = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var reply = await anon.PostAsJsonAsync("/api/incidents", new { title = "A01 anon" });

        Assert.Equal(HttpStatusCode.Unauthorized, reply.StatusCode);
        Assert.Null(reply.Headers.Location);
        Assert.Empty(reply.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", reply.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A02_Login_ThenMe_ReturnsCurrentUser()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        var reply = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, reply.StatusCode);

        using var doc = JsonDocument.Parse(await reply.Content.ReadAsStringAsync());
        var root = doc.RootElement;

        Assert.Equal(DbSeeder.AliceId, root.GetProperty("id").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());
        Assert.False(root.TryGetProperty("password", out _));
        Assert.False(root.TryGetProperty("passwordHash", out _));
        Assert.False(root.TryGetProperty("securityStamp", out _));
    }

    [Fact]
    public async Task A05_ForgedOwnerUserId_IsIgnored_OwnerIsPrincipal()
    {
        const string marker = "A05 forged owner";
        using var client = await factory.LoginAsync("bob", StudyPassword);

        var reply = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = marker,
            description = "Check owner comes from the cookie",
            severity = "Low",
            occurredAtUtc = DateTime.UtcNow.AddMinutes(-5),
            ownerUserId = DbSeeder.AliceId
        });

        Assert.Equal(HttpStatusCode.Created, reply.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        try
        {
            var saved = await db.Incidents.SingleAsync(i => i.Title == marker);
            Assert.Equal(DbSeeder.BobId, saved.OwnerUserId);
        }
        finally
        {
            await db.Incidents.Where(i => i.Title == marker).ExecuteDeleteAsync();
        }
    }
}