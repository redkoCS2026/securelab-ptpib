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
    public async Task A03_ForeignUserIdHeader_DoesNotChangeIdentity()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        var reply = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, reply.StatusCode);

        using var doc = JsonDocument.Parse(await reply.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, doc.RootElement.GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task A04_CreateWithoutOwnerField_OwnerIsLoggedInUser()
    {
        const string marker = "A04 no owner field";
        using var client = await factory.LoginAsync("bob", StudyPassword);

        var reply = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = marker,
            description = "Owner is not sent by the client",
            severity = "Low",
            occurredAtUtc = DateTime.UtcNow.AddMinutes(-5)
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

    [Fact]
    public async Task A06_AfterLogout_ProtectedEndpointReturns401()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        var before = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        var logout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var after = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }
}