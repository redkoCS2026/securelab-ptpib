using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public class CookieFlagsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task LoginCookie_HasSecurityFlags_WithoutExposingValue()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        var reply = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, reply.StatusCode);

        var header = reply.Headers.GetValues("Set-Cookie")
            .FirstOrDefault(h => h.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal));
        Assert.True(header is not null, "Login must set the identity cookie.");

        var attributes = header![(header.IndexOf(';') + 1)..].ToLowerInvariant();

        Assert.True(attributes.Contains("httponly"), "Cookie must have HttpOnly.");
        Assert.True(attributes.Contains("secure"), "Cookie must have Secure on HTTPS.");
        Assert.True(attributes.Contains("samesite=lax"), "Cookie must have SameSite=Lax.");
        Assert.True(attributes.Contains("path=/"), "Cookie must have Path=/.");
    }
}
