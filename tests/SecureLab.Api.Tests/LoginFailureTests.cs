using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public class LoginFailureTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static async Task<string> StableFieldsAsync(HttpResponseMessage reply)
    {
        using var doc = JsonDocument.Parse(await reply.Content.ReadAsStringAsync());
        return string.Join("|", doc.RootElement.EnumerateObject()
            .Where(p => p.Name != "traceId")
            .OrderBy(p => p.Name)
            .Select(p => $"{p.Name}={p.Value}"));
    }

    [Fact]
    public async Task A07_UnknownUser_And_WrongPassword_LookTheSame()
    {
        using var anon = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var unknownUser = await anon.PostAsJsonAsync("/api/auth/login",
            new { userName = "no_such_user", password = "WrongPassw0rd!" });
        var wrongPassword = await anon.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "WrongPassw0rd!" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknownUser.StatusCode);
        Assert.Equal(unknownUser.StatusCode, wrongPassword.StatusCode);

        Assert.Equal(
            unknownUser.Content.Headers.ContentType?.ToString(),
            wrongPassword.Content.Headers.ContentType?.ToString());

        Assert.Equal(
            await StableFieldsAsync(unknownUser),
            await StableFieldsAsync(wrongPassword));

        Assert.False(unknownUser.Headers.Contains("Set-Cookie"));
        Assert.False(wrongPassword.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Login_AfterFiveFailures_Returns429_WithRetryAfter()
    {
        using var anon = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var login = "rate" + Guid.NewGuid().ToString("N")[..10];

        for (var i = 0; i < 5; i++)
        {
            var failed = await anon.PostAsJsonAsync("/api/auth/login",
                new { userName = login, password = "WrongPassw0rd!" });
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
        }

        var blocked = await anon.PostAsJsonAsync("/api/auth/login",
            new { userName = login, password = "WrongPassw0rd!" });

        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.True(blocked.Headers.Contains("Retry-After"));
        Assert.False(blocked.Headers.Contains("Set-Cookie"));
    }
}