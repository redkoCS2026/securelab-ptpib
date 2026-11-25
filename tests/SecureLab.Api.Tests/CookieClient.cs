using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    public static async Task<HttpClient> LoginAsync(this SecureLabApiFactory factory, string userName, string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }
        return client;
    }

    // Бере токен antiforgery у поточного сеансу (cookie зберігається в клієнті).
    public static async Task<string> GetCsrfTokenAsync(this HttpClient client)
    {
        using var response = await client.GetAsync("/api/auth/csrf-token");
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("token").GetString()!;
    }

    public static async Task<HttpResponseMessage> PostJsonWithCsrfAsync<T>(this HttpClient client, string url, T body)
    {
        var token = await client.GetCsrfTokenAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body) };
        request.Headers.Add("X-Lab-CSRF", token);
        return await client.SendAsync(request);
    }

    public static async Task<HttpResponseMessage> PostWithCsrfAsync(this HttpClient client, string url)
    {
        var token = await client.GetCsrfTokenAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Headers.Add("X-Lab-CSRF", token);
        return await client.SendAsync(request);
    }
}