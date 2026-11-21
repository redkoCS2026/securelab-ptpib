using System.Net;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class IncidentAccessTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task A01_Anonymous_GetDetails_Returns401()
    {
        using var client = factory.CreateClient();
        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A02_Owner_GetDetails_Returns200()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A03_Alice_GetBobIncident_Returns404_WithoutData()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("ownerDisplayName", body, StringComparison.Ordinal);
        Assert.DoesNotContain("description", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A03_Bob_GetAliceIncident_Returns404()
    {
        using var client = await factory.LoginAsync("bob", StudyPassword);
        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task A03R_Analyst_GetAliceIncident_Returns200()
    {
        using var client = await factory.LoginAsync("morgan", StudyPassword);
        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A04_Administrator_GetAliceIncident_Returns404()
    {
        using var client = await factory.LoginAsync("admin", StudyPassword);
        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}