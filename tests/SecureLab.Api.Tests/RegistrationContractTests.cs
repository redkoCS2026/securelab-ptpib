using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public class RegistrationContractTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task Register_SameUserNameTwice_SecondReturns409()
    {
        var login = "dup" + Guid.NewGuid().ToString("N")[..10];
        using var client = factory.CreateClient();

        try
        {
            var first = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName = login,
                email = login + "@example.test",
                displayName = "Duplicate test",
                password = StudyPassword
            });
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            var second = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName = login,
                email = login + "2@example.test",
                displayName = "Duplicate test",
                password = StudyPassword
            });
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);

            var text = await second.Content.ReadAsStringAsync();
            Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(login, text, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            using var scope = factory.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var created = await users.FindByNameAsync(login);
            if (created is not null)
                await users.DeleteAsync(created);
        }
    }
}