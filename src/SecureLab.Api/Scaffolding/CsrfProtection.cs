using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Scaffolding;

public static class CsrfProtection
{
    public static RouteHandlerBuilder RequireCsrfToken(this RouteHandlerBuilder builder)
    {
        return builder.AddEndpointFilter(async (context, next) =>
        {
            var antiforgery = context.HttpContext.RequestServices.GetRequiredService<IAntiforgery>();
            try
            {
                await antiforgery.ValidateRequestAsync(context.HttpContext);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.Problem(
                    title: "Недійсний або відсутній токен CSRF",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            return await next(context);
        });
    }
}

