using Microsoft.AspNetCore.Authentication;

namespace RateLimiting.Api.Setup;

public static class AuthenticationExtension
{
    /// <summary>
    /// Registers the ApiKey authentication scheme and authorization services.
    /// Valid keys are bound from "RateLimiting:ValidApiKeys" in appsettings.json.
    /// </summary>
    public static void AddAuthenticationAndConfigure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Bind ApiKeyOptions to the "RateLimiting" config section so that
        // ValidApiKeys maps to "RateLimiting:ValidApiKeys" in appsettings.json
        services.Configure<ApiKeyOptions>(configuration.GetSection("RateLimiting"));

        services
            .AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationHandler.SchemeName, _ => { });
    }
}

