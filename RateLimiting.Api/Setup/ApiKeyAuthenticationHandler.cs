using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace RateLimiting.Api.Setup;

/// <summary>
/// Strongly-typed options that bind to the "RateLimiting" section in appsettings.json.
/// </summary>
public sealed class ApiKeyOptions
{
    public HashSet<string> ValidApiKeys { get; set; } = [];
}

/// <summary>
/// Authentication handler that validates the x-api-key request header.
/// Integrates with the standard ASP.NET Core authentication pipeline so that
/// UseAuthentication / UseAuthorization handle the 401 challenge automatically.
/// </summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptionsMonitor<ApiKeyOptions> apiKeyOptions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var apiKey = Request.Headers["x-api-key"].ToString();

        if (string.IsNullOrEmpty(apiKey))
            return Task.FromResult(AuthenticateResult.Fail("Missing x-api-key header."));

        if (!apiKeyOptions.CurrentValue.ValidApiKeys.Contains(apiKey))
            return Task.FromResult(AuthenticateResult.Fail("Invalid API key."));

        // Build a minimal identity so downstream code can read the key via User.Identity.Name
        var claims = new[] { new Claim(ClaimTypes.Name, apiKey) };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    // Return a plain-text 401 instead of the default empty challenge response
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.ContentType = "text/plain";

        var apiKey = Request.Headers["x-api-key"].ToString();
        await Response.WriteAsync(string.IsNullOrEmpty(apiKey)
            ? "Missing x-api-key header."
            : "Invalid API key.");
    }
}

