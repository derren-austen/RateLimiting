using System.Net;
using Microsoft.Extensions.Options;

namespace RateLimiting.Api.Setup;

/// <summary>
/// Strongly-typed options that bind to the "IpAllowlist" section in appsettings.json.
/// </summary>
public sealed class IpAllowlistOptions
{
    /// <summary>
    /// The set of IPv4 / IPv6 addresses permitted to reach opted-in endpoints.
    /// </summary>
    public HashSet<string> AllowedIPs { get; set; } = [];
}

/// <summary>
/// Endpoint metadata marker.  Adding this to an endpoint signals the
/// <see cref="IpAllowlistMiddleware"/> that it should enforce the IP allow-list.
/// </summary>
public sealed class IpAllowlistMetadata { }

/// <summary>
/// Middleware that enforces an IP allow-list on any endpoint decorated with
/// <see cref="IpAllowlistMetadata"/> (i.e. opted in via <c>.RequireIpAllowlist()</c>).
/// Endpoints without the marker are passed through untouched.
/// </summary>
public sealed class IpAllowlistMiddleware(
    RequestDelegate next,
    IOptionsMonitor<IpAllowlistOptions> options,
    ILogger<IpAllowlistMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();

        // Skip enforcement for endpoints that have not opted in
        if (endpoint?.Metadata.GetMetadata<IpAllowlistMetadata>() is null)
        {
            await next(context);
            return;
        }

        var remoteIp = context.Connection.RemoteIpAddress;

        // Honour the X-Forwarded-For header when running behind a reverse proxy.
        // Only the leftmost (originating) address is used.
        if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwarded))
        {
            var firstEntry = forwarded.ToString().Split(',')[0].Trim();
            if (IPAddress.TryParse(firstEntry, out var parsed))
                remoteIp = parsed;
        }

        if (remoteIp is null)
        {
            logger.LogWarning("IP allowlist: request blocked – unable to determine client IP.");
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied: unable to determine client IP.");
            return;
        }

        // Normalise IPv4-mapped IPv6 addresses (::ffff:127.0.0.1 → 127.0.0.1)
        if (remoteIp.IsIPv4MappedToIPv6)
            remoteIp = remoteIp.MapToIPv4();

        var allowed = options.CurrentValue.AllowedIPs
            .Where(ip => IPAddress.TryParse(ip, out _))
            .Select(IPAddress.Parse)
            .ToHashSet();

        if (!allowed.Contains(remoteIp))
        {
            logger.LogWarning("IP allowlist: request from {IP} was blocked.", remoteIp);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync(
                $"Access denied: {remoteIp} is not on the IP allow-list.");
            return;
        }

        logger.LogDebug("IP allowlist: {IP} passed.", remoteIp);
        await next(context);
    }
}

