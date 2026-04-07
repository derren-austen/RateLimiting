using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using RateLimiting.Api.Setup;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddAuthenticationAndConfigure(builder.Configuration);
builder.Services.AddAuthorization();

builder.Services.AddIpAllowlist(builder.Configuration);

builder.Services.AddRateLimiter(options =>
{
    // 429 Too Many Requests is returned when the limit is exceeded
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // ── 1. Fixed Window ──────────────────────────────────────────────────────
    // Allows a fixed number of requests within a fixed time window.
    // The counter resets completely at the end of each window.
    options.AddFixedWindowLimiter("fixed", o =>
    {
        o.PermitLimit = 5;                              // Max 5 requests…
        o.Window = TimeSpan.FromSeconds(10);            // …per 10-second window
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 0;                               // No queuing – 429 on the 6th request
    });

    // ── 2. Sliding Window ────────────────────────────────────────────────────
    // Similar to Fixed Window but divides the window into segments.
    // Expired segment counts are rolled off gradually, giving a smoother limit.
    options.AddSlidingWindowLimiter("sliding", o =>
    {
        o.PermitLimit = 10;                             // Max 10 requests…
        o.Window = TimeSpan.FromSeconds(30);            // …over 30 seconds
        o.SegmentsPerWindow = 3;                        // 3 × 10-second segments
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 2;
    });

    // ── 3. Token Bucket ──────────────────────────────────────────────────────
    // The bucket holds tokens; each request consumes one token.
    // Tokens are replenished at a steady rate, allowing short bursts
    // (up to TokenLimit) while enforcing a long-term average rate.
    options.AddTokenBucketLimiter("token", o =>
    {
        o.TokenLimit = 10;                              // Bucket capacity (burst ceiling)
        o.ReplenishmentPeriod = TimeSpan.FromSeconds(5);
        o.TokensPerPeriod = 2;                          // +2 tokens every 5 seconds
        o.AutoReplenishment = true;
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 2;
    });

    // ── 4. Concurrency ───────────────────────────────────────────────────────
    // Limits how many requests are processed *simultaneously*, not per time unit.
    // Useful for protecting downstream services from parallel overload.
    options.AddConcurrencyLimiter("concurrency", o =>
    {
        o.PermitLimit = 3;                              // Max 3 concurrent requests
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 2;
    });

    // ── 5. Per-API-Key Partitioned ───────────────────────────────────────────
    // Authentication middleware guarantees the key is valid before this runs.
    // Each key gets its own independent bucket; one client hitting their limit
    // has zero effect on any other client.
    options.AddPolicy("api-key", httpContext =>
    {
        var apiKey = httpContext.Request.Headers["x-api-key"].ToString();
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: $"apikey-{apiKey}",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,                       // 20 requests…
                Window = TimeSpan.FromSeconds(10),      // …per 10 seconds
                QueueLimit = 0
            });
    });

    // Add a Retry-After header to every 429 response so clients know when to retry
    options.OnRejected = async (context, cancellationToken) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter =
                ((int)retryAfter.TotalSeconds).ToString();
        }

        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsync(
            "Rate limit exceeded. Check the Retry-After header.", cancellationToken);
    };
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.WithOpenApiRoutePattern("/openapi/v1.json")
            .WithTitle("Nuget Tester")
            .WithTheme(ScalarTheme.Solarized)
            .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
    });
}

app.UseHttpsRedirection();

// Standard auth middleware — handles the 401 challenge for invalid/missing keys
// before the rate limiter runs, so bad requests never consume quota.
app.UseAuthentication();
app.UseAuthorization();

// IP allow-list: only endpoints that call .RequireIpAllowlist() are gated.
// Placed before the rate limiter so blocked IPs never consume quota.
app.UseIpAllowlist();

// Rate-limiting middleware must be added to the pipeline before endpoint mapping
app.UseRateLimiter();

// Apply the Fixed Window policy
app.MapGet("/limit", () => Results.Ok("Fixed window – max 5 requests per 10 s"))
    .WithName("FixedWindowEndpoint")
    .RequireRateLimiting("fixed");

// Apply the Sliding Window policy
app.MapGet("/limit/sliding", () => Results.Ok("Sliding window – max 10 requests per 30 s (3 segments)"))
    .WithName("SlidingWindowEndpoint")
    .RequireRateLimiting("sliding");

// Apply the Token Bucket policy
app.MapGet("/limit/token", () => Results.Ok("Token bucket – burst up to 10, refills 2 tokens every 5 s"))
    .WithName("TokenBucketEndpoint")
    .RequireRateLimiting("token");

// Apply the Concurrency policy
app.MapGet("/limit/concurrency", () => Results.Ok("Concurrency – max 3 simultaneous requests"))
    .WithName("ConcurrencyEndpoint")
    .RequireRateLimiting("concurrency");

// Apply the Per-API-Key partitioned policy
app.MapGet("/limit/apikey", (HttpContext ctx) =>
    {
        var key = ctx.Request.Headers["x-api-key"].ToString();
        return Results.Ok($"Authenticated as '{key}' – max 20 req/10 s");
    })
    .WithName("ApiKeyEndpoint")
    .RequireAuthorization()               // standard auth enforcement – 401 if not authenticated
    .RequireRateLimiting("api-key");

// ── 6. IP Allow-list (opt-in) ────────────────────────────────────────────────
// Only IPs listed under "IpAllowlist:AllowedIPs" in appsettings.json can reach
// this endpoint.  Any other caller receives 403 Forbidden.
// Remove .RequireIpAllowlist() from an endpoint to open it to all IPs.
app.MapGet("/limit/ip-allowlist", (HttpContext ctx) =>
    {
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return Results.Ok($"Welcome, {ip} – your IP is on the allow-list.");
    })
    .WithName("IpAllowlistEndpoint")
    .RequireIpAllowlist();

app.Run();

