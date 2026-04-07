namespace RateLimiting.Api.Setup;

public static class IpAllowlistExtensions
{
    /// <summary>
    /// Registers IP allow-list options bound to the "IpAllowlist" config section.
    /// Call this inside <c>builder.Services</c>.
    /// </summary>
    public static IServiceCollection AddIpAllowlist(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<IpAllowlistOptions>(configuration.GetSection("IpAllowlist"));
        return services;
    }

    /// <summary>
    /// Adds the <see cref="IpAllowlistMiddleware"/> to the pipeline.
    /// Must be placed <em>after</em> endpoint routing is established so that
    /// endpoint metadata (opt-in marker) is resolvable at request time.
    /// </summary>
    public static IApplicationBuilder UseIpAllowlist(this IApplicationBuilder app)
        => app.UseMiddleware<IpAllowlistMiddleware>();

    /// <summary>
    /// Opts the endpoint into IP allow-list enforcement.
    /// Requests whose source IP is not in <c>IpAllowlist:AllowedIPs</c>
    /// will receive a <c>403 Forbidden</c> response.
    /// </summary>
    public static RouteHandlerBuilder RequireIpAllowlist(this RouteHandlerBuilder builder)
        => builder.WithMetadata(new IpAllowlistMetadata());
}

