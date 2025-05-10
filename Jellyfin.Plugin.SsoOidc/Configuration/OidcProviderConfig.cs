using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Jellyfin.Plugin.SsoOidc.Configuration;

/// <summary>
/// Represents configuration for a single OIDC provider.
/// </summary>
public class OidcProviderConfig
{
    /// <summary>
    /// Gets or sets the display name of the OIDC provider.
    /// </summary>
    public required string ProviderName { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets the OIDC discovery endpoint (metadata URL).
    /// </summary>
    public required string OidEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the client ID used for authentication.
    /// </summary>
    public required string OidClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret used for authentication.
    /// </summary>
    public required string OidSecret { get; set; }

    /// <summary>
    /// Gets or sets the requested OIDC scopes (e.g., "openid email").
    /// </summary>
    public required string OidScope { get; set; }

    /// <summary>
    /// Gets the mapping from identity claim (e.g. email) to Jellyfin user IDs.
    /// </summary>
    public Dictionary<string, string> UserLink { get; } = new();
}
