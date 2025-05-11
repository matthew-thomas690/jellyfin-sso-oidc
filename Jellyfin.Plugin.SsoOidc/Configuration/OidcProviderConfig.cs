using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Xml.Serialization;

namespace Jellyfin.Plugin.SsoOidc.Configuration;

/// <summary>
/// Represents configuration for a single OIDC provider.
/// </summary>
public class OidcProviderConfig
{
    /// <summary>
    /// Gets or sets the display name of the OIDC provider.
    /// </summary>
    public string ProviderName { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets the OIDC discovery endpoint (metadata URL).
    /// </summary>
    public string OidEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the client ID used for authentication.
    /// </summary>
    public string OidClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret used for authentication.
    /// </summary>
    public string OidSecret { get; set; }

    /// <summary>
    /// Gets or sets the requested OIDC scopes (e.g., "openid email").
    /// </summary>
    public string OidScope { get; set; }

    /// <summary>
    /// Gets or sets the mapping from identity claim (e.g. email) to Jellyfin user IDs.
    /// </summary>
    [XmlArray("UserLink")]
    [XmlArrayItem("Entry")]
    public List<UserLinkEntry> UserLink { get; set; } = new();
}

/// <summary>
/// Represents a user mapping between an OIDC claim and a Jellyfin user ID.
/// </summary>
public class UserLinkEntry
{
    public string ClaimValue { get; set; }
    public string UserId { get; set; }
}
