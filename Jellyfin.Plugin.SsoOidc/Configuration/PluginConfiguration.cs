using System.Collections.Generic;
using System.Xml.Serialization;
using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.SsoOidc.Configuration;

/// <summary>
/// Plugin configuration.
/// </summary>
public class PluginConfiguration : BasePluginConfiguration
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PluginConfiguration"/> class.
    /// </summary>
    public PluginConfiguration()
    {
    }

    

    /// <summary>
    /// Gets or sets the list of configured OpenID Connect providers.
    /// </summary>
    [XmlArray("OidConfigs")]
    [XmlArrayItem("Provider")]
    public List<OidcProviderConfig> OidConfigs { get; set; } = new List<OidcProviderConfig>();
}
