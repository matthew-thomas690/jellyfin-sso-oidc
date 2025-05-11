using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Jellyfin.Plugin.SsoOidc.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.SsoOidc
{
    /// <summary>
    /// The main plugin.
    /// </summary>
    public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
    {
        public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
            : base(applicationPaths, xmlSerializer)
        {
            Instance = this;
            EnsureDefaultGoogleProvider();
        }

        public override string Name => "SSO OIDC";
        public override Guid   Id   => Guid.Parse("c3ef348c-6871-42c1-8a0e-d03956c9bcf9");

        public static Plugin? Instance { get; private set; }

        // Dashboard config page
        public IEnumerable<PluginPageInfo> GetPages()
        {
            return new[]
            {
                new PluginPageInfo
                {
                    // This shows up at /web/Plugins/SsoOidc
                    Name                 = Name,
                    EmbeddedResourcePath = $"{GetType().Namespace}.Configuration.configPage.html"
                }
            };
        }

        private void EnsureDefaultGoogleProvider()
        {
            var cfg = Configuration;
            if (!cfg.OidConfigs.Any(p => string.Equals(p.ProviderName, "Google", StringComparison.OrdinalIgnoreCase)))
            {
                cfg.OidConfigs.Add(new OidcProviderConfig
                {
                    ProviderName = "Google",
                    Enabled      = false,
                    OidEndpoint  = "https://accounts.google.com",
                    OidClientId  = string.Empty,
                    OidSecret    = string.Empty,
                    OidScope     = "openid email"
                });
                SaveConfiguration();
            }
        }
    }
}
