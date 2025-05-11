using System;
using Jellyfin.Plugin.SsoOidc.Services;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.SsoOidc
{
    /// <summary>
    /// Registers plugin-specific services into Jellyfin's DI container.
    /// </summary>
    public class ServiceRegistrator : IPluginServiceRegistrator
    {
        /// <summary>
        /// Called by Jellyfin at startup to register services.
        /// </summary>
        public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
        {
            // 1) OIDC state store & cleanup
            serviceCollection.AddSingleton<IOidcStateStore, InMemoryOidcStateStore>();
            serviceCollection.AddHostedService<OidcStateCleanupService>();

            // 2) Expose plugin configuration
            serviceCollection.AddSingleton(_ => Plugin.Instance!.Configuration);

        }
    }
}
