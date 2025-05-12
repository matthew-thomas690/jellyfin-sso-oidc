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
            serviceCollection.AddSingleton<IOidcStateStore, InMemoryOidcStateStore>();
            serviceCollection.AddHostedService<OidcStateCleanupService>();
            serviceCollection.AddTransient(_ => Plugin.Instance!.Configuration);
            serviceCollection.AddTransient<AutoLoginHtmlBuilder>();
            serviceCollection.AddTransient<SSOLoginPageHtmlBuilder>();
        }
    }
}
