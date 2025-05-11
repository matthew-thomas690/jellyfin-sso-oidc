using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SsoOidc.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SsoOidc.Services
{
    /// <summary>
    /// Background task to periodically clean up expired OIDC state entries.
    /// </summary>
    public class OidcStateCleanupService : IHostedService, IDisposable
    {
        private readonly InMemoryOidcStateStore _store;
        private readonly ILogger<OidcStateCleanupService> _logger;
        private Timer _timer;
        private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(10);

        public OidcStateCleanupService(IOidcStateStore store, ILogger<OidcStateCleanupService> logger)
        {
            _store = store as InMemoryOidcStateStore;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _timer = new Timer(_ => {
                _logger.LogInformation("Cleaning up expired OIDC states...");
                _store.Cleanup(MaxAge);
            }, null, TimeSpan.Zero, Interval);

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _timer?.Change(Timeout.Infinite, 0);
            return Task.CompletedTask;
        }

        public void Dispose() => _timer?.Dispose();
    }
}