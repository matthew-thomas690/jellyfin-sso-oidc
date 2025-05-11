using System;
using System.Collections.Concurrent;
using Jellyfin.Plugin.SsoOidc.Controllers; // for OidcStateEntry

namespace Jellyfin.Plugin.SsoOidc.Services
{
    /// <summary>
    /// In-memory implementation of IOidcStateStore using ConcurrentDictionary.
    /// </summary>
    public class InMemoryOidcStateStore : IOidcStateStore
    {
        private readonly ConcurrentDictionary<string, OidcStateEntry> _store = new();

        public void Store(string state, OidcStateEntry entry)
        {
            entry.Created = DateTime.UtcNow;
            _store[state] = entry;
        }

        public bool TryGet(string state, out OidcStateEntry entry)
        {
            return _store.TryGetValue(state, out entry);
        }

        public void Remove(string state)
        {
            _store.TryRemove(state, out _);
        }

        /// <summary>
        /// Cleanup entries older than the specified max age.
        /// </summary>
        /// <param name="maxAge">Maximum allowed age for entries.</param>
        public void Cleanup(TimeSpan maxAge)
        {
            var cutoff = DateTime.UtcNow - maxAge;
            foreach (var kvp in _store)
            {
                if (kvp.Value.Created < cutoff)
                {
                    _store.TryRemove(kvp.Key, out _);
                }
            }
        }
    }
}