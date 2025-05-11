namespace Jellyfin.Plugin.SsoOidc.Services
{
    /// <summary>
    /// Interface for storing OIDC login state entries.
    /// </summary>
    public interface IOidcStateStore
    {
        /// <summary>
        /// Save a new state entry before redirecting to the provider.
        /// </summary>
        /// <param name="state">The OAuth2 state parameter.</param>
        /// <param name="entry">The state entry containing PKCE verifier and metadata.</param>
        void Store(string state, OidcStateEntry entry);

        /// <summary>
        /// Retrieve a stored entry by state.
        /// </summary>
        bool TryGet(string state, out OidcStateEntry entry);

        /// <summary>
        /// Remove an entry once processed or expired.
        /// </summary>
        void Remove(string state);
    }
}