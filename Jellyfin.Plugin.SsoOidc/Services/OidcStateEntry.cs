using System;
using Duende.IdentityModel.OidcClient;

namespace Jellyfin.Plugin.SsoOidc.Services
{
    /// <summary>
    /// Stores information about an in-flight OIDC login request.
    /// </summary>
    public class OidcStateEntry
    {
        /// <summary>PKCE code verifier to use during token exchange.</summary>
        public AuthorizeState AuthState { get; set; }

        /// <summary>Jellyfin user ID that initiated the request.</summary>
        public string JellyfinUserId { get; set; }

        /// <summary>Claim value this login is tied to (e.g. email).</summary>
        public string ClaimValue { get; set; }

        /// <summary>Timestamp when this state entry was created (for expiration).</summary>
        public DateTime Created { get; set; }
    }
}
