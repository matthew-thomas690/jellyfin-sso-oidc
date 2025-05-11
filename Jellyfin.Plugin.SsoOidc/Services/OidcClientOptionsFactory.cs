// File: Services/OidcClientOptionsFactory.cs
using System;
using System.Collections.Generic;
using Duende.IdentityModel.OidcClient;

namespace Jellyfin.Plugin.SsoOidc.Services
{
    /// <summary>
    /// Factory to create OidcClientOptions per provider using delegate-based builders.
    /// </summary>
    public static class OidcClientOptionsFactory
    {
        // Delegate signature for building OIDC options
        public delegate OidcClientOptions Builder(
            string authority,
            string clientId,
            string clientSecret,
            string scope,
            string redirectUri
        );

        // Map provider names to their specific builder delegate
        private static readonly Dictionary<string, Builder> _builders =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["Google"] = (authority, clientId, clientSecret, scope, redirectUri) =>
                {
                    return new OidcClientOptions
                    {
                        Authority = authority.TrimEnd('/'),
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        Scope = scope,
                        RedirectUri = redirectUri,
                        Policy =
                        {
                            //RequireIdentityTokenSignature = true,
                            Discovery = { ValidateEndpoints = false }
                        }
                    };
                }
                // Add more provider-specific builders here...
            };

        /// <summary>
        /// Creates OidcClientOptions by invoking the provider-specific builder if available,
        /// otherwise falling back to a default implementation.
        /// </summary>
        public static OidcClientOptions Create(
            string providerName,
            string authority,
            string clientId,
            string clientSecret,
            string scope,
            string redirectUri)
        {
            if (_builders.TryGetValue(providerName, out var build))
            {
                return build(authority, clientId, clientSecret, scope, redirectUri);
            }

            // Default builder
            return new OidcClientOptions
            {
                Authority = authority.TrimEnd('/'),
                ClientId = clientId,
                ClientSecret = clientSecret,
                Scope = scope,
                RedirectUri = redirectUri,
                Policy =
                {
                    //RequireIdentityTokenSignature = true
                }
            };
        }
    }
}
