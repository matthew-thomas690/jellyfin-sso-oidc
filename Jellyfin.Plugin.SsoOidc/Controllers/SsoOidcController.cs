using System;
using System.Linq;
using System.Reflection;
using System.IO;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SsoOidc.Configuration;
using Jellyfin.Plugin.SsoOidc.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http.Extensions;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.SsoOidc.Controllers
{
    [ApiController]
    [Route("Plugins/SsoOidc")]
    public class SsoOidcController : ControllerBase
    {
        private readonly PluginConfiguration _config;
        private readonly ISessionManager _sessionManager;
        private readonly ILogger<SsoOidcController> _logger;
        private readonly IOidcStateStore _stateStore;
        private readonly IUserManager _userManager;

        public SsoOidcController(
            PluginConfiguration config,
            ISessionManager sessionManager,
            ILogger<SsoOidcController> logger,
            IOidcStateStore stateStore,
            IUserManager userManager)
        {
            _config         = config;
            _sessionManager = sessionManager;
            _logger         = logger;
            _stateStore     = stateStore;
            _userManager    = userManager;
            _logger.LogInformation("SsoOidcController initialized");
        }

        [HttpGet("Authenticate/{providerName}")]
        public async Task<IActionResult> Authenticate(string providerName)
        {
            var provider = _config.OidConfigs
                .FirstOrDefault(p => 
                    p.ProviderName.Equals(providerName, StringComparison.OrdinalIgnoreCase) &&
                    p.Enabled);
            if (provider == null)
            {
                _logger.LogWarning("Unknown or disabled provider {Provider}", providerName);
                return BadRequest("Provider not found.");
            }

            var redirectUri = Url.Action(nameof(Callback), "SsoOidc", new { providerName }, "https");
            var options     = OidcClientOptionsFactory.Create(
                providerName,
                provider.OidEndpoint,
                provider.OidClientId,
                provider.OidSecret,
                provider.OidScope,
                redirectUri);

            var client       = new OidcClient(options);
            var loginRequest = await client.PrepareLoginAsync();

            _stateStore.Store(loginRequest.State, new OidcStateEntry
            {
                AuthState = loginRequest,
                Created   = DateTime.UtcNow
            });

            _logger.LogInformation("Redirecting to {Provider} authorize URL", providerName);
            return Redirect(loginRequest.StartUrl);
        }

        [HttpGet("Callback/{providerName}")]
        public async Task<IActionResult> Callback(string providerName)
        {
            // 1. Retrieve and validate state
            var stateKey = Request.Query["state"].ToString();
            if (string.IsNullOrEmpty(stateKey) || !_stateStore.TryGet(stateKey, out var entry))
            {
                return BadRequest("Invalid state.");
            }

            // 2. Lookup provider config
            var provider = _config.OidConfigs
                .FirstOrDefault(p => p.ProviderName.Equals(providerName, StringComparison.OrdinalIgnoreCase) && p.Enabled);
            if (provider == null)
            {
                return BadRequest("Provider not found.");
            }

            // 3. Exchange code for tokens
            var redirectUri = Url.Action(nameof(Callback), "SsoOidc", new { providerName }, "https");
            var options = OidcClientOptionsFactory.Create(
                providerName,
                provider.OidEndpoint,
                provider.OidClientId,
                provider.OidSecret,
                provider.OidScope,
                redirectUri
            );
            var client = new OidcClient(options);
            var oidcResponse = await client.ProcessResponseAsync(Request.GetEncodedUrl(), entry.AuthState);
            if (oidcResponse.IsError)
            {
                _logger.LogError("OIDC processing error: {Error}", oidcResponse.Error);
                return BadRequest("Error processing login response.");
            }

            // 4. Map returned claim to Jellyfin user ID
            var returnedClaim = oidcResponse.User.Claims
                .FirstOrDefault(c => provider.UserLink.Any(u => u.ClaimValue == c.Value));
            if (returnedClaim == null)
            {
                return Unauthorized();
            }
            var mapping = provider.UserLink.First(u => u.ClaimValue == returnedClaim.Value);
            var userId = Guid.Parse(mapping.UserId);

            // 5. Load the Jellyfin user via IUserManager
            var jellyfinUser = _userManager.GetUserById(userId);
            if (jellyfinUser == null)
            {
                return Unauthorized();
            }

            // 6. Build and send Jellyfin authentication request
            var authRequest = new AuthenticationRequest
            {
                UserId     = userId,
                Username   = jellyfinUser.Username,
                DeviceId   = $"SSO-{providerName}",
                DeviceName = $"SSO via {providerName}",
                App    = $"SSO OIDC Plugin ({providerName})",
                AppVersion = Plugin.Instance?.Version.ToString() ?? "1.0.0"
            };

            var authResult = await _sessionManager.AuthenticateDirect(authRequest);

            // 7. Check that we got an access token back
            if (string.IsNullOrEmpty(authResult?.AccessToken))
            {
                _logger.LogError("Jellyfin authentication failed: no access token");
                return StatusCode(500, "Sign-in failed.");
            }

            // 8. Issue token cookie & clean up
            Response.Cookies.Append("Jellyfin_AccessToken",
                authResult.AccessToken,
                new CookieOptions { HttpOnly = true, Secure = true });

            _stateStore.Remove(stateKey);

            // 9. Redirect back into the Jellyfin UI
            return LocalRedirect("~/web/index.html");
        }
    }
}
