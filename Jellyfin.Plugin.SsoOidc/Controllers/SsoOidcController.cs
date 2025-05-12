using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SsoOidc.Configuration;
using Jellyfin.Plugin.SsoOidc.Services;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using static Jellyfin.Plugin.SsoOidc.Plugin;

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
            _config = config;
            _sessionManager = sessionManager;
            _logger = logger;
            _stateStore = stateStore;
            _userManager = userManager;
            _logger.LogInformation("SsoOidcController initialized.");
        }

        [HttpGet("Login")]
        public IActionResult Login()
        {
            var providers = _config?.OidConfigs?
                .Where(p => p.Enabled && !string.IsNullOrWhiteSpace(p.ProviderName))
                .Select(p => p.ProviderName!)
                .Distinct()
                .ToList()
                ?? new List<string>();

            var html = new StringBuilder();

            // --- HTML head with Material Icons stylesheet ---
            html.AppendLine("<!DOCTYPE html>");
            html.AppendLine("<html><head>");
            html.AppendLine("  <meta charset='utf-8' />");
            html.AppendLine("  <title>SSO Login</title>");
            html.AppendLine("  <!-- Load Google Material Icons -->");
            html.AppendLine("  <link href=\"https://fonts.googleapis.com/icon?family=Material+Icons\" rel=\"stylesheet\" />");
            html.AppendLine("  <style>");
            html.AppendLine("    body { font-family: Arial; padding:20px; }");
            html.AppendLine("    .btn {");
            html.AppendLine("      display:flex; align-items:center; justify-content:center;");
            html.AppendLine("      gap:10px; padding:12px 20px; font-size:16px;");
            html.AppendLine("      background:#007bff; color:#fff; border:none; border-radius:4px;");
            html.AppendLine("      text-decoration:none;");
            html.AppendLine("    }");
            html.AppendLine("    form { margin: 1em auto; width: fit-content; }");
            html.AppendLine("  </style>");
            html.AppendLine("</head><body>");

            html.AppendLine("  <h2>Select your SSO provider</h2>");

            foreach (var prov in providers)
            {
                var encoded = HtmlEncoder.Default.Encode(prov);

                // Form wrapper to preserve _deviceId2 in Android WebView
                html.AppendLine(CultureInfo.InvariantCulture, $"  <form action=\"/Plugins/SsoOidc/Authenticate/{encoded}\" method=\"get\" target=\"_self\">");
                html.AppendLine("    <button class=\"btn emby-button button-submit\"");
                html.AppendLine("            onclick=\"");
                html.AppendLine("              if (!localStorage.getItem('_deviceId2') && window.NativeShell?.AppHost?.deviceId) {");
                html.AppendLine("                localStorage.setItem('_deviceId2', window.NativeShell.AppHost.deviceId());");
                html.AppendLine("              }");
                html.AppendLine("            \"");
                html.AppendLine("            type=\"submit\">");
                html.AppendLine("      <span class=\"material-icons\" aria-hidden=\"true\">shield</span>");
                html.AppendLine(CultureInfo.InvariantCulture, $"      <span>Sign in with {encoded}</span>");
                html.AppendLine("    </button>");
                html.AppendLine("  </form>");
            }

            html.AppendLine("</body></html>");

            return Content(html.ToString(), "text/html");
        }

        [HttpGet("Users")]
        public IActionResult GetAllUsers()
        {
            var users = _userManager.Users
                .Select(u => new
                {
                    userId = u.Id.ToString(),
                    username = u.Username
                })
                .ToList();

            return Ok(users);
        }

        [HttpGet("ActiveProviders")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public ActionResult<List<string>> GetActiveOidcProviders()
        {
            _logger.LogInformation("GetActiveOidcProviders: Request received.");

            if (_config?.OidConfigs is not { } oidConfigs)
            {
                _logger.LogWarning("Plugin configuration or OidConfigs list is null.");
                return new List<string>();
            }

            var providers = oidConfigs
                .Where(p => p.Enabled && !string.IsNullOrWhiteSpace(p.ProviderName))
                .Select(p => p.ProviderName!)
                .Distinct()
                .ToList();

            _logger.LogInformation(
                "GetActiveOidcProviders: Returning {Count} active providers: {Providers}",
                providers.Count,
                providers);

            return providers;
        }

        [HttpGet("Authenticate/{providerName}")]
        public async Task<IActionResult> Authenticate(string providerName)
        {
            _logger.LogInformation("Authenticate: Request for provider: {ProviderName}", providerName);
            var oidcProviderConfig = _config.OidConfigs
                .FirstOrDefault(p => 
                    p.ProviderName.Equals(providerName, StringComparison.OrdinalIgnoreCase) &&
                    p.Enabled);

            if (oidcProviderConfig == null)
            {
                _logger.LogWarning("Authenticate: Unknown or disabled provider '{ProviderName}'", providerName);
                return BadRequest("Provider not found.");
            }

            var scheme = HttpContext.Request.Scheme;
            if (!string.Equals(scheme, "https", StringComparison.OrdinalIgnoreCase) &&
                !HttpContext.Request.Host.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
                !HttpContext.Request.Host.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("Authenticate: Current scheme is '{CurrentScheme}' for non-local host '{Host}'. Forcing HTTPS for redirect URI.", scheme, HttpContext.Request.Host.Host);
                scheme = "https";
            }

            var redirectUri = Url.Action(nameof(Callback), "SsoOidc", new { providerName }, scheme);
            _logger.LogInformation("Authenticate: Determined Redirect URI: {RedirectUri}", redirectUri);

            var options = OidcClientOptionsFactory.Create(
                oidcProviderConfig.ProviderName,
                oidcProviderConfig.OidEndpoint,
                oidcProviderConfig.OidClientId,
                oidcProviderConfig.OidSecret,
                oidcProviderConfig.OidScope,
                redirectUri);

            var client = new OidcClient(options);
            var loginRequest = await client.PrepareLoginAsync(); // This is Duende.IdentityModel.OidcClient.AuthorizeState

            if (loginRequest.IsError)
            {
                _logger.LogError("Authenticate: OIDC PrepareLoginAsync error: {Error}", loginRequest.Error);
                return BadRequest($"Error preparing login: {loginRequest.Error}");
            }

            _stateStore.Store(loginRequest.State, new OidcStateEntry
            {
                AuthState = loginRequest, 
                Created   = DateTime.UtcNow
            });

            _logger.LogInformation("Authenticate: Redirecting to OIDC provider '{ProviderName}' authorize URL: {AuthorizeUrl}", oidcProviderConfig.ProviderName, loginRequest.StartUrl);
            return Redirect(loginRequest.StartUrl);
        }

        [HttpGet("Callback/{providerName}")]
        public async Task<IActionResult> Callback(string providerName)
        {
            _logger.LogInformation("Callback: Processing OIDC callback for provider: {ProviderName}", providerName);

            var stateKey = Request.Query["state"].ToString();
            if (string.IsNullOrEmpty(stateKey) || !_stateStore.TryGet(stateKey, out var storedStateEntry) || storedStateEntry.AuthState == null)
            {
                _logger.LogWarning("Callback: Invalid or missing OIDC state parameter, or state entry is invalid/corrupt. StateKey: '{StateKey}'", stateKey);
                return Content("<h1>Login Error</h1><p>Invalid or expired session state. Please try logging in again.</p>", "text/html");
            }

            var oidcProviderConfig = _config.OidConfigs
                .FirstOrDefault(p => p.ProviderName.Equals(providerName, StringComparison.OrdinalIgnoreCase) && p.Enabled);

            if (oidcProviderConfig == null)
            {
                _logger.LogWarning("Callback: Provider configuration not found or disabled for '{ProviderName}'", providerName);
                _stateStore.Remove(stateKey); // Clean up state
                return Content("<h1>Configuration Error</h1><p>SSO provider configuration not found or is disabled. Please contact your administrator.</p>", "text/html");
            }

            var redirectUri = Url.Action(nameof(Callback), "SsoOidc", new { providerName }, "https");
            _logger.LogInformation("Callback: Determined Redirect URI for OIDC client: {RedirectUri}", redirectUri);

            var oidcClientOptions = OidcClientOptionsFactory.Create(
                oidcProviderConfig.ProviderName,
                oidcProviderConfig.OidEndpoint,
                oidcProviderConfig.OidClientId,
                oidcProviderConfig.OidSecret,
                oidcProviderConfig.OidScope,
                redirectUri);

            var oidcClient = new OidcClient(oidcClientOptions);
            var currentCallbackUrl = Request.GetEncodedUrl();
            _logger.LogInformation("Callback: Processing OIDC response with Full URL: {CurrentCallbackUrl}", currentCallbackUrl);

            LoginResult oidcProcessingResult = await oidcClient.ProcessResponseAsync(currentCallbackUrl, storedStateEntry.AuthState);
            _stateStore.Remove(stateKey); 

            if (oidcProcessingResult.IsError)
            {
                _logger.LogError(
                    "Callback: OIDC ProcessResponseAsync error: {Error}. Description: {ErrorDescription}. " +
                                 "TokenResponse HttpError: {TokenResponseHttpError}, TokenResponse HttpErrorReason: {TokenResponseHttpErrorReason}, TokenResponse Error: {TokenResponseError}, TokenResponse ErrorDescription: {TokenResponseErrorDescription}, TokenResponse Raw: {TokenResponseRaw}", 
                    oidcProcessingResult.Error,
                    oidcProcessingResult.ErrorDescription,
                    oidcProcessingResult.TokenResponse?.HttpStatusCode,
                    oidcProcessingResult.TokenResponse?.HttpErrorReason,
                    oidcProcessingResult.TokenResponse?.Error,
                    oidcProcessingResult.TokenResponse?.ErrorDescription,
                    oidcProcessingResult.TokenResponse?.Raw);
                return Content($"<h1>Login Error</h1><p>Could not process the response from the SSO provider.</p><p>Details: {oidcProcessingResult.Error} - {oidcProcessingResult.ErrorDescription}</p><p>Please check plugin logs for more technical details and contact your administrator if the issue persists.</p>", "text/html");
            }

            if (oidcProcessingResult.User == null || !oidcProcessingResult.User.Claims.Any())
            {
                _logger.LogError("Callback: OIDC ProcessResponseAsync succeeded but returned no user claims. TokenResponse Raw (if available): {TokenResponseRaw}", oidcProcessingResult.TokenResponse?.Raw);
                return Content("<h1>Login Error</h1><p>Authentication with SSO provider succeeded, but no user information (claims) was returned. Please check the OIDC provider configuration and ensure scopes like 'openid', 'profile', 'email' are requested and allowed. Contact your administrator if the issue persists.</p>", "text/html");
            }
            _logger.LogInformation("Callback: OIDC response processed successfully. Found {ClaimCount} claims.", oidcProcessingResult.User.Claims.Count());

            // --- STEP 1: Determine which claim type to use for this provider ---
            var claimType = GetClaimTypeFromScope(oidcProviderConfig.OidScope);
            // (throws if OidScope is anything other than "openid" or "openid {claim}")

            // --- STEP 2: Find that claim in the provider’s response ---
            var returnedOidcClaim = oidcProcessingResult.User.Claims
                .FirstOrDefault(c => 
                    c.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase));

            if(claimType == "email")
            {
                var emailVerifiedClaim = oidcProcessingResult.User.Claims
                    .FirstOrDefault(c => c.Type.Equals("email_verified", StringComparison.OrdinalIgnoreCase));

                    if (emailVerifiedClaim == null 
                        || !bool.TryParse(emailVerifiedClaim.Value, out var isVerified) 
                        || !isVerified)
                    {
                        return Content(
                        "<h1>Login Failed</h1>" +
                        "<p>Your email address has not been verified. Please verify it with your SSO provider before logging in.</p>",
                        "text/html");
                    }
            }

            if (returnedOidcClaim == null)
            {
                var available = string.Join(
                    "; ",
                    oidcProcessingResult.User.Claims
                        .Select(c => $"{c.Type}='{c.Value}'"));
                _logger.LogWarning(
                    "Callback: Required claim '{ClaimType}' not found in OIDC response for provider '{ProviderName}'. Available: [{Available}].", claimType, oidcProviderConfig.ProviderName, available);
                return Content(
                    "<h1>Login Failed</h1>" +
                    $"<p>Required claim '{claimType}' was not returned by the SSO provider.</p>",
                    "text/html");
            }

            // --- STEP 3: Extract the claim’s value for mapping ---
            var claimValue = returnedOidcClaim.Value;
            _logger.LogInformation(
                "Callback: Using OIDC claim '{ClaimType}' = '{ClaimValue}' for user lookup.", claimType, claimValue);

            // --- STEP 4: Find the UserLink entry by claimValue only (the provider’s ClaimType is implicit) ---
            var userMappingEntry = oidcProviderConfig.UserLink
                .FirstOrDefault(u =>
                    u.ClaimValue.Equals(claimValue, StringComparison.OrdinalIgnoreCase));

            if (userMappingEntry == null)
            {
                var configured = string.Join(", ",
                    oidcProviderConfig.UserLink.Select(u => u.ClaimValue));
                _logger.LogWarning(
                    "Callback: No UserLink entry with ClaimValue='{ClaimValue}' for provider '{ProviderName}'. Configured: [{Configured}].", claimValue, oidcProviderConfig.ProviderName, configured);
                return Content(
                    "<h1>Login Failed</h1>" +
                    "<p>Your account is not linked for this SSO provider. Please contact your administrator.</p>",
                    "text/html");
            }

            // --- STEP 5: Parse the Jellyfin user GUID and handle errors ---
            if (!Guid.TryParse(userMappingEntry.UserId, out var jellyfinUserIdGuid))
            {
                _logger.LogError(
                    "Callback: Invalid UserId '{ConfiguredUserId}' in mapping for provider '{ProviderName}'.", userMappingEntry.UserId, oidcProviderConfig.ProviderName);
                return Content(
                    "<h1>Configuration Error</h1>" +
                    "<p>The configured Jellyfin UserId is not a valid GUID. Please contact your administrator.</p>",
                    "text/html");
            }

            _logger.LogInformation(
                "Callback: Mapped OIDC claim value '{ClaimValue}' to Jellyfin UserId {JellyfinUserId}.",
                claimValue, jellyfinUserIdGuid);

            // jellyfinUser is of type Jellyfin.Data.Entities.User which has a Username property
            var jellyfinUser = _userManager.GetUserById(jellyfinUserIdGuid);
            if (jellyfinUser == null)
            {
                _logger.LogWarning("Callback: Jellyfin user not found in the database for mapped UserId: {JellyfinUserIdGuid}", jellyfinUserIdGuid);
                return Content("<h1>Login Failed</h1><p>The Jellyfin user associated with your SSO account could not be found. Please contact your administrator.</p>", "text/html");
            }

            _logger.LogInformation("Callback: Successfully loaded Jellyfin user: '{Username}' (Id: {UserId})", jellyfinUser.Username, jellyfinUser.Id);

            var jellyfinAuthRequest = new AuthenticationRequest
            {
                UserId = jellyfinUser.Id, 
                Username = jellyfinUser.Username, // Correct: Jellyfin.Data.Entities.User.Username
                DeviceId = $"SSO-{oidcProviderConfig.ProviderName.Replace(" ", "")}",
                DeviceName = $"SSO via {oidcProviderConfig.ProviderName}",
                App = $"SSO OIDC Plugin ({oidcProviderConfig.ProviderName})",
                AppVersion = Instance?.Version.ToString() ?? "1.0.4" // Using static Plugin.Instance, incremented version
            };

            _logger.LogInformation("Callback: Attempting Jellyfin internal authentication for user '{Username}' with DeviceId '{DeviceId}'", jellyfinAuthRequest.Username, jellyfinAuthRequest.DeviceId);

            // jellyfinAuthResult is MediaBrowser.Controller.Authentication.AuthenticationResult
            var jellyfinAuthResult = await _sessionManager.AuthenticateDirect(jellyfinAuthRequest);

            if (jellyfinAuthResult == null)
            {
                 _logger.LogError("Callback: Jellyfin AuthenticateDirect returned null. Authentication failed for user '{Username}'.", jellyfinAuthRequest.Username);
                 return Content("<h1>Login Failed</h1><p>Could not obtain a Jellyfin session (result was null). Please check server logs and contact your administrator.</p>", "text/html");
            }

            if (string.IsNullOrEmpty(jellyfinAuthResult.AccessToken))
            {
                 _logger.LogError("Callback: Jellyfin AuthenticateDirect returned an empty AccessToken. Authentication failed for user '{Username}'. ServerId (from result): {ServerId}", jellyfinAuthRequest.Username, jellyfinAuthResult.ServerId);
                 return Content("<h1>Login Failed</h1><p>Could not obtain a Jellyfin session token. Please check server logs and contact your administrator.</p>", "text/html");
            }

            if (jellyfinAuthResult.User == null)
            { // jellyfinAuthResult.User is MediaBrowser.Model.Dto.UserDto
                 _logger.LogError("Callback: Jellyfin AuthenticateDirect returned a null User object (UserDto). Authentication failed for user '{Username}'. ServerId: {ServerId}", jellyfinAuthRequest.Username, jellyfinAuthResult.ServerId);
                 return Content("<h1>Login Failed</h1><p>Could not obtain Jellyfin user details for the session. Please check server logs and contact your administrator.</p>", "text/html");
            }

            // Correctly use .Name for UserDto
            _logger.LogInformation("Callback: Jellyfin internal authentication successful for user '{UserDtoName}'. AccessToken obtained. ServerId: {ServerId}, UserId (from Dto): {UserDtoId}", jellyfinAuthResult.User.Name, jellyfinAuthResult.ServerId, jellyfinAuthResult.User.Id);

            // Data for JavaScript
            string DtoUserId = jellyfinAuthResult.User.Id.ToString();
            string DtoUsernameOrName = jellyfinAuthResult.User.Name; // Use .Name as per UserDto.cs

            _logger.LogDebug("Callback: Data for JS - AccessToken: {AccessTokenLength} chars, UserId (from Dto): {UserId}, ServerId: {ServerId}, Username/Name (from Dto): {UsernameOrName}", jellyfinAuthResult.AccessToken.Length, DtoUserId, jellyfinAuthResult.ServerId, DtoUsernameOrName);

            var currentRequest = HttpContext.Request;
            string webClientBaseUrl = $"{currentRequest.Scheme}://{currentRequest.Host}{currentRequest.PathBase}";

            string jsAccessToken = JavaScriptEncoder.Default.Encode(jellyfinAuthResult.AccessToken);
            string jsUserId = JavaScriptEncoder.Default.Encode(DtoUserId);
            string jsServerId = JavaScriptEncoder.Default.Encode(jellyfinAuthResult.ServerId);
            string jsUsername = JavaScriptEncoder.Default.Encode(DtoUsernameOrName); // Changed to use DtoUsernameOrName
            string jsRedirectBaseUrl = JavaScriptEncoder.Default.Encode(webClientBaseUrl);

            string htmlOutput = $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8' />
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>Finalizing Login...</title>
    <style>body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }} .info {{ border: 1px solid #ddd; padding: 15px; margin-top:15px; background-color:#fdfdfd; border-radius: 4px; }} .error {{ color: red; font-weight: bold; }}</style>
</head>
<body>
    <p>Please wait, finalizing your login...</p>
    <div id='ssoProcessLog' class='info'>
        <p><strong>Login Progress (SSO Plugin):</strong></p>
        <p>Status: Preparing client-side session...</p>
        <p>Token Hint: {jsAccessToken.Substring(0, Math.Min(10, jsAccessToken.Length))}...</p>
        <p>UserID: {jsUserId}</p>
        <p>ServerID: {jsServerId}</p>
        <p>Username/Name: {jsUsername}</p> 
        <p>Redirect Base URL: {jsRedirectBaseUrl}</p>
    </div>
    <iframe id='jf-init-helper-iframe' style='display:none; width:0; height:0; border:0;' title='Jellyfin Initialization Helper'></iframe>
    <script>
        async function completeSsoLogin() {{
            const accessToken = '{jsAccessToken}';
            const userId = '{jsUserId}';
            const serverId = '{jsServerId}';
            const username = '{jsUsername}'; // This now holds UserDto.Name
            const redirectBaseUrl = '{jsRedirectBaseUrl}';
            const targetRedirectUrl = `${{redirectBaseUrl}}/web/index.html`;
            const processLog = document.getElementById('ssoProcessLog');

            function logToPage(message, isError = false) {{
                console.log(`SSO Client: ${{message}}`);
                const p = document.createElement('p');
                p.textContent = message;
                if (isError) p.classList.add('error');
                processLog.appendChild(p);
            }}

            logToPage('Client-side script started.');

            function updateLocalStorageCredentials() {{
                const credKey = 'jellyfin_credentials';
                let currentCreds = null;
                logToPage('Attempting to read existing credentials from localStorage.');
                try {{
                    const storedCreds = localStorage.getItem(credKey);
                    if (storedCreds) {{
                        currentCreds = JSON.parse(storedCreds);
                        logToPage('Successfully parsed existing credentials.');
                    }} else {{
                        logToPage('No existing credentials found.');
                    }}
                }} catch (e) {{
                    logToPage(`Error parsing existing credentials: ${{e.message}}. Will create new.`, true);
                    currentCreds = null; 
                }}

                if (!currentCreds || typeof currentCreds !== 'object') currentCreds = {{}};
                if (!Array.isArray(currentCreds.Servers)) currentCreds.Servers = [];

                let serverConfigEntry = currentCreds.Servers.find(s => s.Id === serverId);
                if (serverConfigEntry) {{
                    logToPage('Found matching server entry. Updating tokens.');
                    serverConfigEntry.AccessToken = accessToken;
                    serverConfigEntry.UserId = userId;
                    serverConfigEntry.DateLastAccessed = Date.now();
                }} else {{
                    logToPage('No matching server entry for this ServerId. Adding new server entry.');
                    currentCreds.Servers.push({{
                        Id: serverId,
                        AccessToken: accessToken,
                        UserId: userId,
                        DateLastAccessed: Date.now(),
                        Name: 'Jellyfin Server' 
                    }});
                }}
                localStorage.setItem(credKey, JSON.stringify(currentCreds));
                logToPage('jellyfin_credentials updated in localStorage.');
            }}

            function storeUserSpecificDetails() {{
                const userKey = `user-${{userId}}-${{serverId}}`;
                const userDetails = {{
                    Id: userId,
                    ServerId: serverId,
                    Name: username, // This is UserDto.Name
                    EnableAutoLogin: true
                }};
                localStorage.setItem(userKey, JSON.stringify(userDetails));
                logToPage(`User-specific details stored under key: ${{userKey}}`);
            }}
            
            const initFrame = document.getElementById('jf-init-helper-iframe');
            logToPage(`Loading helper iframe with target: ${{targetRedirectUrl}} to help ensure localStorage context.`);
            initFrame.src = targetRedirectUrl;

            let initAttempts = 0;
            const maxInitAttempts = 70; 
            const initCheckInterval = 100;

            function waitForJellyfinClientInitAndProceed() {{
                initAttempts++;
                const jellyfinDeviceId = localStorage.getItem('_deviceId2');

                if (jellyfinDeviceId || initAttempts >= maxInitAttempts) {{
                    if (initAttempts >= maxInitAttempts && !jellyfinDeviceId) {{
                        logToPage('Timeout waiting for Jellyfin client (_deviceId2). Proceeding with auth data setup.', true);
                    }} else {{
                        logToPage('Jellyfin client initialization detected (_deviceId2 found) or timeout.');
                    }}
                    
                    try {{
                        updateLocalStorageCredentials();
                        storeUserSpecificDetails();
                        localStorage.setItem('enableAutoLogin', 'true'); 
                        logToPage('All authentication data stored in localStorage. Redirecting now...', false);
                        window.location.replace(targetRedirectUrl);
                    }} catch (e) {{
                        logToPage(`CRITICAL ERROR during localStorage setup or redirect: ${{e.message}}`, true);
                        document.body.innerHTML = `<h1>Login Finalization Error</h1><p>A client-side error occurred: ${{e.message}}</p><p>Please check the browser console (F12) for details and inform your administrator.</p>`;
                    }}
                }} else {{
                    logToPage(`Waiting for Jellyfin client initialization (attempt ${{initAttempts}} of ${{maxInitAttempts}})...`);
                    setTimeout(waitForJellyfinClientInitAndProceed, initCheckInterval);
                }}
            }}
            
            logToPage('Waiting briefly before checking localStorage state...');
            setTimeout(waitForJellyfinClientInitAndProceed, 400); 
        }}

        if (document.readyState === 'loading') {{
            document.addEventListener('DOMContentLoaded', completeSsoLogin);
        }} else {{
            completeSsoLogin();
        }}
    </script>
</body>
</html>";

            _logger.LogInformation("Callback: Returning HTML content with embedded JavaScript to client for final login steps.");
            return Content(htmlOutput, "text/html");
        }

        /// <summary>
        /// Parses an OIDC scope of the form "openid" or "openid {claim}",
        /// returning the claim type to match ("sub" for bare "openid", or "{claim}" otherwise).
        /// Throws ArgumentException on any other format.
        /// </summary>
        private string GetClaimTypeFromScope(string oidScope)
        {
            if (string.IsNullOrWhiteSpace(oidScope))
            {
                throw new ArgumentException(
                    "OIDC scope is not configured. Expected \"openid\" or \"openid {claim}\".",
                    nameof(oidScope));
            }

            var parts = oidScope
                .Trim()
                .Split(' ', StringSplitOptions.RemoveEmptyEntries);

            // exactly "openid" → sub
            if (parts.Length == 1 &&
                parts[0].Equals("openid", StringComparison.OrdinalIgnoreCase))
            {
                return "sub";
            }

            // exactly "openid {claim}"
            if (parts.Length == 2 &&
                parts[0].Equals("openid", StringComparison.OrdinalIgnoreCase))
            {
                return parts[1];
            }

            // anything else is a hard failure
            throw new ArgumentException(
                $"Invalid OIDC scope format: '{oidScope}'. " +
                "Expected exactly 'openid' or 'openid {claim}'.");
        }
    }
}
