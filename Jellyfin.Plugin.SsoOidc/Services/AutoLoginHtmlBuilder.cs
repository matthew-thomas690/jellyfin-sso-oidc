using System;
using System.Text;
using System.Text.Encodings.Web;

namespace Jellyfin.Plugin.SsoOidc.Services
{
    /// <summary>
    /// In-memory implementation of IOidcStateStore using ConcurrentDictionary.
    /// </summary>
    public class AutoLoginHtmlBuilder
    {
        public string CreateAutoLoginHtml(string tokenHint, string userId, string serverId, string username, string redirectBaseUrl, string accessToken)
        {
            return $@"
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
                    <p>Token Hint: {tokenHint}...</p>
                    <p>UserID: {userId}</p>
                    <p>ServerID: {serverId}</p>
                    <p>Username/Name: {username}</p> 
                    <p>Redirect Base URL: {redirectBaseUrl}</p>
                </div>
                <iframe id='jf-init-helper-iframe' style='display:none; width:0; height:0; border:0;' title='Jellyfin Initialization Helper'></iframe>
                <script>
                    async function completeSsoLogin() {{
                        const accessToken = '{accessToken}';
                        const userId = '{userId}';
                        const serverId = '{serverId}';
                        const username = '{username}'; // This now holds UserDto.Name
                        const redirectBaseUrl = '{redirectBaseUrl}';
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
        }
    }    
}

