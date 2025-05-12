using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;

namespace Jellyfin.Plugin.SsoOidc.Services
{
    /// <summary>
    /// In-memory implementation of IOidcStateStore using ConcurrentDictionary.
    /// </summary>
    public class SSOLoginPageHtmlBuilder
    {
        public string CreateLoginPageHtml(List<string> providers)
        {
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
            return html.ToString();
        }
    }    
}

