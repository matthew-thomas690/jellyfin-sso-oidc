using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;

namespace Jellyfin.Plugin.SsoOidc.Services
{
    /// <summary>
    /// Builds a styled HTML SSO login page that visually matches the Jellyfin login screen.
    /// </summary>
    public class SSOLoginPageHtmlBuilder
    {
        public string CreateLoginPageHtml(List<string> providers)
        {
            var body = new StringBuilder();

            foreach (var prov in providers)
            {
                var encoded = HtmlEncoder.Default.Encode(prov);
                body.AppendLine(
                    CultureInfo.InvariantCulture,
                    $@"
        <form action=""/Plugins/SsoOidc/Authenticate/{encoded}"" method=""get"">
            <button class=""btn"" onclick=""if (!localStorage.getItem('_deviceId2') && window.NativeShell?.AppHost?.deviceId) {{
                localStorage.setItem('_deviceId2', window.NativeShell.AppHost.deviceId());
            }}"">
                <span>Sign in with {encoded}</span>
            </button>
        </form>");
            }

            var html = $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>SSO Login</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: sans-serif;
            background-color: #101010;
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }}
        .container {{
            text-align: center;
            background-color: #1b1b1b;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.4);
        }}
        h2 {{
            margin-bottom: 2rem;
        }}
        .btn {{
            width: 100%;
            max-width: 300px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            padding: 12px;
            background-color: #03a9f4;
            color: white;
            font-weight: bold;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .btn:hover {{
            background-color: #0288d1;
        }}
        form {{
            margin: 1rem 0;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <h2>Connect using SSO</h2>
        {body}
    </div>
</body>
</html>";

            return html;
        }
    }
}
