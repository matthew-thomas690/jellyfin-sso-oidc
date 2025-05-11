# Jellyfin SSO Plugin

## Overview
The **Jellyfin SSO Plugin** enables single sign-on by linking **existing** Jellyfin user accounts to OpenID Connect claims (e.g., Google `email`, Auth0 `sub`). You manually create each Jellyfin user, then map their Jellyfin **UserId** to the provider’s claim value in the plugin XML config. Once linked, users can authenticate via the **Connect using SSO** button on the Jellyfin login page.

This was thrown togther over a few hours on a weekend, I understand it is not the most polished code but it is just a frist iteration for now. I will be cleaning it up and expanding the functionality whenever I have time.

## Features
- Link existing Jellyfin users to any OIDC/OpenID Connect claim  
- Per-provider enable/disable toggle  
- XML configuration for claim-to-user mappings  
- Lightweight: no auto-creation of users  
- Works on Android

## Requirements
- Jellyfin **≥ 10.8.0**  
- An OpenID Connect–compliant identity provider  
- Administrative access to your Jellyfin server  

## Installation
1. Download the latest `SsoOidc.dll` from the [releases page](https://github.com/yourrepo/jellyfin-sso/releases).  
2. Copy `SsoOidc.dll` into:
   ```text
   <Jellyfin-Data-Directory>/plugins/SsoOidc/
   ```
3. Restart the Jellyfin service.

## Configuration

Edit (or create) the XML config at:  
```text
<Jellyfin-Data-Directory>/plugins/SsoOidc/config.xml
```

Below is an **example XML** with two providers—Google (with one user mapping) and Auth0 (no mappings yet):

```xml
<?xml version="1.0" encoding="utf-8"?>
<PluginConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <OidConfigs>
    <!-- Google OIDC Provider -->
    <Provider>
      <ProviderName>Google</ProviderName>
      <Enabled>true</Enabled>
      <OidEndpoint>https://accounts.google.com</OidEndpoint>
      <OidClientId>fgdfgfdh</OidClientId>
      <OidSecret>gdfhgdsdfhggdf</OidSecret>
      <OidScope>openid email</OidScope>
      <UserLink>
        <!-- Map Google email “davc.thiu@gmail.com” to Jellyfin userId -->
        <Entry>
          <ClaimValue>davc.thiu@gmail.com</ClaimValue>
          <UserId>sfghdfhfdh</UserId>
        </Entry>
      </UserLink>
    </Provider>

    <!-- Auth0 OIDC Provider -->
    <Provider>
      <ProviderName>Auth0</ProviderName>
      <Enabled>true</Enabled>
      <OidEndpoint>https://sdsgsdfgsdfgfdsd.com</OidEndpoint>
      <OidClientId>sdgdfshsrfedfrsg</OidClientId>
      <OidSecret>sdfsdgsgsdfsdg</OidSecret>
      <OidScope>openid email</OidScope>
      <!-- No user mappings yet -->
      <UserLink />
    </Provider>
  </OidConfigs>
</PluginConfiguration>
```

### Mapping Users
- **ClaimValue** must match exactly the claim returned by your provider (e.g., Google `email`, Auth0 `sub`).  
- **UserId** is the Jellyfin user’s ID (GUID) from **Dashboard → Users → [Select User] → Advanced**.

After editing, **restart Jellyfin** to apply changes.

## Usage
1. On the Jellyfin login screen, users will see a **Connect using SSO** button.  
2. Clicking it redirects to the configured provider’s login page.  
3. After authentication, the plugin matches the returned claim to your `<UserLink>` entry and logs the user into that Jellyfin account.

## Disclaimer Snippet
Insert the following into **Dashboard → Branding → Disclaimer** to render the SSO button:

```html
<style>
  .emby-button.button-submit::before {
    display: none !important;
  }
</style>

<form
  action="https://your-server-address/Plugins/SsoOidc/Login"
  method="get"
  target="_self"
>
  <button
    class="raised block emby-button button-submit"
    type="submit"
    onclick="
      // Android-only: stash native deviceId before redirect
      if (
        !localStorage.getItem('_deviceId2') &&
        window.NativeShell?.AppHost?.deviceId
      ) {
        localStorage.setItem(
          '_deviceId2',
          window.NativeShell.AppHost.deviceId()
        );
      }
    "
    style="
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 12px 20px;
      font-size: 16px;
    "
  >
    Connect using SSO
  </button>
</form>
```

## Contributing
Contributions, issues, and feature requests are welcome!  
1. Fork the repository  
2. Create a feature branch (`git checkout -b feature/fooBar`)  
3. Commit your changes (`git commit -am "Add fooBar"`)  
4. Push (`git push origin feature/fooBar`)  
5. Open a Pull Request

## License
This project is licensed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007.
