# Aliaser

A single-page web app for managing email aliases across multiple providers, without touching their admin interfaces.

![PHP](https://img.shields.io/badge/PHP-8.2-777bb4?logo=php&logoColor=white)
![Vanilla JS](https://img.shields.io/badge/JS-Vanilla-f7df1e?logo=javascript&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-ready-2496ed?logo=docker&logoColor=white)

## Supported providers

| Provider | List | Create | Delete | Disable | Notes | Contacts |
|---|---|---|---|---|---|---|
| **OVH** (Zimbra) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| **Infomaniak** | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| **SimpleLogin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Addy.io** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Cloudflare** | ✅ | ✅ | ✅ | — | ✅ | — |
| **Haltman** | ✅ | ✅ | ✅ | ✅ | ✅ | — |

## Features

- Manage aliases from multiple providers and accounts in one place
- Create aliases with custom or auto-generated names
- Add notes to aliases (synced to provider API where supported)
- Copy alias address in one click
- Disable/re-enable aliases without deleting them
- Search across all aliases (address, target, note)
- SimpleLogin & Addy.io contacts / reverse aliases management
- Dark theme, responsive (mobile + desktop)
- Installable PWA, with instant load from a cached alias list (stale-while-revalidate)
- All data stored server-side, encrypted credentials

## Screenshots

![aliaser-preview-1](https://github.com/user-attachments/assets/7e109b81-ac51-4f8f-902d-44e53b206ab8)

![aliaser-preview-2](https://github.com/user-attachments/assets/23b7ea29-0372-4e2e-8f8f-96a5cb888db5)

![aliaser-preview-3](https://github.com/user-attachments/assets/7fc968ae-909f-4e05-afc9-f26abb455783)

## Architecture

No framework, no build step — vanilla JS + PHP.

```
app/
  index.html        — UI (single page)
  css/style.css     — Styles (dark theme, responsive)
  js/app.js         — All frontend logic
  proxy.php         — PHP backend: signs OVH requests, proxies API calls, persists data
  json/             — Server-side data (auto-created, not committed)
extensions/
  chrome/           — Chrome extension (MV3)
  firefox/          — Firefox extension
docker/             — Dockerfile, entrypoint, Apache security-headers config
docker-compose.yml
```

Data is persisted in `app/json/` on the server:
- `state.json` — accounts and settings
- `notes.json` — alias notes
- `credentials.json` — API tokens (AES-256-GCM encrypted)
- `addy-contacts.json` — Addy.io contacts cache

## Deployment

### Docker with Portainer (recommended)

1. In Portainer → Stacks → Add stack → Web editor:
   ```yaml
   services:
     aliaser:
       image: kitround/aliaser
       restart: unless-stopped
       ports:
         - "8090:80"
       volumes:
         - ~/aliaser/app/json:/var/www/html/json
       environment:
         ALIASER_SECRET_KEY: "your_key_here"
   ```

2. Generate `ALIASER_SECRET_KEY` with `openssl rand -hex 32` (64 hex chars) and keep it stable — it encrypts credentials and the auth store.

3. Open `http://YOUR_HOST:8090`. On first run you'll create the admin account, enrol TOTP two-factor (scan/enter the secret in an authenticator app), and save the one-time backup codes. Then add your provider accounts from Settings.

### Manual (nginx / Apache + PHP 8.2+)

Requirements: PHP 8.2+, `openssl` extension, `curl` extension.

1. Copy the `app/` folder contents to your web root.

2. Make `json/` writable by the web server:
   ```bash
   mkdir -p json && chown www-data:www-data json
   ```

3. Set the encryption key as an environment variable in your PHP-FPM or Apache config:
   ```bash
   ALIASER_SECRET_KEY=your_64_char_hex_key
   ```

   If not set, a key is auto-generated and stored in `json/secret.key` (less secure).

4. Open the app — complete the first-run admin + TOTP setup, then add your accounts from Settings.

## Browser extensions

The Chrome/Firefox popups talk to the same server.

1. Load the extension (`extensions/chrome` or `extensions/firefox`).
2. Open the extension **Options** and set the **Server URL** (e.g. `https://YOUR_HOST`).
3. In the app: **Settings → Security → Extension tokens → Generate**, copy the token (shown once).
4. Paste it into the extension's **Device token** field in Options and save.

Tokens are revocable from the same screen. One token per device/browser is recommended.

## Sign-in & two-factor

On first run you create the admin account and enrol **TOTP** (authenticator app) with one-time backup codes.

In **Settings → Security → Two-factor** you can then:

- **Add passkeys** (WebAuthn / FIDO2 — Touch ID, Windows Hello, Android, security keys). A passkey is a **passwordless** login: on the sign-in screen, tap **"Sign in with a passkey"** and confirm with biometrics/PIN — no username or password needed.
- Enable/disable TOTP. You can't remove your last factor, so you always keep a way in.

Password + TOTP stays available as the alternative to passkeys.

> **Passkeys require HTTPS and a real domain name** (not a bare IP). The `rpId` is derived from the request host, so it works on any self-hosted domain — including the installed mobile PWA. Make sure your reverse proxy forwards the original `Host` header and `X-Forwarded-Proto: https`.

## Security

- **Login required**: password (argon2id) + **TOTP** (RFC 6238, backup codes) and/or **passwordless passkeys** (WebAuthn / FIDO2, ES256).
- Secure session cookies (`HttpOnly`, `SameSite=Lax`, `Secure` under HTTPS), CSRF tokens on writes, brute-force lockout.
- Extensions authenticate with a revocable **device token** (Settings → Security → Extension tokens), pasted into the extension Options.
- API tokens are stored **encrypted** (AES-256-GCM) in `credentials.json` — never in plain text, and never returned to the browser (resolved server-side per request).
- Auth data (`auth.json`) is encrypted at rest; tokens never written to `state.json`.
- Per-provider API path allowlist — the proxy can only reach the providers' alias endpoints, not arbitrary URLs.
- Direct HTTP access to the `json/` data directory is denied.
- Security headers on every response: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.

> ⚠️ **For public exposure, serve over HTTPS** (reverse proxy / Cloudflare). HTTPS is required for `Secure` cookies and to protect the password in transit. Also set a stable `ALIASER_SECRET_KEY` so `auth.json` survives restarts.

## Adding accounts

### OVH
1. Create an app at [eu.api.ovh.com/createApp](https://eu.api.ovh.com/createApp/) to get an **App Key** and **App Secret**
2. Add the account in Settings → authenticate to get a Consumer Key

### Infomaniak
1. Go to [manager.infomaniak.com/v3/profile/api](https://manager.infomaniak.com/v3/profile/api)
2. Create a token with **Mail Hosting** read + write permissions

### SimpleLogin
1. Go to [app.simplelogin.io/dashboard/api_key](https://app.simplelogin.io/dashboard/api_key)
2. Copy your API key

### Addy.io
1. Go to [app.addy.io/settings](https://app.addy.io/settings) → API Keys section
2. Create an API key

### Cloudflare
1. Go to [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Create a token with **Email Routing** read + edit permissions
