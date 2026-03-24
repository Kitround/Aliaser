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

## Features

- Manage aliases from multiple providers and accounts in one place
- Create aliases with custom or auto-generated names
- Add notes to aliases (synced to provider API where supported)
- Copy alias address in one click
- Disable/re-enable aliases without deleting them
- Search across all aliases (address, target, note)
- SimpleLogin & Addy.io contacts / reverse aliases management
- Dark theme, responsive (mobile + desktop)
- All data stored server-side, encrypted credentials

## Screenshots

![aliaser-preview-1](https://github.com/user-attachments/assets/7e109b81-ac51-4f8f-902d-44e53b206ab8)

![aliaser-preview-2](https://github.com/user-attachments/assets/23b7ea29-0372-4e2e-8f8f-96a5cb888db5)

![aliaser-preview-3](https://github.com/user-attachments/assets/7fc968ae-909f-4e05-afc9-f26abb455783)

## Architecture

No framework, no build step — vanilla JS + PHP.

```
index.html   — UI (single page)
css/style.css — Styles (dark theme, responsive)
js/app.js    — All frontend logic
proxy.php    — PHP backend: signs OVH requests, proxies API calls, persists data
json/        — Server-side data (auto-created, not committed)
```

Data is persisted in `json/` on the server:
- `state.json` — accounts and settings
- `notes.json` — alias notes
- `credentials.json` — API tokens (AES-256-CBC encrypted)
- `addy-contacts.json` — Addy.io contacts cache

## Deployment

### Docker (recommended)

1. Generate a secret key:
   ```bash
   openssl rand -hex 32
   ```

2. Edit `docker-compose.yml` and set `ALIASER_SECRET_KEY` to the generated key.

3. Start:
   ```bash
   docker compose up -d
   ```

4. Open `http://localhost:8080` and add your accounts from Settings.

### Manual (nginx / Apache + PHP 8.2+)

Requirements: PHP 8.2+, `openssl` extension, `curl` extension.

1. Copy all files to your web root.

2. Make `json/` writable by the web server:
   ```bash
   mkdir -p json && chown www-data:www-data json
   ```

3. Set the encryption key — choose one method:

   **Environment variable** (recommended):
   ```bash
   # In your PHP-FPM or Apache config:
   ALIASER_SECRET_KEY=your_64_char_hex_key
   ```

   **File above web root** (shared hosting):
   ```bash
   echo "your_64_char_hex_key" > /path/above/webroot/aliaser.key
   chmod 600 /path/above/webroot/aliaser.key
   ```

   If neither is set, a key is auto-generated and stored in `json/secret.key` (less secure — key and encrypted data in the same directory).

4. Open the app in your browser and add your accounts from Settings.

## Security

- API tokens are stored **encrypted** (AES-256-CBC) in `credentials.json` — never in plain text
- Tokens are never written to `state.json`
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- No authentication layer — intended for **private/LAN/VPN** use only

> ⚠️ Do not expose this app on the public internet without adding authentication (e.g. HTTP Basic Auth via nginx).

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
