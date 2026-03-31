# Aliaser

A single-page web app for managing email aliases across multiple providers, without touching their admin interfaces.

This app is 100% vibe coded using Claude Code so use it with caution, only in local + VPN for outside needs and give only mail access to the API generated on the different providers.

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

## Extensions

Chrome and Firefox extensions are available (soon on the addons stores).

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
docker/             — Dockerfile, entrypoint
docker-compose.yml
```

Data is persisted in `app/json/` on the server:
- `state.json` — accounts and settings
- `notes.json` — alias notes
- `credentials.json` — API tokens (AES-256-CBC encrypted)
- `addy-contacts.json` — Addy.io contacts cache

# Deployment

## Security

- API tokens are stored **encrypted** (AES-256-CBC) in `credentials.json` — never in plain text
- Tokens are never written to `state.json`
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- No authentication layer — intended for **private/LAN/VPN** use only

> ⚠️ Do not expose this app on the public internet without adding authentication (e.g. HTTP Basic Auth via nginx).

## Docker with Portainer (recommended)

1. Generate a secret key:
   ```bash
   openssl rand -hex 32
   ```

2. Clone the repo on your Docker host:
   ```bash
   git clone https://github.com/Kitround/Aliaser.git ~/aliaser
   ```

3. Build the image:
   ```bash
   docker build -f ~/aliaser/docker/Dockerfile -t aliaser:latest ~/aliaser
   ```

4. In Portainer → Stacks → Add stack → Web editor:
   ```yaml
   services:
     aliaser:
       image: aliaser:latest
       pull_policy: never
       ports:
         - "8090:80"
       volumes:
         - ~/aliaser/app/json:/var/www/html/json
       environment:
         ALIASER_SECRET_KEY: "your_key_here"
       restart: unless-stopped
   ```

5. Open `http://YOUR_HOST:8090` and add your accounts from Settings.

## Docker (standalone)

1. Generate a secret key:
   ```bash
   openssl rand -hex 32
   ```

2. Set the key and start:
   ```bash
   ALIASER_SECRET_KEY=your_key docker compose up -d
   ```

3. Open `http://localhost:8090` and add your accounts from Settings.

## Manual (nginx / Apache + PHP 8.2+)

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

4. Open the app in your browser and add your accounts from Settings.



