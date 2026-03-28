# Aliaser — Context file

## Overview

**Aliaser** is a single-page web app for managing email aliases via: **OVH** (Zimbra), **Infomaniak**, **SimpleLogin**, **Addy.io**, and **Cloudflare**. A **Chrome extension** (`/chrome/`) provides a popup UI connecting to the same PHP backend.

- **Stack**: Vanilla JS + PHP, no framework, no build step
- **Hosting**: PHP + Apache (Docker recommended)
- **Security**: credentials stored AES-256-CBC encrypted in `json/credentials.json`, never in Docker layers

---

## File structure

```
index.html              — HTML structure, modals, topbar, mobile bar
css/style.css           — Styles (dark theme, responsive)
js/app.js               — All frontend logic (state, API, render, events)
proxy.php               — PHP backend: signs OVH requests, forwards to providers, handles persistence
json/state.json         — accounts, consumerKeys, zimbraPlatformIds, disabledAliases
json/notes.json         — { "alias@domain.com": "text" }
json/credentials.json   — Encrypted per-account tokens
json/secret.key         — Encryption key fallback
json/addy-contacts.json — Local cache of Addy.io contact → reverse address mappings
chrome/                 — MV3 Chrome extension (popup.html, popup.js, config.js, options.html/js)
```

---

## Data model

### Account
```js
{
  id, provider, label, account, domain, isDefault,
  // OVH: consumerKey, ovhAppKey, ovhAppSecret
  // Infomaniak: hostingId
  // SimpleLogin: mailboxId, email, isPremium
  // Addy: email, isFree
  // Cloudflare: zoneId, targetAddress
  token,  // all providers — stored in credentials.json, merged at runtime
}
```

### Alias
```js
{
  id, aliasAddress, targetAddress, provider, accountId, accountLabel,
  pending,   // true during creation (optimistic UI)
  disabled,  // true if alias is disabled
  // SL: slNbForward, slNbReply, slNbBlock, slLatestActivity
  // Addy: addyNbForward, addyNbReply, addyNbSend, addyNbBlock
  // CF: cfPriority
}
```

### Global state
```js
state = {
  accounts: [], aliases: [], filteredAliases: [],
  dataLoaded, isLoading,
  ovhZimbraPlatformIds: {},   // persisted
  ovhZimbraAccountIds: {},    // in-memory only
  slSuffixes: {},             // { accountId: {suffixes, prefixSuggestion, mailboxId} }
  selectedSlSignedSuffix, selectedSlSuffix,
  lastSelectedAccountId, pendingDeleteAlias, lastCreatedAliasId,
  searchQuery, notes: {}, disabledAliases: [], credentials: {},
  addyContacts: {},           // { aliasId: [{email, reverse}] }
}
```

---

## Persistence

| File | Contents |
|---|---|
| `state.json` | accounts (no tokens), consumerKeys, zimbraPlatformIds, disabledAliases |
| `notes.json` | `{ [aliasAddress]: "text" }` — written independently, never mixed with state |
| `credentials.json` | `{ perAccount: { [accountId]: { token, ovhAppKey?, ovhAppSecret? } } }` |
| `addy-contacts.json` | `{ [aliasId]: [{email, reverse}] }` — local only, no API sync |

**Key rules:**
- `saveServerState()` strips all credential fields and never includes notes
- `disabledAliases[]` used for OVH/IK only — SL/Addy/CF disabled state comes from provider API
- All GET requests use `Cache-Control: no-cache`

---

## Provider flows (summary)

| Provider | Auth | Disable method |
|---|---|---|
| OVH | OAuth consumerKey via `/auth/credential` | Delete + remember in `disabledAliases[]` |
| Infomaniak | Bearer token | Delete + remember in `disabledAliases[]` |
| SimpleLogin | API key | Provider toggle (`POST /api/aliases/<id>/toggle`) |
| Addy.io | Bearer token | Provider toggle (`POST/DELETE /api/v1/active-aliases`) |
| Cloudflare | Bearer token | Provider toggle (`PUT` rule with `enabled` flag) |

**OVH specifics:** HMAC-SHA1 signed requests. `NOT_GRANTED`/`INVALID_CREDENTIAL` → clear consumerKey, re-auth. `getAnyWorkingZimbraPlatform()` falls back to any cached platform if current fails.

**Notes sync:** SL → `PATCH /api/aliases/<id>` with `{note}`. Addy → `PATCH /api/v1/aliases/<id>` with `{description}`. OVH/IK/CF → local `notes.json` only.

---

## UI rules

### Alias card — action buttons (fixed order, never changes)
1. Copy — always present, works on disabled cards
2. Disable / Re-enable
3. Contacts — SL and Addy only
4. Edit note
5. Delete

### Optimistic UI
- **Create**: pending alias inserted immediately → replaced on success, removed on error
- **Delete**: removed immediately → restored on error
- **Disable/Enable**: state updated immediately → restored on error

### Responsive — two breakpoints only
- `≤ 600px`: 1-col grid, mobile bottom bar, `alias-actions` as 2×2 grid always visible, 16px inputs (iOS zoom)
- `> 600px`: auto-fill grid, full topbar, hover-only actions

### CSS variables (`:root`)
```css
--bg: #0f0f0f; --surface: #171717; --surface2: #1e1e1e; --surface3: #242424;
--border: #2a2a2a; --border2: #333; --text: #e0e0e0; --text-muted: #808080;
--text-dim: #515151; --accent: #5b54e8; --accent-hover: #6b65f0;
--red: #e05050; --green: #0098ff; --orange: #e09040;
--sl: #c026a0; --addy: #0ea5e9; --cf: #f97316;
```

### Toasts
- **Copy toast** (`#copy-toast-global`): `showCopyToast(anchorEl, text, duration)` — 1600ms default, 3500ms on creation
- **Error toast** (`#error-banner`): `position:fixed`, pill-shaped, `top:62px` desktop / `top:54px` mobile, auto-dismissed after 5s

### Misc
- New alias card: `.alias-card-new` → border + `card-new-glow` pulse (6s) + `scrollIntoView`
- Desktop hover: card body → opacity `.05`, actions appear centered absolute
- Search: filters on aliasAddress, targetAddress, and note content (case-insensitive)
- Addy free tier: alias name input hidden, name auto-generated by API

---

## Chrome extension

MV3 popup (420×580px). Connects to main backend via configurable server URL (stored in `localStorage['aliaser_proxy_url']`).

**Differences from main app:** no settings/account management, no Edit Note modal, simpler search (no note search), no new-alias glow, CORS enabled for `chrome-extension://` origins.

---

## Development directives

- **Backward compatibility**: any change must be compatible with production state
- **Minimal modification**: no opportunistic refactoring, no new dependency without justification
- **Complete files**: always deliver the entire file — no diffs or partial excerpts
- **Reference base**: always start from the last validated deployed files
- **Separation of concerns**: UI logic → `app.js`, styles → `style.css`, proxy/auth → `proxy.php`, state → `state.json`, notes → `notes.json`, credentials → `credentials.json`
- **Dead code**: removed features must be fully cleaned up (JS, CSS, HTML)
- **Desktop AND mobile**: every UI change must work on both breakpoints
- **English only**: all UI text, error messages, placeholders, labels, code comments
- **Chrome extension parity**: applicable features must be reflected in `popup.js` / `popup.html`
- **Conciseness**: minimize token usage — no explanations unless explicitly requested, make only necessary changes in specific code sections, be precise and direct
