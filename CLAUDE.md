# Aliaser — Context file

## Overview

**Aliaser** is a single-page web app (SPA) for managing email aliases via three providers: **OVH** (Zimbra), **Infomaniak**, and **SimpleLogin**. It allows creating, listing, copying, disabling, and deleting email aliases without touching the providers' admin interfaces.

---

## Hosting environment

- **Server**: Mac Mini, macOS, local network
- **Server stack**: nginx + PHP via **Laravel Herd** (local app) + **openresty** reverse proxy in front
- **Access**: local network only, or via **VPN** — no public Internet exposure
- **Security implications**: the private/LAN context justifies choices that would be risky in public production — notably storing sensitive credentials (tokens) in `config.php`, and the absence of an authentication layer on the app itself
- **Deployment**: manual copy/paste of files — no CI/CD pipeline

---

## Architecture

```
index.html   — HTML structure, modals, topbar, mobile bar
style.css    — Styles (dark theme, responsive)
app.js       — All frontend business logic (state, API, render, events)
proxy.php    — PHP backend proxy: signs OVH requests, forwards to Infomaniak/SimpleLogin
config.php   — OVH API keys (app key + secret), Infomaniak token, SimpleLogin token
state.json   — Server-side persistent state (accounts, consumerKeys, zimbraPlatformIds, disabledAliases)
notes.json   — Server-side persistent notes (separate from state.json)
```

No framework, no build step — vanilla JS + PHP.

---

## Language

**The entire app must be in English** — all UI text, error messages, placeholders, labels, comments and code strings must be in English. No French anywhere.

---

## File responsibilities

### `index.html`
Complete static structure. Contains:
- Topbar (logo, search, refresh/add/settings buttons)
- Content area with states (loading, no-config, empty, list)
- Mobile bottom bar (settings, refresh, search, add)
- Modal **Settings** (account management, OVH auth, IK add, SL add)
- Modal **New Alias** (account selector pills, name field, random generator, note field, preview, suggestions)
- Modal **Edit Note** (edit or add a note to an existing alias)
- Modal **SL Contacts** (SimpleLogin contacts and reverse aliases management)
- Overlay **Confirm Delete**
- Global copy toast
- Global error toast (fixed, floating, pill-shaped — always visible regardless of scroll position)

### `style.css`
Full dark theme. CSS variables in `:root`. Responsive with breakpoints:
- `≤ 600px`: 1-column grid, visible mobile bar, hidden desktop search, `alias-actions` always visible in a **2×2 grid**
- `601–860px`: auto-fill grid, reduced search
- `> 860px`: full desktop layout

Two breakpoints only — mobile (`≤ 600px`) and desktop (everything else). No intermediate breakpoint.

**CSS variables (`:root`):**
```css
--bg: #0f0f0f
--bg2: #0f0f0f
--surface: #171717
--surface2: #1e1e1e
--surface3: #242424
--border: #2a2a2a
--border2: #333
--text: #e0e0e0
--text-muted: #808080
--text-dim: #515151        /* used for domain part, redirect address, note text, arrow */
--accent: #5b54e8
--accent-soft: rgba(91,84,232,.12)
--accent-hover: #6b65f0
--red: #e05050
--red-soft: rgba(224,80,80,.1)
--green: #0098ff
--green-soft: rgba(0,152,255,.08)
--orange: #e09040
--sl: #c026a0
--sl-soft: rgba(192,38,160,.12)
```

### `app.js`
All JS in a single file. Sections:

| Section | Role |
|---|---|
| `state` | Global object: `accounts`, `aliases`, `filteredAliases`, `isLoading`, `dataLoaded`, `searchQuery`, `ovhZimbraPlatformIds`, `ovhZimbraAccountIds`, `slSuffixes`, `pendingDeleteAlias`, `notes`, `disabledAliases`, `selectedSlSignedSuffix`, `selectedSlSuffix` |
| Server state | `loadServerState()`, `saveServerState()` — state.json via proxy.php |
| Notes | `loadNotes()`, `saveNotes()` — notes.json via proxy.php |
| `proxyCall()` | Fetch to proxy.php with network retry (2 attempts, 500ms backoff) |
| OVH | `ovhCall()`, `authenticate()`, `getZimbraPlatform()`, `ovhGetZimbraAccountId()`, `getAnyWorkingZimbraPlatform()`, `ovhFetchForAccount()`, `ovhCreateAlias()`, `ovhDeleteAlias()` |
| Infomaniak | `ikCall()`, `ikFetchForAccount()`, `ikCreateAlias()`, `ikDeleteAlias()` |
| SimpleLogin | `slCall()`, `slFetchForAccount()`, `slGetOptions()`, `slCreateAlias()`, `slDeleteAlias()`, `slToggleAlias()`, `slUpdateNote()`, `slFetchContacts()`, `slCreateContact()`, `slToggleContact()` |
| Unified | `fetchAliases()`, `createAlias()`, `deleteAlias()`, `disableAlias()`, `enableAlias()` |
| Filter | `applyFilter()`, `canAddAlias()` |
| Render | `renderList()`, `renderAccountList()`, `renderAccountSelector()`, `renderAliasSuggestions()`, `render()`, `renderSettingsStatus()` |
| Helpers | `genId()`, `esc()`, `showError()`, `hideError()`, `setLoading()`, `copyText()`, `showCopyToast()`, `loadAliases()`, `setThemeColor()`, `generateAliasName()` |
| Settings UI | `openSettings()`, `closeSettings()`, `showAddForm()`, `hideAddForms()` |
| New Alias UI | `openAddAlias()`, `_updateAliasPreview()`, `_getSelectedAccountId()` |
| Edit Note UI | `openEditNote()`, `closeEditNote()` |
| SL Contacts UI | `openContactsModal()`, `closeContactsModal()`, `_renderContactsLoading()`, `_renderContactsList()`, `_renderContactsError()` |
| Events | Listeners on all buttons/inputs/modals |
| Init | `Promise.all([loadServerState(), loadNotes()])` → `render()` → `loadAliases()` if accounts present |

### `proxy.php`
Receives POST JSON with `{provider, method, path, body?, consumerKey?, useV2?}`.
- **OVH**: computes HMAC-SHA1 signature (`$1$sha1(secret+ck+method+url+body+ts)`), calls `eu.api.ovh.com/v2` (or `/1.0` for `/auth/`)
- **Infomaniak**: adds `Authorization: Bearer TOKEN`, forwards to `api.infomaniak.com`
- **SimpleLogin**: adds `Authentication: TOKEN`, forwards to `app.simplelogin.io`

Also handles state and notes persistence:
- `GET ?action=state` → reads `state.json` (with `no-cache` headers)
- `POST ?action=state` → writes `state.json` (strips `notes` field)
- `GET ?action=notes` → reads `notes.json` (with `no-cache` headers)
- `POST ?action=notes` → writes `notes.json`

### `config.php`
PHP constants:
- `OVH_APP_KEY` / `OVH_APP_SECRET` — OVH application keys
- `INFOMANIAK_TOKEN` — Infomaniak Bearer token
- `SIMPLELOGIN_TOKEN` — SimpleLogin API key

### `state.json`
Server-side persistent state. Fields:
```json
{
  "accounts": [...],
  "consumerKeys": [{"id": "...", "key": "..."}],
  "zimbraPlatformIds": { "<accountId>": "<platformId>" },
  "zimbraPlatformId": "",
  "disabledAliases": [...]
}
```

### `notes.json`
Server-side persistent notes. Stored as a plain object keyed by alias address:
```json
{
  "alias@domain.com": "note text"
}
```
Must always be a JSON object `{}`, never an array `[]`.

---

## Data model

### Account (`account`)
```js
{
  id: string,           // genId()
  provider: 'ovh' | 'infomaniak' | 'simplelogin',
  label: string,        // e.g. "user@domain.com" or "My SimpleLogin"
  account: string,      // email or login (not used for SL)
  domain: string,       // not used for SL
  hostingId?: string,   // Infomaniak only
  consumerKey?: string, // OVH only (stored in state.json under consumerKeys[])
  isDefault?: boolean,  // default account for new alias modal
  mailboxId?: number,   // SimpleLogin only — default mailbox ID
  email?: string,       // SimpleLogin only — default mailbox email
}
```

### Alias
```js
{
  id: string,               // OVH: resource UUID / IK: alias name / SL: numeric id as string
  aliasAddress: string,     // e.g. "shopping@domain.com"
  targetAddress: string,    // target mailbox
  provider: 'ovh' | 'infomaniak' | 'simplelogin',
  accountId: string,
  accountLabel: string,
  pending?: boolean,        // true during creation (optimistic UI)
  disabled?: boolean,       // true if alias is disabled
  slNbForward?: number,     // SimpleLogin only
  slNbReply?: number,       // SimpleLogin only
  slNbBlock?: number,       // SimpleLogin only
  slLatestActivity?: any,   // SimpleLogin only
}
```

### Notes
```js
// state.notes: { [aliasAddress: string]: string }
// Loaded from notes.json at startup, saved independently via saveNotes()
```

---

## OVH flow

1. **Auth**: `POST /auth/credential` → gets `validationUrl` + `consumerKey`
2. User validates the token in their browser
3. `consumerKey` stored in `state.json` under `consumerKeys[]`
4. **Fetch aliases**:
   - `GET /zimbra/platform` → gets Zimbra platform ID (cached per account in `zimbraPlatformIds`)
   - `GET /zimbra/platform/<pid>/account` → finds the Zimbra account UUID for the mailbox (cached in `state.ovhZimbraAccountIds` in memory)
   - `GET /zimbra/platform/<pid>/alias` → fetches all platform aliases, filtered by `targetAccountId === zid`
5. **Create**: `POST /zimbra/platform/<pid>/alias` with `{targetSpec: {alias, targetId: zid}}`
6. **Delete**: `DELETE /zimbra/platform/<pid>/alias/<aliasId>`

**Important**: OVH Zimbra uses a shared platform — all domains share the same `platformId`. `getAnyWorkingZimbraPlatform()` falls back to any cached platform ID if the current account's own platform lookup fails. Each account has its own Zimbra account UUID (`zid`) which is used to filter aliases.

**Session expiry**: if OVH returns `NOT_GRANTED` or `INVALID_CREDENTIAL`, the consumerKey is cleared and the user is asked to re-authenticate.

## Infomaniak flow

1. No interactive auth — token is in `config.php`
2. **Fetch**: `GET /1/mail_hostings/<hostingId>/mailboxes/<mailbox>/aliases`
3. **Create**: `POST` on the same endpoint with `{alias: "name"}`
4. **Delete**: `DELETE /1/mail_hostings/<hostingId>/mailboxes/<mailbox>/aliases/<name>`

## SimpleLogin flow

1. No interactive auth — token is in `config.php`
2. **Add account**: verifies token via `GET /api/user_info`, fetches default mailbox via `GET /api/mailboxes`, stores `mailboxId` + `email`
3. **Fetch aliases**: paginated `GET /api/v2/aliases?page_id=N` (20 per page, loop until `items.length < 20`). Notes from SL API (`a.note`) are merged into `state.notes`
4. **Create**: fetches options via `GET /api/v5/alias/options` (suffixes, prefix suggestion) + `GET /api/mailboxes`. Then `POST /api/v3/alias/custom/new` with `{alias_prefix, signed_suffix, mailbox_ids, note?}`
5. **Delete**: `DELETE /api/aliases/<id>`
6. **Toggle** (disable/enable): `POST /api/aliases/<id>/toggle` → returns `{enabled: bool}`
7. **Update note**: `PATCH /api/aliases/<id>` with `{note}`
8. **Contacts**: paginated `GET /api/aliases/<id>/contacts?page_id=N` (20 per page, loop until `items.length < 20`), `POST /api/aliases/<id>/contacts`, `POST /api/contacts/<id>/toggle`
9. **Disabled state**: comes directly from API (`enabled` field) — NOT stored in `disabledAliases[]`

---

## Server-side persistence

| File | Contents |
|---|---|
| `state.json` | accounts, consumerKeys, zimbraPlatformIds, disabledAliases |
| `notes.json` | `{ [aliasAddress]: "text" }` |

**Key principle**: `notes.json` is written independently from `state.json` via `saveNotes()`. They are never mixed. `loadServerState()` does not touch `state.notes`. `saveServerState()` does not include notes.

**Cache busting**: all GET requests to `proxy.php?action=state` and `proxy.php?action=notes` include `Cache-Control: no-cache` headers. The proxy also returns `no-cache` headers on those routes to bypass openresty caching.

**disabledAliases**: stored in `state.json` for OVH and Infomaniak only. SimpleLogin disabled state comes from the API. `saveServerState()` merges live disabled aliases from `state.aliases` with persisted ones not yet fetched, to avoid data loss.

---

## UI — Alias card

Each card contains:
- **`.alias-address`**: alias email split into two parts — local part (white, `font-weight:500`) + **`.alias-domain`** (`@domain.xxx`, `color: var(--text-dim)`, `font-weight:400`). Long addresses fade out via `mask-image` gradient (no ellipsis `...`)
- **`.alias-target`**: redirect address with arrow SVG — both in `color: var(--text-dim)`, arrow at `opacity:.6`
- **`.alias-badges`**: provider badge, optional `disabled` badge, SL stats (forward/reply/block counts)
- **`.alias-note`** / **`.alias-note-empty`**: note text in `color: var(--text-dim)`
- **`.alias-actions`**: action buttons — always in fixed order: **copy → disable/enable → (contacts, SL only) → note → delete**

**Alias actions button order** (never changes regardless of disabled state):
1. Copy (`.copy-btn`) — always present, works even on disabled cards
2. Disable (`.disable-btn`) or Re-enable (`.enable-btn`)
3. Contacts (`.contacts-btn`) — SimpleLogin only
4. Edit note (`.edit-note-btn`)
5. Delete (`.danger.delete-btn`)

### Desktop hover behavior
On `hover:hover` + `pointer:fine` devices: card body fades to opacity `.05` on hover, actions appear centered in absolute position over the card.

### Mobile behavior (≤ 600px)
`.alias-actions` displayed as a **2×2 grid** (`grid-template-columns: repeat(2, 30px)`), always visible (no hover required).

---

## Error toast
- `#error-banner` is placed at body level (before `<script>`), outside `.content-scroll`
- `position:fixed`, centered, pill-shaped — same pattern as `#copy-toast-global`
- Desktop: `top:62px` (below the 52px topbar). Mobile: `top:54px` (below the 46px topbar)
- Visibility toggled via `.visible` class (`opacity:0/1` + `pointer-events`), auto-dismissed after 5s

## UI — Main states

| State | Condition |
|---|---|
| `state-loading` | `isLoading && !canAddAlias()` |
| `state-config` | `!isLoading && !canAddAlias()` |
| `state-empty` | Accounts OK, data loaded, empty filtered list |
| List | Accounts OK, data loaded, aliases > 0 |

## Optimistic UI
- **Creation**: `pending` alias inserted immediately, replaced by real data on success, removed on error
- **Deletion**: alias removed immediately, restored on error
- **Disable**: alias marked `disabled:true` immediately, restored on error
- **Enable**: alias marked `pending:true, disabled:false` immediately, replaced by real alias on success

## Notes feature
- A note can be added at alias creation time (optional textarea in New Alias modal)
- A note can be added or edited on any existing alias via the pencil button in alias card actions
- For SimpleLogin, notes are synced to the SL API via `PATCH /api/aliases/<id>` and loaded from the API on fetch
- Notes are displayed on the alias card, always visible, in `color: var(--text-dim)`, truncated if too long
- The pencil button gets the `has-note` CSS class when a note exists (class present in HTML, no visual style applied by design)
- Notes are deleted automatically when an alias is deleted
- Stored in `notes.json` as `{ "alias@domain.com": "text" }`

## Search
- `applyFilter()` filters on `aliasAddress`, `targetAddress`, and note content (case-insensitive)

## Disabled aliases feature
- **OVH / Infomaniak**: alias is actually deleted from the provider but remembered in `disabledAliases[]` in `state.json`. Re-enabling recreates it via the provider API
- **SimpleLogin**: disable/enable uses `POST /api/aliases/<id>/toggle`. State comes from the API, not from `disabledAliases[]`
- Disabled cards show a `disabled` badge. The copy button remains available on disabled cards

## SL Contacts feature
- Accessible via the contacts button (`.contacts-btn`) on SimpleLogin alias cards
- Lists existing contacts with their reverse alias address
- Allows creating new contacts (generates a reverse alias)
- Allows blocking/unblocking senders per contact via `POST /api/contacts/<id>/toggle`
- Contact icons (block + copy) use same colors as alias card actions: `color: var(--text-muted)` at rest, danger red on block hover

## Random alias generator
- Generates `word + 3-digit-number` (e.g. `swift412`)
- Word list: 40 adjectives + 40 nature nouns
- Used in New Alias modal (suggestion rows)
- For SimpleLogin, prefix suggestion comes from `GET /api/v5/alias/options`
- SL suffix rows: clicking fills the input and stores the selection in `state.selectedSlSignedSuffix` / `state.selectedSlSuffix` — **no visual active state** on the row
- Non-SL rows: no persistent visual active state either
- Selected SL suffix is preserved across typing and used at creation time; cleared on modal open or account switch

---

## Responsive

| Breakpoint | Interface |
|---|---|
| `≤ 600px` | 1-col grid, fixed mobile bar at bottom, hidden desktop search, `alias-actions` as 2×2 grid always visible |
| `> 600px` | auto-fill grid, full topbar, hover-only actions |

---

## Explored / not implemented features

### Reading emails received on an alias
OVH Zimbra and Infomaniak REST APIs **do not expose routes to read messages** — they are limited to administrative management (accounts, aliases, domains).

The only viable path is **IMAP via PHP** (`proxy.php` or dedicated file):
- IMAP connection with the target mailbox credentials
- Filtering messages by `To:` / `Delivered-To:` matching the alias
- Return: message count + date of last received

**Feasibility**: yes, in this LAN/VPN context. Storing the IMAP password in `config.php` is acceptable given the absence of public access.

**What would need to be added:**
- "IMAP password" field per account in Settings (stored in `config.php` or encrypted localStorage)
- New `imap.php` file called by `proxy.php`
- Display on alias card: badge with count and date of last received mail
- Server-side or localStorage cache to avoid querying IMAP on every render

**Status**: not implemented — decision pending on IMAP credential storage.

---

## Development directives

- **Backward compatibility**: any modification must be compatible with the production state
- **Minimal modification**: no opportunistic refactoring, no new dependency without justification
- **Complete files**: always deliver the entire file — no diffs or partial excerpts
- **Reference base**: always start from the last validated and deployed files
- **Separation of concerns**: UI logic → `app.js`, styles → `style.css`, proxy/auth → `proxy.php`, keys → `config.php`, state → `state.json`, notes → `notes.json`
- **Dead code**: any removed feature entails complete removal of associated code, CSS and HTML
- **Desktop AND mobile**: every UI modification must work on both breakpoints
- **English only**: all UI text, error messages, placeholders, labels, code comments — everything must be in English
