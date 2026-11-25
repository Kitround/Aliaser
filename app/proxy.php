<?php
/**
 * Aliaser Proxy — OVH, Infomaniak, SimpleLogin, Addy.io, Cloudflare, Haltman
 *                + state persistence
 *
 * Security-hardened:
 *  - Strict permissions on persisted files (umask 0077)
 *  - Optional auth token via ALIASER_AUTH_TOKEN env var (X-Aliaser-Auth header)
 *  - Origin/Referer check on writes
 *  - Per-provider path whitelist (prevents SSRF via arbitrary endpoints)
 *  - 1 MiB body size cap
 *  - CSP / HSTS / Permissions-Policy headers
 *  - Server-side token resolution by accountId — tokens never leave the server
 *  - Strict 64-hex encryption key validation, no silent webroot fallback
 *  - Login required (session or device token) — see auth.php
 */

require_once __DIR__ . '/auth.php'; // umask, file constants, crypto, auth core

// ── Security headers ──────────────────────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
if (!empty($_SERVER['HTTPS']) || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// ── CORS for browser extensions (Chrome + Firefox) ───────────────────────────
$origin    = $_SERVER['HTTP_ORIGIN']  ?? '';
$isExtOrigin = (str_starts_with($origin, 'chrome-extension://') || str_starts_with($origin, 'moz-extension://'));
if ($isExtOrigin) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: GET, POST, DELETE, PUT, PATCH, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Cache-Control, Pragma, X-Aliaser-Auth');
    header('Access-Control-Max-Age: 86400');
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

header('Content-Type: application/json');

// ── Health check (unauthenticated, no sensitive info) ────────────────────────
// For container/readiness probes. Verifies the data dir is writable. Returns
// only a status string — no paths, versions or config.
if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['action'] ?? '') === 'health') {
    header('Cache-Control: no-store');
    $ok = is_dir(__DIR__ . '/json') && is_writable(__DIR__ . '/json');
    http_response_code($ok ? 200 : 503);
    echo json_encode(['status' => $ok ? 'ok' : 'degraded']);
    exit();
}

// ── Authentication gate (web session OR extension device token) ──────────────
aliaser_require_auth();

// ── Origin / Referer check + CSRF on writes ─────────────────────────────────
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
    aliaser_require_csrf(); // no-op for device-token (extension) requests
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    $host    = $_SERVER['HTTP_HOST']    ?? '';
    $sameOrigin = false;
    if ($origin) {
        $oh = parse_url($origin, PHP_URL_HOST);
        $op = parse_url($origin, PHP_URL_PORT);
        $expected = $host;
        $sameOrigin = ($oh && (($op ? $oh.':'.$op : $oh) === $expected || $oh === parse_url('http://'.$expected, PHP_URL_HOST)));
    } elseif ($referer) {
        $rh = parse_url($referer, PHP_URL_HOST);
        $rp = parse_url($referer, PHP_URL_PORT);
        $sameOrigin = ($rh && (($rp ? $rh.':'.$rp : $rh) === $host || $rh === parse_url('http://'.$host, PHP_URL_HOST)));
    } else {
        // No Origin/Referer at all — only allow if extension already validated above
        $sameOrigin = $isExtOrigin;
    }
    if (!$sameOrigin && !$isExtOrigin) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden origin']);
        exit;
    }
}

// ── Body size cap (1 MiB) ────────────────────────────────────────────────────
$rawInput = '';
if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
    $rawInput = file_get_contents('php://input', false, null, 0, 1048576);
    if (strlen($rawInput) >= 1048576) {
        http_response_code(413);
        echo json_encode(['error' => 'Payload too large']);
        exit;
    }
}

// File constants and crypto helpers (getEncryptionKey / encryptData /
// decryptData) now live in auth.php, which is required at the top of this file.

// ── Credentials helpers ───────────────────────────────────────────────────────
function readCredentials() {
    $creds = [
        'ovhAppKey'        => '',
        'ovhAppSecret'     => '',
        'infomaniakToken'  => '',
        'simpleloginToken' => '',
        'addyToken'        => '',
        'cloudflareToken'  => '',
        'perAccount'       => [],
    ];
    if (file_exists(CREDS_FILE)) {
        $dec = decryptData(file_get_contents(CREDS_FILE));
        if (is_array($dec)) {
            foreach ($dec as $k => $v) {
                if ($k === 'perAccount') {
                    if (is_array($v)) $creds['perAccount'] = $v;
                } elseif (!empty($v)) {
                    $creds[$k] = $v;
                }
            }
        }
    }
    return $creds;
}

// Per-field merge: preserves existing secrets for fields the client did not
// re-send (frontend cannot read them back after the GET-redaction change).
// Accounts present in $data['perAccount'] are kept; accounts NOT present are
// dropped (so account removal still works — frontend rebuilds the full set).
function writeCredentials($data) {
    // Serialize the whole read-modify-write so concurrent saves can't clobber
    // each other (the per-field merge below reads existing secrets first).
    $lock = fopen(CREDS_FILE . '.lock', 'c');
    if ($lock) flock($lock, LOCK_EX);
    $existing = readCredentials();
    $allowedGlobal = ['ovhAppKey', 'ovhAppSecret', 'infomaniakToken', 'simpleloginToken', 'addyToken', 'cloudflareToken'];
    $filtered = [];
    foreach ($allowedGlobal as $g) {
        $filtered[$g] = (isset($data[$g]) && $data[$g] !== '') ? $data[$g] : ($existing[$g] ?? '');
    }
    $perAccount = [];
    if (isset($data['perAccount']) && is_array($data['perAccount'])) {
        foreach ($data['perAccount'] as $id => $newFields) {
            if (!is_array($newFields)) continue;
            $old = $existing['perAccount'][$id] ?? [];
            $merged = is_array($old) ? $old : [];
            foreach (['token', 'ovhAppKey', 'ovhAppSecret'] as $f) {
                if (isset($newFields[$f]) && $newFields[$f] !== '') {
                    $merged[$f] = $newFields[$f];
                }
            }
            if (!empty($merged)) $perAccount[$id] = $merged;
        }
    }
    $filtered['perAccount'] = $perAccount;
    $payload = encryptData($filtered);
    if ($payload === false) return false;
    $result = file_put_contents(CREDS_FILE, $payload, LOCK_EX);
    if ($result !== false) @chmod(CREDS_FILE, 0600);
    if ($lock) { flock($lock, LOCK_UN); fclose($lock); }
    return $result;
}

// Strip secret values, return only which credential keys are present per account.
function readCredentialsRedacted() {
    $c = readCredentials();
    $perAccount = [];
    foreach ($c['perAccount'] as $id => $v) {
        if (!is_array($v)) continue;
        $perAccount[$id] = [
            'hasToken'        => !empty($v['token']),
            'hasOvhAppKey'    => !empty($v['ovhAppKey']),
            'hasOvhAppSecret' => !empty($v['ovhAppSecret']),
        ];
    }
    return [
        'perAccount' => $perAccount,
        'legacyGlobal' => [
            'ovhAppKey'        => !empty($c['ovhAppKey']),
            'ovhAppSecret'     => !empty($c['ovhAppSecret']),
            'infomaniakToken'  => !empty($c['infomaniakToken']),
            'simpleloginToken' => !empty($c['simpleloginToken']),
            'addyToken'        => !empty($c['addyToken']),
            'cloudflareToken'  => !empty($c['cloudflareToken']),
        ],
    ];
}

function readState() {
    if (!file_exists(STATE_FILE)) {
        return ['accounts' => [], 'zimbraPlatformIds' => [], 'zimbraPlatformId' => '', 'disabledAliases' => []];
    }
    $data = json_decode(file_get_contents(STATE_FILE), true);
    return is_array($data) ? $data : ['accounts' => [], 'zimbraPlatformIds' => [], 'zimbraPlatformId' => '', 'disabledAliases' => []];
}

function writeState($data) {
    $result = file_put_contents(STATE_FILE, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    if ($result !== false) @chmod(STATE_FILE, 0600);
    return $result;
}

function readNotes() {
    if (!file_exists(NOTES_FILE)) return [];
    $data = json_decode(file_get_contents(NOTES_FILE), true);
    if (!is_array($data) || array_values($data) === $data) return [];
    return $data;
}

function writeNotes($data) {
    if (array_values($data) === $data) $data = (object)[];
    $result = file_put_contents(NOTES_FILE, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    if ($result !== false) @chmod(NOTES_FILE, 0600);
    return $result;
}

function readAddyContacts() {
    if (!file_exists(ADDY_CONTACTS_FILE)) return [];
    $data = json_decode(file_get_contents(ADDY_CONTACTS_FILE), true);
    if (!is_array($data) || array_values($data) === $data) return [];
    return $data;
}

function writeAddyContacts($data) {
    if (array_values($data) === $data) $data = (object)[];
    $result = file_put_contents(ADDY_CONTACTS_FILE, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    if ($result !== false) @chmod(ADDY_CONTACTS_FILE, 0600);
    return $result;
}

// ── Per-key patches ───────────────────────────────────────────────────────────
// The dashboard tab and the popups each hold their own copy of these stores. A
// whole-file POST from one silently dropped whatever another had saved since it
// loaded: a note, a disabled alias (already deleted at the provider, so it then
// vanished for good), an account added in the dashboard. Clients now POST only
// what changed to ?action=state-patch / notes-patch / addy-contacts-patch,
// applied under a lock to the file as it is now.
// New routes, not a new body on the old ones: the extensions load from disk and
// can run ahead of the server. An older server does not know these actions,
// hands them to the provider proxy and answers 400 — where a {"patch": …} body
// on its ?action=notes would have been written as the whole file.
// The old whole-file routes stay for extension builds still installed.

// A write the client must hear about: 400 on a malformed patch (null), 500 when
// the file could not be written (false). A 200 {"ok":false} went unnoticed.
function respondWrite($ok) {
    if ($ok === null) { http_response_code(400); echo json_encode(['error' => 'Invalid patch']); return; }
    if (!$ok) { http_response_code(500); echo json_encode(['error' => 'Could not write to the data volume']); return; }
    echo json_encode(['ok' => true]);
}

// notes / addy-contacts: {key: value-or-null}; null or "" removes the key.
// $valid says what a value must be. Returns null on a malformed patch.
function patchMap(array $map, $patch, callable $valid) {
    if (!is_array($patch) || ($patch && array_is_list($patch))) return null;
    foreach ($patch as $k => $v) {
        $k = (string)$k;
        if ($k === '') return null;
        if ($v === null || $v === '') { unset($map[$k]); continue; }
        if (!$valid($v)) return null;
        $map[$k] = $v;
    }
    return $map;
}

// state: ops on the shared collections. Every op is optional.
//   disabledSet       [entry]                 upsert by accountId + aliasAddress
//   disabledUnset     [{accountId, aliasAddress}]
//   seen              {"accountId|address": ms}  first sighting only, never moved
//   seenUnset         ["accountId|address"]
//   zimbraPlatformIds {accountId: platformId}
//   consumerKeyUnset  [accountId]             OVH refused the key
//   accountSet        {accountId: {isFree|isPremium: bool}}
//   dropAccounts      [accountId]             everything keyed on a removed account
function applyStatePatch(array $s, $p) {
    if (!is_array($p) || ($p && array_is_list($p))) return null;
    $list = fn($k) => (isset($p[$k]) && is_array($p[$k])) ? $p[$k] : [];
    $isEntry = fn($e) => is_array($e) && is_string($e['accountId'] ?? null) && is_string($e['aliasAddress'] ?? null);
    $entryKey = fn($e) => $e['accountId'] . '|' . $e['aliasAddress'];
    foreach (['disabledSet', 'disabledUnset'] as $k) {
        foreach ($list($k) as $e) if (!$isEntry($e)) return null;
    }
    foreach (['seenUnset', 'consumerKeyUnset', 'dropAccounts'] as $k) {
        foreach ($list($k) as $v) if (!is_string($v)) return null;
    }
    foreach (['seen', 'zimbraPlatformIds', 'accountSet'] as $k) {   // maps, keyed by id
        if ($list($k) && array_is_list($list($k))) return null;
    }
    $drop = array_flip($list('dropAccounts'));

    $gone = [];
    foreach (array_merge($list('disabledUnset'), $list('disabledSet')) as $e) $gone[$entryKey($e)] = true;
    $dis = [];
    foreach ((is_array($s['disabledAliases'] ?? null) ? $s['disabledAliases'] : []) as $d) {
        if (!$isEntry($d)) { $dis[] = $d; continue; }
        if (isset($gone[$entryKey($d)]) || isset($drop[$d['accountId']])) continue;
        $dis[] = $d;
    }
    foreach ($list('disabledSet') as $e) $dis[] = $e;
    $s['disabledAliases'] = $dis;

    $seen = (is_array($s['aliasSeen'] ?? null) && array_values($s['aliasSeen']) !== $s['aliasSeen']) ? $s['aliasSeen'] : [];
    foreach ($list('seen') as $k => $v) {
        if (is_int($v) || is_float($v)) { if (!isset($seen[(string)$k])) $seen[(string)$k] = $v; }
        else return null;
    }
    foreach ($list('seenUnset') as $k) unset($seen[(string)$k]);
    foreach ($seen as $k => $_) {
        if (isset($drop[strstr((string)$k, '|', true)])) unset($seen[$k]);
    }
    $s['aliasSeen'] = $seen ?: (object)[];

    $zp = is_array($s['zimbraPlatformIds'] ?? null) ? $s['zimbraPlatformIds'] : [];
    foreach ($list('zimbraPlatformIds') as $id => $pid) {
        if (!is_string($pid) && !is_int($pid)) return null;
        $zp[(string)$id] = $pid;
    }
    foreach ($drop as $id => $_) unset($zp[$id]);
    $s['zimbraPlatformIds'] = $zp ?: (object)[];

    $unsetKey = array_flip($list('consumerKeyUnset')) + $drop;
    if (isset($s['consumerKeys']) && is_array($s['consumerKeys'])) {
        $s['consumerKeys'] = array_values(array_filter($s['consumerKeys'],
            fn($c) => !(is_array($c) && isset($unsetKey[(string)($c['id'] ?? '')]))));
    }

    $set = $list('accountSet');
    if ($set && isset($s['accounts']) && is_array($s['accounts'])) {
        foreach ($s['accounts'] as &$acc) {
            if (!is_array($acc) || !is_string($acc['id'] ?? null)) continue;
            $f = $set[$acc['id']] ?? null;
            if (!is_array($f)) continue;
            foreach (['isFree', 'isPremium'] as $flag) {
                if (array_key_exists($flag, $f) && is_bool($f[$flag])) $acc[$flag] = $f[$flag];
            }
        }
        unset($acc);
    }
    return $s;
}

// Resolve an account's stored token / OVH keys server-side from accountId.
function resolveAccountSecret($accountId, $field) {
    if (!$accountId) return '';
    $c = readCredentials();
    $a = $c['perAccount'][$accountId] ?? null;
    if (is_array($a) && !empty($a[$field])) return $a[$field];
    return '';
}

// ── CSRF token (web session) ──────────────────────────────────────────────────
if ($method === 'GET' && ($_GET['action'] ?? '') === 'csrf') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    echo json_encode(['csrf' => auth_csrf_token()]);
    exit();
}

// ── Logout ────────────────────────────────────────────────────────────────────
if ($method === 'POST' && ($_GET['action'] ?? '') === 'logout') {
    auth_logout();
    echo json_encode(['ok' => true]);
    exit();
}

// ── Device tokens (extensions) — web session only ─────────────────────────────
if (($_GET['action'] ?? '') === 'device-tokens') {
    if (($GLOBALS['auth_via'] ?? '') !== 'session') {
        http_response_code(403); echo json_encode(['error' => 'Web session required']); exit();
    }
    if ($method === 'GET') {
        header('Cache-Control: no-store, no-cache, must-revalidate');
        echo json_encode(['tokens' => auth_list_device_tokens()]); exit();
    }
    if ($method === 'POST') {
        $in = json_decode($rawInput, true);
        if (!is_array($in)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
        if (!empty($in['revoke'])) { echo json_encode(['ok' => auth_revoke_device_token($in['revoke'])]); exit(); }
        $tok = auth_add_device_token($in['label'] ?? 'Extension');
        if ($tok === null) { http_response_code(500); echo json_encode(['error' => 'Could not save the token']); exit(); }
        echo json_encode(['token' => $tok]); exit();
    }
}

// ── 2FA management (web session only) ─────────────────────────────────────────
$AUTH_MGMT = ['auth-methods','passkeys','passkey-register-options','passkey-register-verify','totp-setup','totp-enable','totp-disable'];
if (in_array(($_GET['action'] ?? ''), $AUTH_MGMT, true)) {
    if (($GLOBALS['auth_via'] ?? '') !== 'session') {
        http_response_code(403); echo json_encode(['error' => 'Web session required']); exit();
    }
    $action = $_GET['action'];
    $in = $rawInput ? json_decode($rawInput, true) : [];
    if (!is_array($in)) $in = [];
    header('Cache-Control: no-store, no-cache, must-revalidate');

    if ($action === 'auth-methods') {
        echo json_encode(['methods' => auth_methods(), 'passkeys' => auth_list_passkeys()]); exit();
    }
    if ($action === 'passkeys' && $method === 'GET') {
        echo json_encode(['passkeys' => auth_list_passkeys()]); exit();
    }
    if ($action === 'passkeys' && $method === 'POST') {
        $r = auth_remove_passkey($in['remove'] ?? '');
        if ($r === 'last') { http_response_code(400); echo json_encode(['error' => 'Cannot remove the last second factor — enable TOTP first.']); exit(); }
        echo json_encode(['ok' => (bool)$r]); exit();
    }
    if ($action === 'passkey-register-options') {
        echo json_encode(webauthn_register_options()); exit();
    }
    if ($action === 'passkey-register-verify') {
        $res = webauthn_register_verify(
            is_array($in['response'] ?? null) ? $in['response'] : [],
            is_string($in['label'] ?? null) ? $in['label'] : 'Passkey'
        );
        if ($res === true) { echo json_encode(['ok' => true]); }
        else { http_response_code(400); echo json_encode(['error' => $res]); }
        exit();
    }
    if ($action === 'totp-setup') {
        $secret = auth_totp_new_secret();
        $_SESSION['totp_pending'] = $secret;
        echo json_encode(['secret' => $secret, 'uri' => auth_totp_uri($secret, auth_username())]); exit();
    }
    if ($action === 'totp-enable') {
        $secret = $_SESSION['totp_pending'] ?? '';
        if (!$secret || !auth_totp_verify($secret, $in['code'] ?? '')) {
            http_response_code(400); echo json_encode(['error' => 'Invalid code']); exit();
        }
        $codes = auth_generate_backup_codes(8);
        // Under the auth-store lock, like every read-modify-write of it (see
        // auth_add_device_token()).
        $ok = auth_with_lock(AUTH_FILE, function () use ($secret, $codes) {
            $a = auth_read();
            $a['user']['totpSecret']  = $secret;
            $a['user']['totpEnabled'] = true;
            $a['user']['backupCodes'] = array_map('auth_hash_backup_code', $codes);
            return auth_write($a) !== false;
        });
        if (!$ok) { http_response_code(500); echo json_encode(['error' => 'Could not save TOTP']); exit(); }
        unset($_SESSION['totp_pending']);
        echo json_encode(['ok' => true, 'backupCodes' => $codes]); exit();
    }
    if ($action === 'totp-disable') {
        // The passkey check sits inside the lock: checked outside, a passkey
        // removal landing in between could leave the account with no factor.
        $r = auth_with_lock(AUTH_FILE, function () {
            $a = auth_read();
            if (empty($a['user']['passkeys'])) return 'no-passkey';
            $a['user']['totpEnabled'] = false;
            $a['user']['totpSecret']  = '';
            $a['user']['backupCodes'] = [];
            return auth_write($a) !== false;
        });
        if ($r === 'no-passkey') { http_response_code(400); echo json_encode(['error' => 'Add a passkey before disabling TOTP.']); exit(); }
        if (!$r) { http_response_code(500); echo json_encode(['error' => 'Could not save']); exit(); }
        echo json_encode(['ok' => true]); exit();
    }
}

// ── State routes ──────────────────────────────────────────────────────────────
if ($method === 'GET' && ($_GET['action'] ?? '') === 'state') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(readState());
    exit();
}

if ($method === 'POST' && ($_GET['action'] ?? '') === 'state') {
    $input = json_decode($rawInput, true);
    if (!is_array($input) || ($input && array_is_list($input))) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    unset($input['notes']);
    if (isset($input['accounts']) && is_array($input['accounts'])) {
        $credFields = ['token', 'ovhAppKey', 'ovhAppSecret'];
        $input['accounts'] = array_map(function($acc) use ($credFields) {
            return is_array($acc) ? array_diff_key($acc, array_flip($credFields)) : $acc;
        }, $input['accounts']);
    }
    // Top-level merge: a key the client did not send keeps its stored value, so
    // the dashboard's account save leaves the popups' disabled aliases and dates
    // alone. Older builds send every key, which is the old whole-file replace.
    respondWrite(auth_with_lock(STATE_FILE, fn() => writeState(array_merge(readState(), $input)) !== false));
    exit();
}

// ── Patch routes (see "Per-key patches" above) ────────────────────────────────
if ($method === 'POST' && in_array($_GET['action'] ?? '', ['state-patch', 'notes-patch', 'addy-contacts-patch'], true)) {
    $patch = json_decode($rawInput, true);
    $isContactList = fn($v) => is_array($v) && array_is_list($v)
        && !array_filter($v, fn($x) => !is_array($x) || !is_string($x['email'] ?? null) || !is_string($x['reverse'] ?? null));
    respondWrite(match ($_GET['action']) {
        'state-patch' => auth_with_lock(STATE_FILE, function () use ($patch) {
            $s = applyStatePatch(readState(), $patch);
            return $s === null ? null : writeState($s) !== false;
        }),
        'notes-patch' => auth_with_lock(NOTES_FILE, function () use ($patch) {
            $n = patchMap(readNotes(), $patch, fn($v) => is_string($v));
            return $n === null ? null : writeNotes($n) !== false;
        }),
        'addy-contacts-patch' => auth_with_lock(ADDY_CONTACTS_FILE, function () use ($patch, $isContactList) {
            $c = patchMap(readAddyContacts(), $patch, $isContactList);
            return $c === null ? null : writeAddyContacts($c) !== false;
        }),
    });
    exit();
}

// ── Notes routes ──────────────────────────────────────────────────────────────
if ($method === 'GET' && ($_GET['action'] ?? '') === 'notes') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(readNotes());
    exit();
}

if ($method === 'POST' && ($_GET['action'] ?? '') === 'notes') {
    $input = json_decode($rawInput, true);
    if (!is_array($input)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    // Whole map: extension builds before notes-patch.
    respondWrite(auth_with_lock(NOTES_FILE, fn() => writeNotes($input) !== false));
    exit();
}

// ── Addy contacts routes ──────────────────────────────────────────────────────
if ($method === 'GET' && ($_GET['action'] ?? '') === 'addy-contacts') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(readAddyContacts());
    exit();
}

if ($method === 'POST' && ($_GET['action'] ?? '') === 'addy-contacts') {
    $input = json_decode($rawInput, true);
    if (!is_array($input)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    // Whole map: extension builds before addy-contacts-patch.
    respondWrite(auth_with_lock(ADDY_CONTACTS_FILE, fn() => writeAddyContacts($input) !== false));
    exit();
}

// ── Credentials routes ────────────────────────────────────────────────────────
// GET returns ONLY a redacted view (booleans only, never secret values).
if ($method === 'GET' && ($_GET['action'] ?? '') === 'credentials') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(readCredentialsRedacted());
    exit();
}

if ($method === 'POST' && ($_GET['action'] ?? '') === 'credentials') {
    $input = json_decode($rawInput, true);
    if (!is_array($input)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    echo json_encode(['ok' => writeCredentials($input) !== false]);
    exit();
}

// ── Proxy routes ──────────────────────────────────────────────────────────────
$input = json_decode($rawInput, true);
if (!$input) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON input']); exit(); }
$GLOBALS['input'] = $input;

$provider = $input['provider']  ?? 'ovh';
$method   = $input['method']    ?? 'GET';
$path     = $input['path']      ?? '';
$body     = isset($input['body']) ? json_encode($input['body']) : '';

// Every field below is attacker-controlled. Reject non-strings before they reach
// preg_match / array offsets (TypeError → 500) and, above all, before $method
// reaches CURLOPT_CUSTOMREQUEST: libcurl does not validate that string, so a
// CR/LF in it rewrites the whole request line and defeats the path whitelist.
if (!is_string($provider) || !is_string($method) || !is_string($path)) {
    http_response_code(400); echo json_encode(['error' => 'Invalid request fields']); exit();
}
$method = strtoupper($method);
if (!in_array($method, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], true)) {
    http_response_code(400); echo json_encode(['error' => 'Method not allowed']); exit();
}

if (empty($path)) { http_response_code(400); echo json_encode(['error' => 'Missing required field: path']); exit(); }
if (!function_exists('curl_init')) { http_response_code(500); echo json_encode(['error' => 'curl extension not available']); exit(); }

// ── Path whitelists per provider (defense against SSRF / privilege escalation) ──
$WHITELISTS = [
    'ovh' => [
        '#^/auth/credential$#',
        '#^/zimbra/platform$#',
        '#^/zimbra/platform/[^/]+/account$#',
        '#^/zimbra/platform/[^/]+/alias$#',
        '#^/zimbra/platform/[^/]+/alias/[^/]+$#',
    ],
    'infomaniak' => [
        '#^/1/mail_hostings/[^/]+/mailboxes/[^/]+/aliases(/[^/]+)?$#',
    ],
    'simplelogin' => [
        '#^/api/user_info$#',
        '#^/api/mailboxes$#',
        '#^/api/v[2-9]/aliases(\?.*)?$#',
        '#^/api/v[3-9]/alias/custom/new$#',
        '#^/api/v[3-9]/alias/options$#',
        '#^/api/aliases/[^/]+(/(toggle|contacts(\?.*)?))?$#',
        '#^/api/contacts/[^/]+/toggle$#',
    ],
    'addy' => [
        '#^/api/v1/account-details$#',
        '#^/api/v1/recipients(\?.*)?$#',
        '#^/api/v1/aliases(\?.*)?$#',
        '#^/api/v1/aliases/[^/]+$#',
        '#^/api/v1/active-aliases(/[^/]+)?$#',
    ],
    'cloudflare' => [
        '#^/zones/[^/]+$#',
        '#^/zones/[^/]+/email/routing/rules(\?.*)?$#',
        '#^/zones/[^/]+/email/routing/rules/[^/]+$#',
    ],
    'haltman' => [
        '#^/api/domains$#',
        '#^/api/alias/list(\?.*)?$#',
        '#^/api/alias/(create|delete)$#',
    ],
];

if (!isset($WHITELISTS[$provider])) {
    http_response_code(400); echo json_encode(['error' => 'Unknown provider']); exit();
}
$pathOk = false;
foreach ($WHITELISTS[$provider] as $rx) {
    // 'D' modifier: without it PCRE lets '$' match before a trailing newline, so
    // "/api/user_info\n" would pass the whitelist and land in the outgoing URL.
    if (preg_match($rx . 'D', $path)) { $pathOk = true; break; }
}
if (!$pathOk) {
    http_response_code(403);
    echo json_encode(['error' => 'Path not allowed for provider']);
    exit();
}

if ($provider === 'infomaniak')  handleInfomaniak($method, $path, $body);
elseif ($provider === 'simplelogin') handleSimpleLogin($method, $path, $body);
elseif ($provider === 'addy')        handleAddy($method, $path, $body);
elseif ($provider === 'cloudflare')  handleCloudflare($method, $path, $body);
elseif ($provider === 'haltman')     handleHaltman($method, $path, $body);
else                                 handleOVH($method, $path, $body, $input);

// Resolve a token for a non-OVH provider with this priority:
//   1. accountId → encrypted credentials store (preferred)
//   2. legacy: explicit token in request body (kept for setup-time flows)
//   3. legacy global token from credentials.json
function resolveToken($provider, $accountId, $explicit) {
    if ($accountId) {
        $t = resolveAccountSecret($accountId, 'token');
        if ($t) return $t;
    }
    if (is_string($explicit) && $explicit !== '') return $explicit;
    $creds = readCredentials();
    $key = $provider . 'Token';
    return $creds[$key] ?? '';
}

// ── Infomaniak ────────────────────────────────────────────────────────────────
function handleInfomaniak($method, $path, $body) {
    $token = resolveToken('infomaniak', $GLOBALS['input']['accountId'] ?? '', $GLOBALS['input']['token'] ?? '');
    if (empty($token)) { http_response_code(401); echo json_encode(['error' => 'Infomaniak token not configured']); exit(); }
    $url = 'https://api.infomaniak.com' . $path;
    $headers = ['Content-Type: application/json', 'Authorization: Bearer ' . $token];
    sendCurl($method, $url, $headers, $body, ['POST', 'PUT', 'PATCH']);
}

// ── SimpleLogin ───────────────────────────────────────────────────────────────
function handleSimpleLogin($method, $path, $body) {
    $token = resolveToken('simplelogin', $GLOBALS['input']['accountId'] ?? '', $GLOBALS['input']['token'] ?? '');
    if (empty($token)) { http_response_code(401); echo json_encode(['error' => 'SimpleLogin token not configured']); exit(); }
    $url = 'https://app.simplelogin.io' . $path;
    $headers = ['Content-Type: application/json', 'Authentication: ' . $token];
    sendCurl($method, $url, $headers, $body, ['POST', 'PUT', 'PATCH', 'DELETE']);
}

// ── Addy.io ───────────────────────────────────────────────────────────────────
function handleAddy($method, $path, $body) {
    $token = resolveToken('addy', $GLOBALS['input']['accountId'] ?? '', $GLOBALS['input']['token'] ?? '');
    if (empty($token)) { http_response_code(401); echo json_encode(['error' => 'Addy.io token not configured']); exit(); }
    $url = 'https://app.addy.io' . $path;
    $headers = [
        'Content-Type: application/json',
        'Accept: application/json',
        'Authorization: Bearer ' . $token,
        'X-Requested-With: XMLHttpRequest',
    ];
    sendCurl($method, $url, $headers, $body, ['POST', 'PATCH']);
}

// ── Cloudflare ────────────────────────────────────────────────────────────────
function handleCloudflare($method, $path, $body) {
    $token = resolveToken('cloudflare', $GLOBALS['input']['accountId'] ?? '', $GLOBALS['input']['token'] ?? '');
    if (empty($token)) { http_response_code(401); echo json_encode(['error' => 'Cloudflare token not configured']); exit(); }
    $url = 'https://api.cloudflare.com/client/v4' . $path;
    $headers = ['Content-Type: application/json', 'Authorization: Bearer ' . $token];
    sendCurl($method, $url, $headers, $body, ['POST', 'PUT', 'PATCH']);
}

// ── Haltman ───────────────────────────────────────────────────────────────────
function handleHaltman($method, $path, $body) {
    $accountId = $GLOBALS['input']['accountId'] ?? '';
    $explicit  = $GLOBALS['input']['token']     ?? '';
    $token = $accountId ? resolveAccountSecret($accountId, 'token') : '';
    if (!$token && is_string($explicit) && $explicit !== '') $token = $explicit;
    $url = 'https://mail.haltman.io' . $path;
    $headers = ['Content-Type: application/json'];
    if (!empty($token)) $headers[] = 'X-API-Key: ' . $token;
    sendCurl($method, $url, $headers, $body, ['POST']);
}

// ── OVH ───────────────────────────────────────────────────────────────────────

function ovhSignedRequest($method, $url, $appKey, $appSecret, $consumerKey, $body, $extraHeaders = []) {
    $timestamp = (string) time();
    $toSign    = $appSecret . '+' . $consumerKey . '+' . $method . '+' . $url . '+' . $body . '+' . $timestamp;
    $signature = '$1$' . sha1($toSign);
    $hdrs = [
        'Content-Type: application/json',
        'X-Ovh-Application: ' . $appKey,
        'X-Ovh-Timestamp: ' . $timestamp,
    ];
    if (!empty($consumerKey)) {
        $hdrs[] = 'X-Ovh-Consumer: '  . $consumerKey;
        $hdrs[] = 'X-Ovh-Signature: ' . $signature;
    }
    foreach ($extraHeaders as $h) { $hdrs[] = $h; }
    assertSafeHeaders($hdrs);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST,  $method);
    curl_setopt($ch, CURLOPT_HTTPHEADER,     $hdrs);
    curl_setopt($ch, CURLOPT_TIMEOUT,        30);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_PROTOCOLS,      CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_HEADER,         true);
    if (in_array($method, ['POST','PUT','DELETE']) && !empty($body)) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $raw       = curl_exec($ch);
    $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hdrSize   = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $curlError = curl_error($ch);
    if ($curlError) {
        return ['code' => 502, 'body' => json_encode(['error' => 'Network error']), 'headers' => []];
    }
    $hdrStr  = substr($raw, 0, $hdrSize);
    $bodyStr = substr($raw, $hdrSize);
    $parsedHdrs = [];
    foreach (explode("\r\n", $hdrStr) as $line) {
        $pos = strpos($line, ':');
        if ($pos !== false) {
            $k = strtolower(trim(substr($line, 0, $pos)));
            $v = trim(substr($line, $pos + 1));
            $parsedHdrs[$k] = $v;
        }
    }
    return ['code' => $httpCode, 'body' => $bodyStr, 'headers' => $parsedHdrs];
}

function handleOVH($method, $path, $body, $input) {
    $accountId = $input['accountId'] ?? '';
    $creds     = readCredentials();
    // Setup-time: client may pass appKey/appSecret in body before account exists.
    $appKey    = (!empty($input['appKey']))    ? $input['appKey']    : ($accountId ? resolveAccountSecret($accountId, 'ovhAppKey')    : '');
    $appSecret = (!empty($input['appSecret'])) ? $input['appSecret'] : ($accountId ? resolveAccountSecret($accountId, 'ovhAppSecret') : '');
    if (!$appKey)    $appKey    = $creds['ovhAppKey']    ?? '';
    if (!$appSecret) $appSecret = $creds['ovhAppSecret'] ?? '';
    if (empty($appKey) || empty($appSecret)) {
        http_response_code(401); echo json_encode(['error' => 'OVH API keys not configured']); exit();
    }
    $consumerKey = $input['consumerKey'] ?? '';
    $useV2       = $input['useV2'] ?? false;
    $base        = $useV2 ? 'https://eu.api.ovh.com/v2' : 'https://eu.api.ovh.com/1.0';

    if ($useV2 && $method === 'GET' && preg_match('#^/zimbra/platform/[^/]+/alias$#', $path)) {
        $allItems = [];
        $cursor   = null;
        for ($page = 0; $page < 50; $page++) {
            $currentUrl   = $base . $path;
            $extraHeaders = $cursor ? ['X-Pagination-Cursor: ' . $cursor] : [];
            $res = ovhSignedRequest('GET', $currentUrl, $appKey, $appSecret, $consumerKey, '', $extraHeaders);
            if ($res['code'] >= 400) {
                http_response_code($res['code']);
                echo $res['body'];
                return;
            }
            $data = json_decode($res['body'], true);
            if (is_array($data)) {
                if (isset($data['items']) && is_array($data['items'])) {
                    $allItems = array_merge($allItems, $data['items']);
                    $cursor   = $data['cursor']['next'] ?? null;
                } else {
                    $allItems = array_merge($allItems, $data);
                    $cursor   = null;
                }
            }
            if (empty($cursor)) {
                $cursor = $res['headers']['x-pagination-cursor-next'] ?? null;
            }
            if (empty($cursor)) break;
        }
        http_response_code(200);
        echo json_encode(array_values($allItems));
        return;
    }

    $url       = $base . $path;
    $timestamp = (string) time();
    $toSign    = $appSecret . '+' . $consumerKey . '+' . $method . '+' . $url . '+' . $body . '+' . $timestamp;
    $signature = '$1$' . sha1($toSign);
    $headers = [
        'Content-Type: application/json',
        'X-Ovh-Application: ' . $appKey,
        'X-Ovh-Timestamp: ' . $timestamp,
    ];
    if (!empty($consumerKey)) {
        $headers[] = 'X-Ovh-Consumer: ' . $consumerKey;
        $headers[] = 'X-Ovh-Signature: ' . $signature;
    }
    sendCurl($method, $url, $headers, $body, ['POST', 'PUT', 'DELETE']);
}

// Reject header lines carrying CR/LF (or NUL). Tokens and OVH keys reach these
// headers from client input; libcurl copies the string verbatim, so an embedded
// CRLF would inject arbitrary headers into the outgoing provider request.
function assertSafeHeaders($headers) {
    foreach ($headers as $h) {
        if (!is_string($h) || preg_match('/[\r\n\0]/', $h)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid credential or header value']);
            exit();
        }
    }
}

// ── Shared curl helper ────────────────────────────────────────────────────────
function sendCurl($method, $url, $headers, $body, $bodyMethods) {
    assertSafeHeaders($headers);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // no redirect-driven SSRF
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    if (in_array($method, $bodyMethods) && !empty($body)) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $response  = curl_exec($ch);
    $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    if ($curlError) {
        error_log('Aliaser curl error: ' . $curlError);
        http_response_code(502);
        echo json_encode(['error' => 'Network error, please try again']);
        exit();
    }
    http_response_code($httpCode);
    echo $response;
}
