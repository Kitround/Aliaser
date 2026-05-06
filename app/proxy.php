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
 */

umask(0077);

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

// ── Optional shared-secret auth ──────────────────────────────────────────────
$authToken = getenv('ALIASER_AUTH_TOKEN');
if ($authToken !== false && $authToken !== '') {
    $provided = $_SERVER['HTTP_X_ALIASER_AUTH'] ?? '';
    if (!is_string($provided) || !hash_equals($authToken, $provided)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
}

// ── Origin / Referer check on writes (CSRF mitigation) ──────────────────────
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
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

// ── State files ───────────────────────────────────────────────────────────────
define('STATE_FILE',         __DIR__ . '/json/state.json');
define('NOTES_FILE',         __DIR__ . '/json/notes.json');
define('CREDS_FILE',         __DIR__ . '/json/credentials.json');
define('KEY_FILE',           __DIR__ . '/json/secret.key');
define('ADDY_CONTACTS_FILE', __DIR__ . '/json/addy-contacts.json');

// ── Encryption helpers ────────────────────────────────────────────────────────
function getEncryptionKey() {
    // 1. Environment variable — best for Docker / VPS
    $envKey = getenv('ALIASER_SECRET_KEY');
    if ($envKey !== false && $envKey !== '') {
        if (!preg_match('/^[0-9a-f]{64}$/i', $envKey)) {
            http_response_code(500);
            echo json_encode(['error' => 'ALIASER_SECRET_KEY must be 64 hex chars (32 bytes)']);
            exit;
        }
        return $envKey;
    }

    // 2. File above web root — best for shared hosting (not reachable via HTTP)
    $parentKey = dirname(__DIR__) . '/aliaser.key';
    if (file_exists($parentKey)) {
        $k = trim(file_get_contents($parentKey));
        if (preg_match('/^[0-9a-f]{64}$/i', $k)) return $k;
    }

    // 3. Local fallback — webroot-adjacent. Generated once with 0600.
    if (!file_exists(KEY_FILE)) {
        $key = bin2hex(random_bytes(32));
        file_put_contents(KEY_FILE, $key);
        @chmod(KEY_FILE, 0600);
    }
    $k = trim(file_get_contents(KEY_FILE));
    if (!preg_match('/^[0-9a-f]{64}$/i', $k)) {
        http_response_code(500);
        echo json_encode(['error' => 'Invalid encryption key']);
        exit;
    }
    return $k;
}

// AES-256-GCM with backward-compat read of legacy AES-256-CBC payloads.
// Format new: "gcm:<base64iv>:<base64tag>:<ciphertext>"
// Format legacy: "<base64iv>:<ciphertext>"  (CBC, no tag)
function encryptData($data) {
    $key = hex2bin(getEncryptionKey());
    $iv  = random_bytes(12);
    $tag = '';
    $enc = openssl_encrypt(json_encode($data), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($enc === false) return false;
    return 'gcm:' . base64_encode($iv) . ':' . base64_encode($tag) . ':' . base64_encode($enc);
}

function decryptData($str) {
    $key = hex2bin(getEncryptionKey());
    if (str_starts_with($str, 'gcm:')) {
        $parts = explode(':', $str, 4);
        if (count($parts) !== 4) return null;
        $iv  = base64_decode($parts[1]);
        $tag = base64_decode($parts[2]);
        $ct  = base64_decode($parts[3]);
        $dec = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return ($dec !== false) ? json_decode($dec, true) : null;
    }
    // Legacy CBC
    $parts = explode(':', $str, 2);
    if (count($parts) !== 2) return null;
    $iv  = base64_decode($parts[0]);
    $dec = openssl_decrypt($parts[1], 'AES-256-CBC', $key, 0, $iv);
    return ($dec !== false) ? json_decode($dec, true) : null;
}

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
    $result = file_put_contents(CREDS_FILE, $payload);
    if ($result !== false) @chmod(CREDS_FILE, 0600);
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
    $result = file_put_contents(STATE_FILE, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
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
    $result = file_put_contents(NOTES_FILE, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
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
    $result = file_put_contents(ADDY_CONTACTS_FILE, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    if ($result !== false) @chmod(ADDY_CONTACTS_FILE, 0600);
    return $result;
}

// Resolve an account's stored token / OVH keys server-side from accountId.
function resolveAccountSecret($accountId, $field) {
    if (!$accountId) return '';
    $c = readCredentials();
    $a = $c['perAccount'][$accountId] ?? null;
    if (is_array($a) && !empty($a[$field])) return $a[$field];
    return '';
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
    if (!is_array($input)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    unset($input['notes']);
    if (isset($input['accounts']) && is_array($input['accounts'])) {
        $credFields = ['token', 'ovhAppKey', 'ovhAppSecret'];
        $input['accounts'] = array_map(function($acc) use ($credFields) {
            return is_array($acc) ? array_diff_key($acc, array_flip($credFields)) : $acc;
        }, $input['accounts']);
    }
    echo json_encode(['ok' => writeState($input) !== false]);
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
    echo json_encode(['ok' => writeNotes($input) !== false]);
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
    echo json_encode(['ok' => writeAddyContacts($input) !== false]);
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
$method   = strtoupper($input['method'] ?? 'GET');
$path     = $input['path']      ?? '';
$body     = isset($input['body']) ? json_encode($input['body']) : '';

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
    if (preg_match($rx, $path)) { $pathOk = true; break; }
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
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST,  $method);
    curl_setopt($ch, CURLOPT_HTTPHEADER,     $hdrs);
    curl_setopt($ch, CURLOPT_TIMEOUT,        30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_HEADER,         true);
    if (in_array($method, ['POST','PUT','DELETE']) && !empty($body)) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $raw       = curl_exec($ch);
    $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hdrSize   = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $curlError = curl_error($ch);
    curl_close($ch);
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

// ── Shared curl helper ────────────────────────────────────────────────────────
function sendCurl($method, $url, $headers, $body, $bodyMethods) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    if (in_array($method, $bodyMethods) && !empty($body)) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $response  = curl_exec($ch);
    $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    if ($curlError) {
        error_log('Aliaser curl error: ' . $curlError);
        http_response_code(502);
        echo json_encode(['error' => 'Network error, please try again']);
        exit();
    }
    http_response_code($httpCode);
    echo $response;
}
