<?php
/**
 * Aliaser Proxy — OVH, Infomaniak, SimpleLogin, Addy.io, Cloudflare + state persistence
 */

// ── Security headers ──────────────────────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');

// ── CORS for browser extensions (Chrome + Firefox) ───────────────────────────
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (str_starts_with($origin, 'chrome-extension://') || str_starts_with($origin, 'moz-extension://')) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Methods: GET, POST, DELETE, PUT, PATCH, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Cache-Control, Pragma');
    header('Access-Control-Max-Age: 86400');
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

header('Content-Type: application/json');


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
    if ($envKey !== false && strlen($envKey) >= 16) return $envKey;

    // 2. File above web root — best for shared hosting (not reachable via HTTP)
    $parentKey = dirname(__DIR__) . '/aliaser.key';
    if (file_exists($parentKey)) return trim(file_get_contents($parentKey));

    // 3. Local fallback — legacy, less secure (key stored alongside ciphertext)
    if (!file_exists(KEY_FILE)) {
        $key = bin2hex(random_bytes(32));
        file_put_contents(KEY_FILE, $key);
        @chmod(KEY_FILE, 0600);
    }
    return trim(file_get_contents(KEY_FILE));
}

function encryptData($data) {
    $key = hex2bin(getEncryptionKey());
    $iv  = random_bytes(16);
    $enc = openssl_encrypt(json_encode($data), 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($iv) . ':' . $enc;
}

function decryptData($str) {
    $key   = hex2bin(getEncryptionKey());
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

function writeCredentials($data) {
    $allowedGlobal = ['ovhAppKey', 'ovhAppSecret', 'infomaniakToken', 'simpleloginToken', 'addyToken', 'cloudflareToken'];
    $filtered = array_intersect_key($data, array_flip($allowedGlobal));
    if (isset($data['perAccount']) && is_array($data['perAccount'])) {
        $filtered['perAccount'] = $data['perAccount'];
    }
    $result = file_put_contents(CREDS_FILE, encryptData($filtered));
    if ($result !== false) @chmod(CREDS_FILE, 0600);
    return $result;
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

// ── State routes ──────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['action'] ?? '') === 'state') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(readState());
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_GET['action'] ?? '') === 'state') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (!is_array($input)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    unset($input['notes']);
    // Strip any credential fields that may have leaked into accounts
    if (isset($input['accounts']) && is_array($input['accounts'])) {
        $credFields = ['token', 'ovhAppKey', 'ovhAppSecret'];
        $input['accounts'] = array_map(function($acc) use ($credFields) {
            return array_diff_key($acc, array_flip($credFields));
        }, $input['accounts']);
    }
    echo json_encode(['ok' => writeState($input) !== false]);
    exit();
}

// ── Notes routes ──────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['action'] ?? '') === 'notes') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(readNotes());
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_GET['action'] ?? '') === 'notes') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (!is_array($input)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    echo json_encode(['ok' => writeNotes($input) !== false]);
    exit();
}

// ── Addy contacts routes ──────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['action'] ?? '') === 'addy-contacts') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(readAddyContacts());
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_GET['action'] ?? '') === 'addy-contacts') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (!is_array($input)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    echo json_encode(['ok' => writeAddyContacts($input) !== false]);
    exit();
}

// ── Credentials routes ────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['action'] ?? '') === 'credentials') {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    echo json_encode(readCredentials());
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_GET['action'] ?? '') === 'credentials') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (!is_array($input)) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON']); exit(); }
    echo json_encode(['ok' => writeCredentials($input) !== false]);
    exit();
}

// ── Proxy routes ──────────────────────────────────────────────────────────────
$input = json_decode(file_get_contents('php://input'), true);
if (!$input) { http_response_code(400); echo json_encode(['error' => 'Invalid JSON input']); exit(); }
$GLOBALS['input'] = $input;

$provider = $input['provider'] ?? 'ovh';
$method   = strtoupper($input['method'] ?? 'GET');
$path     = $input['path'] ?? '';
$body     = isset($input['body']) ? json_encode($input['body']) : '';

if (empty($path)) { http_response_code(400); echo json_encode(['error' => 'Missing required field: path']); exit(); }

if (!function_exists('curl_init')) { http_response_code(500); echo json_encode(['error' => 'curl extension not available']); exit(); }

if ($provider === 'infomaniak') handleInfomaniak($method, $path, $body);
elseif ($provider === 'simplelogin') handleSimpleLogin($method, $path, $body);
elseif ($provider === 'addy') handleAddy($method, $path, $body);
elseif ($provider === 'cloudflare') handleCloudflare($method, $path, $body);
elseif ($provider === 'haltman') handleHaltman($method, $path, $body);
else handleOVH($method, $path, $body, $input);

// ── Infomaniak ────────────────────────────────────────────────────────────────
function handleInfomaniak($method, $path, $body) {
    $creds = readCredentials();
    $token = (!empty($GLOBALS['input']['token'])) ? $GLOBALS['input']['token'] : ($creds['infomaniakToken'] ?? '');
    if (empty($token)) {
        http_response_code(500); echo json_encode(['error' => 'Infomaniak token not configured']); exit();
    }
    $url = 'https://api.infomaniak.com' . $path;
    $headers = ['Content-Type: application/json', 'Authorization: Bearer ' . $token];
    sendCurl($method, $url, $headers, $body, ['POST', 'PUT', 'PATCH']);
}

// ── SimpleLogin ───────────────────────────────────────────────────────────────
function handleSimpleLogin($method, $path, $body) {
    $creds = readCredentials();
    $token = (!empty($GLOBALS['input']['token'])) ? $GLOBALS['input']['token'] : ($creds['simpleloginToken'] ?? '');
    if (empty($token)) {
        http_response_code(500); echo json_encode(['error' => 'SimpleLogin token not configured']); exit();
    }
    $url = 'https://app.simplelogin.io' . $path;
    $headers = ['Content-Type: application/json', 'Authentication: ' . $token];
    sendCurl($method, $url, $headers, $body, ['POST', 'PUT', 'PATCH', 'DELETE']);
}

// ── Addy.io ───────────────────────────────────────────────────────────────────
function handleAddy($method, $path, $body) {
    $creds = readCredentials();
    $token = (!empty($GLOBALS['input']['token'])) ? $GLOBALS['input']['token'] : ($creds['addyToken'] ?? '');
    if (empty($token)) {
        http_response_code(500); echo json_encode(['error' => 'Addy.io token not configured']); exit();
    }
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
    $creds = readCredentials();
    $token = (!empty($GLOBALS['input']['token'])) ? $GLOBALS['input']['token'] : ($creds['cloudflareToken'] ?? '');
    if (empty($token)) {
        http_response_code(500); echo json_encode(['error' => 'Cloudflare token not configured']); exit();
    }
    $url = 'https://api.cloudflare.com/client/v4' . $path;
    $headers = ['Content-Type: application/json', 'Authorization: Bearer ' . $token];
    sendCurl($method, $url, $headers, $body, ['POST', 'PUT', 'PATCH']);
}

// ── Haltman ───────────────────────────────────────────────────────────────────
function handleHaltman($method, $path, $body) {
    $token = $GLOBALS['input']['token'] ?? '';
    $url = 'https://mail.haltman.io' . $path;
    $headers = ['Content-Type: application/json'];
    if (!empty($token)) $headers[] = 'X-API-Key: ' . $token;
    sendCurl($method, $url, $headers, $body, ['POST']);
}

// ── OVH ───────────────────────────────────────────────────────────────────────
function handleOVH($method, $path, $body, $input) {
    $creds     = readCredentials();
    $appKey    = (!empty($input['appKey']))    ? $input['appKey']    : ($creds['ovhAppKey']    ?? '');
    $appSecret = (!empty($input['appSecret'])) ? $input['appSecret'] : ($creds['ovhAppSecret'] ?? '');
    if (empty($appKey) || empty($appSecret)) {
        http_response_code(500); echo json_encode(['error' => 'OVH API keys not configured']); exit();
    }
    $consumerKey = $input['consumerKey'] ?? '';
    $useV2       = $input['useV2'] ?? false;
    $base        = $useV2 ? 'https://eu.api.ovh.com/v2' : 'https://eu.api.ovh.com/1.0';
    $url         = $base . $path;
    $timestamp   = (string) time();
    $toSign      = $appSecret . '+' . $consumerKey . '+' . $method . '+' . $url . '+' . $body . '+' . $timestamp;
    $signature   = '$1$' . sha1($toSign);

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
