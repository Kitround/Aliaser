<?php
/**
 * Aliaser — authentication core (zero-dependency, pure PHP).
 *
 * Included by:
 *   - proxy.php  → API/data gate (aliaser_require_auth)
 *   - login.php  → setup / login / 2FA / logout UI
 *
 * Auth model:
 *   - Single admin account: username + password (argon2id) + TOTP (RFC 6238).
 *   - One-time backup codes for TOTP recovery.
 *   - Web app authenticates via a secure PHP session (HttpOnly, SameSite=Strict,
 *     Secure under HTTPS). Writes additionally require a CSRF token.
 *   - Extensions authenticate via a long-lived device token (header
 *     X-Aliaser-Auth), revocable, hashed at rest. The ALIASER_AUTH_TOKEN env var
 *     is also accepted as a static device token.
 *   - Designed to grow: verifySecondFactor() centralises the 2FA step so a
 *     passkey/WebAuthn factor can be added later without touching callers.
 *
 * All auth state lives in json/auth.json (encrypted at rest, web-inaccessible).
 */

umask(0077);

// ── Persisted file paths (canonical — proxy.php relies on these) ───────────────
define('STATE_FILE',         __DIR__ . '/json/state.json');
define('NOTES_FILE',         __DIR__ . '/json/notes.json');
define('CREDS_FILE',         __DIR__ . '/json/credentials.json');
define('KEY_FILE',           __DIR__ . '/json/secret.key');
define('ADDY_CONTACTS_FILE', __DIR__ . '/json/addy-contacts.json');
define('AUTH_FILE',          __DIR__ . '/json/auth.json');
define('THROTTLE_FILE',      __DIR__ . '/json/auth-throttle.json');

// Tunables
define('AUTH_MAX_FAILS',      5);        // failed logins before lockout
define('AUTH_LOCK_SECONDS',   300);      // lockout duration (5 min)
define('AUTH_IDLE_SECONDS',   3600);     // session idle timeout (1 h)
define('AUTH_ABS_SECONDS',    7 * 86400);// session absolute lifetime (7 d)

// ── Encryption (canonical; shared with proxy.php) ─────────────────────────────
function getEncryptionKey() {
    $envKey = getenv('ALIASER_SECRET_KEY');
    if ($envKey !== false && $envKey !== '') {
        if (!preg_match('/^[0-9a-f]{64}$/i', $envKey)) {
            http_response_code(500);
            echo json_encode(['error' => 'ALIASER_SECRET_KEY must be 64 hex chars (32 bytes)']);
            exit;
        }
        return $envKey;
    }
    $parentKey = dirname(__DIR__) . '/aliaser.key';
    if (file_exists($parentKey)) {
        $k = trim(file_get_contents($parentKey));
        if (preg_match('/^[0-9a-f]{64}$/i', $k)) return $k;
    }
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

// AES-256-GCM, with backward-compat read of legacy AES-256-CBC payloads.
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
    $parts = explode(':', $str, 2);
    if (count($parts) !== 2) return null;
    $iv  = base64_decode($parts[0]);
    $dec = openssl_decrypt($parts[1], 'AES-256-CBC', $key, 0, $iv);
    return ($dec !== false) ? json_decode($dec, true) : null;
}

// ── Auth store (json/auth.json, encrypted) ────────────────────────────────────
function auth_read() {
    if (!file_exists(AUTH_FILE)) return ['user' => null, 'deviceTokens' => []];
    $d = decryptData(file_get_contents(AUTH_FILE));
    if (!is_array($d)) return ['user' => null, 'deviceTokens' => []];
    if (!isset($d['deviceTokens']) || !is_array($d['deviceTokens'])) $d['deviceTokens'] = [];
    if (!isset($d['user'])) $d['user'] = null;
    return $d;
}
function auth_write($data) {
    $p = encryptData($data);
    if ($p === false) return false;
    $r = file_put_contents(AUTH_FILE, $p);
    if ($r !== false) @chmod(AUTH_FILE, 0600);
    return $r;
}
function auth_user_exists()   { $a = auth_read(); return !empty($a['user']); }
function auth_username()      { $a = auth_read(); return $a['user']['username'] ?? ''; }
// Which second factors are enabled. A user is "configured" once at least one is.
function auth_methods() {
    $a = auth_read();
    return [
        'totp'    => !empty($a['user']['totpEnabled']),
        'passkey' => !empty($a['user']['passkeys']),
    ];
}
function auth_is_configured() {
    $m = auth_methods();
    return auth_user_exists() && ($m['totp'] || $m['passkey']);
}

// ── Password ──────────────────────────────────────────────────────────────────
function auth_hash_password($pw) {
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    return password_hash($pw, $algo);
}
function auth_verify_password($pw) {
    $a = auth_read();
    $hash = $a['user']['passwordHash'] ?? '';
    if ($hash === '') return false;
    return password_verify($pw, $hash);
}

// ── Base32 (RFC 4648, no padding) — for TOTP secrets ──────────────────────────
function auth_base32_encode($bin) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $out = ''; $bits = 0; $val = 0;
    for ($i = 0, $n = strlen($bin); $i < $n; $i++) {
        $val = ($val << 8) | ord($bin[$i]); $bits += 8;
        while ($bits >= 5) { $bits -= 5; $out .= $alphabet[($val >> $bits) & 0x1f]; }
    }
    if ($bits > 0) $out .= $alphabet[($val << (5 - $bits)) & 0x1f];
    return $out;
}
function auth_base32_decode($b32) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
    $bits = 0; $val = 0; $out = '';
    for ($i = 0, $n = strlen($b32); $i < $n; $i++) {
        $val = ($val << 5) | strpos($alphabet, $b32[$i]); $bits += 5;
        if ($bits >= 8) { $bits -= 8; $out .= chr(($val >> $bits) & 0xff); }
    }
    return $out;
}

// ── TOTP (RFC 6238 — SHA1, 6 digits, 30 s step) ───────────────────────────────
function auth_totp_new_secret() { return auth_base32_encode(random_bytes(20)); }
function auth_totp_code($secretB32, $ts = null) {
    $key = auth_base32_decode($secretB32);
    $counter = intdiv($ts ?? time(), 30);
    $bin = pack('N', 0) . pack('N', $counter); // 8-byte big-endian counter
    $hash = hash_hmac('sha1', $bin, $key, true);
    $offset = ord($hash[19]) & 0x0f;
    $part = ((ord($hash[$offset]) & 0x7f) << 24)
          | ((ord($hash[$offset + 1]) & 0xff) << 16)
          | ((ord($hash[$offset + 2]) & 0xff) << 8)
          |  (ord($hash[$offset + 3]) & 0xff);
    return str_pad((string)($part % 1000000), 6, '0', STR_PAD_LEFT);
}
function auth_totp_verify($secretB32, $code, $window = 1) {
    $code = preg_replace('/\D/', '', (string)$code);
    if (strlen($code) !== 6) return false;
    $ts = time();
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(auth_totp_code($secretB32, $ts + $i * 30), $code)) return true;
    }
    return false;
}
function auth_totp_uri($secretB32, $account, $issuer = 'Aliaser') {
    return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account)
         . '?secret=' . $secretB32
         . '&issuer=' . rawurlencode($issuer)
         . '&algorithm=SHA1&digits=6&period=30';
}

// ── Backup codes (one-time TOTP recovery) ─────────────────────────────────────
function auth_generate_backup_codes($n = 8) {
    $codes = [];
    for ($i = 0; $i < $n; $i++) {
        $raw = strtoupper(bin2hex(random_bytes(4))); // 8 hex chars
        $codes[] = substr($raw, 0, 4) . '-' . substr($raw, 4, 4);
    }
    return $codes;
}
function auth_hash_backup_code($code) {
    return hash('sha256', strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $code)));
}
// Consumes a matching backup code (single use). Returns true if consumed.
function auth_consume_backup_code($code) {
    $a = auth_read();
    $h = auth_hash_backup_code($code);
    $codes = $a['user']['backupCodes'] ?? [];
    $idx = array_search($h, $codes, true);
    if ($idx === false) return false;
    array_splice($codes, $idx, 1);
    $a['user']['backupCodes'] = array_values($codes);
    auth_write($a);
    return true;
}

// ── Second factor (centralised — passkey can be added here later) ─────────────
function auth_verify_second_factor($code) {
    $a = auth_read();
    $secret = $a['user']['totpSecret'] ?? '';
    if ($secret === '') return false;
    if (auth_totp_verify($secret, $code)) return true;
    // Fall back to a one-time backup code.
    return auth_consume_backup_code($code);
}

// ── Device tokens (extensions) ────────────────────────────────────────────────
function auth_verify_device_token($token) {
    if (!is_string($token) || $token === '') return false;
    $env = getenv('ALIASER_AUTH_TOKEN');
    if ($env !== false && $env !== '' && hash_equals($env, $token)) return true;
    $a = auth_read();
    $h = hash('sha256', $token);
    foreach ($a['deviceTokens'] as $d) {
        if (isset($d['hash']) && hash_equals($d['hash'], $h)) return true;
    }
    return false;
}
function auth_add_device_token($label) {
    $token = bin2hex(random_bytes(32));
    $a = auth_read();
    $a['deviceTokens'][] = [
        'id'      => bin2hex(random_bytes(8)),
        'label'   => mb_substr((string)$label, 0, 60),
        'hash'    => hash('sha256', $token),
        'created' => time(),
    ];
    auth_write($a);
    return $token; // shown once, never recoverable
}
function auth_list_device_tokens() {
    $a = auth_read();
    return array_map(fn($d) => ['id' => $d['id'] ?? '', 'label' => $d['label'] ?? '', 'created' => $d['created'] ?? 0], $a['deviceTokens']);
}
function auth_revoke_device_token($id) {
    $a = auth_read();
    $a['deviceTokens'] = array_values(array_filter($a['deviceTokens'], fn($d) => ($d['id'] ?? '') !== $id));
    return auth_write($a) !== false;
}

// ── WebAuthn / passkeys (pure PHP, ES256 only) ────────────────────────────────
// Implements the standard registration/assertion verification steps. Limited to
// ES256 (P-256), which every modern platform authenticator and security key
// supports. Requires HTTPS and a real domain (rpId cannot be a bare IP).
function b64url_encode($bin) { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }
function b64url_decode($s) {
    $s = strtr($s, '-_', '+/');
    $pad = strlen($s) % 4;
    if ($pad) $s .= str_repeat('=', 4 - $pad);
    return base64_decode($s);
}

// rpId = the host the browser is talking to (no port). origin = scheme://host[:port].
function webauthn_rp_id() {
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return preg_replace('/:\d+$/', '', $host);
}
function webauthn_origin() {
    $scheme = aliaser_is_https() ? 'https' : 'http';
    return $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
}

// Minimal CBOR decoder — enough for attestationObject and COSE keys.
// Returns [value, nextOffset].
function cbor_decode($d, $off = 0) {
    $ib = ord($d[$off]); $off++;
    $major = $ib >> 5; $ai = $ib & 0x1f;
    $readLen = function($ai) use ($d, &$off) {
        if ($ai < 24) return $ai;
        if ($ai === 24) { $v = ord($d[$off]); $off += 1; return $v; }
        if ($ai === 25) { $v = unpack('n', substr($d, $off, 2))[1]; $off += 2; return $v; }
        if ($ai === 26) { $v = unpack('N', substr($d, $off, 4))[1]; $off += 4; return $v; }
        if ($ai === 27) { $v = unpack('J', substr($d, $off, 8))[1]; $off += 8; return $v; }
        throw new Exception('CBOR len');
    };
    switch ($major) {
        case 0: return [$readLen($ai), $off];                       // uint
        case 1: return [-1 - $readLen($ai), $off];                  // negative int
        case 2: $n = $readLen($ai); $v = substr($d, $off, $n); $off += $n; return [$v, $off]; // bytes
        case 3: $n = $readLen($ai); $v = substr($d, $off, $n); $off += $n; return [$v, $off]; // text
        case 4: $n = $readLen($ai); $arr = [];                      // array
                for ($i = 0; $i < $n; $i++) { [$val, $off] = cbor_decode($d, $off); $arr[] = $val; }
                return [$arr, $off];
        case 5: $n = $readLen($ai); $map = [];                      // map
                for ($i = 0; $i < $n; $i++) { [$k, $off] = cbor_decode($d, $off); [$val, $off] = cbor_decode($d, $off); $map[$k] = $val; }
                return [$map, $off];
        case 7: if ($ai === 20) return [false, $off]; if ($ai === 21) return [true, $off]; if ($ai === 22) return [null, $off]; return [null, $off];
    }
    throw new Exception('CBOR major ' . $major);
}

// Build a PEM SubjectPublicKeyInfo from a COSE EC2 P-256 key (kty=2, crv=1).
function cose_ec2_to_pem($cose) {
    if (($cose[1] ?? null) != 2)  return null;   // kty must be EC2
    if (($cose[3] ?? null) != -7) return null;   // alg must be ES256
    if (($cose[-1] ?? null) != 1) return null;   // crv must be P-256
    $x = $cose[-2] ?? ''; $y = $cose[-3] ?? '';
    if (strlen($x) !== 32 || strlen($y) !== 32) return null;
    // Fixed DER prefix for an uncompressed P-256 SubjectPublicKeyInfo + 0x04||x||y.
    $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y;
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

// Passkey storage
function auth_list_passkeys() {
    $a = auth_read();
    return array_map(fn($p) => ['id' => $p['id'] ?? '', 'label' => $p['label'] ?? '', 'created' => $p['created'] ?? 0],
        $a['user']['passkeys'] ?? []);
}
function auth_get_passkey($credIdB64) {
    $a = auth_read();
    foreach ($a['user']['passkeys'] ?? [] as $p) {
        if (hash_equals($p['id'] ?? '', $credIdB64)) return $p;
    }
    return null;
}
function auth_remove_passkey($credIdB64) {
    $a = auth_read();
    if (empty($a['user'])) return false;
    $before = count($a['user']['passkeys'] ?? []);
    $a['user']['passkeys'] = array_values(array_filter($a['user']['passkeys'] ?? [],
        fn($p) => ($p['id'] ?? '') !== $credIdB64));
    // Never let the account end up with zero factors.
    if (empty($a['user']['passkeys']) && empty($a['user']['totpEnabled'])) return 'last';
    auth_write($a);
    return count($a['user']['passkeys']) < $before;
}

// Registration: returns options for navigator.credentials.create (challenge in session).
function webauthn_register_options() {
    $challenge = random_bytes(32);
    $_SESSION['webauthn_chal'] = b64url_encode($challenge);
    $a = auth_read();
    $exclude = array_map(fn($p) => ['type' => 'public-key', 'id' => $p['id']], $a['user']['passkeys'] ?? []);
    return [
        'challenge' => b64url_encode($challenge),
        'rp'   => ['id' => webauthn_rp_id(), 'name' => 'Aliaser'],
        'user' => ['id' => b64url_encode(auth_username() ?: 'admin'), 'name' => auth_username() ?: 'admin', 'displayName' => auth_username() ?: 'admin'],
        'pubKeyCredParams'       => [['type' => 'public-key', 'alg' => -7]],
        'timeout'                => 60000,
        'attestation'            => 'none',
        'excludeCredentials'     => $exclude,
        'authenticatorSelection' => ['userVerification' => 'preferred', 'residentKey' => 'preferred'],
    ];
}

// Registration verify: $resp = decoded JSON from the browser. Returns true on success.
function webauthn_register_verify($resp, $label) {
    $clientDataJson = b64url_decode($resp['response']['clientDataJSON'] ?? '');
    $cd = json_decode($clientDataJson, true);
    if (!is_array($cd)) return 'Bad clientData';
    if (($cd['type'] ?? '') !== 'webauthn.create') return 'Bad type';
    if (!hash_equals($_SESSION['webauthn_chal'] ?? '', $cd['challenge'] ?? '')) return 'Challenge mismatch';
    if (($cd['origin'] ?? '') !== webauthn_origin()) return 'Origin mismatch';

    $att = b64url_decode($resp['response']['attestationObject'] ?? '');
    try { [$attObj] = cbor_decode($att, 0); } catch (Exception $e) { return 'Bad attestation'; }
    $authData = $attObj['authData'] ?? '';
    if (strlen($authData) < 37) return 'Bad authData';
    $rpIdHash = substr($authData, 0, 32);
    if (!hash_equals(hash('sha256', webauthn_rp_id(), true), $rpIdHash)) return 'rpId mismatch';
    $flags = ord($authData[32]);
    if (!($flags & 0x01)) return 'User not present';
    if (!($flags & 0x40)) return 'No attested credential';
    $credIdLen = unpack('n', substr($authData, 53, 2))[1];
    $credId = substr($authData, 55, $credIdLen);
    [$cose] = cbor_decode($authData, 55 + $credIdLen);
    $pem = cose_ec2_to_pem($cose);
    if (!$pem) return 'Unsupported key (need ES256/P-256)';
    $signCount = unpack('N', substr($authData, 33, 4))[1];

    $a = auth_read();
    if (empty($a['user'])) return 'No user';
    if (!isset($a['user']['passkeys'])) $a['user']['passkeys'] = [];
    $a['user']['passkeys'][] = [
        'id'        => b64url_encode($credId),
        'publicKey' => $pem,
        'signCount' => $signCount,
        'label'     => mb_substr((string)$label, 0, 60) ?: 'Passkey',
        'created'   => time(),
    ];
    auth_write($a);
    unset($_SESSION['webauthn_chal']);
    return true;
}

// Assertion (login): options for navigator.credentials.get.
function webauthn_assertion_options() {
    $challenge = random_bytes(32);
    $_SESSION['webauthn_chal'] = b64url_encode($challenge);
    $a = auth_read();
    $allow = array_map(fn($p) => ['type' => 'public-key', 'id' => $p['id']], $a['user']['passkeys'] ?? []);
    return [
        'challenge'        => b64url_encode($challenge),
        'rpId'             => webauthn_rp_id(),
        'timeout'          => 60000,
        'userVerification' => 'preferred',
        'allowCredentials' => $allow,
    ];
}

// Assertion verify. Returns true on success.
function webauthn_assertion_verify($resp) {
    $credId = $resp['id'] ?? '';
    $pk = auth_get_passkey($credId);
    if (!$pk) return 'Unknown credential';

    $clientDataJson = b64url_decode($resp['response']['clientDataJSON'] ?? '');
    $cd = json_decode($clientDataJson, true);
    if (!is_array($cd)) return 'Bad clientData';
    if (($cd['type'] ?? '') !== 'webauthn.get') return 'Bad type';
    if (!hash_equals($_SESSION['webauthn_chal'] ?? '', $cd['challenge'] ?? '')) return 'Challenge mismatch';
    if (($cd['origin'] ?? '') !== webauthn_origin()) return 'Origin mismatch';

    $authData = b64url_decode($resp['response']['authenticatorData'] ?? '');
    if (strlen($authData) < 37) return 'Bad authData';
    if (!hash_equals(hash('sha256', webauthn_rp_id(), true), substr($authData, 0, 32))) return 'rpId mismatch';
    if (!(ord($authData[32]) & 0x01)) return 'User not present';

    $sig = b64url_decode($resp['response']['signature'] ?? '');
    $signedData = $authData . hash('sha256', $clientDataJson, true);
    $ok = openssl_verify($signedData, $sig, $pk['publicKey'], OPENSSL_ALGO_SHA256);
    if ($ok !== 1) return 'Bad signature';

    // Clone/replay defence: sign counter must move forward (unless device reports 0).
    $newCount = unpack('N', substr($authData, 33, 4))[1];
    if ($newCount !== 0 || ($pk['signCount'] ?? 0) !== 0) {
        if ($newCount <= ($pk['signCount'] ?? 0)) return 'Sign-count replay';
    }
    $a = auth_read();
    foreach ($a['user']['passkeys'] as &$p) {
        if (hash_equals($p['id'], $credId)) { $p['signCount'] = $newCount; break; }
    }
    unset($p);
    auth_write($a);
    unset($_SESSION['webauthn_chal']);
    return true;
}

// ── Rate limiting / lockout (per client IP) ───────────────────────────────────
// Use REMOTE_ADDR only — never the client-supplied X-Forwarded-For, which an
// attacker can rotate to bypass the lockout entirely. Behind a reverse proxy
// this is the proxy's IP (lockout is then effectively global, which is fine for
// a single-admin app). For public exposure, add fail2ban/WAF at the proxy too.
function auth_throttle_key() {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}
function auth_throttle_read() {
    if (!file_exists(THROTTLE_FILE)) return [];
    $d = json_decode(file_get_contents(THROTTLE_FILE), true);
    return is_array($d) ? $d : [];
}
function auth_throttle_write($d) {
    $r = file_put_contents(THROTTLE_FILE, json_encode($d));
    if ($r !== false) @chmod(THROTTLE_FILE, 0600);
}
function auth_lock_remaining() {
    $t = auth_throttle_read();
    $e = $t[auth_throttle_key()] ?? null;
    return $e ? max(0, ($e['until'] ?? 0) - time()) : 0;
}
function auth_is_locked() { return auth_lock_remaining() > 0; }
function auth_record_fail() {
    $t = auth_throttle_read();
    $k = auth_throttle_key();
    $e = $t[$k] ?? ['fails' => 0, 'until' => 0];
    $e['fails'] = ($e['fails'] ?? 0) + 1;
    if ($e['fails'] >= AUTH_MAX_FAILS) { $e['until'] = time() + AUTH_LOCK_SECONDS; $e['fails'] = 0; }
    $t[$k] = $e;
    auth_throttle_write($t);
}
function auth_reset_fails() {
    $t = auth_throttle_read();
    unset($t[auth_throttle_key()]);
    auth_throttle_write($t);
}

// ── Sessions ──────────────────────────────────────────────────────────────────
function aliaser_is_https() {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}
function aliaser_session_start() {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    // SameSite=Lax (not Strict): lets the session survive a top-level navigation
    // from outside (bookmark / installed-PWA launch / external link) so the user
    // isn't bounced to login spuriously. CSRF is still fully covered — writes
    // require the X-CSRF-Token header, and Lax never sends the cookie on
    // cross-site POST/subresource requests.
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => aliaser_is_https(),
    ]);
    session_name('aliaser_sid');
    session_start();
}
function auth_establish_session($username) {
    aliaser_session_start();
    session_regenerate_id(true);
    $_SESSION['authed']  = true;
    $_SESSION['user']    = $username;
    $_SESSION['created'] = time();
    $_SESSION['last']    = time();
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
function auth_session_valid() {
    if (empty($_SESSION['authed'])) return false;
    $now = time();
    if ($now - ($_SESSION['last'] ?? 0) > AUTH_IDLE_SECONDS) return false;
    if ($now - ($_SESSION['created'] ?? 0) > AUTH_ABS_SECONDS) return false;
    $_SESSION['last'] = $now;
    return true;
}
function auth_logged_in() {
    aliaser_session_start();
    return auth_session_valid();
}
function auth_csrf_token() {
    aliaser_session_start();
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function auth_logout() {
    aliaser_session_start();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'] ?? '', $p['secure'], $p['httponly']);
    }
    session_destroy();
}

// ── Gate used by proxy.php ────────────────────────────────────────────────────
// Accepts a valid device token (extensions) OR a valid web session. Records the
// auth method in $GLOBALS['auth_via'] so CSRF is enforced only for sessions.
function aliaser_require_auth() {
    $dt = $_SERVER['HTTP_X_ALIASER_AUTH'] ?? '';
    if (auth_verify_device_token($dt)) { $GLOBALS['auth_via'] = 'token'; return; }
    aliaser_session_start();
    if (auth_session_valid()) { $GLOBALS['auth_via'] = 'session'; return; }
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Authentication required', 'login' => 'login.php']);
    exit;
}
// CSRF check for state-changing requests authenticated by a session cookie.
// Device-token (extension) requests carry no ambient credential → exempt.
function aliaser_require_csrf() {
    if (($GLOBALS['auth_via'] ?? '') !== 'session') return;
    $t = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($t) || $t === '' || !hash_equals($_SESSION['csrf'] ?? '', $t)) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid or missing CSRF token']);
        exit;
    }
}
