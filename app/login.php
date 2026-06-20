<?php
/**
 * Aliaser — login / setup / 2FA / logout UI.
 * Self-contained page; uses the auth core in auth.php.
 *
 * Flow:
 *   - No account yet            → setup (create admin) → TOTP enrolment → app
 *   - Account, TOTP incomplete  → login (password) → resume TOTP enrolment
 *   - Account configured        → login (password) → 2FA (TOTP / backup code) → app
 */

require_once __DIR__ . '/auth.php';
aliaser_session_start();

// Already authenticated → straight to the app.
if (auth_session_valid()) { header('Location: ./'); exit; }

function form_csrf() {
    if (empty($_SESSION['form_csrf'])) $_SESSION['form_csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['form_csrf'];
}
function check_form_csrf() {
    $t = $_POST['csrf'] ?? '';
    return is_string($t) && $t !== '' && hash_equals($_SESSION['form_csrf'] ?? '', $t);
}
function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

// ── Passwordless passkey login — JSON sub-API ─────────────────────────────────
// A passkey (device possession + user verification) is a strong single step:
// no password needed. Available whenever at least one passkey is enrolled.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && in_array($_GET['action'] ?? '', ['passkey-login-options', 'passkey-login-verify'], true)) {
    header('Content-Type: application/json');
    if (!auth_methods()['passkey']) { http_response_code(400); echo json_encode(['error' => 'No passkey enrolled']); exit; }
    if (auth_is_locked()) { http_response_code(429); echo json_encode(['error' => 'Too many attempts']); exit; }
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    if (!hash_equals($_SESSION['form_csrf'] ?? '', $in['csrf'] ?? '')) { http_response_code(403); echo json_encode(['error' => 'CSRF']); exit; }
    if (($_GET['action']) === 'passkey-login-options') { echo json_encode(webauthn_assertion_options()); exit; }
    $res = webauthn_assertion_verify($in['response'] ?? []);
    if ($res === true) {
        auth_reset_fails();
        auth_establish_session(auth_username());
        echo json_encode(['ok' => true, 'redirect' => './']); exit;
    }
    auth_record_fail();
    http_response_code(400); echo json_encode(['error' => is_string($res) ? $res : 'Verification failed']); exit;
}

$error = '';
$stage = 'login';            // login | setup | enroll | twofa | backup
$backupCodes = [];

$hasUser = auth_user_exists();
$configured = auth_is_configured();

// Decide the initial stage from state + session.
if (!$hasUser)                              $stage = 'setup';
elseif (!empty($_SESSION['enroll']))        $stage = 'enroll';
elseif (!empty($_SESSION['pending_user']))  $stage = 'twofa';
else                                        $stage = 'login';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if (!check_form_csrf()) {
        $error = 'Session expired, please try again.';
    } elseif ($action === 'setup' && !$hasUser) {
        $username = trim($_POST['username'] ?? '');
        $pw  = (string)($_POST['password'] ?? '');
        $pw2 = (string)($_POST['password2'] ?? '');
        if (strlen($username) < 3)        $error = 'Username must be at least 3 characters.';
        elseif (strlen($pw) < 10)         $error = 'Password must be at least 10 characters.';
        elseif ($pw !== $pw2)             $error = 'Passwords do not match.';
        else {
            $secret = auth_totp_new_secret();
            auth_write([
                'user' => [
                    'username'     => $username,
                    'passwordHash' => auth_hash_password($pw),
                    'totpSecret'   => $secret,
                    'totpEnabled'  => false,
                    'backupCodes'  => [],
                ],
                'deviceTokens' => [],
            ]);
            $_SESSION['enroll'] = $username;
            $stage = 'enroll';
        }
        if ($error) $stage = 'setup';
    } elseif ($action === 'enroll' && !empty($_SESSION['enroll'])) {
        $a = auth_read();
        $secret = $a['user']['totpSecret'] ?? '';
        $code = $_POST['code'] ?? '';
        if ($secret && auth_totp_verify($secret, $code)) {
            $codes = auth_generate_backup_codes(8);
            $a['user']['totpEnabled'] = true;
            $a['user']['backupCodes'] = array_map('auth_hash_backup_code', $codes);
            auth_write($a);
            unset($_SESSION['enroll']);
            auth_establish_session($a['user']['username']);
            $backupCodes = $codes;          // shown once
            $stage = 'backup';
        } else {
            $error = 'Invalid code, try again.';
            $stage = 'enroll';
        }
    } elseif ($action === 'login' && $hasUser) {
        if (auth_is_locked()) {
            $error = 'Too many attempts. Try again in ' . ceil(auth_lock_remaining() / 60) . ' min.';
        } else {
            $username = trim($_POST['username'] ?? '');
            $pw = (string)($_POST['password'] ?? '');
            if ($username === auth_username() && auth_verify_password($pw)) {
                auth_reset_fails();
                if (!$configured) {                 // enrolment was interrupted
                    $_SESSION['enroll'] = $username;
                    $stage = 'enroll';
                } elseif (auth_methods()['totp']) {
                    $_SESSION['pending_user'] = $username;
                    $stage = 'twofa';
                } else {
                    // Only a passkey is configured — password path can't 2FA.
                    $error = 'This account signs in with a passkey — use the “Sign in with a passkey” button.';
                    $stage = 'login';
                }
            } else {
                auth_record_fail();
                $error = 'Invalid username or password.';
                $stage = 'login';
            }
        }
    } elseif ($action === 'twofa' && !empty($_SESSION['pending_user'])) {
        if (auth_is_locked()) {
            $error = 'Too many attempts. Try again in ' . ceil(auth_lock_remaining() / 60) . ' min.';
            $stage = 'twofa';
        } elseif (auth_verify_second_factor($_POST['code'] ?? '')) {
            auth_reset_fails();
            $user = $_SESSION['pending_user'];
            unset($_SESSION['pending_user']);
            auth_establish_session($user);
            header('Location: ./');
            exit;
        } else {
            auth_record_fail();
            $error = 'Invalid code.';
            $stage = 'twofa';
        }
    } elseif ($action === 'logout') {
        auth_logout();
        header('Location: login.php');
        exit;
    }
}

// Data needed for the enrolment view.
$enrollSecret = '';
$enrollUri = '';
if ($stage === 'enroll') {
    $a = auth_read();
    $enrollSecret = $a['user']['totpSecret'] ?? '';
    $enrollUri = auth_totp_uri($enrollSecret, $a['user']['username'] ?? 'admin');
}
$csrf = form_csrf();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aliaser — Sign in</title>
<link rel="icon" type="image/png" href="images/favicon.png">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f0f0f;color:#e0e0e0;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:20px}
  .card{background:#171717;border:1px solid #2a2a2a;border-radius:12px;padding:26px;width:100%;max-width:360px}
  .brand{font-family:ui-monospace,monospace;font-size:1.1rem;font-weight:600;margin-bottom:4px}
  .sub{font-size:.82rem;color:#808080;margin-bottom:18px;line-height:1.5}
  label{display:block;font-size:.7rem;font-family:ui-monospace,monospace;color:#515151;text-transform:uppercase;letter-spacing:.07em;margin:12px 0 5px}
  input{width:100%;background:#0f0f0f;border:1px solid #2a2a2a;border-radius:8px;padding:10px;font-family:ui-monospace,monospace;font-size:16px;color:#e0e0e0;outline:none}
  input:focus{border-color:#5b54e8}
  button{width:100%;margin-top:18px;background:#5b54e8;color:#fff;border:none;border-radius:8px;padding:11px;font-size:.9rem;font-weight:500;cursor:pointer}
  button:hover{background:#6b65f0}
  .err{background:rgba(224,80,80,.1);border:1px solid rgba(224,80,80,.25);color:#e08080;border-radius:8px;padding:9px 12px;font-size:.8rem;margin-bottom:14px}
  .secret{font-family:ui-monospace,monospace;font-size:.95rem;letter-spacing:2px;word-break:break-all;background:#0f0f0f;border:1px solid #2a2a2a;border-radius:8px;padding:10px;margin-top:6px;color:#5b54e8}
  .uri{font-size:.66rem;color:#515151;word-break:break-all;margin-top:8px}
  .codes{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:10px}
  .codes span{font-family:ui-monospace,monospace;font-size:.9rem;background:#0f0f0f;border:1px solid #2a2a2a;border-radius:6px;padding:8px;text-align:center}
  .warn{font-size:.76rem;color:#e09040;margin-top:12px;line-height:1.5}
  a.btnlink{display:block;text-align:center;margin-top:18px;background:#5b54e8;color:#fff;border-radius:8px;padding:11px;text-decoration:none;font-size:.9rem;font-weight:500}
</style>
</head>
<body>
<div class="card">
  <div class="brand">Aliaser</div>

  <?php if ($error): ?><div class="err"><?= h($error) ?></div><?php endif; ?>

  <?php if ($stage === 'setup'): ?>
    <div class="sub">First run — create your admin account. You'll set up two-factor authentication next.</div>
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
      <input type="hidden" name="action" value="setup">
      <label>Username</label>
      <input name="username" type="text" autocapitalize="none" autocomplete="username" required>
      <label>Password <span style="text-transform:none;opacity:.6">(min 10 chars)</span></label>
      <input name="password" type="password" autocomplete="new-password" required>
      <label>Confirm password</label>
      <input name="password2" type="password" autocomplete="new-password" required>
      <button type="submit">Create account</button>
    </form>

  <?php elseif ($stage === 'enroll'): ?>
    <div class="sub">Add this secret to your authenticator app (Google Authenticator, Aegis, 1Password…), then enter the 6-digit code to confirm.</div>
    <label>Secret key</label>
    <div class="secret"><?= h(trim(chunk_split($enrollSecret, 4, ' '))) ?></div>
    <div class="uri"><?= h($enrollUri) ?></div>
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
      <input type="hidden" name="action" value="enroll">
      <label>6-digit code</label>
      <input name="code" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" required>
      <button type="submit">Confirm &amp; enable 2FA</button>
    </form>

  <?php elseif ($stage === 'backup'): ?>
    <div class="sub">✅ Two-factor authentication is enabled. Save these one-time backup codes somewhere safe — each works once if you lose your authenticator.</div>
    <div class="codes">
      <?php foreach ($backupCodes as $c): ?><span><?= h($c) ?></span><?php endforeach; ?>
    </div>
    <div class="warn">⚠ They will not be shown again.</div>
    <a class="btnlink" href="./">Continue to Aliaser</a>

  <?php elseif ($stage === 'twofa'): ?>
    <div class="sub">Enter the 6-digit code from your authenticator app (or a backup code).</div>
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
      <input type="hidden" name="action" value="twofa">
      <label>Code</label>
      <input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" autofocus required>
      <button type="submit">Verify</button>
    </form>

  <?php else: $m = auth_methods(); ?>
    <input type="hidden" id="form-csrf" value="<?= h($csrf) ?>">
    <?php if ($m['passkey']): ?>
      <button type="button" id="pk-login-btn">Sign in with a passkey</button>
      <div class="err" id="pk-error" style="display:none"></div>
      <div class="sub" style="margin-top:18px">…or with your username and password.</div>
    <?php else: ?>
      <div class="sub">Sign in to manage your aliases.</div>
    <?php endif; ?>
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
      <input type="hidden" name="action" value="login">
      <label>Username</label>
      <input name="username" type="text" autocapitalize="none" autocomplete="username" required<?= $m['passkey'] ? '' : ' autofocus' ?>>
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
  <?php endif; ?>
</div>
<?php if ($stage !== 'twofa' && auth_methods()['passkey']): ?>
<script src="webauthn.js"></script>
<?php endif; ?>
</body>
</html>
