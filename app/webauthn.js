'use strict';
// Passkey (WebAuthn) assertion for the login page. Loaded only on the 2FA step
// when a passkey is enrolled. Talks to login.php's JSON sub-API.
(function () {
  function b64urlToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4; if (pad) s += '='.repeat(4 - pad);
    const bin = atob(s); const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf); let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function csrf() { return document.getElementById('form-csrf')?.value || ''; }

  async function post(action, body) {
    const r = await fetch('login.php?action=' + action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.assign({ csrf: csrf() }, body || {})),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    return d;
  }

  async function loginWithPasskey() {
    const err = document.getElementById('pk-error');
    const btn = document.getElementById('pk-login-btn');
    if (err) err.style.display = 'none';
    if (btn) btn.disabled = true;
    try {
      if (!window.PublicKeyCredential) throw new Error('Passkeys not supported in this browser');
      const opt = await post('passkey-login-options');
      opt.challenge = b64urlToBuf(opt.challenge);
      (opt.allowCredentials || []).forEach(c => { c.id = b64urlToBuf(c.id); });
      const cred = await navigator.credentials.get({ publicKey: opt });
      const resp = {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON:    bufToB64url(cred.response.clientDataJSON),
          authenticatorData: bufToB64url(cred.response.authenticatorData),
          signature:         bufToB64url(cred.response.signature),
          userHandle:        cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
        },
      };
      const out = await post('passkey-login-verify', { response: resp });
      window.location.href = out.redirect || './';
    } catch (e) {
      if (err) { err.textContent = 'Passkey failed: ' + (e.message || e); err.style.display = ''; }
      if (btn) btn.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('pk-login-btn');
    if (btn) btn.addEventListener('click', loginWithPasskey);
  });
})();
