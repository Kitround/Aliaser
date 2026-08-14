window.ALIASER_POPUP_MODE = true; // prevent app.js from running its own init

function _applyUrl(val) {
  window.ALIASER_PROXY_URL = val + '/proxy.php';
  window.ALIASER_BASE_URL  = val;
}

// Config lives in chrome.storage.local, not localStorage: extension
// localStorage can be cleared by "Clear browsing data", which silently drops the
// server URL and the device token. Values written by older builds are migrated
// on first run, then removed.
// Resolves once the URL is known AND (if setup is needed) the user has saved it.
window.ALIASER_CONFIG_READY = new Promise(resolve => {

  const domReady = new Promise(res => {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', res, { once: true });
    } else {
      res();
    }
  });

  const legacyUrl   = localStorage.getItem('aliaser_proxy_url');
  const legacyToken = localStorage.getItem('aliaser_device_token');

  chrome.storage.local.get(['aliaser_proxy_url', 'aliaser_device_token']).then(result => {
    let saved = result?.aliaser_proxy_url || '';
    let token = result?.aliaser_device_token || '';

    // One-time migration from the pre-chrome.storage builds.
    if ((!saved && legacyUrl) || (!token && legacyToken)) {
      saved = saved || legacyUrl || '';
      token = token || legacyToken || '';
      const move = {};
      if (saved) move.aliaser_proxy_url = saved;
      if (token) move.aliaser_device_token = token;
      chrome.storage.local.set(move).then(() => {
        localStorage.removeItem('aliaser_proxy_url');
        localStorage.removeItem('aliaser_device_token');
      });
    }

    window.ALIASER_DEVICE_TOKEN = token;

    if (saved) {
      _applyUrl(saved);
      window.ALIASER_SETUP_MODE = false;
      resolve(); // URL already known — proceed immediately
    } else {
      window.ALIASER_SETUP_MODE = true;
      _applyUrl('http://localhost:8080');

      domReady.then(() => {
        const overlay = document.getElementById('setup-overlay');
        const input   = document.getElementById('setup-url');
        const btn     = document.getElementById('setup-save');
        if (overlay) overlay.classList.add('visible');

        const doSave = () => {
          let val = (input?.value || '').trim().replace(/\/$/, '');
          // Do NOT force http -> https; respect whatever the user typed
          if (val && !/^https?:\/\//i.test(val)) val = 'http://' + val;
          val = val || 'http://localhost:8080';
          chrome.storage.local.set({ aliaser_proxy_url: val }).then(() => {
            _applyUrl(val);
            window.ALIASER_SETUP_MODE = false;
            if (overlay) overlay.classList.remove('visible');
            resolve(); // URL now known — let popup.js init
          });
        };

        btn?.addEventListener('click', doSave);
        input?.addEventListener('keydown', e => { if (e.key === 'Enter') doSave(); });
      });
    }
  });
});

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-dashboard')?.addEventListener('click', () => {
    chrome.tabs.create({ url: window.ALIASER_BASE_URL });
  });
});
