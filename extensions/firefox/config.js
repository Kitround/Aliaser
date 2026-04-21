window.ALIASER_POPUP_MODE = true; // prevent app.js from running its own init

function _applyUrl(val) {
  window.ALIASER_PROXY_URL = val + '/proxy.php';
  window.ALIASER_BASE_URL  = val;
}

// Resolves once the URL is known AND (if setup needed) the user has saved it.
window.ALIASER_CONFIG_READY = new Promise(resolve => {

  const domReady = new Promise(res => {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', res, { once: true });
    } else {
      res();
    }
  });

  browser.storage.local.get('aliaser_proxy_url').then(result => {
    const saved = result?.aliaser_proxy_url;

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
          browser.storage.local.set({ aliaser_proxy_url: val }).then(() => {
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
    browser.tabs.create({ url: window.ALIASER_BASE_URL });
  });
});
