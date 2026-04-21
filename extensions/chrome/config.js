window.ALIASER_POPUP_MODE = true; // prevent app.js from running its own init

const _savedUrl = localStorage.getItem('aliaser_proxy_url');

if (!_savedUrl) {
  window.ALIASER_PROXY_URL  = 'http://localhost:8080/proxy.php';
  window.ALIASER_BASE_URL   = 'http://localhost:8080';
  window.ALIASER_SETUP_MODE = true;

  document.addEventListener('DOMContentLoaded', () => {
    const overlay = document.getElementById('setup-overlay');
    const input   = document.getElementById('setup-url');
    const btn     = document.getElementById('setup-save');
    if (overlay) overlay.classList.add('visible');

    const doSave = () => {
      let val = (input?.value || '').trim().replace(/\/$/, '');
      if (val && !/^https?:\/\//i.test(val)) val = 'http://' + val;
      val = val || 'http://localhost:8080';
      localStorage.setItem('aliaser_proxy_url', val);
      window.ALIASER_PROXY_URL  = val + '/proxy.php';
      window.ALIASER_BASE_URL   = val;
      window.ALIASER_SETUP_MODE = false;
      if (overlay) overlay.classList.remove('visible');
      if (typeof window.ALIASER_INIT === 'function') window.ALIASER_INIT();
    };

    btn?.addEventListener('click', doSave);
    input?.addEventListener('keydown', e => { if (e.key === 'Enter') doSave(); });
  });
} else {
  window.ALIASER_PROXY_URL  = _savedUrl + '/proxy.php';
  window.ALIASER_BASE_URL   = _savedUrl;
  window.ALIASER_SETUP_MODE = false;
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-dashboard')?.addEventListener('click', () => {
    chrome.tabs.create({url: window.ALIASER_BASE_URL});
  });
});
