const input = document.getElementById('proxy-url');
const tokenInput = document.getElementById('device-token');
const status = document.getElementById('save-status');

// chrome.storage.local, with a read-through to the localStorage keys older
// builds used so an upgrade doesn't look like a wiped configuration.
chrome.storage.local.get(['aliaser_proxy_url', 'aliaser_device_token']).then(result => {
  input.value      = result?.aliaser_proxy_url    || localStorage.getItem('aliaser_proxy_url')    || '';
  tokenInput.value = result?.aliaser_device_token || localStorage.getItem('aliaser_device_token') || '';
});

document.getElementById('btn-save').addEventListener('click', () => {
  let val = input.value.trim().replace(/\/$/, '');
  if (val && !/^https?:\/\//i.test(val)) val = 'http://' + val; // no forced upgrade — user chooses http or https
  const setOps = {};
  const removeKeys = [];
  if (val) setOps.aliaser_proxy_url = val; else removeKeys.push('aliaser_proxy_url');
  const token = tokenInput.value.trim();
  if (token) setOps.aliaser_device_token = token; else removeKeys.push('aliaser_device_token');
  Promise.all([
    Object.keys(setOps).length ? chrome.storage.local.set(setOps) : Promise.resolve(),
    removeKeys.length ? chrome.storage.local.remove(removeKeys) : Promise.resolve(),
  ]).then(() => {
    // Drop the legacy copies so the two stores can't disagree later.
    localStorage.removeItem('aliaser_proxy_url');
    localStorage.removeItem('aliaser_device_token');
    status.classList.add('visible');
    setTimeout(() => status.classList.remove('visible'), 2000);
  });
});
