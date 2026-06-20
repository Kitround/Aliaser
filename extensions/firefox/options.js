const input  = document.getElementById('proxy-url');
const tokenInput = document.getElementById('device-token');
const status = document.getElementById('save-status');

// Load saved values from browser.storage.local (Firefox MV3 compatible)
browser.storage.local.get(['aliaser_proxy_url', 'aliaser_device_token']).then(result => {
  input.value = result?.aliaser_proxy_url || '';
  tokenInput.value = result?.aliaser_device_token || '';
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
    Object.keys(setOps).length ? browser.storage.local.set(setOps) : Promise.resolve(),
    removeKeys.length ? browser.storage.local.remove(removeKeys) : Promise.resolve(),
  ]).then(() => {
    status.classList.add('visible');
    setTimeout(() => status.classList.remove('visible'), 2000);
  });
});
