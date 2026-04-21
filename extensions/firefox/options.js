const input  = document.getElementById('proxy-url');
const status = document.getElementById('save-status');

// Load saved value from browser.storage.local (Firefox MV3 compatible)
browser.storage.local.get('aliaser_proxy_url').then(result => {
  input.value = result?.aliaser_proxy_url || '';
});

document.getElementById('btn-save').addEventListener('click', () => {
  let val = input.value.trim().replace(/\/$/, '');
  if (val && !/^https?:\/\//i.test(val)) val = 'http://' + val; // no forced upgrade — user chooses http or https
  const op = val
    ? browser.storage.local.set({ aliaser_proxy_url: val })
    : browser.storage.local.remove('aliaser_proxy_url');
  op.then(() => {
    status.classList.add('visible');
    setTimeout(() => status.classList.remove('visible'), 2000);
  });
});
