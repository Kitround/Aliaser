const input = document.getElementById('proxy-url');
const tokenInput = document.getElementById('device-token');
const status = document.getElementById('save-status');

// Load saved values
input.value = localStorage.getItem('aliaser_proxy_url') || '';
tokenInput.value = localStorage.getItem('aliaser_device_token') || '';

document.getElementById('btn-save').addEventListener('click', () => {
  let val = input.value.trim().replace(/\/$/, '');
  if (val && !/^https?:\/\//i.test(val)) val = 'http://' + val;
  if (val) localStorage.setItem('aliaser_proxy_url', val);
  else localStorage.removeItem('aliaser_proxy_url');

  const token = tokenInput.value.trim();
  if (token) localStorage.setItem('aliaser_device_token', token);
  else localStorage.removeItem('aliaser_device_token');

  status.classList.add('visible');
  setTimeout(() => status.classList.remove('visible'), 2000);
});
