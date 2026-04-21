const input = document.getElementById('proxy-url');
const status = document.getElementById('save-status');

// Load saved value
input.value = localStorage.getItem('aliaser_proxy_url') || '';

document.getElementById('btn-save').addEventListener('click', () => {
  let val = input.value.trim().replace(/\/$/, '');
  if (val && !/^https?:\/\//i.test(val)) val = 'http://' + val;
  if (val) {
    localStorage.setItem('aliaser_proxy_url', val);
  } else {
    localStorage.removeItem('aliaser_proxy_url');
  }
  status.classList.add('visible');
  setTimeout(() => status.classList.remove('visible'), 2000);
});
