'use strict';

// ── Popup state ────────────────────────────────────────────────────────────────
const ps = {
  accounts:          [],
  aliases:           [],
  filtered:          [],
  notes:             {},
  zimbraPlatformIds: {},   // { accountId: platformId }
  zimbraAccountIds:  {},   // { accountId: zimbraAccountId } — in-memory only
  disabledAliases:   [],
  slOptions:         {},   // { accountId: {suffixes, prefixSuggestion, mailboxId} }
  selectedSuffix:    {},   // { accountId: {suffix, signed_suffix} }
  searchQuery:       '',
  selectedAccountId: null,
  currentTabHost:    '',
};

// Read dynamically so it picks up the URL set by config.js after first-time setup
function getProxy() { return window.ALIASER_PROXY_URL || './proxy.php'; }

// ── Helpers ───────────────────────────────────────────────────────────────────
function genId() { return Date.now().toString(36) + Math.random().toString(36).slice(2); }
function esc(s)  { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

let _toastTimer = null;
function showToast(text, duration = 1600) {
  const t = document.getElementById('copy-toast-global');
  document.getElementById('copy-toast-text').textContent = text;
  t.classList.remove('anchored');
  t.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), duration);
}

function showError(msg) {
  document.getElementById('error-text').textContent = msg;
  document.getElementById('error-banner').classList.add('visible');
  setTimeout(() => document.getElementById('error-banner').classList.remove('visible'), 5000);
}

function accForAlias(alias) {
  return ps.accounts.find(a => a.id === alias.accountId) || {};
}

const _RAND_ADJ = [
  'amber','arctic','azure','bold','brave','bright','calm','cedar','clear','cool',
  'crisp','dawn','deep','dry','dusk','fast','firm','fleet','fresh','frost',
  'gentle','golden','grand','green','hard','hardy','high','hollow','jade','keen',
  'lean','light','lofty','lone','loud','low','mild','misty','noble','north',
];
const _RAND_NOUN = [
  'ash','bark','bay','birch','blaze','bloom','bog','branch','brook','canyon',
  'cave','cliff','cloud','coast','coral','creek','dale','delta','dew','dune',
  'fern','field','fjord','flame','fog','forest','gale','glen','grove','gulf',
  'hail','heath','hill','hollow','ice','island','ivy','jungle','lake','leaf',
];
function generateAliasName() {
  const adj  = _RAND_ADJ[Math.floor(Math.random() * _RAND_ADJ.length)];
  const noun = _RAND_NOUN[Math.floor(Math.random() * _RAND_NOUN.length)];
  const num  = Math.floor(Math.random() * 900) + 100;
  return adj + noun + num;
}

// ── Proxy call ────────────────────────────────────────────────────────────────
async function pc(provider, method, path, body = null, extra = {}, retries = 2) {
  const payload = { provider, method, path, ...extra };
  if (body !== null && body !== undefined) payload.body = body;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res  = await fetch(getProxy(), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const text = await res.text();
      let data; try { data = JSON.parse(text); } catch { data = text || null; }
      if (!res.ok) throw new Error(data?.message || data?.error || 'HTTP ' + res.status);
      return data;
    } catch (e) {
      const isNet = e instanceof TypeError || e.message === 'Failed to fetch' || e.message.includes('NetworkError');
      if (isNet && attempt < retries) { await new Promise(r => setTimeout(r, 500 * (attempt + 1))); continue; }
      throw e;
    }
  }
}

// ── Load / save state ─────────────────────────────────────────────────────────
// Uses plain fetch (no Cache-Control headers) to avoid CORS preflight from the extension.
async function loadPopupState() {
  const base = getProxy().replace(/\/proxy\.php(\?.*)?$/, '');
  const [sd, nd, cd] = await Promise.all([
    fetch(base + '/proxy.php?action=state').then(r => r.json()),
    fetch(base + '/proxy.php?action=notes').then(r => r.json()),
    fetch(base + '/proxy.php?action=credentials').then(r => r.json()).catch(() => ({})),
  ]);

  ps.accounts          = sd.accounts || [];
  ps.notes             = (nd && !Array.isArray(nd)) ? nd : {};
  ps.zimbraPlatformIds = sd.zimbraPlatformIds || {};
  ps.disabledAliases   = sd.disabledAliases || [];

  // Apply consumerKeys
  (sd.consumerKeys || []).forEach(({ id, key }) => {
    const acc = ps.accounts.find(a => a.id === id);
    if (acc) acc.consumerKey = key;
  });

  // Merge per-account credentials
  const perAccount = cd?.perAccount || {};
  ps.accounts.forEach(acc => {
    const c = perAccount[acc.id] || {};
    if (c.token      && !acc.token)      acc.token      = c.token;
    if (c.ovhAppKey  && !acc.ovhAppKey)  acc.ovhAppKey  = c.ovhAppKey;
    if (c.ovhAppSecret && !acc.ovhAppSecret) acc.ovhAppSecret = c.ovhAppSecret;
  });

  // Migrate legacy global credentials
  const g = cd || {};
  ps.accounts.forEach(acc => {
    if (acc.provider === 'ovh') {
      if (!acc.ovhAppKey    && g.ovhAppKey)    acc.ovhAppKey    = g.ovhAppKey;
      if (!acc.ovhAppSecret && g.ovhAppSecret) acc.ovhAppSecret = g.ovhAppSecret;
    } else if (acc.provider === 'infomaniak'  && !acc.token && g.infomaniakToken)  acc.token = g.infomaniakToken;
    else if (acc.provider === 'simplelogin'   && !acc.token && g.simpleloginToken) acc.token = g.simpleloginToken;
    else if (acc.provider === 'addy'          && !acc.token && g.addyToken)        acc.token = g.addyToken;
    else if (acc.provider === 'cloudflare'    && !acc.token && g.cloudflareToken)  acc.token = g.cloudflareToken;
  });
}

async function saveNotes() {
  const base = getProxy().replace(/\/proxy\.php(\?.*)?$/, '');
  try {
    await fetch(base + '/proxy.php?action=notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ps.notes),
    });
  } catch (e) { console.error('Failed to save notes:', e); }
}

async function saveServerState() {
  const apiProviders = new Set(['simplelogin', 'addy', 'cloudflare']);
  const liveDisabled = ps.aliases
    .filter(a => a.disabled && !a.pending && !apiProviders.has(a.provider))
    .map(({ pending: _, ...rest }) => rest);
  const notYetLoaded = ps.disabledAliases.filter(d =>
    !ps.aliases.some(a => a.aliasAddress === d.aliasAddress && a.accountId === d.accountId)
  );
  const allDisabled = [...liveDisabled, ...notYetLoaded];
  ps.disabledAliases = allDisabled;

  const payload = {
    accounts:          ps.accounts.map(({ consumerKey: _ck, token: _t, ovhAppKey: _k, ovhAppSecret: _s, ...rest }) => rest),
    consumerKeys:      ps.accounts.filter(a => a.consumerKey).map(a => ({ id: a.id, key: a.consumerKey })),
    zimbraPlatformIds: ps.zimbraPlatformIds || {},
    zimbraPlatformId:  '',
    disabledAliases:   allDisabled,
  };
  try {
    await fetch(getProxy() + '?action=state', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  } catch (e) { console.error('Failed to save state:', e); }
}

// ── OVH ───────────────────────────────────────────────────────────────────────
async function ovhCall(acc, method, path, body = null) {
  const useV2 = !path.startsWith('/auth/');
  const consumerKey = acc?.consumerKey || '';
  try {
    return await pc('ovh', method, path, body, { consumerKey, useV2, appKey: acc?.ovhAppKey || '', appSecret: acc?.ovhAppSecret || '' });
  } catch (e) {
    if (e.message && (e.message.includes('NOT_GRANTED') || e.message.includes('INVALID_CREDENTIAL') || e.message.includes('not been granted'))) {
      if (acc) { acc.consumerKey = ''; await saveServerState(); }
      throw new Error('OVH session expired — please re-authenticate in Settings.');
    }
    throw e;
  }
}

async function getZimbraPlatform(acc) {
  if (ps.zimbraPlatformIds[acc.id]) return ps.zimbraPlatformIds[acc.id];
  const raw = await ovhCall(acc, 'GET', '/zimbra/platform');
  const p   = Array.isArray(raw) ? raw : (raw?.items || []);
  if (!p[0]?.id) throw new Error('No Zimbra platform found');
  ps.zimbraPlatformIds[acc.id] = p[0].id;
  await saveServerState();
  return ps.zimbraPlatformIds[acc.id];
}

async function ovhGetZimbraAccountId(acc, pid) {
  if (ps.zimbraAccountIds[acc.id]) return ps.zimbraAccountIds[acc.id];
  const fa = acc.account.includes('@') ? acc.account : acc.account + '@' + acc.domain;
  const raw = await ovhCall(acc, 'GET', '/zimbra/platform/' + pid + '/account');
  const accounts = Array.isArray(raw) ? raw : (raw?.items || []);
  const ao = accounts.find(a => a.currentState?.email === fa);
  if (!ao?.id) throw new Error('Zimbra account not found for: ' + fa);
  ps.zimbraAccountIds[acc.id] = ao.id;
  return ao.id;
}

async function getAnyWorkingZimbraPlatform() {
  const cached = Object.values(ps.zimbraPlatformIds);
  if (cached.length) return cached[0];
  const firstOvh = ps.accounts.find(a => a.provider === 'ovh' && a.consumerKey);
  if (!firstOvh) throw new Error('No authenticated OVH account');
  return getZimbraPlatform(firstOvh);
}

async function ovhFetchForAccount(acc) {
  let pid;
  try { pid = await getZimbraPlatform(acc); }
  catch { try { pid = await getAnyWorkingZimbraPlatform(); } catch (e) { throw new Error('Cannot reach Zimbra platform for ' + acc.label + ': ' + e.message); } }
  const zid = await ovhGetZimbraAccountId(acc, pid);
  const fa  = acc.account.includes('@') ? acc.account : acc.account + '@' + acc.domain;
  const raw = await ovhCall(acc, 'GET', '/zimbra/platform/' + pid + '/alias');
  const data = Array.isArray(raw) ? raw : (raw?.items || []);
  return data
    .map(o => {
      const id = o.id, ae = o.currentState?.alias?.name;
      if (!id || !ae) return null;
      return { id, aliasAddress: ae, targetAddress: fa, provider: 'ovh', accountId: acc.id, accountLabel: acc.label,
        _targetId: o.currentState?.alias?.targetAccountId || o.targetAccountId || '' };
    })
    .filter(Boolean)
    .filter(a => a._targetId ? a._targetId === zid : a.aliasAddress.endsWith('@' + acc.domain))
    .map(({ _targetId: _, ...rest }) => rest);
}

async function ovhCreateAlias(acc, aliasName) {
  let pid;
  try { pid = await getZimbraPlatform(acc); } catch { pid = await getAnyWorkingZimbraPlatform(); }
  const zid = await ovhGetZimbraAccountId(acc, pid);
  const fa  = acc.account.includes('@') ? acc.account : acc.account + '@' + acc.domain;
  const fl  = aliasName.includes('@') ? aliasName : aliasName + '@' + acc.domain;
  const resp = await ovhCall(acc, 'POST', '/zimbra/platform/' + pid + '/alias', { targetSpec: { alias: fl, targetId: zid } });
  return { id: resp?.id || genId(), aliasAddress: fl, targetAddress: fa, provider: 'ovh', accountId: acc.id, accountLabel: acc.label };
}

async function ovhDeleteAlias(alias, acc) {
  const pid = await getZimbraPlatform(acc);
  await ovhCall(acc, 'DELETE', '/zimbra/platform/' + pid + '/alias/' + alias.id);
}

// ── Infomaniak ────────────────────────────────────────────────────────────────
async function ikCall(acc, method, path, body = null) {
  return pc('infomaniak', method, path, body, { token: acc?.token || '' });
}

async function ikFetchForAccount(acc) {
  const mailbox = acc.account.includes('@') ? acc.account.split('@')[0] : acc.account;
  const domain  = acc.account.includes('@') ? acc.account.split('@')[1] : acc.domain;
  const fa      = mailbox + '@' + domain;
  const data    = await ikCall(acc, 'GET', '/1/mail_hostings/' + acc.hostingId + '/mailboxes/' + mailbox + '/aliases');
  const list    = data?.data?.aliases;
  if (!Array.isArray(list)) throw new Error('Unexpected Infomaniak response');
  return list.map(alias => {
    if (!alias) return null;
    const aliasAddress = alias.includes('@') ? alias : alias + '@' + domain;
    return { id: alias, aliasAddress, targetAddress: fa, provider: 'infomaniak', accountId: acc.id, accountLabel: acc.label };
  }).filter(Boolean);
}

async function ikCreateAlias(acc, aliasName) {
  const mailbox = acc.account.includes('@') ? acc.account.split('@')[0] : acc.account;
  const domain  = acc.account.includes('@') ? acc.account.split('@')[1] : acc.domain;
  const fa      = mailbox + '@' + domain;
  const fl      = aliasName.includes('@') ? aliasName : aliasName + '@' + domain;
  const alias   = fl.split('@')[0];
  await ikCall(acc, 'POST', '/1/mail_hostings/' + acc.hostingId + '/mailboxes/' + mailbox + '/aliases', { alias });
  return { id: alias, aliasAddress: fl, targetAddress: fa, provider: 'infomaniak', accountId: acc.id, accountLabel: acc.label };
}

async function ikDeleteAlias(alias, acc) {
  const mailbox    = acc.account.includes('@') ? acc.account.split('@')[0] : acc.account;
  const aliasName  = alias.id.includes('@') ? alias.id.split('@')[0] : alias.id;
  await ikCall(acc, 'DELETE', '/1/mail_hostings/' + acc.hostingId + '/mailboxes/' + mailbox + '/aliases/' + aliasName);
}

// ── SimpleLogin ───────────────────────────────────────────────────────────────
async function slCall(acc, method, path, body = null) {
  return pc('simplelogin', method, path, body, { token: acc?.token || '' });
}

async function slFetchForAccount(acc) {
  const aliases = [];
  let page = 0;
  while (true) {
    const data  = await slCall(acc, 'GET', '/api/v2/aliases?page_id=' + page);
    const items = data?.aliases || [];
    items.forEach(a => {
      aliases.push({
        id:             String(a.id),
        aliasAddress:   a.email,
        targetAddress:  acc.email || acc.label,
        provider:       'simplelogin',
        accountId:      acc.id,
        accountLabel:   acc.label,
        disabled:       !a.enabled,
        slNbForward:    a.nb_forward || 0,
        slNbReply:      a.nb_reply   || 0,
        slNbBlock:      a.nb_block   || 0,
        slLatestActivity: a.latest_activity || null,
      });
      if (a.note && a.note.trim()) ps.notes[a.email] = a.note.trim();
    });
    if (items.length < 20) break;
    page++;
  }
  return aliases;
}

async function slGetOptions(acc) {
  if (ps.slOptions[acc.id]?.mailboxId) return ps.slOptions[acc.id];
  const [optData, mbData] = await Promise.all([
    slCall(acc, 'GET', '/api/v5/alias/options'),
    acc.mailboxId ? Promise.resolve(null) : slCall(acc, 'GET', '/api/mailboxes'),
  ]);
  const suffixes         = optData?.suffixes || [];
  const prefixSuggestion = optData?.prefix_suggestion || '';
  let mailboxId          = acc.mailboxId || 0;
  if (!mailboxId) {
    const def = (mbData?.mailboxes || []).find(m => m.default) || mbData?.mailboxes?.[0];
    if (def) mailboxId = def.id;
  }
  ps.slOptions[acc.id] = { suffixes, prefixSuggestion, mailboxId };
  return ps.slOptions[acc.id];
}

async function slCreateAlias(acc, prefix = '', note = '') {
  // Always fetch fresh options to avoid expired signed_suffix tokens
  delete ps.slOptions[acc.id];
  const opts = await slGetOptions(acc);
  // Match by plain suffix (stable)
  const plainSuffix = ps.selectedSuffix[acc.id]?.suffix || null;
  let chosen;
  if (plainSuffix) {
    chosen = opts.suffixes.find(s => s.suffix === plainSuffix) || opts.suffixes[0];
  } else {
    chosen = opts.suffixes[0];
  }
  if (!chosen) throw new Error('No SimpleLogin suffix available');
  const mailboxId = acc.mailboxId || opts.mailboxId || 0;
  const body = {
    alias_prefix:  prefix || generateAliasName(),
    signed_suffix: chosen.signed_suffix || chosen['signed-suffix'],
    mailbox_ids:   [mailboxId],
  };
  if (note) body.note = note;
  const data = await slCall(acc, 'POST', '/api/v3/alias/custom/new', body);
  if (!data?.email) throw new Error(data?.error || data?.message || JSON.stringify(data) || 'SimpleLogin alias creation failed');
  return {
    id:           String(data.id),
    aliasAddress: data.email,
    targetAddress: acc.email || acc.label,
    provider:     'simplelogin',
    accountId:    acc.id,
    accountLabel: acc.label,
  };
}

async function slDeleteAlias(alias) {
  await slCall(accForAlias(alias), 'DELETE', '/api/aliases/' + alias.id);
}

async function slToggleAlias(alias) {
  const data = await slCall(accForAlias(alias), 'POST', '/api/aliases/' + alias.id + '/toggle');
  return data?.enabled ?? false;
}

async function slFetchContacts(alias) {
  const contacts = [];
  let page = 0;
  while (true) {
    const data  = await slCall(accForAlias(alias), 'GET', '/api/aliases/' + alias.id + '/contacts?page_id=' + page);
    const items = data?.contacts || [];
    contacts.push(...items);
    if (items.length < 20) break;
    page++;
  }
  return contacts;
}

async function slCreateContact(alias, email) {
  const data = await slCall(accForAlias(alias), 'POST', '/api/aliases/' + alias.id + '/contacts', { contact: email });
  if (!data?.id && !data?.existed) throw new Error(data?.error || 'Failed to create contact');
  return data;
}

// ── Addy ──────────────────────────────────────────────────────────────────────
async function addyCall(acc, method, path, body = null) {
  return pc('addy', method, path, body, { token: acc?.token || '' });
}

async function addyFetchForAccount(acc) {
  // Refresh subscription tier
  try {
    const details = await addyCall(acc, 'GET', '/api/v1/account-details');
    const info    = details?.data?.id ? details.data : (details?.data?.[0] ?? null);
    if (info) {
      const sub    = info.subscription;
      const endsAt = info.subscription_ends_at;
      const isFree = !sub || sub === 'free' || (endsAt && new Date(endsAt) < new Date());
      if (acc.isFree !== !!isFree) { acc.isFree = !!isFree; saveServerState(); }
    }
  } catch (_) {}
  const aliases = [];
  let page = 1;
  while (true) {
    const data  = await addyCall(acc, 'GET', '/api/v1/aliases?page[size]=100&page[number]=' + page);
    const items = data?.data || [];
    items.forEach(a => {
      if (acc.domain && a.domain !== acc.domain) return;
      const target = a.recipients?.[0]?.email || acc.email || acc.label;
      aliases.push({
        id:            a.id,
        aliasAddress:  a.email,
        targetAddress: target,
        provider:      'addy',
        accountId:     acc.id,
        accountLabel:  acc.label,
        disabled:      !a.active,
        addyNbForward: a.emails_forwarded || 0,
        addyNbReply:   a.emails_replied   || 0,
        addyNbBlock:   a.emails_blocked   || 0,
      });
      if (a.description && a.description.trim()) ps.notes[a.email] = a.description.trim();
    });
    const lastPage = data?.meta?.last_page || 1;
    if (page >= lastPage) break;
    page++;
  }
  return aliases;
}

async function addyCreateAlias(acc, aliasName = '', note = '') {
  const body = { domain: acc.domain || 'anonaddy.me' };
  if (aliasName) body.local_part = aliasName;
  if (note) body.description = note;
  const data = await addyCall(acc, 'POST', '/api/v1/aliases', body);
  if (!data?.data?.email) throw new Error(data?.message || 'Addy alias creation failed');
  const a      = data.data;
  const target = a.recipients?.[0]?.email || acc.email || acc.label;
  return { id: a.id, aliasAddress: a.email, targetAddress: target, provider: 'addy', accountId: acc.id, accountLabel: acc.label };
}

async function addyDeleteAlias(alias) {
  await addyCall(accForAlias(alias), 'DELETE', '/api/v1/aliases/' + alias.id);
}

async function addyToggleAlias(alias, enable) {
  const acc = accForAlias(alias);
  if (enable) { await addyCall(acc, 'POST',   '/api/v1/active-aliases',            { id: alias.id }); }
  else        { await addyCall(acc, 'DELETE', '/api/v1/active-aliases/' + alias.id); }
}

// ── Cloudflare ────────────────────────────────────────────────────────────────
async function cfCall(acc, method, path, body = null) {
  const data = await pc('cloudflare', method, path, body, { token: acc?.token || '' });
  if (data && typeof data === 'object' && data.success === false) {
    throw new Error(data.errors?.[0]?.message || 'Cloudflare API error');
  }
  return data;
}

async function cfFetchForAccount(acc) {
  const data  = await cfCall(acc, 'GET', '/zones/' + acc.zoneId + '/email/routing/rules?per_page=50');
  const rules = data?.result || [];
  return rules
    .filter(r => r.matchers?.some(m => m.type === 'literal' && m.field === 'to'))
    .map(r => {
      const matcher       = r.matchers.find(m => m.type === 'literal' && m.field === 'to');
      const action        = r.actions?.find(a => a.type === 'forward');
      const targetAddress = action?.value?.[0] || acc.targetAddress || acc.label;
      return { id: r.tag, aliasAddress: matcher.value, targetAddress, provider: 'cloudflare', accountId: acc.id, accountLabel: acc.label, disabled: !r.enabled, cfPriority: r.priority || 10 };
    });
}

async function cfCreateAlias(acc, aliasName) {
  const localPart    = aliasName.includes('@') ? aliasName.split('@')[0] : aliasName;
  const aliasAddress = localPart + '@' + acc.domain;
  const body = {
    name:     localPart,
    enabled:  true,
    matchers: [{ type: 'literal', field: 'to', value: aliasAddress }],
    actions:  [{ type: 'forward', value: [acc.targetAddress] }],
    priority: 10,
  };
  const data = await cfCall(acc, 'POST', '/zones/' + acc.zoneId + '/email/routing/rules', body);
  const rule = data?.result;
  return { id: rule?.tag || genId(), aliasAddress, targetAddress: acc.targetAddress, provider: 'cloudflare', accountId: acc.id, accountLabel: acc.label, cfPriority: 10 };
}

async function cfDeleteAlias(alias, acc) {
  await cfCall(acc, 'DELETE', '/zones/' + acc.zoneId + '/email/routing/rules/' + alias.id);
}

async function cfToggleAlias(alias, enable) {
  const acc = accForAlias(alias);
  if (!acc.id) throw new Error('Account not found');
  const body = {
    name:     alias.aliasAddress.split('@')[0],
    enabled:  enable,
    matchers: [{ type: 'literal', field: 'to', value: alias.aliasAddress }],
    actions:  [{ type: 'forward', value: [alias.targetAddress] }],
    priority: alias.cfPriority || 10,
  };
  await cfCall(acc, 'PUT', '/zones/' + acc.zoneId + '/email/routing/rules/' + alias.id, body);
}

// ── Fetch all aliases ─────────────────────────────────────────────────────────
async function fetchAll() {
  setListHtml('<div class="p-state"><div class="p-spinner"></div></div>');
  const results = await Promise.all(ps.accounts.map(acc => {
    switch (acc.provider) {
      case 'ovh':         return ovhFetchForAccount(acc).catch(e  => { showError('OVH (' + acc.label + '): ' + e.message); return []; });
      case 'infomaniak':  return ikFetchForAccount(acc).catch(e   => { showError('IK (' + acc.label + '): ' + e.message);  return []; });
      case 'simplelogin': return slFetchForAccount(acc).catch(e   => { showError('SL (' + acc.label + '): ' + e.message);  return []; });
      case 'addy':        return addyFetchForAccount(acc).catch(e => { showError('Addy (' + acc.label + '): ' + e.message); return []; });
      case 'cloudflare':  return cfFetchForAccount(acc).catch(e   => { showError('CF (' + acc.label + '): ' + e.message);  return []; });
      default:            return [];
    }
  }));
  // Merge fetched aliases with disabled ones not yet returned by the API
  const live         = results.flat();
  const apiProviders = new Set(['simplelogin', 'addy', 'cloudflare']);
  const disabled     = ps.disabledAliases.filter(d =>
    !apiProviders.has(d.provider) &&
    ps.accounts.some(a => a.id === d.accountId) &&
    !live.some(l => l.aliasAddress === d.aliasAddress && l.accountId === d.accountId)
  );
  ps.aliases = [...live, ...disabled.map(d => ({ ...d, disabled: true }))];
  applyFilter();
  renderList();
  updateCount();
}

// ── Create alias ──────────────────────────────────────────────────────────────
async function createAlias(name, note = '') {
  const acc = ps.accounts.find(a => a.id === ps.selectedAccountId);
  if (!acc) throw new Error('No account selected');
  switch (acc.provider) {
    case 'ovh':         return (await ovhCreateAlias(acc, name)).aliasAddress;
    case 'infomaniak':  return (await ikCreateAlias(acc, name)).aliasAddress;
    case 'simplelogin': return (await slCreateAlias(acc, name, note)).aliasAddress;
    case 'addy':        return (await addyCreateAlias(acc, acc.isFree ? '' : name, note)).aliasAddress;
    case 'cloudflare':  return (await cfCreateAlias(acc, name)).aliasAddress;
    default: throw new Error('Unsupported provider');
  }
}

// ── Delete alias ──────────────────────────────────────────────────────────────
async function deleteAlias(alias) {
  const acc = ps.accounts.find(a => a.id === alias.accountId);
  switch (alias.provider) {
    case 'ovh':         await ovhDeleteAlias(alias, acc);  break;
    case 'infomaniak':  await ikDeleteAlias(alias, acc);   break;
    case 'simplelogin': await slDeleteAlias(alias);        break;
    case 'addy':        await addyDeleteAlias(alias);      break;
    case 'cloudflare':  await cfDeleteAlias(alias, acc);   break;
  }
  ps.aliases = ps.aliases.filter(a => a.id !== alias.id);
  delete ps.notes[alias.aliasAddress];
  applyFilter();
  renderList();
  updateCount();
}

// ── Toggle alias (all providers) ──────────────────────────────────────────────
async function toggleAlias(alias) {
  const acc      = ps.accounts.find(a => a.id === alias.accountId);
  const enabling = !!alias.disabled; // true = we're re-enabling

  // Optimistic update
  alias.disabled = !enabling;
  applyFilter(); renderList();

  try {
    if (enabling) {
      switch (alias.provider) {
        case 'simplelogin': await slToggleAlias(alias);           break;
        case 'addy':        await addyToggleAlias(alias, true);   break;
        case 'cloudflare':  await cfToggleAlias(alias, true);     break;
        case 'ovh':
        case 'infomaniak': {
          const name     = alias.aliasAddress.includes('@') ? alias.aliasAddress.split('@')[0] : alias.aliasAddress;
          const newAlias = alias.provider === 'infomaniak'
            ? await ikCreateAlias(acc, name)
            : await ovhCreateAlias(acc, name);
          const i = ps.aliases.findIndex(a => a.aliasAddress === alias.aliasAddress && a.accountId === alias.accountId);
          if (i !== -1) ps.aliases[i] = { ...newAlias, disabled: false };
          ps.disabledAliases = ps.disabledAliases.filter(d =>
            !(d.aliasAddress === alias.aliasAddress && d.accountId === alias.accountId)
          );
          await saveServerState();
          break;
        }
      }
    } else {
      switch (alias.provider) {
        case 'simplelogin': await slToggleAlias(alias);           break;
        case 'addy':        await addyToggleAlias(alias, false);  break;
        case 'cloudflare':  await cfToggleAlias(alias, false);    break;
        case 'ovh':
        case 'infomaniak': {
          if (alias.provider === 'infomaniak') await ikDeleteAlias(alias, acc);
          else                                  await ovhDeleteAlias(alias, acc);
          const { id: _, pending: __, ...rest } = alias;
          if (!ps.disabledAliases.some(d => d.aliasAddress === rest.aliasAddress && d.accountId === rest.accountId))
            ps.disabledAliases.push({ ...rest, disabled: true });
          await saveServerState();
          break;
        }
      }
    }
  } catch (e) {
    alias.disabled = enabling; // revert
    applyFilter(); renderList();
    throw e;
  }

  applyFilter(); renderList();
}

// ── Contacts panel ─────────────────────────────────────────────────────────────
let _contactsAlias = null;

async function openContacts(alias) {
  _contactsAlias = alias;
  document.getElementById('contacts-alias-label').textContent = alias.aliasAddress;
  document.getElementById('contacts-new-email').value = '';
  document.getElementById('contacts-add-btn').disabled = false;
  document.getElementById('contacts-list').innerHTML = '<div class="contacts-state"><div class="p-spinner"></div></div>';
  document.getElementById('contacts-panel').classList.add('open');
  try {
    const contacts = await slFetchContacts(alias);
    renderContacts(contacts);
  } catch (e) {
    document.getElementById('contacts-list').innerHTML = `<div class="contacts-state">Error: ${esc(e.message)}</div>`;
  }
}

function closeContacts() {
  _contactsAlias = null;
  document.getElementById('contacts-panel').classList.remove('open');
}

function renderContacts(contacts) {
  const el = document.getElementById('contacts-list');
  if (!contacts.length) {
    el.innerHTML = '<div class="contacts-state">No contacts yet.<br>Add one to get a reverse alias.</div>';
    return;
  }
  el.innerHTML = contacts.map(c => {
    const raw     = c.reverse_alias || '';
    const match   = raw.match(/<([^>]+)>/);
    const reverse = match ? match[1] : raw;
    const email   = c.contact;
    const blocked = !!c.block_forward;
    const cid     = String(c.id);
    return `<div class="contact-item${blocked ? ' is-blocked' : ''}" data-contact-id="${esc(cid)}">
      <div class="contact-info">
        <div class="contact-email">${esc(email)}</div>
        <div class="contact-reverse">${esc(reverse)}</div>
      </div>
      <div class="contact-actions">
        <button class="contact-btn block-btn${blocked ? ' is-blocked-btn' : ''}" data-contact-id="${esc(cid)}" title="${blocked ? 'Unblock' : 'Block'}">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
          </svg>
        </button>
        <button class="contact-btn copy-btn" data-reverse="${esc(reverse)}" title="Copy reverse alias">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <rect x="9" y="9" width="13" height="13" rx="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
      </div>
    </div>`;
  }).join('');
}

document.getElementById('contacts-close').addEventListener('click', closeContacts);

document.getElementById('contacts-list').addEventListener('click', async e => {
  const blockBtn = e.target.closest('.block-btn');
  if (blockBtn) {
    blockBtn.disabled = true;
    try {
      const acc     = ps.accounts.find(a => a.id === _contactsAlias?.accountId);
      const data    = await slCall(acc, 'POST', '/api/contacts/' + blockBtn.dataset.contactId + '/toggle');
      const blocked = !!(data?.block_forward);
      blockBtn.closest('.contact-item')?.classList.toggle('is-blocked', blocked);
      blockBtn.classList.toggle('is-blocked-btn', blocked);
      blockBtn.title = blocked ? 'Unblock' : 'Block';
    } catch (e) { showError('Failed: ' + e.message); }
    blockBtn.disabled = false;
    return;
  }
  const copyBtn = e.target.closest('.copy-btn');
  if (copyBtn) {
    navigator.clipboard?.writeText(copyBtn.dataset.reverse).catch(() => {});
    showToast('Copied');
  }
});

document.getElementById('contacts-add-btn').addEventListener('click', async () => {
  const input = document.getElementById('contacts-new-email');
  const email = input.value.trim();
  if (!email || !email.includes('@')) { showError('Enter a valid email address'); return; }
  const btn = document.getElementById('contacts-add-btn');
  btn.disabled = true;
  try {
    await slCreateContact(_contactsAlias, email);
    input.value = '';
    renderContacts(await slFetchContacts(_contactsAlias));
  } catch (e) { showError('Failed: ' + e.message); }
  btn.disabled = false;
});

document.getElementById('contacts-new-email').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('contacts-add-btn').click();
});

// ── Filter ────────────────────────────────────────────────────────────────────
function applyFilter() {
  const q = ps.searchQuery.toLowerCase();
  ps.filtered = (q
    ? ps.aliases.filter(a =>
        a.aliasAddress.toLowerCase().includes(q) ||
        (a.targetAddress || '').toLowerCase().includes(q) ||
        (a.accountLabel || '').toLowerCase().includes(q) ||
        (ps.notes[a.aliasAddress] || '').toLowerCase().includes(q))
    : [...ps.aliases]
  ).sort((a, b) => a.aliasAddress.localeCompare(b.aliasAddress));
}

// ── Render ────────────────────────────────────────────────────────────────────
function setListHtml(html) {
  document.getElementById('p-list').innerHTML = html;
}

function renderList() {
  if (!ps.filtered.length) {
    setListHtml(`<div class="p-state">${ps.aliases.length === 0 ? 'No aliases yet' : 'No results'}</div>`);
    return;
  }
  document.getElementById('p-list').innerHTML = ps.filtered.map(a => {
    const at      = a.aliasAddress.indexOf('@');
    const local   = at >= 0 ? a.aliasAddress.slice(0, at) : a.aliasAddress;
    const domain  = at >= 0 ? a.aliasAddress.slice(at)    : '';
    const note    = ps.notes[a.aliasAddress] || '';
    const disabled = !!a.disabled;
    const isSl    = a.provider === 'simplelogin';

    const btnToggle = `
      <button class="p-btn${disabled ? '' : ' toggle-on'} toggle-btn" data-id="${esc(a.id)}" title="${disabled ? 'Enable' : 'Disable'}">
        <svg width="18" height="11" viewBox="0 0 30 18">
          ${disabled
            ? `<rect width="30" height="18" rx="9" fill="currentColor" opacity=".25"/><circle cx="9" cy="9" r="7" fill="currentColor" opacity=".5"/>`
            : `<rect width="30" height="18" rx="9" fill="currentColor" opacity=".35"/><circle cx="21" cy="9" r="7" fill="currentColor"/>`}
        </svg>
      </button>`;

    const btnContacts = isSl ? `
      <button class="p-btn contacts-btn" data-id="${esc(a.id)}" title="Contacts">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
          <circle cx="9" cy="7" r="4"/>
          <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
        </svg>
      </button>` : '';

    return `<div class="p-item${disabled ? ' is-disabled' : ''}" data-id="${esc(a.id)}">
      <div class="p-item-addr">
        <div class="p-item-local">${esc(local)}<span class="p-item-domain">${esc(domain)}</span></div>
        ${note ? `<div class="p-item-note">${esc(note)}</div>` : ''}
      </div>
      <div class="p-actions">
        <button class="p-btn copy-btn" data-id="${esc(a.id)}" title="Copy">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <rect x="9" y="9" width="13" height="13" rx="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
        ${btnContacts}
        ${btnToggle}
        <button class="p-btn danger delete-btn" data-id="${esc(a.id)}" title="Delete">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
            <path d="M10 11v6"/><path d="M14 11v6"/>
            <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
          </svg>
        </button>
      </div>
    </div>`;
  }).join('');
}

function updateCount() {
  const el = document.getElementById('popup-alias-count');
  if (!el) return;
  const n = ps.aliases.length;
  if (n > 0) { el.textContent = `${n} alias${n > 1 ? 'es' : ''}`; el.classList.add('visible'); }
  else el.classList.remove('visible');
}

// ── Account pills ─────────────────────────────────────────────────────────────
function renderPills() {
  const el = document.getElementById('p-pills');
  el.innerHTML = ps.accounts.map(acc =>
    `<button class="p-pill${acc.id === ps.selectedAccountId ? ' active' : ''}" data-id="${esc(acc.id)}">${esc(acc.label)}</button>`
  ).join('');
}

async function selectAccount(id) {
  ps.selectedAccountId = id;
  renderPills();
  const acc        = ps.accounts.find(a => a.id === id);
  const isAddyFree = acc?.provider === 'addy' && !!acc?.isFree;

  const nameWrap = document.getElementById('p-name-wrap');
  if (nameWrap) nameWrap.style.display = isAddyFree ? 'none' : '';

  if (acc?.provider === 'simplelogin') {
    await loadSlOptions(acc);
    populateSlSuffixSelect(acc);
    document.getElementById('p-suffix-field').style.display = '';
  } else {
    document.getElementById('p-suffix-field').style.display = 'none';
  }
  updatePreview();
}

async function loadSlOptions(acc) {
  const opts = await slGetOptions(acc);
  if (!ps.selectedSuffix[acc.id] && opts.suffixes.length)
    ps.selectedSuffix[acc.id] = opts.suffixes[0];
}

function populateSlSuffixSelect(acc) {
  const sel      = document.getElementById('p-suffix-select');
  const suffixes = ps.slOptions[acc.id]?.suffixes || [];
  if (!sel || !suffixes.length) return;
  const all    = acc.isPremium ? suffixes : suffixes.filter(s => !(s.is_custom || s.premium));
  const sorted = [...all].sort((a, b) => ((b.is_custom || b.premium) ? 1 : 0) - ((a.is_custom || a.premium) ? 1 : 0));
  const current  = ps.selectedSuffix[acc.id];
  sel.innerHTML  = sorted.map(s => {
    const label = (s.is_custom || s.premium) ? '★ ' + s.suffix : s.suffix;
    return `<option value="${esc(s.signed_suffix || s['signed-suffix'] || '')}">${esc(label)}</option>`;
  }).join('');
  const signed   = current?.signed_suffix || current?.['signed-suffix'] || sorted[0]?.signed_suffix || '';
  sel.value      = signed;
  // Sync selected state to dropdown
  const chosen   = sorted.find(s => (s.signed_suffix || s['signed-suffix']) === sel.value) || sorted[0];
  if (chosen) ps.selectedSuffix[acc.id] = chosen;
}

// ── Preview ───────────────────────────────────────────────────────────────────
function updatePreview() {
  const name = document.getElementById('p-name').value.trim();
  const acc  = ps.accounts.find(a => a.id === ps.selectedAccountId);
  const prev = document.getElementById('p-preview');
  const btn  = document.getElementById('p-create-btn');
  const _pt  = (t, ph) => {
    prev.innerHTML = `<span>${esc(t)}</span>`;
    prev.classList.toggle('p-preview-ph', !!ph);
  };

  if (!acc) { prev.innerHTML = ''; btn.disabled = true; return; }

  const isAddyFree = acc.provider === 'addy' && !!acc.isFree;
  if (isAddyFree) { _pt('Auto-generated', true); btn.disabled = false; return; }

  if (acc.provider === 'simplelogin') {
    const selEl  = document.getElementById('p-suffix-select');
    const suf    = selEl?.value
      ? (ps.slOptions[acc.id]?.suffixes || []).find(s => (s.signed_suffix || s['signed-suffix']) === selEl.value) || ps.selectedSuffix[acc.id]
      : ps.selectedSuffix[acc.id];
    const suffix = suf ? suf.suffix : (acc.domain ? '@' + acc.domain : '');
    _pt((name || 'alias') + suffix, !name);
    btn.disabled = !name;
  } else {
    const domain = acc.domain || (acc.account?.includes('@') ? acc.account.split('@')[1] : '');
    if (domain) {
      _pt(name ? `${name}@${domain}` : `alias@${domain}`, !name);
    } else {
      _pt('alias@domain.xxx', true);
    }
    btn.disabled = !name;
  }

  requestAnimationFrame(() => {
    const span = prev.querySelector('span');
    prev.classList.toggle('preview-overflow', !!span && span.scrollWidth > prev.clientWidth);
  });
}

// ── Auto-fill from current tab ────────────────────────────────────────────────
function fillFromTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    try {
      const url   = new URL(tabs[0]?.url || '');
      const host  = url.hostname.replace(/^www\./, '');
      ps.currentTabHost = host;
      const parts = host.split('.');
      const name  = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
      if (name) { document.getElementById('p-name').value = name; updatePreview(); }
    } catch (_) {}
  });
}

// ── Events ────────────────────────────────────────────────────────────────────
document.getElementById('p-name').addEventListener('input', updatePreview);

document.getElementById('p-rand-btn').addEventListener('click', () => {
  document.getElementById('p-name').value = generateAliasName();
  updatePreview();
  document.getElementById('p-name').focus();
});

document.getElementById('p-name').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !document.getElementById('p-create-btn').disabled)
    document.getElementById('p-create-btn').click();
});

document.getElementById('p-pills').addEventListener('click', e => {
  const pill = e.target.closest('.p-pill');
  if (pill) selectAccount(pill.dataset.id);
});

document.getElementById('p-suffix-select').addEventListener('change', function () {
  const acc = ps.accounts.find(a => a.id === ps.selectedAccountId);
  if (acc) {
    const found = (ps.slOptions[acc.id]?.suffixes || []).find(s => (s.signed_suffix || s['signed-suffix']) === this.value);
    if (found) { ps.selectedSuffix[acc.id] = found; updatePreview(); }
  }
});

const BTN_HTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Create &amp; copy alias`;

document.getElementById('p-create-btn').addEventListener('click', async () => {
  const acc        = ps.accounts.find(a => a.id === ps.selectedAccountId);
  const isAddyFree = acc?.provider === 'addy' && !!acc?.isFree;
  const name       = document.getElementById('p-name').value.trim();
  if (!name && !isAddyFree) return;
  const btn = document.getElementById('p-create-btn');
  btn.disabled = true;
  btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Creating…`;
  try {
    const noteText = ps.currentTabHost ? 'Used on ' + ps.currentTabHost : '';
    const addr = await createAlias(name, noteText);
    if (noteText) { ps.notes[addr] = noteText; saveNotes(); }
    showToast(addr, 3500);
    navigator.clipboard?.writeText(addr).catch(() => {});
    document.getElementById('p-name').value = '';
    document.getElementById('p-preview').textContent = '';
    btn.innerHTML = BTN_HTML;
    btn.disabled  = true;
    fetchAll();
  } catch (e) {
    showError('Failed: ' + e.message);
    btn.innerHTML = BTN_HTML;
    btn.disabled  = false;
  }
});

document.getElementById('p-search').addEventListener('input', e => {
  ps.searchQuery = e.target.value;
  applyFilter();
  renderList();
});

document.getElementById('p-list').addEventListener('click', e => {
  const id = e.target.closest('[data-id]')?.dataset.id;
  if (!id) return;

  if (e.target.closest('.copy-btn')) {
    const alias = ps.aliases.find(a => a.id === id);
    if (alias) { navigator.clipboard?.writeText(alias.aliasAddress).catch(() => {}); showToast('Copied'); }
    return;
  }
  if (e.target.closest('.contacts-btn')) {
    const alias = ps.aliases.find(a => a.id === id);
    if (alias) openContacts(alias);
    return;
  }
  if (e.target.closest('.toggle-btn')) {
    const alias = ps.aliases.find(a => a.id === id);
    if (alias) toggleAlias(alias).catch(err => showError('Toggle failed: ' + err.message));
    return;
  }
  if (e.target.closest('.delete-btn')) {
    const alias = ps.aliases.find(a => a.id === id);
    if (alias) deleteAlias(alias).catch(err => showError('Delete failed: ' + err.message));
    return;
  }
});

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  if (window.ALIASER_SETUP_MODE) return;

  setListHtml('<div class="p-state"><div class="p-spinner"></div></div>');
  try {
    await loadPopupState();

    if (!ps.accounts.length) {
      document.getElementById('p-create-section').style.display = 'none';
      setListHtml('<div class="p-state">No accounts configured.<br>Open the dashboard to add one.</div>');
      return;
    }

    const def = ps.accounts.find(a => a.isDefault) || ps.accounts[0];
    ps.selectedAccountId = def.id;
    renderPills();

    const isAddyFree = def.provider === 'addy' && !!def.isFree;
    const nameWrap   = document.getElementById('p-name-wrap');
    if (nameWrap) nameWrap.style.display = isAddyFree ? 'none' : '';

    if (def.provider === 'simplelogin') {
      await loadSlOptions(def);
      populateSlSuffixSelect(def);
      document.getElementById('p-suffix-field').style.display = '';
    }

    fillFromTab();
    fetchAll();
  } catch (e) {
    showError('Cannot connect to server');
    setListHtml('<div class="p-state">Could not connect to server.<br>Check the URL in Options.</div>');
  }
}

window.ALIASER_INIT = init;
init();
