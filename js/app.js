// ── State ─────────────────────────────────────────────────────────────────────
const state={
  accounts:[],
  aliases:[],
  filteredAliases:[],
  dataLoaded:false,
  isLoading:false,
  ovhZimbraPlatformIds:{},
  ovhZimbraAccountIds:{},
  slSuffixes:{},// { accountId: {suffixes:[], prefixSuggestion:'', mailboxId:0} }
  selectedSlSignedSuffix:null,
  selectedSlSuffix:null,
  lastSelectedAccountId:null,
  pendingDeleteAlias:null,
  searchQuery:'',
  notes:{},
  disabledAliases:[],
  credentials:{},
  addyContacts:{},// { aliasId: [{email, reverse}] }
};
const PROXY='./proxy.php';

// ── Server state ──────────────────────────────────────────────────────────────
async function loadServerState(){
  try{
    const res=await fetch(PROXY+'?action=state',{headers:{'Cache-Control':'no-cache','Pragma':'no-cache'}});
    const data=await res.json();
    state.accounts=data.accounts||[];
    state.ovhZimbraPlatformIds=data.zimbraPlatformIds||{};
    state.disabledAliases=data.disabledAliases||[];
    if(!Object.keys(state.ovhZimbraPlatformIds).length&&data.zimbraPlatformId){
      const firstOvh=state.accounts.find(a=>a.provider==='ovh');
      if(firstOvh)state.ovhZimbraPlatformIds[firstOvh.id]=data.zimbraPlatformId;
    }
    (data.consumerKeys||[]).forEach(({id,key})=>{
      const acc=state.accounts.find(a=>a.id===id);
      if(acc)acc.consumerKey=key;
    });
  }catch(e){
    console.error('Failed to load server state:',e);
    state.accounts=[];
  }
}

async function saveServerState(){
  // Only OVH/IK store disabled state — API-driven providers (SL, Addy, CF) do not
  const apiProviders=new Set(['simplelogin','addy','cloudflare']);
  const liveDisabled=state.aliases
    .filter(a=>a.disabled&&!a.pending&&!apiProviders.has(a.provider))
    .map(({pending:_,...rest})=>rest);
  const notYetLoaded=state.disabledAliases.filter(d=>
    !state.aliases.some(a=>a.aliasAddress===d.aliasAddress&&a.accountId===d.accountId)
  );
  const allDisabled=[...liveDisabled,...notYetLoaded];
  state.disabledAliases=allDisabled;
  const payload={
    accounts:state.accounts.map(({consumerKey:_ck,token:_t,ovhAppKey:_k,ovhAppSecret:_s,...rest})=>rest),
    consumerKeys:state.accounts.filter(a=>a.consumerKey).map(a=>({id:a.id,key:a.consumerKey})),
    zimbraPlatformIds:state.ovhZimbraPlatformIds||{},
    zimbraPlatformId:'',
    disabledAliases:allDisabled,
  };
  try{
    await fetch(PROXY+'?action=state',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  }catch(e){console.error('Failed to save server state:',e);}
}


// ── Notes persistence ─────────────────────────────────────────────────────────
async function loadNotes(){
  try{
    const res=await fetch(PROXY+'?action=notes',{headers:{'Cache-Control':'no-cache','Pragma':'no-cache'}});
    const data=await res.json();
    state.notes=(data&&!Array.isArray(data))?data:{};
  }catch(e){console.error('Failed to load notes:',e);state.notes={};}
}
async function saveNotes(notes){
  try{
    await fetch(PROXY+'?action=notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(notes||state.notes)});
  }catch(e){console.error('Failed to save notes:',e);}
}

// ── Addy contacts persistence ─────────────────────────────────────────────────
async function loadAddyContacts(){
  try{
    const res=await fetch(PROXY+'?action=addy-contacts',{headers:{'Cache-Control':'no-cache','Pragma':'no-cache'}});
    const data=await res.json();
    state.addyContacts=(data&&typeof data==='object'&&!Array.isArray(data))?data:{};
  }catch(e){console.error('Failed to load addy contacts:',e);state.addyContacts={};}
}
async function saveAddyContacts(){
  try{
    await fetch(PROXY+'?action=addy-contacts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(state.addyContacts)});
  }catch(e){console.error('Failed to save addy contacts:',e);}
}
function addyBuildReverseAddress(aliasEmail,recipientEmail){
  const at=aliasEmail.indexOf('@');
  const aliasLocal=aliasEmail.slice(0,at),aliasDomain=aliasEmail.slice(at+1);
  const rat=recipientEmail.indexOf('@');
  const recLocal=recipientEmail.slice(0,rat),recDomain=recipientEmail.slice(rat+1);
  return`${aliasLocal}+${recLocal}=${recDomain}@${aliasDomain}`;
}

// ── Credentials persistence ───────────────────────────────────────────────────
async function loadCredentials(){
  try{
    const res=await fetch(PROXY+'?action=credentials',{headers:{'Cache-Control':'no-cache','Pragma':'no-cache'}});
    const data=await res.json();
    state.credentials=(data&&typeof data==='object'&&!Array.isArray(data))?data:{};
  }catch(e){console.error('Failed to load credentials:',e);state.credentials={};}
}
async function saveCredentials(creds){
  await fetch(PROXY+'?action=credentials',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(creds)});
}

// Save per-account tokens to encrypted credentials.json (never in state.json)
async function saveAccountCredentials(){
  const perAccount={};
  state.accounts.forEach(a=>{
    const c={};
    if(a.token)c.token=a.token;
    if(a.ovhAppKey)c.ovhAppKey=a.ovhAppKey;
    if(a.ovhAppSecret)c.ovhAppSecret=a.ovhAppSecret;
    if(Object.keys(c).length)perAccount[a.id]=c;
  });
  await saveCredentials({perAccount});
}

// Merge per-account credentials loaded from credentials.json back into accounts in memory
function mergeCredentialsIntoAccounts(){
  const perAccount=(state.credentials&&state.credentials.perAccount)||{};
  state.accounts.forEach(a=>{
    const c=perAccount[a.id]||{};
    if(c.token&&!a.token)a.token=c.token;
    if(c.ovhAppKey&&!a.ovhAppKey)a.ovhAppKey=c.ovhAppKey;
    if(c.ovhAppSecret&&!a.ovhAppSecret)a.ovhAppSecret=c.ovhAppSecret;
  });
}

// Migrate legacy global credentials + any account tokens not yet in perAccount store
// Returns true if a save is needed
function migrateTokensIfNeeded(){
  const c=state.credentials||{};
  const perAccount=c.perAccount||{};
  let changed=false;
  state.accounts.forEach(a=>{
    // Migrate from legacy global credentials
    if(a.provider==='ovh'){
      if(!a.ovhAppKey&&c.ovhAppKey){a.ovhAppKey=c.ovhAppKey;changed=true;}
      if(!a.ovhAppSecret&&c.ovhAppSecret){a.ovhAppSecret=c.ovhAppSecret;changed=true;}
    }else if(a.provider==='infomaniak'){
      if(!a.token&&c.infomaniakToken){a.token=c.infomaniakToken;changed=true;}
    }else if(a.provider==='simplelogin'){
      if(!a.token&&c.simpleloginToken){a.token=c.simpleloginToken;changed=true;}
    }else if(a.provider==='addy'){
      if(!a.token&&c.addyToken){a.token=c.addyToken;changed=true;}
    }else if(a.provider==='cloudflare'){
      if(!a.token&&c.cloudflareToken){a.token=c.cloudflareToken;changed=true;}
    }
    // Detect accounts whose tokens are not yet stored in perAccount
    const existing=perAccount[a.id]||{};
    if((a.token&&!existing.token)||(a.ovhAppKey&&!existing.ovhAppKey)){
      changed=true;
    }
  });
  return changed;
}

// ── Proxy call with retry ─────────────────────────────────────────────────────
async function proxyCall(provider,method,path,body=null,extra={},retries=2){
  const payload={provider,method,path,...extra};
  if(body!==null&&body!==undefined)payload.body=body;
  for(let attempt=0;attempt<=retries;attempt++){
    try{
      const res=await fetch(PROXY,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      const text=await res.text();let data;try{data=JSON.parse(text)}catch{data=text||null}
      if(!res.ok)throw new Error(data?.message||data?.error||'HTTP '+res.status);
      return data;
    }catch(e){
      const isNetworkErr=e instanceof TypeError||e.message==='Failed to fetch'||e.message.includes('NetworkError');
      if(isNetworkErr&&attempt<retries){
        await new Promise(r=>setTimeout(r,500*(attempt+1)));
        continue;
      }
      throw e;
    }
  }
}

// ── OVH ───────────────────────────────────────────────────────────────────────
function getOvhConsumerKey(acc){return acc?.consumerKey||''}
function ovhIsAuthenticated(acc){return !!getOvhConsumerKey(acc)}

async function ovhCall(acc,method,path,body=null){
  const useV2=!path.startsWith('/auth/');
  const consumerKey=getOvhConsumerKey(acc);
  try{
    return await proxyCall('ovh',method,path,body,{consumerKey,useV2,appKey:acc?.ovhAppKey||'',appSecret:acc?.ovhAppSecret||''});
  }catch(e){
    if(e.message&&(e.message.includes('not been granted')||e.message.includes('NOT_GRANTED')||e.message.includes('INVALID_CREDENTIAL'))){
      if(acc){acc.consumerKey='';await saveServerState();}
      throw new Error('OVH session expired — please re-authenticate in Settings.');
    }
    throw e;
  }
}

async function authenticate(appKey,appSecret){
  const payload={provider:'ovh',method:'POST',path:'/auth/credential',consumerKey:'',useV2:false,
    appKey:appKey||'',appSecret:appSecret||'',
    body:{accessRules:[
      {method:'GET',path:'/zimbra/*'},
      {method:'POST',path:'/zimbra/*'},
      {method:'DELETE',path:'/zimbra/*'},
    ],redirection:'https://www.ovh.com'}};
  const res=await fetch(PROXY,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await res.json();
  if(!res.ok)throw new Error(data.message||data.error||'Auth failed');
  const validationUrl=data.validationUrl||data.validation_url||data.validationURL;
  const consumerKey=data.consumerKey||data.consumer_key;
  if(!validationUrl||!consumerKey)throw new Error('Invalid auth response: '+JSON.stringify(data));
  return{validationUrl,consumerKey};
}

async function getZimbraPlatform(acc){
  if(state.ovhZimbraPlatformIds[acc.id])return state.ovhZimbraPlatformIds[acc.id];
  const raw=await ovhCall(acc,'GET','/zimbra/platform');
  const p=Array.isArray(raw)?raw:(raw?.items||[]);
  if(!p[0]?.id)throw new Error('No Zimbra platform found');
  state.ovhZimbraPlatformIds[acc.id]=p[0].id;
  await saveServerState();
  return state.ovhZimbraPlatformIds[acc.id];
}

async function ovhGetZimbraAccountId(acc,pid){
  if(state.ovhZimbraAccountIds[acc.id])return state.ovhZimbraAccountIds[acc.id];
  const fa=acc.account.includes('@')?acc.account:acc.account+'@'+acc.domain;
  const rawAccounts=await ovhCall(acc,'GET','/zimbra/platform/'+pid+'/account');
  const accounts=Array.isArray(rawAccounts)?rawAccounts:(rawAccounts?.items||[]);
  const ao=accounts.find(a=>a.currentState?.email===fa);
  if(!ao?.id)throw new Error('Zimbra account not found for: '+fa);
  state.ovhZimbraAccountIds[acc.id]=ao.id;
  return ao.id;
}

async function getAnyWorkingZimbraPlatform(){
  const cached=Object.values(state.ovhZimbraPlatformIds);
  if(cached.length)return cached[0];
  const firstOvh=state.accounts.find(a=>a.provider==='ovh'&&ovhIsAuthenticated(a));
  if(!firstOvh)throw new Error('No authenticated OVH account');
  return getZimbraPlatform(firstOvh);
}

async function ovhFetchForAccount(acc){
  let pid;
  try{pid=await getZimbraPlatform(acc);}
  catch{
    try{pid=await getAnyWorkingZimbraPlatform();}
    catch(e){throw new Error('Cannot reach Zimbra platform for '+acc.label+': '+e.message);}
  }
  const zid=await ovhGetZimbraAccountId(acc,pid);
  const fa=acc.account.includes('@')?acc.account:acc.account+'@'+acc.domain;
  const raw=await ovhCall(acc,'GET','/zimbra/platform/'+pid+'/alias');
  const data=Array.isArray(raw)?raw:(raw?.items||[]);
  return data
    .map(o=>{
      const id=o.id,ae=o.currentState?.alias?.name;
      if(!id||!ae)return null;
      return{id,aliasAddress:ae,targetAddress:fa,provider:'ovh',accountId:acc.id,accountLabel:acc.label,
        _targetId:o.currentState?.alias?.targetAccountId||o.targetAccountId||''};
    })
    .filter(Boolean)
    .filter(a=>a._targetId?a._targetId===zid:a.aliasAddress.endsWith('@'+acc.domain))
    .map(({_targetId:_,...rest})=>rest);
}

async function ovhCreateAlias(acc,aliasName){
  let pid;
  try{pid=await getZimbraPlatform(acc);}
  catch{pid=await getAnyWorkingZimbraPlatform();}
  const zid=await ovhGetZimbraAccountId(acc,pid);
  const fa=acc.account.includes('@')?acc.account:acc.account+'@'+acc.domain;
  const fl=aliasName.includes('@')?aliasName:aliasName+'@'+acc.domain;
  const resp=await ovhCall(acc,'POST','/zimbra/platform/'+pid+'/alias',{targetSpec:{alias:fl,targetId:zid}});
  return{id:resp?.id||genId(),aliasAddress:fl,targetAddress:fa,provider:'ovh',accountId:acc.id,accountLabel:acc.label};
}

async function ovhDeleteAlias(alias,acc){
  const pid=await getZimbraPlatform(acc);
  await ovhCall(acc,'DELETE','/zimbra/platform/'+pid+'/alias/'+alias.id);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function accForAlias(alias){return state.accounts.find(a=>a.id===alias.accountId)||{};}

// ── Infomaniak ────────────────────────────────────────────────────────────────
async function ikCall(acc,method,path,body=null){
  return proxyCall('infomaniak',method,path,body,{token:acc?.token||''});
}
async function ikFetchForAccount(acc){
  const mailbox=acc.account.includes('@')?acc.account.split('@')[0]:acc.account;
  const domain=acc.account.includes('@')?acc.account.split('@')[1]:acc.domain;
  const fa=mailbox+'@'+domain;
  const data=await ikCall(acc,'GET','/1/mail_hostings/'+acc.hostingId+'/mailboxes/'+mailbox+'/aliases');
  const list=data?.data?.aliases;
  if(!Array.isArray(list))throw new Error('Unexpected Infomaniak response');
  return list.map(alias=>{
    if(!alias)return null;
    const aliasAddress=alias.includes('@')?alias:alias+'@'+domain;
    return{id:alias,aliasAddress,targetAddress:fa,provider:'infomaniak',accountId:acc.id,accountLabel:acc.label};
  }).filter(Boolean);
}
async function ikCreateAlias(acc,aliasName){
  const mailbox=acc.account.includes('@')?acc.account.split('@')[0]:acc.account;
  const domain=acc.account.includes('@')?acc.account.split('@')[1]:acc.domain;
  const fa=mailbox+'@'+domain;
  const fl=aliasName.includes('@')?aliasName:aliasName+'@'+domain;
  const alias=fl.split('@')[0];
  await ikCall(acc,'POST','/1/mail_hostings/'+acc.hostingId+'/mailboxes/'+mailbox+'/aliases',{alias});
  return{id:alias,aliasAddress:fl,targetAddress:fa,provider:'infomaniak',accountId:acc.id,accountLabel:acc.label};
}
async function ikDeleteAlias(alias,acc){
  const mailbox=acc.account.includes('@')?acc.account.split('@')[0]:acc.account;
  const aliasName=alias.id.includes('@')?alias.id.split('@')[0]:alias.id;
  await ikCall(acc,'DELETE','/1/mail_hostings/'+acc.hostingId+'/mailboxes/'+mailbox+'/aliases/'+aliasName);
}

// ── SimpleLogin ───────────────────────────────────────────────────────────────
async function slCall(acc,method,path,body=null){
  return proxyCall('simplelogin',method,path,body,{token:acc?.token||''});
}

async function slFetchForAccount(acc){
  const aliases=[];
  let page=0;
  while(true){
    const data=await slCall(acc,'GET','/api/v2/aliases?page_id='+page);
    const items=data?.aliases||[];
    items.forEach(a=>{
      aliases.push({
        id:String(a.id),
        aliasAddress:a.email,
        targetAddress:acc.email||acc.label,
        provider:'simplelogin',
        accountId:acc.id,
        accountLabel:acc.label,
        disabled:!a.enabled,
        slNbForward:a.nb_forward||0,
        slNbReply:a.nb_reply||0,
        slNbBlock:a.nb_block||0,
        slLatestActivity:a.latest_activity||null,
      });
      if(a.note&&a.note.trim())state.notes[a.email]=a.note.trim();
    });
    if(items.length<20)break;
    page++;
  }
  return aliases;
}

async function slGetOptions(acc){
  if(state.slSuffixes[acc.id]&&state.slSuffixes[acc.id].mailboxId)return state.slSuffixes[acc.id];
  const needsPremiumCheck=acc.isPremium===undefined||acc.isPremium===null;
  const [optData,mbData,userInfo]=await Promise.all([
    slCall(acc,'GET','/api/v5/alias/options'),
    acc.mailboxId?Promise.resolve(null):slCall(acc,'GET','/api/mailboxes'),
    needsPremiumCheck?slCall(acc,'GET','/api/user_info'):Promise.resolve(null),
  ]);
  const suffixes=optData?.suffixes||[];
  const prefixSuggestion=optData?.prefix_suggestion||'';
  let mailboxId=acc.mailboxId||0;
  if(!mailboxId){
    const def=(mbData?.mailboxes||[]).find(m=>m.default)||mbData?.mailboxes?.[0];
    if(def){mailboxId=def.id;}
  }
  if(needsPremiumCheck&&userInfo){
    acc.isPremium=!!(userInfo.is_premium);
    saveServerState();
  }
  state.slSuffixes[acc.id]={suffixes,prefixSuggestion,mailboxId};
  return state.slSuffixes[acc.id];
}

async function slCreateAlias(acc,prefix='',note=''){
  const opts=await slGetOptions(acc);
  const signedSuffix=state.selectedSlSignedSuffix;
  let chosen;
  if(signedSuffix){
    chosen=opts.suffixes.find(s=>(s.signed_suffix||s['signed-suffix'])===signedSuffix)||opts.suffixes[0];
  }else{
    chosen=opts.suffixes[0];
  }
  if(!chosen)throw new Error('No SimpleLogin suffix available');
  const mailboxId=acc.mailboxId||opts.mailboxId||0;
  const body={alias_prefix:prefix||generateAliasName(),signed_suffix:chosen.signed_suffix||chosen['signed-suffix'],mailbox_ids:[mailboxId]};
  if(note)body.note=note;
  const data=await slCall(acc,'POST','/api/v3/alias/custom/new',body);
  if(!data?.email)throw new Error(data?.error||data?.message||JSON.stringify(data)||'SimpleLogin alias creation failed');
  return{
    id:String(data.id),
    aliasAddress:data.email,
    targetAddress:acc.email||acc.label,
    provider:'simplelogin',
    accountId:acc.id,
    accountLabel:acc.label,
  };
}

async function slDeleteAlias(alias){
  await slCall(accForAlias(alias),'DELETE','/api/aliases/'+alias.id);
}

async function slToggleAlias(alias){
  const data=await slCall(accForAlias(alias),'POST','/api/aliases/'+alias.id+'/toggle');
  return data?.enabled??false;
}

async function slUpdateNote(alias,note){
  await slCall(accForAlias(alias),'PATCH','/api/aliases/'+alias.id,{note:note||''});
}

async function slFetchContacts(alias){
  const contacts=[];
  let page=0;
  while(true){
    const data=await slCall(accForAlias(alias),'GET','/api/aliases/'+alias.id+'/contacts?page_id='+page);
    const items=data?.contacts||[];
    contacts.push(...items);
    if(items.length<20)break;
    page++;
  }
  return contacts;
}

async function slCreateContact(alias,email){
  const data=await slCall(accForAlias(alias),'POST','/api/aliases/'+alias.id+'/contacts',{contact:email});
  if(!data?.id&&!data?.existed)throw new Error(data?.error||'Failed to create contact');
  return data;
}

async function slToggleContact(contactId){
  const data=await slCall(accForAlias(_contactsAlias||{}),'POST','/api/contacts/'+contactId+'/toggle');
  return data?.block_forward??false;
}

// ── Addy ───────────────────────────────────────────────────────────────────
async function addyCall(acc,method,path,body=null){
  return proxyCall('addy',method,path,body,{token:acc?.token||''});
}

async function addyFetchForAccount(acc){
  // Refresh subscription tier from API
  try{
    const details=await addyCall(acc,'GET','/api/v1/account-details');
    const info=details?.data?.id?details.data:(details?.data?.[0]??null);
    if(info){
      const sub=info.subscription;
      const endsAt=info.subscription_ends_at;
      const isFree=!sub||sub==='free'||(endsAt&&new Date(endsAt)<new Date());
      if(acc.isFree!==!!isFree){acc.isFree=!!isFree;saveServerState();}
    }
  }catch(_){}
  const aliases=[];
  let page=1;
  while(true){
    const data=await addyCall(acc,'GET','/api/v1/aliases?page[size]=100&page[number]='+page);
    const items=data?.data||[];
    items.forEach(a=>{
      // Filter by domain if one is configured on the account
      if(acc.domain&&a.domain!==acc.domain)return;
      const target=a.recipients?.[0]?.email||acc.email||acc.label;
      aliases.push({
        id:a.id,
        aliasAddress:a.email,
        targetAddress:target,
        provider:'addy',
        accountId:acc.id,
        accountLabel:acc.label,
        disabled:!a.active,
        addyNbForward:a.emails_forwarded||0,
        addyNbReply:a.emails_replied||0,
        addyNbSend:a.emails_sent||0,
        addyNbBlock:a.emails_blocked||0,
      });
      if(a.description&&a.description.trim())state.notes[a.email]=a.description.trim();
    });
    const lastPage=data?.meta?.last_page||1;
    if(page>=lastPage)break;
    page++;
  }
  return aliases;
}

async function addyCreateAlias(acc,aliasName,note=''){
  const body={domain:acc.domain||'anonaddy.me'};
  if(aliasName)body.local_part=aliasName;
  if(note)body.description=note;
  const data=await addyCall(acc,'POST','/api/v1/aliases',body);
  if(!data?.data?.email)throw new Error(data?.message||'Addy alias creation failed');
  const a=data.data;
  const target=a.recipients?.[0]?.email||acc.email||acc.label;
  return{
    id:a.id,
    aliasAddress:a.email,
    targetAddress:target,
    provider:'addy',
    accountId:acc.id,
    accountLabel:acc.label,
  };
}

async function addyDeleteAlias(alias){
  await addyCall(accForAlias(alias),'DELETE','/api/v1/aliases/'+alias.id);
}

async function addyToggleAlias(alias,enable){
  const acc=accForAlias(alias);
  if(enable){
    await addyCall(acc,'POST','/api/v1/active-aliases',{id:alias.id});
  }else{
    await addyCall(acc,'DELETE','/api/v1/active-aliases/'+alias.id);
  }
}

async function addyUpdateNote(alias,note){
  await addyCall(accForAlias(alias),'PATCH','/api/v1/aliases/'+alias.id,{description:note||''});
}

// ── Cloudflare ────────────────────────────────────────────────────────────────
async function cfCall(acc,method,path,body=null){
  const data=await proxyCall('cloudflare',method,path,body,{token:acc?.token||''});
  // Cloudflare returns success:false with HTTP 200 for some errors
  if(data&&typeof data==='object'&&data.success===false){
    throw new Error(data.errors?.[0]?.message||'Cloudflare API error');
  }
  return data;
}

async function cfFetchForAccount(acc){
  const data=await cfCall(acc,'GET','/zones/'+acc.zoneId+'/email/routing/rules?per_page=50');
  const rules=data?.result||[];
  return rules
    .filter(r=>r.matchers?.some(m=>m.type==='literal'&&m.field==='to'))
    .map(r=>{
      const matcher=r.matchers.find(m=>m.type==='literal'&&m.field==='to');
      const action=r.actions?.find(a=>a.type==='forward');
      const targetAddress=action?.value?.[0]||acc.targetAddress||acc.label;
      return{
        id:r.tag,
        aliasAddress:matcher.value,
        targetAddress,
        provider:'cloudflare',
        accountId:acc.id,
        accountLabel:acc.label,
        disabled:!r.enabled,
        cfPriority:r.priority||10,
      };
    });
}

async function cfCreateAlias(acc,aliasName){
  const localPart=aliasName.includes('@')?aliasName.split('@')[0]:aliasName;
  const aliasAddress=localPart+'@'+acc.domain;
  const body={
    name:localPart,
    enabled:true,
    matchers:[{type:'literal',field:'to',value:aliasAddress}],
    actions:[{type:'forward',value:[acc.targetAddress]}],
    priority:10,
  };
  const data=await cfCall(acc,'POST','/zones/'+acc.zoneId+'/email/routing/rules',body);
  const rule=data?.result;
  return{
    id:rule?.tag||genId(),
    aliasAddress,
    targetAddress:acc.targetAddress,
    provider:'cloudflare',
    accountId:acc.id,
    accountLabel:acc.label,
    cfPriority:10,
  };
}

async function cfDeleteAlias(alias,acc){
  await cfCall(acc,'DELETE','/zones/'+acc.zoneId+'/email/routing/rules/'+alias.id);
}

async function cfToggleAlias(alias,enable){
  const acc=accForAlias(alias);
  if(!acc.id)throw new Error('Account not found');
  const body={
    name:alias.aliasAddress.split('@')[0],
    enabled:enable,
    matchers:[{type:'literal',field:'to',value:alias.aliasAddress}],
    actions:[{type:'forward',value:[alias.targetAddress]}],
    priority:alias.cfPriority||10,
  };
  await cfCall(acc,'PUT','/zones/'+acc.zoneId+'/email/routing/rules/'+alias.id,body);
}

// ── Unified fetch ─────────────────────────────────────────────────────────────
async function fetchAliases(){
  if(!state.accounts.length)return;
  const tasks=state.accounts.map(acc=>{
    if(acc.provider==='ovh')
      return ovhFetchForAccount(acc).catch(e=>{showError('OVH ('+acc.label+'): '+e.message);return[];});
    else if(acc.provider==='infomaniak')
      return ikFetchForAccount(acc).catch(e=>{showError('IK ('+acc.label+'): '+e.message);return[];});
    else if(acc.provider==='addy')
      return addyFetchForAccount(acc).catch(e=>{showError('Addy ('+acc.label+'): '+e.message);return[];});
    else if(acc.provider==='cloudflare')
      return cfFetchForAccount(acc).catch(e=>{showError('Cloudflare ('+acc.label+'): '+e.message);return[];});
    else
      return slFetchForAccount(acc).catch(e=>{showError('SL ('+acc.label+'): '+e.message);return[];});
  });
  const results=await Promise.all(tasks);
  const live=[].concat(...results);
  // API-driven providers (SL, Addy, CF) manage disabled state via their APIs
  const apiAccountIds=new Set(state.accounts.filter(a=>
    a.provider==='simplelogin'||a.provider==='addy'||a.provider==='cloudflare'
  ).map(a=>a.id));
  const disabled=state.disabledAliases.filter(d=>
    !apiAccountIds.has(d.accountId)&&
    state.accounts.some(a=>a.id===d.accountId)&&
    !live.some(l=>l.aliasAddress===d.aliasAddress&&l.accountId===d.accountId)
  );
  state.aliases=[...live,...disabled.map(d=>({...d,disabled:true}))]
    .sort((a,b)=>a.aliasAddress.localeCompare(b.aliasAddress));
  state.dataLoaded=true;
  applyFilter();
}

async function createAlias(aliasName,accountId,note=''){
  const acc=state.accounts.find(a=>a.id===accountId);
  if(!acc)throw new Error('Account not found');
  const isSL=acc.provider==='simplelogin';
  const isAddy=acc.provider==='addy';
  const domain=acc.domain||(acc.account?.includes('@')?acc.account.split('@')[1]:'');
  const fa=acc.account?.includes('@')?acc.account:acc.account+'@'+domain;
  const resolvedName=aliasName||generateAliasName();
  let fl;
  if(isSL)fl='Generating…';
  else if(isAddy)fl=aliasName?(aliasName+'@'+(acc.domain||'anonaddy.me')):'Generating…';
  else fl=resolvedName.includes('@')?resolvedName:resolvedName+'@'+domain;
  const placeholder={id:'__pending__'+genId(),aliasAddress:fl,targetAddress:isSL||isAddy?acc.label:fa,
    provider:acc.provider,accountId:acc.id,accountLabel:acc.label,pending:true};
  state.aliases.unshift(placeholder);
  state.aliases.sort((a,b)=>a.aliasAddress.localeCompare(b.aliasAddress));
  applyFilter();render();
  try{
    let newAlias;
    if(acc.provider==='infomaniak') newAlias=await ikCreateAlias(acc,resolvedName);
    else if(acc.provider==='simplelogin') newAlias=await slCreateAlias(acc,aliasName,note);
    else if(acc.provider==='addy') newAlias=await addyCreateAlias(acc,aliasName,note);
    else if(acc.provider==='cloudflare') newAlias=await cfCreateAlias(acc,resolvedName);
    else newAlias=await ovhCreateAlias(acc,resolvedName);
    const idx=state.aliases.findIndex(a=>a.id===placeholder.id);
    if(idx!==-1)state.aliases[idx]=newAlias;
    else state.aliases.unshift(newAlias);
    state.aliases.sort((a,b)=>a.aliasAddress.localeCompare(b.aliasAddress));
    if(note.trim()){state.notes[newAlias.aliasAddress]=note.trim();await saveNotes();}
    await saveServerState();
    _lastListKey='';
    applyFilter();render();
    return newAlias;
  }catch(e){
    state.aliases=state.aliases.filter(a=>a.id!==placeholder.id);
    applyFilter();render();
    throw e;
  }
}

async function deleteAlias(alias){
  const acc=state.accounts.find(a=>a.id===alias.accountId);
  if(!acc)throw new Error('Account not found');
  const backup=[...state.aliases];
  state.aliases=state.aliases.filter(a=>!(a.id===alias.id&&a.accountId===alias.accountId));
  applyFilter();render();
  try{
    if(alias.provider==='infomaniak') await ikDeleteAlias(alias,acc);
    else if(alias.provider==='simplelogin') await slDeleteAlias(alias);
    else if(alias.provider==='addy') await addyDeleteAlias(alias);
    else if(alias.provider==='cloudflare') await cfDeleteAlias(alias,acc);
    else await ovhDeleteAlias(alias,acc);
    if(state.notes[alias.aliasAddress]){delete state.notes[alias.aliasAddress];await saveNotes();}
    state.disabledAliases=state.disabledAliases.filter(d=>!(d.aliasAddress===alias.aliasAddress&&d.accountId===alias.accountId));
    await saveServerState();
  }catch(e){
    state.aliases=backup;
    applyFilter();render();
    throw e;
  }
}

async function disableAlias(alias){
  const acc=state.accounts.find(a=>a.id===alias.accountId);
  if(!acc)throw new Error('Account not found');
  const backup=[...state.aliases];
  const idx=state.aliases.findIndex(a=>a.id===alias.id&&a.accountId===alias.accountId);
  if(idx!==-1)state.aliases[idx]={...state.aliases[idx],disabled:true};
  applyFilter();render();
  try{
    if(alias.provider==='simplelogin'){
      await slToggleAlias(alias);
    }else if(alias.provider==='addy'){
      await addyToggleAlias(alias,false);
    }else if(alias.provider==='cloudflare'){
      await cfToggleAlias(alias,false);
    }else if(alias.provider==='infomaniak'){
      await ikDeleteAlias(alias,acc);
    }else{
      await ovhDeleteAlias(alias,acc);
    }
    // Only OVH/IK store disabled state locally
    if(alias.provider!=='simplelogin'&&alias.provider!=='addy'&&alias.provider!=='cloudflare'){
      const{id:_,pending:__,...rest}=alias;
      if(!state.disabledAliases.some(d=>d.aliasAddress===rest.aliasAddress&&d.accountId===rest.accountId))
        state.disabledAliases.push({...rest,disabled:true});
      await saveServerState();
    }
  }catch(e){
    state.aliases=backup;
    applyFilter();render();
    throw e;
  }
}

async function enableAlias(alias){
  const acc=state.accounts.find(a=>a.id===alias.accountId);
  if(!acc)throw new Error('Account not found');
  const idx=state.aliases.findIndex(a=>a.aliasAddress===alias.aliasAddress&&a.accountId===alias.accountId);
  if(idx!==-1)state.aliases[idx]={...state.aliases[idx],pending:true,disabled:false};
  _lastListKey='';applyFilter();render();
  try{
    if(alias.provider==='simplelogin'){
      await slToggleAlias(alias);
      const i=state.aliases.findIndex(a=>a.aliasAddress===alias.aliasAddress&&a.accountId===alias.accountId);
      if(i!==-1)state.aliases[i]={...state.aliases[i],disabled:false,pending:false};
    }else if(alias.provider==='addy'){
      await addyToggleAlias(alias,true);
      const i=state.aliases.findIndex(a=>a.aliasAddress===alias.aliasAddress&&a.accountId===alias.accountId);
      if(i!==-1)state.aliases[i]={...state.aliases[i],disabled:false,pending:false};
    }else if(alias.provider==='cloudflare'){
      await cfToggleAlias(alias,true);
      const i=state.aliases.findIndex(a=>a.aliasAddress===alias.aliasAddress&&a.accountId===alias.accountId);
      if(i!==-1)state.aliases[i]={...state.aliases[i],disabled:false,pending:false};
    }else{
      const aliasName=alias.aliasAddress.includes('@')?alias.aliasAddress.split('@')[0]:alias.aliasAddress;
      const newAlias=acc.provider==='infomaniak'?await ikCreateAlias(acc,aliasName):await ovhCreateAlias(acc,aliasName);
      state.disabledAliases=state.disabledAliases.filter(d=>!(d.aliasAddress===alias.aliasAddress&&d.accountId===alias.accountId));
      const i=state.aliases.findIndex(a=>a.aliasAddress===alias.aliasAddress&&a.accountId===alias.accountId);
      if(i!==-1)state.aliases[i]=newAlias;
      await saveServerState();
    }
    _lastListKey='';applyFilter();render();
  }catch(e){
    const i=state.aliases.findIndex(a=>a.aliasAddress===alias.aliasAddress&&a.accountId===alias.accountId);
    if(i!==-1)state.aliases[i]={...alias,disabled:true,pending:false};
    _lastListKey='';applyFilter();render();
    throw e;
  }
}

function applyFilter(){
  const q=state.searchQuery.toLowerCase();
  state.filteredAliases=q?state.aliases.filter(a=>
    a.aliasAddress.toLowerCase().includes(q)||
    a.targetAddress.toLowerCase().includes(q)||
    (state.notes[a.aliasAddress]||'').toLowerCase().includes(q)
  ):[...state.aliases];
}
function canAddAlias(){return state.accounts.length>0}

// ── Render list ───────────────────────────────────────────────────────────────
let _lastListKey='';
function renderList(){
  const hasList=canAddAlias()&&state.dataLoaded&&state.filteredAliases.length>0;
  const listEl=document.getElementById('alias-list');
  if(!hasList){if(listEl.innerHTML)listEl.innerHTML='';return;}
  const key=state.filteredAliases.map(a=>a.id+'|'+a.accountId+(a.pending?'p':'')+(a.disabled?'d':'')+(state.notes[a.aliasAddress]?'n':'')).join(',');
  if(key===_lastListKey)return;
  _lastListKey=key;
  let html='';
  let currentLetter='';
  state.filteredAliases.forEach(a=>{
    const letter=a.aliasAddress[0].toUpperCase();
    if(letter!==currentLetter){currentLetter=letter;html+=`<div class="alias-letter">${letter}</div>`;}
    const providerClass=
      a.provider==='infomaniak'?'ik':
      a.provider==='simplelogin'?'sl':
      a.provider==='addy'?'addy':
      a.provider==='cloudflare'?'cf':'ovh';
    const providerLabel=
      a.provider==='infomaniak'?'Infomaniak':
      a.provider==='simplelogin'?'SimpleLogin':
      a.provider==='addy'?'Addy':
      a.provider==='cloudflare'?'Cloudflare':'OVH';
    html+=`
    <div class="alias-card${a.disabled?' alias-card-disabled':''}" data-id="${esc(a.id)}" data-account="${esc(a.accountId)}" style="${a.pending?'opacity:.5;pointer-events:none':''}">
      <div class="alias-card-body">
        <div class="alias-address">${(s=>{const i=s.indexOf('@');return i<0?esc(s):esc(s.slice(0,i))+'<span class="alias-domain">'+esc(s.slice(i))+'</span>'})(a.aliasAddress)}</div>
        <div class="alias-target">
          <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
            <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
          </svg>${esc(a.targetAddress)}
        </div>
        <div class="alias-badges">
          <span class="pbadge pbadge-${providerClass}">${providerLabel}</span>
          ${a.disabled?'<span class="badge-disabled">disabled</span>':''}
          ${a.provider==='simplelogin'&&!a.disabled?`<span class="sl-stat" title="Forwarded">↓${a.slNbForward||0}</span><span class="sl-stat" title="Replied">↑${a.slNbReply||0}</span>${(a.slNbBlock||0)>0?`<span class="sl-stat sl-stat-block" title="Blocked">✕${a.slNbBlock}</span>`:''}`:'' }
          ${a.provider==='addy'&&!a.disabled?`<span class="addy-stat" title="Forwarded">↓${a.addyNbForward||0}</span><span class="addy-stat" title="Replied">↑${a.addyNbReply||0}</span><span class="addy-stat" title="Sent">→${a.addyNbSend||0}</span>${(a.addyNbBlock||0)>0?`<span class="addy-stat addy-stat-block" title="Blocked">✕${a.addyNbBlock}</span>`:''}`:''}
        </div>
        ${state.notes[a.aliasAddress]?`<div class="alias-note">${esc(state.notes[a.aliasAddress])}</div>`:'<div class="alias-note-empty">no description</div>'}
      </div>
      <div class="alias-actions">
        <button class="icon-btn copy-btn" title="Copy">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
        ${a.disabled?`
        <button class="icon-btn enable-btn" title="Re-enable">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>
        </button>`:`
        <button class="icon-btn disable-btn" title="Disable">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
          </svg>
        </button>`}
        ${(a.provider==='simplelogin'||a.provider==='addy')?`
        <button class="icon-btn contacts-btn" title="Contacts / Reverse aliases">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
        </button>`:''}
        <button class="icon-btn edit-note-btn${state.notes[a.aliasAddress]?' has-note':''}" title="Edit note">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
          </svg>
        </button>
        <button class="icon-btn danger delete-btn" title="Delete">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
          </svg>
        </button>
      </div>
    </div>`;
  });
  listEl.innerHTML=html;
}

// ── Render settings account list ──────────────────────────────────────────────
function renderAccountList(){
  const el=document.getElementById('account-list');
  const lbl=document.getElementById('settings-accounts-label');
  lbl.style.display=state.accounts.length?'':'none';
  lbl.textContent=state.accounts.length>1?'Accounts':'Account';
  if(!state.accounts.length){
    el.innerHTML='';
    return;
  }
  el.innerHTML=state.accounts.map(acc=>{
    const cls=
      acc.provider==='infomaniak'?'ik':
      acc.provider==='simplelogin'?'sl':
      acc.provider==='addy'?'addy':
      acc.provider==='cloudflare'?'cf':'ovh';
    const lbl=
      acc.provider==='infomaniak'?'Infomaniak':
      acc.provider==='simplelogin'?'SimpleLogin':
      acc.provider==='addy'?'Addy':
      acc.provider==='cloudflare'?'Cloudflare':'OVH';
    const displayName=(acc.provider==='addy'||acc.provider==='cloudflare')&&acc.email?acc.email:acc.label;
    let tierBadge='';
    if(acc.provider==='simplelogin'&&acc.isPremium!==undefined&&acc.isPremium!==null){
      tierBadge=acc.isPremium
        ?'<span class="account-item-badge badge-tier-premium">Premium</span>'
        :'<span class="account-item-badge badge-tier-free">Free</span>';
    }else if(acc.provider==='addy'&&acc.isFree!==undefined){
      tierBadge=acc.isFree
        ?'<span class="account-item-badge badge-tier-free">Free</span>'
        :'<span class="account-item-badge badge-tier-premium">Premium</span>';
    }
    return`<div class="account-item">
      <div class="account-item-info">
        <div class="account-item-name">${esc(displayName)}</div>
        <span class="account-item-badge badge-${cls}">${lbl}</span>${tierBadge}
      </div>
      <button class="icon-btn edit-account-btn" data-account-id="${esc(acc.id)}" title="Settings">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <circle cx="12" cy="12" r="3"/>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
      </button>
      <button class="icon-btn default-btn${acc.isDefault?' default-active':''}" data-account-id="${esc(acc.id)}" title="${acc.isDefault?'Default account':'Set as default'}">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="${acc.isDefault?'currentColor':'none'}" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
        </svg>
      </button>
      <button class="icon-btn danger remove-account-btn" data-account-id="${esc(acc.id)}" title="Remove">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <polyline points="3 6 5 6 21 6"/>
          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
        </svg>
      </button>
    </div>`;
  }).join('');
}

function removeAccount(id){
  const toClean=[
    ...state.aliases.filter(a=>a.accountId===id),
    ...state.disabledAliases.filter(a=>a.accountId===id),
  ];
  toClean.forEach(a=>delete state.notes[a.aliasAddress]);
  if(toClean.length)saveNotes();
  state.accounts=state.accounts.filter(a=>a.id!==id);
  state.aliases=state.aliases.filter(a=>a.accountId!==id);
  state.filteredAliases=state.filteredAliases.filter(a=>a.accountId!==id);
  state.disabledAliases=state.disabledAliases.filter(a=>a.accountId!==id);
  delete state.ovhZimbraPlatformIds[id];
  delete state.ovhZimbraAccountIds[id];
  if(state.credentials&&state.credentials.perAccount)delete state.credentials.perAccount[id];
  _lastListKey='';
  saveServerState();
  saveAccountCredentials();
  renderAccountList();
  render();
}

document.getElementById('account-list').addEventListener('click',e=>{
  const removeBtn=e.target.closest('.remove-account-btn');
  if(removeBtn){const id=removeBtn.dataset.accountId;if(id)removeAccount(id);return;}
  const defaultBtn=e.target.closest('.default-btn');
  if(defaultBtn){
    const id=defaultBtn.dataset.accountId;
    state.accounts.forEach(a=>a.isDefault=a.id===id);
    saveServerState();
    renderAccountList();
    return;
  }

});

// ── Render new alias account selector ────────────────────────────────────────
function renderAccountSelector(){
  const defaultAcc=state.accounts.find(a=>a.isDefault)||state.accounts[0];
  document.getElementById('new-alias-account-label').textContent=state.accounts.length>1?'Accounts':'Account';
  const pillsEl=document.getElementById('new-alias-account-pills');
  pillsEl.innerHTML=state.accounts.map(acc=>{
    const domain=
      acc.provider==='simplelogin'?'simplelogin':
      acc.provider==='addy'?(acc.label||'addy'):
      acc.provider==='cloudflare'?(acc.domain||'cloudflare'):
      (acc.domain||(acc.account?.includes('@')?acc.account.split('@')[1]:''));
    return`<button type="button" class="account-pill${acc.id===defaultAcc?.id?' active':''}" data-account-id="${esc(acc.id)}">@${esc(domain)}</button>`;
  }).join('');
  document.getElementById('new-alias-account-field').style.display=
    state.accounts.length>1?'flex':'none';
}

function _getSelectedAccountId(){
  const active=document.querySelector('.account-pill.active');
  return active?.dataset.accountId||state.accounts[0]?.id||'';
}

// ── Render random suggestions ─────────────────────────────────────────────────
function _slSortedSuffixes(acc){
  const opts=state.slSuffixes[acc.id];
  if(!opts||!opts.suffixes||!opts.suffixes.length)return[];
  const suffixes=acc.isPremium
    ?opts.suffixes
    :opts.suffixes.filter(s=>!(s.is_custom||s.premium));
  return[...suffixes].sort((a,b)=>{
    const ap=a.is_custom||a.premium||false;
    const bp=b.is_custom||b.premium||false;
    return(bp?1:0)-(ap?1:0);
  });
}

function renderAliasSuggestions(){
  const el=document.getElementById('alias-suggestions');
  if(!el)return;
  const wrap=document.getElementById('alias-suggestions-wrap');
  const accId=_getSelectedAccountId();
  const acc=state.accounts.find(a=>a.id===accId);
  const MAX_SUGGESTIONS=3;
  const inputVal=document.getElementById('alias-name-input').value.trim();

  if(acc&&acc.provider==='simplelogin'){
    // SL selected: show up to MAX_SUGGESTIONS suffixes (premium first)
    const sorted=_slSortedSuffixes(acc);
    if(!sorted.length){el.innerHTML='';if(wrap)wrap.style.display='none';return;}
    const opts=state.slSuffixes[acc.id];
    const prefix=inputVal||opts.prefixSuggestion||generateAliasName();
    const shown=sorted.slice(0,MAX_SUGGESTIONS);
    if(wrap)wrap.style.display='';
    el.innerHTML=shown.map(function(s){
      const signed=s.signed_suffix||s['signed-suffix']||'';
      const prem=(s.is_custom||s.premium)?'<span class="suggestion-premium">premium</span>':'';
      return'<div class="suggestion-row sl-suffix-row" data-name="'+esc(prefix)+'" data-account-id="'+esc(acc.id)+'" data-signed-suffix="'+esc(signed)+'" data-suffix="'+esc(s.suffix)+'"><span class="suggestion-full">'+esc(prefix+s.suffix)+'</span>'+prem+'</div>';
    }).join('');
    return;
  }

  // Mixed view: one row per account; SL uses its top suffix
  const activePillId=document.querySelector('.account-pill.active')?.dataset.accountId||null;
  var rows=[];
  for(var i=0;i<state.accounts.length;i++){
    var a=state.accounts[i];
    if(activePillId&&a.id!==activePillId)continue;
    if(a.provider==='addy'&&a.isFree)continue;
    if(a.provider==='simplelogin'){
      var sorted=_slSortedSuffixes(a);
      if(!sorted.length)continue;
      var s=sorted[0];
      var opts=state.slSuffixes[a.id];
      var prefix=inputVal||opts.prefixSuggestion||generateAliasName();
      var signed=s.signed_suffix||s['signed-suffix']||'';
      var isPrem=!!(s.is_custom||s.premium);
      rows.push({accountId:a.id,full:prefix+s.suffix,name:prefix,isSL:true,suffix:s.suffix,signedSuffix:signed,isPremium:isPrem});
    }else{
      var domain=a.domain||(a.account&&a.account.includes('@')?a.account.split('@')[1]:'');
      for(var j=0;j<MAX_SUGGESTIONS;j++){
        var name=generateAliasName();
        rows.push({accountId:a.id,full:name+'@'+domain,name:name,isSL:false});
      }
    }
  }
  if(!rows.length){el.innerHTML='';if(wrap)wrap.style.display='none';return;}
  if(wrap)wrap.style.display='';
  el.innerHTML=rows.map(function(r){
    if(r.isSL){
      var prem=r.isPremium?'<span class="suggestion-premium">premium</span>':'';
      return'<div class="suggestion-row sl-suffix-row" data-name="'+esc(r.name)+'" data-account-id="'+esc(r.accountId)+'" data-signed-suffix="'+esc(r.signedSuffix)+'" data-suffix="'+esc(r.suffix)+'"><span class="suggestion-full">'+esc(r.full)+'</span>'+prem+'</div>';
    }
    return'<div class="suggestion-row" data-name="'+esc(r.name)+'" data-account-id="'+esc(r.accountId)+'"><span class="suggestion-full">'+esc(r.full)+'</span></div>';
  }).join('');
}

// ── Main render ───────────────────────────────────────────────────────────────
function setRefreshSpin(on){document.querySelectorAll('.refresh-icon').forEach(el=>el.classList.toggle('spin-anim',on))}
function render(){
  const loading=state.isLoading,ready=canAddAlias();
  const empty=ready&&state.dataLoaded&&state.filteredAliases.length===0;
  document.getElementById('state-loading').classList.toggle('visible',loading&&!ready);
  document.getElementById('state-config').classList.toggle('visible',!loading&&!ready);
  document.getElementById('state-empty').classList.toggle('visible',!loading&&empty);
  renderList();
  document.getElementById('btn-add').style.display=ready?'inline-flex':'none';
  document.getElementById('mob-add').style.display=ready?'flex':'none';
  const countEl=document.getElementById('alias-count');
  if(state.aliases.length>0){countEl.textContent=state.aliases.length+' alias'+(state.aliases.length>1?'es':'');countEl.classList.add('visible')}
  else countEl.classList.remove('visible');
}
function renderSettingsStatus(){
  const authed=state.accounts.some(a=>a.provider==='ovh'&&ovhIsAuthenticated(a));
  document.getElementById('auth-dot').className='status-dot '+(authed?'green':'orange');
  document.getElementById('auth-status-text').textContent=authed?'Authenticated':'Not authenticated';
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function genId(){return Date.now().toString(36)+Math.random().toString(36).slice(2)}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function showError(msg){document.getElementById('error-text').textContent=msg;document.getElementById('error-banner').classList.add('visible');setTimeout(()=>document.getElementById('error-banner').classList.remove('visible'),5000)}
function hideError(){document.getElementById('error-banner').classList.remove('visible')}

let _copyToastTimer=null;
function showCopyToast(anchorEl){
  const t=document.getElementById('copy-toast-global');
  if(anchorEl){const r=anchorEl.getBoundingClientRect();t.style.left=(r.left+r.width/2)+'px';t.style.top=(r.top-12)+'px';t.classList.add('anchored');}else{t.classList.remove('anchored');}
  t.classList.add('show');clearTimeout(_copyToastTimer);_copyToastTimer=setTimeout(()=>t.classList.remove('show'),1600);
}
async function copyText(text,anchorEl){
  try{await navigator.clipboard.writeText(text);showCopyToast(anchorEl);}
  catch{try{window.getSelection()?.removeAllRanges();const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;top:0;left:0;opacity:0;pointer-events:none';document.body.appendChild(ta);ta.focus();ta.select();const ok=document.execCommand('copy');document.body.removeChild(ta);if(ok)showCopyToast(anchorEl);}catch{}}
}

async function loadAliases(){
  if(!canAddAlias())return;
  setRefreshSpin(true);hideError();
  try{await fetchAliases()}catch(e){showError(e.message)}
  finally{setRefreshSpin(false);render();}
}

function setThemeColor(dark){
  const meta=document.getElementById('theme-color-meta');
  if(meta)meta.content=dark?'#000000':'#0f0f0f';
}

// ── Settings ──────────────────────────────────────────────────────────────────
function openSettings(){
  setThemeColor(true);
  _pendingConsumerKey='';
  document.getElementById('section-add-ovh').style.display='none';
  document.getElementById('section-add-ik').style.display='none';
  document.getElementById('section-add-sl').style.display='none';
  document.getElementById('section-add-addy').style.display='none';
  document.getElementById('section-add-cf').style.display='none';
  document.getElementById('section-edit-account').style.display='none';
  document.getElementById('section-accounts').style.display='';
  document.getElementById('auth-url-box').classList.remove('visible');
  document.getElementById('auth-url-actions').style.display='none';
  document.getElementById('auth-message').classList.remove('visible');
  document.getElementById('settings-modal-title').textContent='Settings';
  document.getElementById('close-settings').style.display='';
  document.getElementById('back-settings').style.display='none';
  renderAccountList();
  document.getElementById('modal-settings').classList.add('open');
}
function closeSettings(){
  setThemeColor(false);
  document.getElementById('modal-settings').classList.remove('open');
  if(canAddAlias())loadAliases();
}

// ── Add account forms ─────────────────────────────────────────────────────────
let _pendingConsumerKey='';
let _editingAccountId=null;
const _addAccountTitles={
  'section-add-ovh':'New OVH account',
  'section-add-ik':'New Infomaniak account',
  'section-add-sl':'New SimpleLogin account',
  'section-add-addy':'New Addy account',
  'section-add-cf':'New Cloudflare account',
  'section-edit-account':'Account Settings',
};

function showAddForm(formId){
  document.getElementById('section-accounts').style.display='none';
  document.getElementById('section-add-ovh').style.display='none';
  document.getElementById('section-add-ik').style.display='none';
  document.getElementById('section-add-sl').style.display='none';
  document.getElementById('section-add-addy').style.display='none';
  document.getElementById('section-add-cf').style.display='none';
  document.getElementById('section-edit-account').style.display='none';
  document.getElementById('auth-url-box').classList.remove('visible');
  document.getElementById('auth-url-actions').style.display='none';
  document.getElementById('auth-message').classList.remove('visible');
  document.getElementById('settings-modal-title').textContent=_addAccountTitles[formId]||'New account';
  document.getElementById('close-settings').style.display='none';
  document.getElementById('back-settings').style.display='';
  document.getElementById('btn-authenticate').style.display='';
  document.getElementById(formId).style.display='flex';
  if(formId!=='section-edit-account')renderSettingsStatus();
}
function hideAddForms(){
  _pendingConsumerKey='';
  document.getElementById('section-add-ovh').style.display='none';
  document.getElementById('section-add-ik').style.display='none';
  document.getElementById('section-add-sl').style.display='none';
  document.getElementById('section-add-addy').style.display='none';
  document.getElementById('section-add-cf').style.display='none';
  document.getElementById('section-edit-account').style.display='none';
  document.getElementById('section-accounts').style.display='';
  document.getElementById('settings-modal-title').textContent='Settings';
  document.getElementById('close-settings').style.display='';
  document.getElementById('back-settings').style.display='none';
  renderAccountList();
}

// OVH
document.getElementById('btn-add-ovh-account').addEventListener('click',()=>{
  showAddForm('section-add-ovh');
  document.getElementById('s-ovh-account').value='';
  document.getElementById('s-ovh-app-key').value='';
  document.getElementById('s-ovh-app-secret').value='';
  _pendingConsumerKey='';
  document.getElementById('auth-dot').className='status-dot orange';
  document.getElementById('auth-status-text').textContent='Not authenticated';
});
document.getElementById('btn-cancel-add-ovh').addEventListener('click',hideAddForms);
document.getElementById('btn-save-ovh-account').addEventListener('click',()=>{
  const account=document.getElementById('s-ovh-account').value.trim();
  const ovhAppKey=document.getElementById('s-ovh-app-key').value.trim();
  const ovhAppSecret=document.getElementById('s-ovh-app-secret').value.trim();
  if(!account||!account.includes('@')){showError('Please enter a valid email address');return;}
  if(!_pendingConsumerKey){showError('Please authenticate with OVH first');return;}
  const domain=account.split('@')[1];
  state.accounts.push({id:genId(),provider:'ovh',label:account,account,domain,consumerKey:_pendingConsumerKey,ovhAppKey,ovhAppSecret});
  saveServerState();saveAccountCredentials();hideAddForms();
});

// Infomaniak
document.getElementById('btn-add-ik-account').addEventListener('click',()=>{
  showAddForm('section-add-ik');
  document.getElementById('s-ik-hosting-id').value='';
  document.getElementById('s-ik-account').value='';
  document.getElementById('s-ik-token').value='';
});
document.getElementById('btn-cancel-add-ik').addEventListener('click',hideAddForms);
document.getElementById('btn-save-ik-account').addEventListener('click',()=>{
  const hostingId=document.getElementById('s-ik-hosting-id').value.trim();
  const account=document.getElementById('s-ik-account').value.trim();
  const token=document.getElementById('s-ik-token').value.trim();
  if(!hostingId||!account||!account.includes('@')){showError('Please fill hosting ID and a valid email');return;}
  if(!token){showError('Please enter your Infomaniak API token');return;}
  const domain=account.split('@')[1];
  state.accounts.push({id:genId(),provider:'infomaniak',label:account,account,domain,hostingId,token});
  saveServerState();saveAccountCredentials();hideAddForms();
});

// SimpleLogin
document.getElementById('btn-add-sl-account').addEventListener('click',()=>{
  showAddForm('section-add-sl');
  document.getElementById('s-sl-label').value='';
  document.getElementById('s-sl-token').value='';
});
document.getElementById('btn-cancel-add-sl').addEventListener('click',hideAddForms);
document.getElementById('btn-save-sl-account').addEventListener('click',async()=>{
  const label=document.getElementById('s-sl-label').value.trim()||'SimpleLogin';
  const token=document.getElementById('s-sl-token').value.trim();
  if(!token){showError('Please enter your SimpleLogin API token');return;}
  const btn=document.getElementById('btn-save-sl-account');
  btn.disabled=true;btn.textContent='Verifying…';
  const tempAcc={token};
  try{
    const userInfo=await slCall(tempAcc,'GET','/api/user_info');
    const isPremium=!!(userInfo?.is_premium);
    let mailboxId=1,email='';
    try{
      const mb=await slCall(tempAcc,'GET','/api/mailboxes');
      const def=mb?.mailboxes?.find(m=>m.default);
      if(def){mailboxId=def.id;email=def.email;}
    }catch(_){}
    state.accounts.push({id:genId(),provider:'simplelogin',label,mailboxId,email,isPremium,token});
    saveServerState();saveAccountCredentials();hideAddForms();
  }catch(e){
    showError('SimpleLogin token invalid or unreachable: '+e.message);
  }finally{
    btn.disabled=false;btn.textContent='Save account';
  }
});

// Addy
document.getElementById('btn-add-addy-account').addEventListener('click',()=>{
  showAddForm('section-add-addy');
  document.getElementById('s-addy-label').value='';
  document.getElementById('s-addy-email').value='';
  document.getElementById('s-addy-domain').value='';
  document.getElementById('s-addy-token').value='';
});
document.getElementById('btn-cancel-add-addy').addEventListener('click',hideAddForms);
document.getElementById('btn-save-addy-account').addEventListener('click',async()=>{
  const label=document.getElementById('s-addy-label').value.trim()||'Addy';
  const emailInput=document.getElementById('s-addy-email').value.trim();
  const domainInput=document.getElementById('s-addy-domain').value.trim();
  const token=document.getElementById('s-addy-token').value.trim();
  if(!token){showError('Please enter your Addy API token');return;}
  const btn=document.getElementById('btn-save-addy-account');
  btn.disabled=true;btn.textContent='Verifying…';
  const tempAcc={token};
  try{
    const data=await addyCall(tempAcc,'GET','/api/v1/account-details');
    const info=data?.data?.id?data.data:(data?.data?.[0]??null);
    if(!info)throw new Error('Invalid response from Addy API');
    const finalDomain=domainInput||info.default_alias_domain||'anonaddy.me';
    const sub=info.subscription;
    const endsAt=info.subscription_ends_at;
    const isFree=!sub||sub==='free'||(endsAt&&new Date(endsAt)<new Date());
    let email=emailInput;
    if(!email){
      try{
        const mb=await addyCall(tempAcc,'GET','/api/v1/recipients?page[size]=10');
        const def=(mb?.data||[]).find(r=>r.id===info.default_recipient_id)||mb?.data?.[0];
        if(def)email=def.email;
      }catch(_){}
    }
    state.accounts.push({id:genId(),provider:'addy',label,domain:finalDomain,email,isFree,token});
    saveServerState();saveAccountCredentials();hideAddForms();
  }catch(e){
    showError('Addy error: '+e.message);
  }finally{
    btn.disabled=false;btn.textContent='Save account';
  }
});

// Cloudflare
document.getElementById('btn-add-cf-account').addEventListener('click',()=>{
  showAddForm('section-add-cf');
  document.getElementById('s-cf-zone-id').value='';
  document.getElementById('s-cf-target').value='';
  document.getElementById('s-cf-token').value='';
});
document.getElementById('btn-cancel-add-cf').addEventListener('click',hideAddForms);
document.getElementById('btn-save-cf-account').addEventListener('click',async()=>{
  const zoneId=document.getElementById('s-cf-zone-id').value.trim();
  const targetAddress=document.getElementById('s-cf-target').value.trim();
  const token=document.getElementById('s-cf-token').value.trim();
  if(!zoneId||!targetAddress||!targetAddress.includes('@')){
    showError('Please fill Zone ID and a valid destination email');return;
  }
  if(!token){showError('Please enter your Cloudflare API token');return;}
  const btn=document.getElementById('btn-save-cf-account');
  btn.disabled=true;btn.textContent='Verifying…';
  const tempAcc={token};
  try{
    const data=await cfCall(tempAcc,'GET','/zones/'+zoneId);
    const domain=data?.result?.name;
    if(!domain)throw new Error('Could not determine domain name from zone');
    state.accounts.push({id:genId(),provider:'cloudflare',label:domain,domain,zoneId,targetAddress,token});
    saveServerState();saveAccountCredentials();hideAddForms();
  }catch(e){
    showError('Cloudflare error: '+e.message);
  }finally{
    btn.disabled=false;btn.textContent='Save account';
  }
});

// Account settings (edit)
function openEditAccount(accId){
  const acc=state.accounts.find(a=>a.id===accId);
  if(!acc)return;
  _editingAccountId=accId;
  showAddForm('section-edit-account');
  const isOvh=acc.provider==='ovh';
  const dashUrls={
    simplelogin:'https://app.simplelogin.io/dashboard/api_key',
    addy:'https://app.addy.io/',
    cloudflare:'https://dash.cloudflare.com/',
  };
  document.getElementById('edit-acc-label').value=acc.label||'';
  document.getElementById('edit-acc-token-wrap').style.display=isOvh?'none':'';
  document.getElementById('edit-acc-ovh-wrap').style.display=isOvh?'':'none';
  const tokenInp=document.getElementById('edit-acc-token');
  tokenInp.value=acc.token||'';
  tokenInp.placeholder='API token';
  document.getElementById('edit-acc-ovh-key').value=isOvh?acc.ovhAppKey||'':'';
  document.getElementById('edit-acc-ovh-secret').value=isOvh?acc.ovhAppSecret||'':'';
  if(isOvh){
    _pendingConsumerKey='';
    document.getElementById('btn-edit-acc-authenticate').style.display=acc.consumerKey?'none':'';
    document.getElementById('edit-acc-auth-url-box').textContent='';
    document.getElementById('edit-acc-auth-url-box').classList.remove('visible');
    document.getElementById('edit-acc-auth-url-actions').style.display='none';
    document.getElementById('edit-acc-auth-message').classList.remove('visible');
  }
  const dashUrl=dashUrls[acc.provider]||null;
  const dashLink=document.getElementById('edit-acc-dashboard-link');
  dashLink.href=dashUrl||'#';
  dashLink.style.display=dashUrl?'':'none';
  // Initial status
  const dot=document.getElementById('edit-acc-status-dot');
  const txt=document.getElementById('edit-acc-status-text');
  if(isOvh){
    dot.className='status-dot '+(acc.consumerKey?'green':'orange');
    txt.textContent=acc.consumerKey?'Authenticated':'Not authenticated';
  }else{
    dot.className='status-dot '+(acc.token?'green':'orange');
    txt.textContent=acc.token?'Configured':'Not configured';
  }
}
document.getElementById('btn-cancel-edit-account').addEventListener('click',hideAddForms);
document.getElementById('btn-edit-acc-authenticate').addEventListener('click',async()=>{
  const appKey=document.getElementById('edit-acc-ovh-key').value.trim();
  const appSecret=document.getElementById('edit-acc-ovh-secret').value.trim();
  if(!appKey||!appSecret){showError('Please enter your OVH App Key and App Secret first');return;}
  const btn=document.getElementById('btn-edit-acc-authenticate');
  btn.disabled=true;btn.textContent='Connecting…';
  try{
    const{validationUrl,consumerKey}=await authenticate(appKey,appSecret);
    _pendingConsumerKey=consumerKey;
    const box=document.getElementById('edit-acc-auth-url-box');
    box.textContent=validationUrl;box.classList.add('visible');
    document.getElementById('edit-acc-btn-open-url').href=validationUrl;
    document.getElementById('edit-acc-auth-url-actions').style.display='flex';
    document.getElementById('edit-acc-auth-message').classList.add('visible');
    document.getElementById('edit-acc-status-dot').className='status-dot orange';
    document.getElementById('edit-acc-status-text').textContent='Pending validation…';
  }catch(e){showError('Authentication failed: '+e.message);}
  finally{btn.disabled=false;btn.innerHTML='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Authenticate with OVH';}
});
document.getElementById('edit-acc-btn-copy-url').addEventListener('click',()=>{
  navigator.clipboard.writeText(document.getElementById('edit-acc-auth-url-box').textContent).catch(()=>{});
  document.getElementById('edit-acc-btn-copy-url').textContent='Copied!';
  setTimeout(()=>document.getElementById('edit-acc-btn-copy-url').textContent='Copy URL',1500);
});
document.getElementById('btn-save-edit-account').addEventListener('click',()=>{
  const acc=state.accounts.find(a=>a.id===_editingAccountId);
  if(!acc)return;
  const isOvh=acc.provider==='ovh';
  const newLabel=document.getElementById('edit-acc-label').value.trim();
  if(newLabel)acc.label=newLabel;
  if(isOvh){
    const k=document.getElementById('edit-acc-ovh-key').value.trim();
    const s=document.getElementById('edit-acc-ovh-secret').value.trim();
    if(k)acc.ovhAppKey=k;
    if(s)acc.ovhAppSecret=s;
    if(_pendingConsumerKey)acc.consumerKey=_pendingConsumerKey;
  }else{
    const t=document.getElementById('edit-acc-token').value.trim();
    if(t)acc.token=t;
  }
  saveServerState();
  saveAccountCredentials();
  hideAddForms();
});
document.getElementById('account-list').addEventListener('click',e=>{
  const btn=e.target.closest('.edit-account-btn');
  if(btn)openEditAccount(btn.dataset.accountId);
});

// OVH auth
document.getElementById('btn-authenticate').addEventListener('click',async()=>{
  const appKey=document.getElementById('s-ovh-app-key').value.trim();
  const appSecret=document.getElementById('s-ovh-app-secret').value.trim();
  if(!appKey||!appSecret){showError('Please enter your OVH App Key and App Secret first');return;}
  const btn=document.getElementById('btn-authenticate');btn.disabled=true;btn.textContent='Connecting…';
  try{
    const{validationUrl,consumerKey}=await authenticate(appKey,appSecret);
    _pendingConsumerKey=consumerKey;
    const box=document.getElementById('auth-url-box');box.textContent=validationUrl;box.classList.add('visible');
    document.getElementById('btn-open-url').href=validationUrl;
    document.getElementById('auth-url-actions').style.display='flex';
    document.getElementById('auth-message').classList.add('visible');
    renderSettingsStatus();
  }catch(e){showError('Authentication failed: '+e.message)}
  finally{btn.disabled=false;btn.innerHTML='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Authenticate with OVH'}
});
document.getElementById('btn-copy-url').addEventListener('click',()=>{
  navigator.clipboard.writeText(document.getElementById('auth-url-box').textContent).catch(()=>{});
  document.getElementById('btn-copy-url').textContent='Copied!';
  setTimeout(()=>document.getElementById('btn-copy-url').textContent='Copy URL',1500);
});



['btn-settings','mob-settings'].forEach(id=>document.getElementById(id)?.addEventListener('click',openSettings));
document.getElementById('close-settings').addEventListener('click',closeSettings);
document.getElementById('back-settings').addEventListener('click',hideAddForms);
let _mousedownInsideModal=false;
document.addEventListener('mousedown',e=>{_mousedownInsideModal=!!e.target.closest('.modal,.confirm-box');});
function _hasSelection(){const s=window.getSelection();return s&&s.toString().length>0;}
function _canCloseOverlay(){return!_hasSelection()&&!_mousedownInsideModal;}
document.getElementById('modal-settings').addEventListener('click',e=>{if(e.target===document.getElementById('modal-settings')&&_canCloseOverlay())closeSettings();});

// ── Random alias generator ────────────────────────────────────────────────────
const _RAND_ADJ=['swift','quiet','brave','bright','clean','crisp','dark','deep','fair','fast',
  'fresh','glad','gold','green','iron','keen','kind','light','mild','neat',
  'noble','plain','prime','pure','quick','rare','rich','safe','sharp','slim',
  'smart','soft','still','strong','sure','tidy','true','vast','warm','wise',
  'amber','azure','bold','calm','coral','dry','dusk','early','easy','elder',
  'epic','even','exact','first','fixed','fleet','fluent','free','full','grand',
  'gray','hard','high','hollow','jade','just','last','lean','lone','low',
  'lunar','lush','magic','main','major','meek','mere','mint','muted','new',
  'next','nice','nimble','north','old','olive','open','oval','opal','pale',
  'polar','proud','red','regal','sage','salt','sandy','silent','solar','solid',
  'spare','spry','stern','tall','tame','thin','tough','trim','ultra','urban',
  'vivid','vocal','wild','winter','wooden','young','zero','zeal','jade','cool'];
const _RAND_NOUN=['ash','bay','brook','cliff','cove','creek','dale','dawn','dew','dune',
  'elm','fern','field','flint','fog','ford','glen','grove','hill','isle',
  'lake','leaf','loch','marsh','mist','moor','peak','pine','pond','reef',
  'ridge','rift','rock','sand','sea','sky','snow','stone','storm','vale',
  'arch','basin','bear','birch','bison','blade','bloom','bolt','bone','branch',
  'cave','cedar','chain','cloud','coal','coast','comet','coral','crane','crest',
  'crown','crystal','dust','eagle','ember','falcon','flame','flare','flash','flint',
  'frost','gale','gem','glacier','grain','hawk','haze','hollow','horizon','ice',
  'jade','jaguar','kelp','kite','lantern','lark','lava','ledge','lichen','light',
  'lion','log','lotus','lynx','maple','marble','marsh','mesa','meteor','moss',
  'moth','mud','nebula','needle','nest','night','oak','orbit','otter','owl',
  'path','pebble','petal','plain','prism','quartz','rain','raven','ray','root',
  'rose','rune','rush','seal','shade','shadow','shell','shore','shrub','silver',
  'smoke','soil','spark','spine','spur','star','steel','stream','summit','swan',
  'thorn','tide','timber','torch','trail','trunk','tundra','vapor','vine','wave',
  'weed','willow','wind','wolf','wood','yarn','yew','zenith','zone','zest'];
function generateAliasName(){
  const adj=_RAND_ADJ[Math.floor(Math.random()*_RAND_ADJ.length)];
  const noun=_RAND_NOUN[Math.floor(Math.random()*_RAND_NOUN.length)];
  const num=Math.floor(Math.random()*900)+100;
  return adj+noun+num;
}

// ── New alias modal ───────────────────────────────────────────────────────────
function openAddAlias(){
  setThemeColor(true);
  state.lastSelectedAccountId=null;
  state.selectedSlSignedSuffix=null;
  state.selectedSlSuffix=null;
  renderAccountSelector();
  document.getElementById('alias-name-input').value='';
  document.getElementById('btn-clear-alias-name').style.display='none';
  document.getElementById('alias-note-input').value='';
  document.getElementById('btn-create-alias').disabled=true;
  renderAliasSuggestions();
  _updateAliasPreview();
  document.getElementById('modal-add').classList.add('open');
  setTimeout(()=>document.getElementById('alias-name-input').focus(),80);
  // Pre-fetch SL options for any SL account
  state.accounts.filter(a=>a.provider==='simplelogin').forEach(acc=>{
    slGetOptions(acc).then(()=>{ _updateAliasPreview(); renderAliasSuggestions(); }).catch(()=>{});
  });
}
function _closeMobSearch(){
  const bubble=document.getElementById('mob-search-bubble');
  bubble.classList.remove('open');
  document.getElementById('mob-search').classList.remove('active');
  document.getElementById('mob-search-input').value='';
  state.searchQuery='';
  applyFilter();render();
}
document.getElementById('mob-search')?.addEventListener('click',()=>{
  const bubble=document.getElementById('mob-search-bubble');
  const isOpen=bubble.classList.contains('open');
  if(isOpen){_closeMobSearch();}
  else{
    bubble.classList.add('open');
    document.getElementById('mob-search').classList.add('active');
    document.getElementById('mob-search-input').focus();
  }
});
document.getElementById('mob-search-cancel')?.addEventListener('click',_closeMobSearch);
document.getElementById('mob-search-input')?.addEventListener('input',e=>{
  state.searchQuery=e.target.value;
  applyFilter();render();
});
['btn-add','mob-add'].forEach(id=>document.getElementById(id)?.addEventListener('click',openAddAlias));
document.getElementById('modal-add').addEventListener('click',e=>{if(e.target===document.getElementById('modal-add')&&_canCloseOverlay()){setThemeColor(false);document.getElementById('modal-add').classList.remove('open');}});
document.getElementById('close-add').addEventListener('click',()=>{setThemeColor(false);document.getElementById('modal-add').classList.remove('open');});


function _updateAliasPreview(overrideAccId){
  const val=document.getElementById('alias-name-input').value;
  const accId=overrideAccId||state.lastSelectedAccountId||_getSelectedAccountId();
  const acc=state.accounts.find(a=>a.id===accId);
  const isSL=acc?.provider==='simplelogin';
  const isAddyFree=acc?.provider==='addy'&&!!acc?.isFree;
  const nameField=document.getElementById('alias-name-field');
  const p=document.getElementById('alias-preview'),b=document.getElementById('btn-create-alias');
  const dupErr=document.getElementById('alias-duplicate-error');
  const slSelect=document.getElementById('sl-suffix-select-wrap');
  if(slSelect)slSelect.remove();
  nameField.style.display='';
  const suggestionsWrap=document.getElementById('alias-suggestions-wrap');
  if(suggestionsWrap)suggestionsWrap.style.display='';
  const _pt=t=>{p.innerHTML=`<span>${esc(t)}</span>`;};
  let isDuplicate=false;
  if(isAddyFree){
    nameField.style.display='none';
    if(suggestionsWrap)suggestionsWrap.style.display='none';
    _pt('Auto-generated');
    p.classList.add('alias-preview-placeholder');
    if(dupErr)dupErr.style.display='none';
    b.disabled=false;
    return;
  }
  if(isSL){
    const slOpts=state.slSuffixes[accId];
    const ready=!!val;
    let suffix='@simplelogin.io';
    if(ready){
      if(state.selectedSlSuffix)suffix=state.selectedSlSuffix;
      else if(slOpts?.suffixes?.[0])suffix=slOpts.suffixes[0].suffix;
    }
    _pt((val||'alias')+suffix);
    p.classList.toggle('alias-preview-placeholder',!ready);
    if(dupErr)dupErr.style.display='none';
  }else{
    const domain=acc?.domain||(acc?.account?.includes('@')?acc.account.split('@')[1]:'');
    if(domain){
      const fullAddress=val?val+'@'+domain:'';
      _pt(fullAddress||'alias@'+domain);
      p.classList.toggle('alias-preview-placeholder',!val);
      isDuplicate=!!fullAddress&&state.aliases.some(a=>
        a.accountId===accId&&a.aliasAddress.toLowerCase()===fullAddress.toLowerCase()
      );
      if(dupErr)dupErr.style.display=isDuplicate?'':'none';
    }else{
      _pt('alias@domain.xxx');
      p.classList.add('alias-preview-placeholder');
      if(dupErr)dupErr.style.display='none';
    }
  }
  b.disabled=p.classList.contains('alias-preview-placeholder')||isDuplicate;
  requestAnimationFrame(()=>{
    const span=p.querySelector('span');
    p.classList.toggle('preview-overflow',!!span&&span.scrollWidth>p.clientWidth);
  });
}

document.getElementById('new-alias-account-pills').addEventListener('click',e=>{
  const pill=e.target.closest('.account-pill');if(!pill)return;
  document.querySelectorAll('.account-pill').forEach(p=>p.classList.remove('active'));
  pill.classList.add('active');
  state.lastSelectedAccountId=null;
  state.selectedSlSignedSuffix=null;
  state.selectedSlSuffix=null;
  // Reset active SL suffix on account switch
  document.querySelectorAll('.sl-suffix-row').forEach(r=>r.classList.remove('sl-suffix-active'));
  renderAliasSuggestions();
  _updateAliasPreview();
});

document.getElementById('alias-suggestions').addEventListener('click',e=>{
  const row=e.target.closest('.suggestion-row');if(!row)return;
  const name=row.dataset.name;
  const rowAccId=row.dataset.accountId||null;
  document.querySelectorAll('.account-pill').forEach(p=>{
    p.classList.toggle('active',rowAccId!==null&&p.dataset.accountId===rowAccId);
  });
  // SL suffix row: fill prefix input, update preview (no persistent highlight)
  if(row.classList.contains('sl-suffix-row')){
    document.querySelectorAll('.suggestion-row').forEach(r=>r.classList.remove('suggestion-active','sl-suffix-active'));
    state.selectedSlSignedSuffix=row.dataset.signedSuffix||null;
    state.selectedSlSuffix=row.dataset.suffix||null;
    if(name){document.getElementById('alias-name-input').value=name;document.getElementById('btn-clear-alias-name').style.display='';}
    state.lastSelectedAccountId=row.dataset.accountId||null;
    _updateAliasPreview();
    document.getElementById('alias-name-input').focus();
    return;
  }
  document.querySelectorAll('.suggestion-row').forEach(r=>r.classList.remove('suggestion-active','sl-suffix-active'));
  document.getElementById('alias-name-input').value=name;
  document.getElementById('btn-clear-alias-name').style.display=name?'':'none';
  state.lastSelectedAccountId=row.dataset.accountId||null;
  _updateAliasPreview(row.dataset.accountId);
  document.getElementById('alias-name-input').focus();
});

document.getElementById('alias-name-input').addEventListener('input',e=>{
  const raw=e.target.value,filtered=raw.replace(/[^a-zA-Z0-9_]/g,'');
  if(filtered!==raw)e.target.value=filtered;
  document.getElementById('btn-clear-alias-name').style.display=e.target.value?'':'none';
  // Update SL suffix rows label live without regenerating
  const inputVal=e.target.value.trim();
  document.querySelectorAll('.suggestion-row.sl-suffix-row').forEach(r=>{
    const suffix=r.dataset.suffix||'';
    const opts=state.slSuffixes[r.dataset.accountId];
    const fallback=opts?.prefixSuggestion||r.dataset.name||'';
    const prefix=inputVal||fallback;
    r.dataset.name=prefix;
    const full=r.querySelector('.suggestion-full');
    if(full)full.textContent=prefix+suffix;
  });
  _updateAliasPreview(state.lastSelectedAccountId||undefined);
});
document.getElementById('alias-name-input').addEventListener('keydown',e=>{
  if(e.key==='Enter'&&!document.getElementById('btn-create-alias').disabled)document.getElementById('btn-create-alias').click();
});
document.getElementById('btn-clear-alias-name').addEventListener('click',()=>{
  const inp=document.getElementById('alias-name-input');
  inp.value='';
  document.getElementById('btn-clear-alias-name').style.display='none';
  document.querySelectorAll('.suggestion-row').forEach(r=>r.classList.remove('suggestion-active','sl-suffix-active'));
  _updateAliasPreview();
  inp.focus();
});
document.getElementById('btn-create-alias').addEventListener('click',async()=>{
  const name=document.getElementById('alias-name-input').value.trim();
  const accountId=_getSelectedAccountId();
  const note=document.getElementById('alias-note-input').value.trim();
  document.getElementById('modal-add').classList.remove('open');
  try{
    const newAlias=await createAlias(name,accountId,note);
    if(newAlias?.aliasAddress)copyText(newAlias.aliasAddress);
    hideError();
  }catch(e){showError('Failed to create alias: '+e.message)}
});

// ── Scroll + double-tap guard (mobile) ───────────────────────────────────────
let _isScrolling=false,_scrollTimer=null;
let _lastTapTime=0;
document.querySelector('.content-scroll')?.addEventListener('scroll',()=>{
  _isScrolling=true;
  clearTimeout(_scrollTimer);
  _scrollTimer=setTimeout(()=>{_isScrolling=false;},150);
},{passive:true});

// ── Alias list clicks ─────────────────────────────────────────────────────────
document.getElementById('alias-list').addEventListener('click',e=>{
  if(_isScrolling)return;
  const now=Date.now();
  if(now-_lastTapTime<350){return;}
  _lastTapTime=now;
  const card=e.target.closest('.alias-card');if(!card)return;
  const id=card.dataset.id,accountId=card.dataset.account;
  const alias=state.aliases.find(a=>a.id===id&&a.accountId===accountId);if(!alias)return;
  if(e.target.closest('.delete-btn')){e.stopPropagation();showConfirm(alias);return;}
  if(e.target.closest('.edit-note-btn')){e.stopPropagation();openEditNote(alias);return;}
  if(e.target.closest('.contacts-btn')){e.stopPropagation();openContactsModal(alias);return;}
  if(e.target.closest('.disable-btn')){e.stopPropagation();
    disableAlias(alias).catch(e=>showError('Failed to disable: '+e.message));return;}
  if(e.target.closest('.enable-btn')){e.stopPropagation();
    enableAlias(alias).catch(e=>showError('Failed to re-enable: '+e.message));return;}
  if(e.target.closest('.copy-btn'))copyText(alias.aliasAddress,card);
});

// ── SL Contacts modal ────────────────────────────────────────────────────────
let _contactsAlias=null;

async function openContactsModal(alias){
  setThemeColor(true);
  _contactsAlias=alias;
  const labelEl=document.getElementById('contacts-alias-address');
  labelEl.textContent=alias.aliasAddress;
  labelEl.className='field-preview contacts-alias-label'+(alias.provider==='addy'?' contacts-alias-label-addy':'');
  document.getElementById('contacts-new-email').value='';
  document.getElementById('contacts-error').style.display='none';
  document.getElementById('btn-create-contact').disabled=false;
  document.getElementById('modal-sl-contacts').classList.add('open');
  if(alias.provider==='addy'){
    _renderContactsList(state.addyContacts[alias.id]||[]);
  }else{
    _renderContactsLoading();
    try{
      const contacts=await slFetchContacts(alias);
      _renderContactsList(contacts);
    }catch(e){
      _renderContactsError(e.message);
    }
  }
}

function closeContactsModal(){
  setThemeColor(false);
  _contactsAlias=null;
  document.getElementById('modal-sl-contacts').classList.remove('open');
}

function _renderContactsLoading(){
  document.getElementById('contacts-list').innerHTML='<div class="contacts-loading"><div class="spinner"></div></div>';
}

function _renderContactsError(msg){
  document.getElementById('contacts-list').innerHTML=`<div class="contacts-empty">Error: ${esc(msg)}</div>`;
}

function _renderContactsList(contacts){
  const el=document.getElementById('contacts-list');
  const isAddy=_contactsAlias?.provider==='addy';
  if(!contacts.length){
    el.innerHTML='<div class="contacts-empty">No contacts yet. Create one to get a reverse alias.</div>';
    return;
  }
  el.innerHTML=contacts.map(c=>{
    let reverse,email,blocked=false,contactId;
    if(isAddy){
      email=c.email;reverse=c.reverse;contactId=c.email;
    }else{
      const raw=c.reverse_alias||'';
      const match=raw.match(/<([^>]+)>/);
      reverse=match?match[1]:raw;
      email=c.contact;blocked=!!c.block_forward;contactId=String(c.id);
    }
    return`<div class="contact-item${blocked?' contact-blocked':''}" data-contact-id="${esc(contactId)}">
      <div class="contact-info">
        <div class="contact-email">${esc(email)}</div>
        <div class="contact-reverse">${esc(reverse)}</div>
      </div>
      <div class="contact-actions">
        ${isAddy?`
        <button class="icon-btn delete-contact-btn" data-contact-email="${esc(email)}" title="Delete contact">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
          </svg>
        </button>`:`
        <button class="icon-btn block-contact-btn${blocked?' blocked-active':''}" data-contact-id="${esc(contactId)}" title="${blocked?'Unblock sender':'Block sender'}">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
          </svg>
        </button>`}
        <button class="icon-btn copy-reverse-btn" data-reverse="${esc(reverse)}" title="Copy reverse alias">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
      </div>
    </div>`;
  }).join('');
}

document.getElementById('modal-sl-contacts').addEventListener('click',e=>{
  if(e.target===document.getElementById('modal-sl-contacts')&&_canCloseOverlay())closeContactsModal();
  const copyBtn=e.target.closest('.copy-reverse-btn');
  if(copyBtn){const rev=copyBtn.dataset.reverse;if(rev)copyText(rev,copyBtn);}
  const deleteBtn=e.target.closest('.delete-contact-btn');
  if(deleteBtn&&_contactsAlias?.provider==='addy'){
    const email=deleteBtn.dataset.contactEmail;
    if(!email||!_contactsAlias)return;
    const list=state.addyContacts[_contactsAlias.id]||[];
    state.addyContacts[_contactsAlias.id]=list.filter(c=>c.email!==email);
    saveAddyContacts();
    _renderContactsList(state.addyContacts[_contactsAlias.id]);
  }
  const blockBtn=e.target.closest('.block-contact-btn');
  if(blockBtn){
    const id=blockBtn.dataset.contactId;
    if(!id)return;
    blockBtn.disabled=true;
    slToggleContact(id).then(blocked=>{
      const item=document.querySelector(`.contact-item[data-contact-id="${id}"]`);
      if(item){
        item.classList.toggle('contact-blocked',blocked);
        blockBtn.classList.toggle('blocked-active',blocked);
        blockBtn.title=blocked?'Unblock sender':'Block sender';
      }
    }).catch(e=>showError('Failed to toggle block: '+e.message))
    .finally(()=>{blockBtn.disabled=false;});
  }
});
document.getElementById('close-sl-contacts').addEventListener('click',closeContactsModal);
document.getElementById('btn-create-contact').addEventListener('click',async()=>{
  const email=document.getElementById('contacts-new-email').value.trim();
  const errEl=document.getElementById('contacts-error');
  if(!email||!email.includes('@')){errEl.textContent='Please enter a valid email address.';errEl.style.display='';return;}
  if(!_contactsAlias)return;
  const btn=document.getElementById('btn-create-contact');
  btn.disabled=true;btn.textContent='Creating…';
  errEl.style.display='none';
  if(_contactsAlias.provider==='addy'){
    try{
      if(!state.addyContacts[_contactsAlias.id])state.addyContacts[_contactsAlias.id]=[];
      if(state.addyContacts[_contactsAlias.id].find(c=>c.email===email)){
        errEl.textContent='This contact already exists.';errEl.style.display='';return;
      }
      const reverse=addyBuildReverseAddress(_contactsAlias.aliasAddress,email);
      state.addyContacts[_contactsAlias.id].push({email,reverse});
      await saveAddyContacts();
      document.getElementById('contacts-new-email').value='';
      _renderContactsList(state.addyContacts[_contactsAlias.id]);
      copyText(reverse);
    }catch(e){errEl.textContent=e.message;errEl.style.display='';}
    finally{btn.disabled=false;btn.textContent='Create reverse alias';}
  }else{
    try{
      await slCreateContact(_contactsAlias,email);
      document.getElementById('contacts-new-email').value='';
      const contacts=await slFetchContacts(_contactsAlias);
      _renderContactsList(contacts);
    }catch(e){errEl.textContent=e.message;errEl.style.display='';}
    finally{btn.disabled=false;btn.textContent='Create reverse alias';}
  }
});

// ── Edit Note modal ───────────────────────────────────────────────────────────
let _editNoteAlias=null;
function openEditNote(alias){
  setThemeColor(true);
  _editNoteAlias=alias;
  document.getElementById('edit-note-alias-address').textContent=alias.aliasAddress;
  document.getElementById('edit-note-input').value=state.notes[alias.aliasAddress]||'';
  document.getElementById('modal-edit-note').classList.add('open');
  setTimeout(()=>document.getElementById('edit-note-input').focus(),80);
}
function closeEditNote(){
  setThemeColor(false);
  _editNoteAlias=null;
  document.getElementById('modal-edit-note').classList.remove('open');
}
document.getElementById('close-edit-note').addEventListener('click',closeEditNote);
document.getElementById('btn-cancel-edit-note').addEventListener('click',closeEditNote);
document.getElementById('modal-edit-note').addEventListener('click',e=>{if(e.target===document.getElementById('modal-edit-note')&&_canCloseOverlay())closeEditNote();});
document.getElementById('btn-save-note').addEventListener('click',async()=>{
  if(!_editNoteAlias)return;
  const note=document.getElementById('edit-note-input').value.trim();
  const addr=_editNoteAlias.aliasAddress;
  if(note)state.notes[addr]=note;
  else delete state.notes[addr];
  if(_editNoteAlias.provider==='simplelogin')
    slUpdateNote(_editNoteAlias,note).catch(()=>{});
  else if(_editNoteAlias.provider==='addy')
    addyUpdateNote(_editNoteAlias,note).catch(()=>{});
  closeEditNote();
  _lastListKey='';
  applyFilter();render();
  await saveNotes();
});

// ── Confirm delete ────────────────────────────────────────────────────────────
function showConfirm(alias){
  setThemeColor(true);
  state.pendingDeleteAlias=alias;
  document.getElementById('confirm-alias-name').textContent=alias.aliasAddress;
  document.getElementById('confirm-overlay').classList.add('open');
}
document.getElementById('confirm-cancel').addEventListener('click',()=>{setThemeColor(false);state.pendingDeleteAlias=null;document.getElementById('confirm-overlay').classList.remove('open');});
document.getElementById('confirm-delete').addEventListener('click',async()=>{
  setThemeColor(false);
  const alias=state.pendingDeleteAlias;state.pendingDeleteAlias=null;document.getElementById('confirm-overlay').classList.remove('open');
  if(!alias)return;
  try{await deleteAlias(alias);hideError()}catch(e){showError('Failed to delete: '+e.message)}
});
document.getElementById('confirm-overlay').addEventListener('click',e=>{
  if(e.target===document.getElementById('confirm-overlay')&&_canCloseOverlay()){setThemeColor(false);state.pendingDeleteAlias=null;document.getElementById('confirm-overlay').classList.remove('open');}
});

// ── Refresh ───────────────────────────────────────────────────────────────────
['btn-refresh','mob-refresh'].forEach(id=>document.getElementById(id)?.addEventListener('click',()=>{if(canAddAlias())loadAliases();}));

// ── Search ────────────────────────────────────────────────────────────────────
document.getElementById('search-clear').addEventListener('click',()=>{
  const inp=document.getElementById('search-input');
  inp.value='';
  document.getElementById('search-clear').style.display='none';
  state.searchQuery='';
  applyFilter();render();
  inp.focus();
});
document.getElementById('search-input').addEventListener('input',e=>{
  state.searchQuery=e.target.value;document.getElementById('search-clear').style.display=e.target.value?'':'none';applyFilter();render();
});

// ── Init ──────────────────────────────────────────────────────────────────────
// Enable :active states on iOS Safari (requires at least one touchstart listener on document)
document.addEventListener('touchstart',()=>{},{passive:true});

Promise.all([loadServerState(),loadNotes(),loadCredentials(),loadAddyContacts()]).then(async()=>{
  mergeCredentialsIntoAccounts();
  if(migrateTokensIfNeeded()){
    await Promise.all([saveAccountCredentials(),saveServerState()]);
  }
  render();
  if(canAddAlias())loadAliases();
});
