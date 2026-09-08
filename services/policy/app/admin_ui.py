from __future__ import annotations


ADMIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>AI Gateway Guardrail Console</title>
  <style>
    :root {
      color-scheme:dark; --bg:#080d13; --panel:#111923; --panel2:#0c131c;
      --line:#293646; --text:#edf4fa; --muted:#91a2b5; --accent:#42c2b8;
      --accent2:#276b78; --bad:#ff6b78; --warn:#f4bf5f; --good:#68d391;
    }
    * { box-sizing:border-box; }
    body { margin:0; background:linear-gradient(150deg,#080d13 0%,#0b1320 55%,#071015 100%); color:var(--text); font:14px/1.45 Inter,ui-sans-serif,system-ui,sans-serif; min-height:100vh; }
    header { position:sticky; top:0; z-index:5; padding:15px 22px; border-bottom:1px solid var(--line); background:rgba(8,13,19,.95); backdrop-filter:blur(10px); display:flex; gap:14px; align-items:center; flex-wrap:wrap; }
    h1,h2,h3,p { margin-top:0; }
    h1 { margin-bottom:0; font-size:20px; letter-spacing:.01em; }
    h2 { margin-bottom:13px; font-size:16px; }
    h3 { margin:16px 0 8px; color:#d6e3ee; font-size:13px; text-transform:uppercase; letter-spacing:.08em; }
    main { max-width:1480px; margin:auto; padding:20px; display:grid; gap:16px; grid-template-columns:minmax(320px,.82fr) minmax(480px,1.45fr); }
    section { background:rgba(17,25,35,.96); border:1px solid var(--line); border-radius:12px; padding:16px; min-width:0; box-shadow:0 10px 30px rgba(0,0,0,.15); }
    .wide { grid-column:1/-1; }
    .subpanel { background:var(--panel2); border:1px solid var(--line); border-radius:9px; padding:12px; }
    .grid2,.grid3,.grid4 { display:grid; gap:10px; }
    .grid2 { grid-template-columns:repeat(2,minmax(0,1fr)); }
    .grid3 { grid-template-columns:repeat(3,minmax(0,1fr)); }
    .grid4 { grid-template-columns:repeat(4,minmax(0,1fr)); }
    .cards { display:grid; grid-template-columns:repeat(5,minmax(150px,1fr)); gap:10px; }
    .card { background:var(--panel2); border:1px solid var(--line); border-radius:9px; padding:12px; }
    .card strong { display:block; font-size:22px; margin-top:3px; }
    .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
    label { display:block; color:var(--muted); margin:8px 0 4px; }
    .check { display:flex; gap:7px; align-items:center; color:var(--text); margin:5px 0; }
    .check input { width:auto; margin:0; }
    input,textarea,select,button { font:inherit; }
    input,textarea,select { width:100%; color:var(--text); background:#09111a; border:1px solid var(--line); border-radius:7px; padding:8px 9px; }
    input:focus,textarea:focus,select:focus { outline:2px solid rgba(66,194,184,.35); border-color:var(--accent); }
    textarea { min-height:82px; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; resize:vertical; }
    button { color:#061111; background:var(--accent); border:0; border-radius:7px; padding:8px 12px; cursor:pointer; font-weight:700; }
    button:hover { filter:brightness(1.08); }
    button.secondary { background:#283647; color:var(--text); }
    button.danger { background:var(--bad); color:#21080c; }
    button:disabled { opacity:.45; cursor:not-allowed; }
    .nav-link { color:var(--text); border:1px solid var(--line); border-radius:7px; padding:7px 10px; text-decoration:none; font-weight:700; }
    .nav-link:hover { border-color:var(--accent); }
    body.auth-required .admin-control { opacity:.38; filter:grayscale(.35); }
    .actions { display:flex; gap:8px; margin-top:12px; flex-wrap:wrap; }
    .toolbar { display:flex; gap:8px; align-items:end; flex-wrap:wrap; margin-bottom:10px; }
    .toolbar > div { min-width:150px; flex:1; }
    table { width:100%; border-collapse:collapse; }
    th,td { text-align:left; border-bottom:1px solid var(--line); padding:8px; vertical-align:top; }
    th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
    tbody tr:hover { background:rgba(255,255,255,.025); }
    code,pre { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
    pre { white-space:pre-wrap; word-break:break-word; background:#081018; border:1px solid var(--line); border-radius:7px; padding:10px; min-height:54px; margin:8px 0 0; }
    .muted { color:var(--muted); }
    .error { color:var(--bad)!important; }
    .ok { color:var(--good)!important; }
    .warning { color:var(--warn)!important; }
    .pill { display:inline-block; padding:2px 7px; border-radius:999px; background:#263444; font-size:12px; }
    .pill.allow { color:var(--good); } .pill.block,.pill.error { color:var(--bad); }
    .category-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:4px 10px; }
    .scroll { overflow:auto; max-height:420px; }
    .help { color:var(--muted); font-size:12px; margin:5px 0 0; }
    #auth { min-width:260px; flex:1; max-width:560px; }
    #status { color:var(--muted); min-width:130px; }
    @media (max-width:1000px) { main { grid-template-columns:1fr; } .wide { grid-column:auto; } .cards,.grid4 { grid-template-columns:repeat(2,minmax(0,1fr)); } }
    @media (max-width:620px) { .grid2,.grid3,.grid4,.cards,.category-grid { grid-template-columns:1fr; } main { padding:10px; } }
  </style>
</head>
<body class="auth-required">
<header>
  <h1>AI Gateway Guardrail Console</h1>
  <a class="nav-link" href="/">Back to AI Gateway</a>
  <div id="auth"><input id="token" type="password" autocomplete="off" placeholder="Optional recovery token"></div>
  <button id="connect">Use recovery token</button>
  <button id="disconnect" class="secondary">Clear recovery token</button>
  <span id="status" role="status" aria-live="polite">Checking gateway administrator session</span>
</header>
<main>
  <section class="wide">
    <h2>Operational readiness</h2>
    <div class="cards">
      <div class="card"><span class="label">Policy service</span><strong id="ready-state">Checking</strong><span id="ready-detail" class="muted">/readyz</span></div>
      <div class="card"><span class="label">Enabled profiles</span><strong id="profile-count">â€”</strong><span class="muted">managed policies</span></div>
      <div class="card"><span class="label">Assignments</span><strong id="assignment-count">â€”</strong><span class="muted">user / group / agent</span></div>
      <div class="card"><span class="label">Recent blocks</span><strong id="blocked-count">â€”</strong><span class="muted">loaded audit window</span></div>
      <div class="card"><span class="label">External spend</span><strong id="external-spend">â€”</strong><span id="external-spend-detail" class="muted">selected profile / month</span></div>
    </div>
  </section>

  <section class="admin-control">
    <h2>Profiles</h2>
    <div class="scroll"><table><thead><tr><th>ID</th><th>Name</th><th>State</th><th></th></tr></thead><tbody id="profiles"></tbody></table></div>
    <div class="actions">
      <button id="new-profile" class="secondary">New</button>
      <button id="clone-profile" class="secondary">Clone selected</button>
      <button id="export-config" class="secondary">Download configuration</button>
      <button id="import-config" class="secondary">Restore configuration</button>
      <input id="import-file" type="file" accept="application/json,.json" hidden>
    </div>
  </section>

  <section class="admin-control">
    <h2>Profile editor</h2>
    <div class="grid2"><div><label>ID</label><input id="profile-id" maxlength="64" placeholder="finance-users"></div><div><label>Name</label><input id="profile-name" maxlength="128"></div></div>
    <label>Description</label><input id="profile-description" maxlength="1000">
    <label class="check"><input id="profile-enabled" type="checkbox"> Enabled</label>

    <h3>Content categories</h3>
    <div class="grid2">
      <div class="subpanel"><strong>Block in prompts</strong><div id="input-categories" class="category-grid"></div><label>Additional categories, one per line</label><textarea id="input-custom" rows="2"></textarea></div>
      <div class="subpanel"><strong>Block in responses</strong><div id="output-categories" class="category-grid"></div><label>Additional categories, one per line</label><textarea id="output-custom" rows="2"></textarea></div>
    </div>

    <h3>Models and tools</h3>
    <div class="grid2">
      <div><label>Allowed model IDs, one per line</label><textarea id="allowed-models"></textarea></div>
      <div><label>Allowed tool names, one per line</label><textarea id="allowed-tools"></textarea></div>
    </div>

    <h3>Limits and capabilities</h3>
    <div class="grid3">
      <div><label>Maximum prompt characters</label><input id="max-input" type="number" min="1" max="2000000"></div>
      <div><label>Local completion tokens</label><input id="local-tokens" type="number" min="1" max="32768"></div>
      <div><label>External completion tokens</label><input id="external-tokens" type="number" min="1" max="32768"></div>
    </div>
    <div class="grid3">
      <label class="check"><input id="allow-external" type="checkbox"> Allow external routing</label>
      <label class="check"><input id="memory-read" type="checkbox"> Allow memory reads</label>
      <label class="check"><input id="memory-write" type="checkbox"> Allow memory writes</label>
    </div>

    <h3>Managed routing</h3>
    <div class="grid3">
      <div><label>Routing mode</label><select id="routing-mode"><option value="local_only">Local only</option><option value="local_first">Local first, governed escalation</option><option value="external_only">External only</option></select></div>
      <div><label>Classifier confidence threshold</label><input id="classifier-threshold" type="number" min="0" max="1" step="0.05"></div>
      <div><label>Escalate prompts longer than characters (0 disables)</label><input id="complexity-threshold" type="number" min="0" max="2000000"></div>
    </div>
    <div class="grid3">
      <label class="check"><input id="classifier-enabled" type="checkbox"> Use local model as routing classifier</label>
      <label class="check"><input id="external-for-tools" type="checkbox"> Escalate tool-capable requests</label>
      <label class="check"><input id="fallback-local-error" type="checkbox"> Escalate after a local provider failure</label>
    </div>
    <label class="check"><input id="allow-route-override" type="checkbox"> Permit end users to force /local or /external</label>
    <label>External task hints, one phrase per line</label><textarea id="external-task-hints"></textarea>

    <h3>Paid-provider budget</h3>
    <div class="grid3">
      <div><label>Calendar-month budget (USD)</label><input id="external-budget" type="number" min="0" max="1000000" step="0.01"></div>
      <div><label>Input price / 1M tokens (USD)</label><input id="external-input-price" type="number" min="0" max="10000" step="0.0001"></div>
      <div><label>Output price / 1M tokens (USD)</label><input id="external-output-price" type="number" min="0" max="10000" step="0.0001"></div>
    </div>
    <p class="help">External routing fails closed until this profile allows it and has a positive monthly budget and reviewed input/output pricing. Secrets remain outside this console.</p>
    <div class="actions">
      <button id="save-profile">Save profile</button>
      <button id="test-external-provider" class="secondary">Test external provider</button>
      <button id="delete-profile" class="danger">Delete profile</button>
    </div>
  </section>

  <section class="wide admin-control">
    <h2>End-user, group, and agent assignments</h2>
    <div class="toolbar">
      <div><label>Subject type</label><select id="assignment-type"><option value="user">User</option><option value="group" selected>Group / team</option><option value="agent">Agent</option></select></div>
      <div><label>End user / team / agent</label><input id="assignment-subject" list="assignment-subject-options" placeholder="Select a user/team or enter an agent ID"><datalist id="assignment-subject-options"></datalist></div>
      <div><label>Profile</label><select id="assignment-profile"></select></div>
      <div><label>Priority</label><input id="assignment-priority" type="number" value="100" min="-10000" max="10000"></div>
      <div style="flex:0"><button id="save-assignment">Assign</button></div>
    </div>
    <p id="assignment-directory-status" class="help">Loading authorized users and teams. User assignments win over agent assignments, which win over group assignments.</p>
    <div class="scroll"><table><thead><tr><th>Type</th><th>Subject</th><th>Profile</th><th>Priority</th><th></th></tr></thead><tbody id="assignments"></tbody></table></div>
  </section>

  <section class="wide admin-control">
    <h2>Effective-policy tester</h2>
    <div class="toolbar">
      <div><label>User ID</label><input id="effective-user" value="policy-preview-user"></div>
      <div><label>Agent ID</label><input id="effective-agent" value="policy-preview-agent"></div>
      <div><label>Group IDs, comma-separated</label><input id="effective-groups"></div>
      <div style="flex:0"><button id="resolve-effective">Resolve</button></div>
    </div>
    <pre id="effective-result">Connect, enter the intended user/team/agent identity, and resolve before assigning access.</pre>
  </section>

  <section class="wide admin-control">
    <h2>Managed client credentials</h2>
    <p class="help">Issue a separate credential for each user and client. The plaintext key is shown exactly once; only its SHA-256 hash and non-secret prefix are stored. Revoking one key does not interrupt other users or the internal Archestra route.</p>
    <div class="toolbar">
      <div><label>Credential name</label><input id="client-key-name" placeholder="Rick - VS Code"></div>
      <div><label>End-user ID</label><input id="client-key-user" list="client-key-user-options" placeholder="Select an authorized user or enter a stable ID"><datalist id="client-key-user-options"></datalist></div>
      <div><label>Client / agent ID</label><input id="client-key-agent" value="managed-client" placeholder="vscode, msty, cli"></div>
      <div><label>Team IDs, comma-separated</label><input id="client-key-groups" list="client-key-group-options" placeholder="Managed team UUID"><datalist id="client-key-group-options"></datalist></div>
      <div><label>Expires (optional)</label><input id="client-key-expires" type="datetime-local"></div>
      <div style="flex:0"><button id="issue-client-key">Issue key</button></div>
    </div>
    <div class="grid2">
      <div class="subpanel"><strong>One-time key delivery</strong><pre id="issued-client-key">No key has been issued in this browser session.</pre><div class="actions"><button id="copy-client-key" class="secondary" disabled>Copy key</button><button id="clear-client-key" class="secondary">Clear display</button></div></div>
      <div class="subpanel"><strong>Client defaults</strong><p><code>Base URL: <span id="client-base-url"></span>/gateway/v1</code><br><code>Model: gateway-auto</code><br><code>Authentication: Bearer &lt;issued key&gt;</code></p><p class="help">The workstation must trust the Gateway gateway CA. Do not configure the local-model or OpenAI provider directly; that bypasses the managed route.</p></div>
    </div>
    <div class="scroll"><table><thead><tr><th>Name</th><th>User / client</th><th>Teams</th><th>Prefix</th><th>State</th><th>Last used</th><th></th></tr></thead><tbody id="client-credentials"></tbody></table></div>
  </section>

  <section class="wide admin-control">
    <h2>Guardrail decisions</h2>
    <div class="toolbar">
      <div><label>Search</label><input id="audit-search" placeholder="user, agent, profile, category, request"></div>
      <div><label>Decision</label><select id="audit-decision"><option value="">All</option><option>allow</option><option>block</option><option>error</option></select></div>
      <div><label>Stage</label><select id="audit-stage"><option value="">All</option><option>input</option><option>output</option><option>route</option></select></div>
      <div><label>Rows</label><select id="audit-limit"><option>100</option><option>250</option><option>500</option><option>1000</option></select></div>
      <div style="flex:0"><button id="refresh-audit" class="secondary">Refresh</button></div>
    </div>
    <div class="scroll"><table><thead><tr><th>Time</th><th>User / agent</th><th>Profile</th><th>Decision</th><th>Stage</th><th>Categories / route</th><th>Request</th></tr></thead><tbody id="audit"></tbody></table></div>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
const knownCategories = [
  ['private_key','Private keys'],['bearer_token','Bearer tokens'],['openai_style_key','OpenAI-style keys'],
  ['github_token','GitHub tokens'],['aws_access_key','AWS access keys'],['us_ssn','US SSNs'],
  ['payment_card','Payment cards'],['email_address','Email addresses'],['phone_number','Phone numbers']
];
const defaultBlocked = ['private_key','bearer_token','openai_style_key','github_token','aws_access_key','us_ssn','payment_card'];
const servicePrefix = window.location.pathname.startsWith('/guardrails/') ? '/guardrails' : '';
const servicePath = path => `${servicePrefix}${path}`;
let token = sessionStorage.getItem('guardrailAdminToken') || '';
let profileCache = [], assignmentCache = [], auditCache = [], clientCredentialCache = [], selectedProfile = null;
let directoryCache = {users:[],groups:[]};
let issuedClientKey = '';

function setStatus(message, kind='') { $('status').textContent=message; $('status').className=kind; }
function setConsoleLocked(locked){document.body.classList.toggle('auth-required',locked);document.querySelectorAll('.admin-control').forEach(section=>{section.inert=locked;section.setAttribute('aria-disabled',String(locked));});}
function showAuthorizationError(error){setConsoleLocked(true);const message=String(error?.message||error);if(message.startsWith('401:'))setStatus('Sign in to AI Gateway as an administrator in this browser, then reload this page â€” or use the recovery token.','error');else if(message.startsWith('403:'))setStatus('The signed-in account is not authorized to administer gateway guardrails.','error');else setStatus(message,'error');}
async function api(path, options={}) {
  const headers={'Content-Type':'application/json',...(options.headers||{})};
  if(token)headers.Authorization=`Bearer ${token}`;
  const response=await fetch(servicePath(path),{...options,credentials:'same-origin',headers});
  if(!response.ok) throw new Error(`${response.status}: ${await response.text()}`);
  if(response.status===204) return null;
  return response.json();
}
function cell(row,value){const td=document.createElement('td');td.textContent=value??'';row.appendChild(td);return td;}
function button(label,className,handler){const b=document.createElement('button');b.type='button';b.textContent=label;b.className=className||'secondary';b.onclick=handler;return b;}
function lines(id){return $(id).value.split(/\r?\n|,/).map(x=>x.trim()).filter((x,i,a)=>x&&a.indexOf(x)===i);}
function setLines(id,values){$(id).value=(values||[]).join('\n');}
function integer(id){const value=Number($(id).value);if(!Number.isInteger(value))throw new Error(`${id} must be a whole number`);return value;}
function number(id){const value=Number($(id).value);if(!Number.isFinite(value))throw new Error(`${id} must be numeric`);return value;}
function escapeQuery(value){return encodeURIComponent(value);}
function checkboxes(containerId,prefix){const root=$(containerId);root.replaceChildren();knownCategories.forEach(([value,label])=>{const wrapper=document.createElement('label');wrapper.className='check';const input=document.createElement('input');input.type='checkbox';input.id=`${prefix}-${value}`;input.value=value;wrapper.append(input,document.createTextNode(label));root.appendChild(wrapper);});}
function selectedCategories(prefix){return knownCategories.filter(([value])=>$(`${prefix}-${value}`).checked).map(([value])=>value);}
function setCategories(prefix,customId,values){const set=new Set(values||[]);knownCategories.forEach(([value])=>$(`${prefix}-${value}`).checked=set.has(value));setLines(customId,[...set].filter(value=>!knownCategories.some(([known])=>known===value)));}
function allCategories(prefix,customId){return [...selectedCategories(prefix),...lines(customId)].filter((x,i,a)=>a.indexOf(x)===i);}

function settingsFromForm(){return {
  input_block_categories:allCategories('input','input-custom'),
  output_block_categories:allCategories('output','output-custom'),
  allowed_models:lines('allowed-models'),routing_mode:$('routing-mode').value,
  allow_external:$('allow-external').checked,classifier_enabled:$('classifier-enabled').checked,
  classifier_confidence_threshold:number('classifier-threshold'),
  allow_user_route_override:$('allow-route-override').checked,
  fallback_on_local_error:$('fallback-local-error').checked,
  external_for_tools:$('external-for-tools').checked,
  external_complexity_threshold_chars:integer('complexity-threshold'),
  external_task_hints:lines('external-task-hints'),
  external_monthly_budget_usd:number('external-budget'),
  external_input_cost_per_million_usd:number('external-input-price'),
  external_output_cost_per_million_usd:number('external-output-price'),
  allowed_tools:lines('allowed-tools'),max_input_chars:integer('max-input'),
  local_max_completion_tokens:integer('local-tokens'),external_max_completion_tokens:integer('external-tokens'),
  memory_read:$('memory-read').checked,memory_write:$('memory-write').checked
};}
function editProfile(profile){selectedProfile=profile;$('profile-id').value=profile.id;$('profile-name').value=profile.name;$('profile-description').value=profile.description||'';$('profile-enabled').checked=profile.enabled;$('profile-id').disabled=profile.id==='default';const s=profile.settings;setCategories('input','input-custom',s.input_block_categories);setCategories('output','output-custom',s.output_block_categories);setLines('allowed-models',s.allowed_models);setLines('allowed-tools',s.allowed_tools);setLines('external-task-hints',s.external_task_hints);$('max-input').value=s.max_input_chars;$('local-tokens').value=s.local_max_completion_tokens;$('external-tokens').value=s.external_max_completion_tokens;$('routing-mode').value=s.routing_mode;$('allow-external').checked=s.allow_external;$('classifier-enabled').checked=s.classifier_enabled;$('classifier-threshold').value=s.classifier_confidence_threshold;$('allow-route-override').checked=s.allow_user_route_override;$('fallback-local-error').checked=s.fallback_on_local_error;$('external-for-tools').checked=s.external_for_tools;$('complexity-threshold').value=s.external_complexity_threshold_chars;$('external-budget').value=s.external_monthly_budget_usd;$('external-input-price').value=s.external_input_cost_per_million_usd;$('external-output-price').value=s.external_output_cost_per_million_usd;$('memory-read').checked=s.memory_read;$('memory-write').checked=s.memory_write;loadUsage(profile.id).catch(error=>setStatus(error.message,'error'));}
document.getElementById('client-base-url').textContent=window.location.origin;
function blankProfile(){editProfile({id:'',name:'',description:'',enabled:true,settings:{input_block_categories:defaultBlocked,output_block_categories:defaultBlocked,allowed_models:['gateway-auto','granite4.1:3b'],routing_mode:'local_only',allow_external:false,classifier_enabled:true,classifier_confidence_threshold:.7,allow_user_route_override:false,fallback_on_local_error:true,external_for_tools:false,external_complexity_threshold_chars:8000,external_task_hints:['architecture','code review','review this code','debug','deep research','legal analysis','medical analysis','security review'],external_monthly_budget_usd:0,external_input_cost_per_million_usd:0,external_output_cost_per_million_usd:0,allowed_tools:[],max_input_chars:20000,local_max_completion_tokens:512,external_max_completion_tokens:1024,memory_read:true,memory_write:true}});$('profile-id').disabled=false;}
function cloneProfile(){if(!selectedProfile)throw new Error('Select a profile to clone');const clone=structuredClone(selectedProfile);clone.id='';clone.name=`${clone.name} copy`;editProfile(clone);$('profile-id').disabled=false;setStatus('Enter a new profile ID, review the controls, then save','warning');}

async function loadReadiness(){try{const response=await fetch(servicePath('/readyz'),{credentials:'same-origin'});const data=await response.json();if(!response.ok)throw new Error(data.detail?.status||response.status);$('ready-state').textContent='Ready';$('ready-state').className='ok';$('ready-detail').textContent=`DB ${data.guardrail_database}; identity ${data.signed_identity}`;}catch(error){$('ready-state').textContent='Degraded';$('ready-state').className='error';$('ready-detail').textContent=error.message;}}
async function loadProfiles(){profileCache=await api('/admin/api/profiles');const body=$('profiles');body.replaceChildren();const select=$('assignment-profile');select.replaceChildren();profileCache.forEach(profile=>{const row=document.createElement('tr');cell(row,profile.id);cell(row,profile.name);const state=cell(row,profile.enabled?'enabled':'disabled');state.className=profile.enabled?'ok':'warning';const action=cell(row,'');action.appendChild(button('Edit','secondary',()=>editProfile(profile)));body.appendChild(row);const option=document.createElement('option');option.value=profile.id;option.textContent=`${profile.id} â€” ${profile.name}`;select.appendChild(option);});$('profile-count').textContent=profileCache.filter(x=>x.enabled).length;if(!selectedProfile?.id&&profileCache.length)editProfile(profileCache.find(x=>x.id==='archestra-managed')||profileCache[0]);}
function directoryItems(type){return type==='user'?directoryCache.users:type==='group'?directoryCache.groups:[];}
function directoryLabel(type,id){const found=directoryItems(type).find(item=>item.id===id);return found?`${found.label} (${id})`:id;}
function renderDirectoryOptions(){const type=$('assignment-type').value,options=$('assignment-subject-options');options.replaceChildren();directoryItems(type).forEach(item=>{const option=document.createElement('option');option.value=item.id;option.label=item.label;options.appendChild(option);});$('assignment-directory-status').textContent=type==='agent'?'Enter the stable agent ID. User assignments win over agent assignments, which win over group assignments.':`${directoryItems(type).length} authorized ${type==='user'?'user(s)':'team(s)'} loaded. Select one by name or paste its stable ID.`;}
function renderClientDirectoryOptions(){const users=$('client-key-user-options'),groups=$('client-key-group-options');users.replaceChildren();groups.replaceChildren();directoryCache.users.forEach(item=>{const option=document.createElement('option');option.value=item.id;option.label=item.label;users.appendChild(option);});directoryCache.groups.forEach(item=>{const option=document.createElement('option');option.value=item.id;option.label=item.label;groups.appendChild(option);});}
async function loadDirectory(){try{directoryCache=await api('/admin/api/directory');renderDirectoryOptions();renderClientDirectoryOptions();}catch(error){directoryCache={users:[],groups:[]};renderDirectoryOptions();renderClientDirectoryOptions();$('assignment-directory-status').textContent=`Directory unavailable: ${error.message}. Stable IDs may still be entered manually.`;}}
async function loadAssignments(){assignmentCache=await api('/admin/api/assignments');const body=$('assignments');body.replaceChildren();assignmentCache.forEach(item=>{const row=document.createElement('tr');cell(row,item.subject_type);cell(row,directoryLabel(item.subject_type,item.subject_id));cell(row,item.profile_id);cell(row,item.priority);const action=cell(row,'');action.appendChild(button('Remove','danger',async()=>{if(!confirm(`Remove ${item.subject_type}:${item.subject_id} â†’ ${item.profile_id}?`))return;await api(`/admin/api/assignments/${item.id}`,{method:'DELETE'});await loadAssignments();setStatus('Assignment removed','ok');}));body.appendChild(row);});$('assignment-count').textContent=assignmentCache.length;}
async function loadClientCredentials(){clientCredentialCache=await api('/admin/api/client-credentials');const body=$('client-credentials');body.replaceChildren();clientCredentialCache.forEach(item=>{const row=document.createElement('tr');cell(row,item.name);cell(row,`${directoryLabel('user',item.user_id)} / ${item.agent_id}`);cell(row,(item.groups||[]).map(id=>directoryLabel('group',id)).join(', '));cell(row,item.key_prefix);const expired=item.expires_at&&new Date(item.expires_at)<=new Date(),state=item.revoked_at?'revoked':expired?'expired':item.enabled?'active':'disabled';const stateCell=cell(row,state);stateCell.className=state==='active'?'ok':state==='expired'?'warning':'error';cell(row,item.last_used_at?new Date(item.last_used_at).toLocaleString():'never');const action=cell(row,'');const revoke=button('Revoke','danger',async()=>{if(!confirm(`Revoke ${item.name} (${item.key_prefix})? This client will immediately lose gateway access.`))return;await api(`/admin/api/client-credentials/${item.id}/revoke`,{method:'POST',body:'{}'});await loadClientCredentials();setStatus(`Revoked ${item.name}`,'ok');});revoke.disabled=state!=='active';action.appendChild(revoke);body.appendChild(row);});}
async function loadAudit(){auditCache=await api(`/admin/api/audit?limit=${$('audit-limit').value}`);renderAudit();}
async function loadUsage(profileId){if(!profileId){$('external-spend').textContent='â€”';$('external-spend-detail').textContent='selected profile / month';return;}const usage=await api(`/admin/api/usage?profile_id=${escapeQuery(profileId)}`);$('external-spend').textContent=`$${Number(usage.cost_usd).toFixed(4)}`;$('external-spend-detail').textContent=`${profileId}; ${usage.requests} request(s)`;}
function renderAudit(){const query=$('audit-search').value.trim().toLowerCase(),decision=$('audit-decision').value,stage=$('audit-stage').value;const rows=auditCache.filter(item=>{const haystack=JSON.stringify(item).toLowerCase();return(!query||haystack.includes(query))&&(!decision||item.decision===decision)&&(!stage||item.stage===stage);});const body=$('audit');body.replaceChildren();rows.forEach(item=>{const row=document.createElement('tr');cell(row,new Date(item.occurred_at).toLocaleString());cell(row,`${item.user_id} / ${item.agent_id}`);cell(row,item.profile_id);const decisionCell=cell(row,item.decision);decisionCell.className=item.decision==='allow'?'ok':item.decision==='block'?'error':'warning';cell(row,item.stage);cell(row,[...(item.categories||[]),item.route_model||'',item.route_reason||''].filter(Boolean).join(' | '));cell(row,item.request_id);body.appendChild(row);});$('blocked-count').textContent=auditCache.filter(x=>x.decision==='block').length;}
async function refresh(){await Promise.all([loadReadiness(),loadProfiles(),loadDirectory(),loadAudit(),loadClientCredentials()]);await loadAssignments();setConsoleLocked(false);setStatus(token?'Connected with recovery token':'Connected as gateway administrator','ok');}

checkboxes('input-categories','input');checkboxes('output-categories','output');blankProfile();
$('connect').onclick=async()=>{try{const entered=$('token').value.trim();if(!entered)throw new Error('Enter the recovery token');token=entered;sessionStorage.setItem('guardrailAdminToken',token);await refresh();$('token').value='';}catch(error){token='';sessionStorage.removeItem('guardrailAdminToken');showAuthorizationError(error);}};
$('disconnect').onclick=()=>{token='';sessionStorage.removeItem('guardrailAdminToken');$('token').value='';refresh().catch(showAuthorizationError);};
$('new-profile').onclick=blankProfile;
$('clone-profile').onclick=()=>{try{cloneProfile();}catch(error){setStatus(error.message,'error');}};
$('export-config').onclick=async()=>{try{const config=await api('/admin/api/config-export');const blob=new Blob([JSON.stringify(config,null,2)+'\n'],{type:'application/json'});const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`ai-gateway-guardrails-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);setStatus('Downloaded secret-free configuration','ok');}catch(error){setStatus(error.message,'error');}};
$('import-config').onclick=()=>$('import-file').click();
$('import-file').onchange=async()=>{const file=$('import-file').files[0];if(!file)return;try{const config=JSON.parse(await file.text());if(!confirm(`Merge ${config.profiles?.length??0} profiles and ${config.assignments?.length??0} assignments from ${file.name}?`))return;const result=await api('/admin/api/config-import',{method:'POST',body:JSON.stringify(config)});selectedProfile=null;await refresh();setStatus(`Restored ${result.profiles_upserted} profiles and ${result.assignments_upserted} assignments`,'ok');}catch(error){setStatus(error.message,'error');}finally{$('import-file').value='';}};
$('save-profile').onclick=async()=>{try{const payload={id:$('profile-id').value.trim(),name:$('profile-name').value.trim(),description:$('profile-description').value.trim(),enabled:$('profile-enabled').checked,settings:settingsFromForm()};if(!payload.id||!payload.name)throw new Error('Profile ID and name are required');if(payload.id==='default'&&!confirm('Update the default policy applied when no assignment matches?'))return;const saved=await api('/admin/api/profiles',{method:'POST',body:JSON.stringify(payload)});selectedProfile=saved;await loadProfiles();editProfile(profileCache.find(x=>x.id===payload.id));setStatus(`Saved ${payload.id}`,'ok');}catch(error){setStatus(error.message,'error');}};
$('test-external-provider').onclick=async()=>{try{const result=await api('/admin/api/providers/external/test',{method:'POST',body:'{}'});setStatus(`External provider ready: ${result.model}`,'ok');}catch(error){setStatus(error.message,'error');}};
$('delete-profile').onclick=async()=>{try{const id=$('profile-id').value.trim();if(!id||id==='default')throw new Error('The default profile cannot be deleted');if(!confirm(`Delete ${id} and all of its assignments?`))return;await api(`/admin/api/profiles/${id}`,{method:'DELETE'});selectedProfile=null;blankProfile();await Promise.all([loadProfiles(),loadAssignments()]);setStatus(`Deleted ${id}`,'ok');}catch(error){setStatus(error.message,'error');}};
$('save-assignment').onclick=async()=>{try{const payload={subject_type:$('assignment-type').value,subject_id:$('assignment-subject').value.trim(),profile_id:$('assignment-profile').value,priority:integer('assignment-priority')};if(!payload.subject_id)throw new Error('Subject ID is required');await api('/admin/api/assignments',{method:'POST',body:JSON.stringify(payload)});await loadAssignments();setStatus(`Assigned ${payload.subject_type}:${payload.subject_id}`,'ok');}catch(error){setStatus(error.message,'error');}};
$('assignment-type').onchange=renderDirectoryOptions;
$('resolve-effective').onclick=async()=>{try{const user=$('effective-user').value.trim(),agent=$('effective-agent').value.trim(),groups=$('effective-groups').value.trim();if(!user||!agent)throw new Error('User ID and agent ID are required');const path=`/admin/api/effective?user_id=${escapeQuery(user)}&agent_id=${escapeQuery(agent)}${groups?`&groups=${escapeQuery(groups)}`:''}`;const result=await api(path);$('effective-result').textContent=JSON.stringify(result,null,2);setStatus(`Resolved ${result.profile_id} from ${result.assignment_subject}`,'ok');}catch(error){$('effective-result').textContent=error.message;setStatus(error.message,'error');}};
$('issue-client-key').onclick=async()=>{try{const expiresValue=$('client-key-expires').value;const payload={name:$('client-key-name').value.trim(),user_id:$('client-key-user').value.trim(),agent_id:$('client-key-agent').value.trim(),groups:lines('client-key-groups'),expires_at:expiresValue?new Date(expiresValue).toISOString():null};if(!payload.name||!payload.user_id||!payload.agent_id)throw new Error('Credential name, end-user ID, and client ID are required');const result=await api('/admin/api/client-credentials',{method:'POST',body:JSON.stringify(payload)});issuedClientKey=result.api_key;$('issued-client-key').textContent=issuedClientKey;$('copy-client-key').disabled=false;await loadClientCredentials();setStatus(`Issued ${result.credential.name}; copy it now because it cannot be recovered`,'warning');}catch(error){setStatus(error.message,'error');}};
$('copy-client-key').onclick=async()=>{try{if(!issuedClientKey)throw new Error('No newly issued key is available');await navigator.clipboard.writeText(issuedClientKey);setStatus('Client key copied to the clipboard','ok');}catch(error){setStatus(error.message,'error');}};
$('clear-client-key').onclick=()=>{issuedClientKey='';$('issued-client-key').textContent='No key has been issued in this browser session.';$('copy-client-key').disabled=true;setStatus('One-time key display cleared','ok');};
$('refresh-audit').onclick=()=>loadAudit().then(()=>setStatus('Audit refreshed','ok')).catch(error=>setStatus(error.message,'error'));
['audit-search','audit-decision','audit-stage'].forEach(id=>$(id).addEventListener(id==='audit-search'?'input':'change',renderAudit));
$('audit-limit').onchange=()=>loadAudit().catch(error=>setStatus(error.message,'error'));
setConsoleLocked(true);
refresh().catch(error=>{loadReadiness();showAuthorizationError(error);});
</script>
</body>
</html>
"""
