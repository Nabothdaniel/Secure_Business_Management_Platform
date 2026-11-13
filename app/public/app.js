import SEAL from '/vendor/seal/index_throws.js';
import { makeContext, generateKeys, encryptValues, decryptValues, validateSecret, BFV_MAX } from './he.js';

/* ---------- tiny helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ICONS = {
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2M16 7l3 3"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
  chart: '<path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 5-6"/>', db: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  alert: '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>', download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>', upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
};
const icon = (n, cls = '') => `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n]}</svg>`;
const schemeName = s => (s === 'CKKS' ? 'Decimals' : 'Whole numbers');
const rel = iso => { const s = (new Date(iso) - Date.now()) / 1000, f = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  for (const [u, n] of [['day', 86400], ['hour', 3600], ['minute', 60]]) if (Math.abs(s) >= n) return f.format(Math.round(s / n), u); return 'just now'; };
const fmtNum = (v, scheme) => { if (Math.abs(v) < 1e-9) v = 0; return new Intl.NumberFormat('en', { maximumFractionDigits: scheme === 'BFV' ? 2 : 4 }).format(v); };
const store = { get: k => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch {} } };

function toast(msg, type = '') {
  const t = document.createElement('div'); t.className = 'toast ' + type; t.textContent = msg; $('#toasts').append(t); setTimeout(() => t.remove(), type === 'bad' ? 6000 : 3500);
}
const dlg = $('#dlg');
const openDlg = html => { dlg.innerHTML = `<div class="dlg">${html}</div>`; if (!dlg.open) dlg.showModal(); dlg.querySelector('[autofocus],input,button')?.focus(); };
const closeDlg = () => dlg.open && dlg.close();
dlg.addEventListener('click', e => { if (e.target === dlg || e.target.closest('[data-close]')) closeDlg(); });

async function busy(btn, label, fn) {
  const old = btn.innerHTML; btn.disabled = true; btn.setAttribute('aria-busy', 'true'); btn.innerHTML = `<span class="spinner" aria-hidden="true"></span>${esc(label)}`;
  await new Promise(r => setTimeout(r, 30)); // let the spinner paint before heavy crypto work
  try { return await fn(); } finally { btn.disabled = false; btn.removeAttribute('aria-busy'); btn.innerHTML = old; }
}

/* ---------- state ---------- */
let seal, session = null;
try { session = JSON.parse(sessionStorage.getItem('session') || 'null'); } catch {}
const ctxs = {}; const ctxFor = s => (ctxs[s] ??= makeContext(seal, s));
const skKey = id => `sbmp:sk:${session.user.id}:${id}`;
const getSK = id => store.get(skKey(id)); const setSK = (id, k) => store.set(skKey(id), k);
let navId = 0;

async function api(method, path, body) {
  const r = await fetch('/api' + path, { method, headers: { 'content-type': 'application/json', ...(session && { authorization: 'Bearer ' + session.token }) }, body: body && JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && session) { signOut(true); throw new Error('Your session expired. Please sign in again.'); }
  if (!r.ok) throw new Error(j.error || 'Something went wrong');
  return j;
}
function signOut(expired) { session = null; sessionStorage.removeItem('session'); location.hash = ''; route(); if (expired) toast('Your session expired. Please sign in again.', 'bad'); }
function downloadText(name, text) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }

/* ---------- shell ---------- */
function shell() {
  const initials = session.user.name.split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase();
  $('#app').innerHTML = `<header class="topbar"><div class="topbar-in">
    <a class="brand" href="#/"><span class="brand-mark">${icon('shield')}</span><span>Secure Business Platform</span></a>
    <nav class="nav" aria-label="Main"><a href="#/" data-nav="datasets">Datasets</a><a href="#/activity" data-nav="activity">Activity</a></nav>
    <div class="userbit"><div class="avatar" aria-hidden="true">${esc(initials)}</div><div class="who"><b>${esc(session.user.name)}</b><span>${esc(session.user.role)}</span></div>
    <button class="btn ghost sm" id="theme" aria-label="Toggle dark mode">${icon('moon')}</button><button class="btn ghost sm" id="out" aria-label="Sign out">${icon('logout')}</button></div></div></header>
    <main id="view" tabindex="-1"></main>`;
  $('#out').onclick = () => signOut();
  $('#theme').onclick = () => { const d = document.documentElement, dark = d.dataset.theme ? d.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches; d.dataset.theme = dark ? 'light' : 'dark'; store.set('sbmp:theme', d.dataset.theme); };
}
const view = () => $('#view');
const skeleton = (n = 3) => `<div class="grid" aria-busy="true" aria-label="Loading">${'<div class="skeleton"></div>'.repeat(n)}</div>`;
const errorState = (e, retryId) => `<div class="card empty"><div class="big" style="background:var(--bad-soft);color:var(--bad)">${icon('alert')}</div><h3>We couldn’t load this</h3><p>${esc(e.message)}</p><button class="btn" id="${retryId}">Try again</button></div>`;

/* ---------- sign in / register ---------- */
// Demo shortcuts on the login page. Set SHOW_DEMO = false to remove them before real use.
const SHOW_DEMO = true;
const DEMOS = [
  { name: 'Demo Manager', email: 'manager@demo.test', password: 'demo-manager-1', role: 'manager', note: 'creates & shares datasets' },
  { name: 'Demo Analyst', email: 'analyst@demo.test', password: 'demo-analyst-1', role: 'analyst', note: 'computes on shared data' },
];
async function demoLogin(d) { // sign in, creating the demo account the first time
  try { return await api('POST', '/login', { email: d.email, password: d.password }); }
  catch (e) { if (!/invalid credentials/.test(e.message)) throw e; }
  await api('POST', '/register', { name: d.name, email: d.email, password: d.password, role: d.role });
  return api('POST', '/login', { email: d.email, password: d.password });
}
function showAuth(mode = 'login') {
  $('#app').innerHTML = `<div class="auth"><section class="auth-hero" aria-label="About">
    <div class="row" style="gap:10px"><span class="brand-mark" style="background:#fff;color:#1f43c4">${icon('shield')}</span><b>Secure Business Platform</b></div>
    <h1>Work out totals from private numbers, safely.</h1>
    <p>Your numbers are locked on your own device before they are saved. The server can still add them up, but it can never read them.</p>
    <ol><li><i>1</i><span><b>Lock</b><br>You type your numbers. They are locked on your device.</span></li>
    <li><i>2</i><span><b>Calculate</b><br>The server adds them up while they are still locked.</span></li>
    <li><i>3</i><span><b>Unlock</b><br>Only you can open the answer.</span></li></ol></section>
    <section class="auth-panel"><div class="auth-card"><h2 id="auth-title">${mode === 'login' ? 'Welcome back' : 'Create your account'}</h2>
    <div class="seg" role="tablist"><button role="tab" id="t-login" aria-selected="${mode === 'login'}">Sign in</button><button role="tab" id="t-reg" aria-selected="${mode !== 'login'}">Create account</button></div>
    <form id="auth-form" class="stack" novalidate>${mode === 'login' ? `
      <div class="field"><label for="email">Email</label><input id="email" type="email" autocomplete="email" required autofocus></div>
      <div class="field"><label for="pw">Password</label><div class="pw"><input id="pw" type="password" autocomplete="current-password" required><button type="button" id="showpw">Show</button></div></div>` : `
      <div class="field"><label for="name">Full name</label><input id="name" type="text" autocomplete="name" required autofocus></div>
      <div class="field"><label for="email">Email</label><input id="email" type="email" autocomplete="email" required></div>
      <div class="field"><label for="pw">Password</label><div class="pw"><input id="pw" type="password" autocomplete="new-password" minlength="8" required aria-describedby="pwh"><button type="button" id="showpw">Show</button></div><p class="hint" id="pwh">At least 8 characters.</p></div>
      <fieldset style="border:0;padding:0;margin:0"><legend class="legend">What will you do?</legend><div class="choice">
        <label><input type="radio" name="role" value="manager" checked><div><b>Manage my own data</b><span>Create datasets, add numbers and share them.</span></div></label>
        <label><input type="radio" name="role" value="analyst"><div><b>Work on data shared with me</b><span>Run calculations on datasets other people give you.</span></div></label></div></fieldset>`}
      <div class="form-err" id="ferr" role="alert" hidden></div>
      <button class="btn block" id="submit" type="submit">${mode === 'login' ? 'Sign in' : 'Create account'}</button></form>
    ${mode !== 'login' ? '<p class="hint" style="margin-top:14px">The first person to sign up becomes the admin.</p>' : ''}
    ${SHOW_DEMO && mode === 'login' ? `<div class="demo" style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line,#ddd)"><p class="hint" style="margin:0 0 8px">Demo logins (one click)</p><div class="row" style="gap:8px;flex-wrap:wrap">${DEMOS.map((d, i) => `<button type="button" class="btn ghost sm" data-demo="${i}" title="${esc(d.note)}">${esc(d.name)}</button>`).join('')}</div></div>` : ''}</div></section></div>`;
  $$('[data-demo]').forEach(b => b.onclick = async () => {
    const err = $('#ferr'); err.hidden = true;
    try { await busy(b, 'Signing in…', async () => { session = await demoLogin(DEMOS[b.dataset.demo]); }); sessionStorage.setItem('session', JSON.stringify(session)); location.hash = '#/'; route(); }
    catch (ex) { err.textContent = ex.message; err.hidden = false; }
  });
  $('#t-login').onclick = () => showAuth('login'); $('#t-reg').onclick = () => showAuth('register');
  $('#showpw').onclick = e => { const i = $('#pw'); i.type = i.type === 'password' ? 'text' : 'password'; e.target.textContent = i.type === 'password' ? 'Show' : 'Hide'; };
  $('#auth-form').onsubmit = async e => {
    e.preventDefault(); const err = $('#ferr'); err.hidden = true;
    const email = $('#email').value.trim(), password = $('#pw').value;
    try {
      if (mode === 'login') {
        if (!email || !password) throw new Error('Enter your email and password.');
        await busy($('#submit'), 'Signing in…', async () => { session = await api('POST', '/login', { email, password }); });
      } else {
        const name = $('#name').value.trim(); if (!name) throw new Error('Enter your name.');
        if (!/^\S+@\S+\.\S+$/.test(email)) throw new Error('Enter a valid email address.'); if (password.length < 8) throw new Error('Use a password of at least 8 characters.');
        await busy($('#submit'), 'Creating account…', async () => { await api('POST', '/register', { name, email, password, role: $('input[name=role]:checked').value }); session = await api('POST', '/login', { email, password }); });
        toast('Welcome! Your account is ready.', 'ok');
      }
      sessionStorage.setItem('session', JSON.stringify(session)); location.hash = '#/'; route();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; }
  };
}

/* ---------- router ---------- */
async function route() {
  if (!seal) return;
  if (!session) return showAuth();
  if (!$('#view')) shell();
  const [a, b, c] = location.hash.replace(/^#\/?/, '').split('/'); const my = ++navId;
  $$('[data-nav]').forEach(l => l.removeAttribute('aria-current'));
  const mark = n => $(`[data-nav=${n}]`)?.setAttribute('aria-current', 'page');
  document.title = 'Secure Business Platform';
  if (a === 'activity') { mark('activity'); return activityView(my); }
  mark('datasets');
  if (a === 'd' && b) return datasetView(my, b, c);
  return datasetsView(my);
}
window.addEventListener('hashchange', route);
const stale = my => my !== navId;

/* ---------- datasets list ---------- */
async function datasetsView(my) {
  view().innerHTML = skeleton();
  let list; try { list = await api('GET', '/datasets'); } catch (e) { if (stale(my)) return; view().innerHTML = errorState(e, 'retry'); $('#retry').onclick = () => datasetsView(my); return; }
  if (stale(my)) return;
  const canCreate = ['admin', 'manager'].includes(session.user.role);
  view().innerHTML = `<div class="page-head"><div><h1>Datasets</h1><p class="muted">Your sets of numbers. Open one to add numbers and see totals.</p></div>${canCreate && list.length ? `<button class="btn" id="new">${icon('plus')}New dataset</button>` : ''}</div>
  ${list.length ? `<div class="grid">${list.map(d => `<a class="card ds-card" href="#/d/${d.dataset_id}"><h3>${esc(d.title)}</h3>
    <div class="ds-meta"><span class="chip primary">${schemeName(d.scheme)}</span><span class="chip">${d.access === 'owner' ? 'You own this' : 'Shared with you'}</span>
    ${d.access === 'owner' ? (getSK(d.dataset_id) ? `<span class="chip ok">${icon('key')}Your key is saved here</span>` : `<span class="chip warn">${icon('key')}Your key is missing</span>`) : ''}</div>
    <div class="ds-foot"><span>${d.record_count} record${d.record_count === 1 ? '' : 's'}</span><span>${d.access === 'owner' ? rel(d.created_at) : 'by ' + esc(d.owner_name)}</span></div></a>`).join('')}</div>`
  : canCreate ? `<div class="card empty"><div class="big">${icon('db')}</div><h3>Create your first dataset</h3><p>It takes about a minute. Your private key is made in this browser and stays here.</p>
      <div class="steps"><div class="step"><b><span class="n">1</span>Name your columns</b><span class="muted small">For example: Sales, Costs.</span></div><div class="step"><b><span class="n">2</span>Add rows</b><span class="muted small">Your numbers are locked as you add them.</span></div><div class="step"><b><span class="n">3</span>See results</b><span class="muted small">Totals, averages and spread.</span></div></div>
      <button class="btn" id="new">${icon('plus')}Create dataset</button></div>`
  : `<div class="card empty"><div class="big">${icon('users')}</div><h3>Nothing has been shared with you yet</h3><p>Ask the dataset owner to share it with <b>${esc(session.user.email)}</b>. It will show up here.</p></div>`}`;
  $('#new')?.addEventListener('click', newDatasetDialog);
}

function parseCols(v) { const seen = new Set(); return v.split(',').map(s => s.trim()).filter(s => s && !seen.has(s.toLowerCase()) && seen.add(s.toLowerCase())); }
function newDatasetDialog() {
  openDlg(`<div class="dlg-head"><h2>New dataset</h2><button class="btn ghost sm" data-close aria-label="Close">✕</button></div>
  <form id="nd" class="stack" novalidate>
    <div class="field"><label for="nt">Name</label><input id="nt" type="text" placeholder="e.g. Shop sales, March" maxlength="80" required autofocus></div>
    <fieldset style="border:0;padding:0;margin:0"><legend class="legend">What kind of numbers?</legend><div class="choice two">
      <label><input type="radio" name="sc" value="CKKS" checked><div><b>Decimals</b><span>Money and measurements, like 1250.50. Answers are accurate to many decimal places.</span></div></label>
      <label><input type="radio" name="sc" value="BFV"><div><b>Whole numbers</b><span>Counts, like 12 or 250 (from −${BFV_MAX} to ${BFV_MAX}). Answers are exact.</span></div></label></div></fieldset>
    <div class="field"><label for="nc">Columns</label><input id="nc" type="text" placeholder="Sales, Costs, Customers" aria-describedby="nch" required><p class="hint" id="nch">Separate with commas. Each row you add will have one number for each column (up to 12).</p><div class="preview-chips" id="chips" aria-live="polite"></div></div>
    <div class="form-err" id="nerr" role="alert" hidden></div>
    <div class="row between"><span class="hint">${icon('lock')} Your private key is made in this browser.</span><button class="btn" id="nsubmit" type="submit">Create dataset</button></div></form>`);
  $('#nc').oninput = e => { $('#chips').innerHTML = parseCols(e.target.value).slice(0, 12).map(c => `<span class="chip primary">${esc(c)}</span>`).join(''); };
  $('#nd').onsubmit = async e => {
    e.preventDefault(); const err = $('#nerr'); err.hidden = true;
    const title = $('#nt').value.trim(), cols = parseCols($('#nc').value), scheme = $('input[name=sc]:checked').value;
    try {
      if (!title) throw new Error('Give the dataset a name.'); if (!cols.length) throw new Error('Add at least one column.'); if (cols.length > 12) throw new Error('Use 12 columns or fewer.');
      if (cols.some(c => c.length > 40)) throw new Error('Keep column names under 40 characters.');
      const id = await busy($('#nsubmit'), 'Setting up…', async () => {
        const k = generateKeys(seal, ctxFor(scheme));
        const { dataset_id } = await api('POST', '/datasets', { title, scheme, columns: cols, public_key: k.publicKey, relin_keys: k.relinKeys });
        setSK(dataset_id, k.secretKey); return dataset_id;
      });
      keyBackupDialog(id, title);
    } catch (ex) { err.textContent = ex.message; err.hidden = false; }
  };
}
function keyBackupDialog(id, title) {
  openDlg(`<div class="dlg-head"><h2>Save your private key</h2></div><div class="stack"><div class="banner">${icon('alert')}<div><b>This is the only copy.</b><p class="small">This key opens “${esc(title)}”. It is saved only in this browser. If you clear your browser data without a backup, you will not be able to read your results again, and nobody else can recover them for you.</p></div></div>
  <button class="btn block" id="bk">${icon('download')}Download my key file</button><button class="btn secondary block" id="done">I’ve saved it — continue</button></div>`);
  $('#bk').onclick = () => { downloadText(`dataset-${id}-secret.key`, getSK(id)); toast('Key file downloaded', 'ok'); };
  $('#done').onclick = () => { closeDlg(); location.hash = `#/d/${id}/records`; };
}

/* ---------- dataset ---------- */
const LVL = { compute: 1, read: 2, write: 3, owner: 9 };
async function datasetView(my, id, tab) {
  view().innerHTML = skeleton(2);
  let ds, recs = [], jobs = [], grants = [];
  try {
    ds = await api('GET', `/datasets/${id}`); const lvl = LVL[ds.access];
    [recs, jobs, grants] = await Promise.all([lvl >= 2 ? api('GET', `/datasets/${id}/records`) : [], api('GET', `/datasets/${id}/jobs`), ds.access === 'owner' ? api('GET', `/datasets/${id}/grants`) : []]);
  } catch (e) { if (stale(my)) return; view().innerHTML = errorState(e, 'retry'); $('#retry').onclick = () => datasetView(my, id, tab); return; }
  if (stale(my)) return;
  const lvl = LVL[ds.access], owner = ds.access === 'owner', haveKey = !!getSK(id);
  const cols = ds.columns || Array.from({ length: Math.max(1, ...recs.map(r => r.n_values)) }, (_, i) => `Column ${i + 1}`);
  const tabs = [['analyze', 'Analyze'], ['records', 'Records'], ...(owner ? [['sharing', 'Sharing']] : []), ['history', 'History']];
  if (!tabs.some(t => t[0] === tab)) tab = recs.length || lvl < 3 ? 'analyze' : 'records';
  document.title = ds.title + ' · Secure Business Platform';
  const ctx = { id, ds, lvl, owner, haveKey, cols, recs, jobs, grants, refresh: () => datasetView(++navId, id, tab) };
  view().innerHTML = `<nav class="crumbs" aria-label="Breadcrumb"><a href="#/">Datasets</a> / <span>${esc(ds.title)}</span></nav>
  <div class="page-head"><div class="stack-sm"><h1>${esc(ds.title)}</h1><div class="row" style="gap:6px"><span class="chip primary">${schemeName(ds.scheme)}</span><span class="chip">${owner ? 'You own this' : 'Shared with you'}</span><span class="chip">${recs.length || (lvl < 2 ? '' : 0)}${lvl < 2 ? 'You can’t see the rows' : ' record' + (recs.length === 1 ? '' : 's')}</span></div></div>
    <div class="row">${haveKey ? `<span class="chip ok">${icon('key')}Your key is saved here</span><button class="btn secondary sm" id="bkkey">${icon('download')}Download key</button>` : `<span class="chip warn">${icon('key')}No key saved here</span>`}<button class="btn secondary sm" id="impkey">${icon('upload')}Add my key</button></div></div>
  ${!haveKey && owner ? `<div class="banner" style="margin-bottom:16px">${icon('alert')}<div><b>Your key isn’t saved on this device.</b><p class="small">You can still add numbers and run calculations, but you can’t read the answers until you add your key file.</p></div></div>` : ''}
  <div class="tabs" role="tablist" aria-label="Dataset sections">${tabs.map(([k, l]) => `<a href="#/d/${id}/${k}" ${k === tab ? 'aria-current="page"' : ''}>${l}</a>`).join('')}</div><div id="pane"></div>`;
  $('#bkkey')?.addEventListener('click', () => { downloadText(`dataset-${id}-secret.key`, getSK(id)); toast('Key file downloaded', 'ok'); });
  $('#impkey').onclick = () => { const f = $('#keyfile'); f.value = ''; f.onchange = async () => { const k = (await f.files[0].text()).trim(); try { validateSecret(seal, ctxFor(ds.scheme), k); } catch { toast('That file is not the right key for this dataset.', 'bad'); return; }
      setSK(id, k); toast('Key added', 'ok'); ctx.refresh(); }; f.click(); };
  ({ analyze: analyzePane, records: recordsPane, sharing: sharingPane, history: historyPane })[tab](ctx);
}

const statCard = (label, value, sub = '') => `<div class="stat"><div class="label">${esc(label)}</div><div class="value num">${value}</div><div class="sub">${sub}</div></div>`;
function analyzePane(c) {
  const pane = $('#pane');
  if (c.owner && !c.recs.length) { pane.innerHTML = `<div class="card empty"><div class="big">${icon('chart')}</div><h3>Add some data first</h3><p>You need at least one row before you can see results.</p><a class="btn" href="#/d/${c.id}/records">${icon('plus')}Add a row</a></div>`; return; }
  pane.innerHTML = `<div class="stack"><div class="card"><div class="row between"><div><h2>Results</h2><p class="muted small">The server adds up your locked numbers. Your browser then unlocks the answer.</p></div><button class="btn" id="run">${icon('chart')}Show results</button></div><div id="res" class="stack" style="margin-top:16px" aria-live="polite"></div></div>
  <div class="card"><h2>Multiply the totals</h2><p class="muted small" style="margin-bottom:12px">Multiply every total by one number, such as a tax rate or exchange rate.</p>
  <form class="row" id="sf" novalidate><div class="field grow" style="max-width:240px"><label class="sr-only" for="k">Factor</label><input id="k" type="number" step="${c.ds.scheme === 'BFV' ? 1 : 'any'}" placeholder="e.g. 1.075" inputmode="decimal"></div><button class="btn secondary" id="sbtn" type="submit">Calculate</button></form><div id="sres" style="margin-top:14px" aria-live="polite"></div></div></div>`;
  const decrypt = (ct, n) => decryptValues(seal, ctxFor(c.ds.scheme), c.ds.scheme, getSK(c.id), ct, n);
  const noKey = () => `<div class="banner">${icon('key')}<div><b>The calculation worked, but you can’t read the answer.</b><p class="small">Ask the dataset owner for their key file, add it with “Add my key” at the top, then try again.</p></div></div>`;
  const job = async body => { try { return await api('POST', `/datasets/${c.id}/jobs`, body); } catch (e) { throw new Error(/no records/.test(e.message) ? 'There are no rows in this dataset yet.' : e.message); } };
  $('#run').onclick = async e => { try { await busy(e.currentTarget, 'Calculating…', async () => {
      const s = await job({ operation: 'sum' }), q = await job({ operation: 'sumsq' });
      if (!getSK(c.id)) { $('#res').innerHTML = noKey(); return; }
      const sums = decrypt(s.result_ciphertext, s.n_values), sq = decrypt(q.result_ciphertext, q.n_values), n = s.record_count, f = v => fmtNum(v, c.ds.scheme);
      const rows = sums.map((v, i) => { const mean = v / n, variance = sq[i] / n - mean ** 2; return { name: c.cols[i] ?? `Column ${i + 1}`, v, mean, variance, sd: Math.sqrt(Math.max(variance, 0)) }; });
      $('#res').innerHTML = `<div class="result-hero">${rows.slice(0, 3).map(r => statCard(r.name, f(r.v), `Average ${f(r.mean)}`)).join('')}</div>
        <div class="table-wrap"><table><thead><tr><th>Column</th><th class="r">Total</th><th class="r">Average</th><th class="r">Variance</th><th class="r">Std. deviation</th></tr></thead><tbody>${rows.map(r => `<tr><td>${esc(r.name)}</td><td class="r num">${f(r.v)}</td><td class="r num">${f(r.mean)}</td><td class="r num">${f(r.variance)}</td><td class="r num">${f(r.sd)}</td></tr>`).join('')}</tbody></table></div>
        <p class="faint small">Variance and standard deviation show how spread out the numbers are. Based on ${n} row${n === 1 ? '' : 's'}; the server took ${(s.duration_ms + q.duration_ms).toFixed(0)} ms; the answer was unlocked on this device.${c.ds.scheme === 'CKKS' ? ' Decimal answers can differ from exact maths by a tiny fraction.' : ''}</p>`;
    }); } catch (ex) { $('#res').innerHTML = `<div class="form-err" role="alert">${esc(ex.message)}</div>`; } };
  $('#sf').onsubmit = async e => { e.preventDefault(); const k = $('#k').value; if (k === '') { $('#sres').innerHTML = '<div class="form-err" role="alert">Type a number to multiply by.</div>'; return; }
    try { await busy($('#sbtn'), 'Calculating…', async () => { const r = await job({ operation: 'scale', scalar: Number(k) });
      if (!getSK(c.id)) { $('#sres').innerHTML = noKey(); return; }
      const v = decrypt(r.result_ciphertext, r.n_values); $('#sres').innerHTML = `<div class="table-wrap"><table><thead><tr><th>Column</th><th class="r">Total × ${esc(k)}</th></tr></thead><tbody>${v.map((x, i) => `<tr><td>${esc(c.cols[i] ?? 'Column ' + (i + 1))}</td><td class="r num">${fmtNum(x, c.ds.scheme)}</td></tr>`).join('')}</tbody></table></div>`; });
    } catch (ex) { $('#sres').innerHTML = `<div class="form-err" role="alert">${esc(ex.message)}</div>`; } };
}

function recordsPane(c) {
  const pane = $('#pane'), bfv = c.ds.scheme === 'BFV';
  const form = c.lvl >= 3 ? `<div class="card"><h2>Add a row</h2><p class="muted small" style="margin-bottom:14px">One row of numbers, such as one shop or one month. It is locked on this device before it is sent.</p>
    <form id="rf" class="stack" novalidate><div class="field" style="max-width:360px"><label for="lbl">Label</label><input id="lbl" type="text" placeholder="e.g. Lagos shop" maxlength="80"></div>
    <div class="cols-grid">${c.cols.map((n, i) => `<div class="field"><label for="v${i}">${esc(n)}</label><input id="v${i}" type="number" inputmode="decimal" step="${bfv ? 1 : 'any'}" ${bfv ? `min="-${BFV_MAX}" max="${BFV_MAX}"` : ''} placeholder="0"></div>`).join('')}</div>
    <div class="form-err" id="rerr" role="alert" hidden></div><div><button class="btn" id="rbtn" type="submit">${icon('lock')}Lock and add</button></div></form>
    <details class="more" style="margin-top:16px"><summary>Add many rows at once</summary><div class="stack-sm"><p class="muted small">Put one row on each line: <span class="mono">name, ${c.cols.map(x => esc(x)).join(', ')}</span>. The name is optional.</p><textarea id="csv" aria-label="Rows to import" placeholder="Lagos, 1200500.50, 80250.25&#10;Abuja, 200400.40, 15500.50"></textarea><div class="form-err" id="cerr" role="alert" hidden></div><button class="btn secondary" id="cbtn">${icon('upload')}Lock and add rows</button></div></details></div>` : '';
  const table = c.lvl >= 2 ? (c.recs.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th class="r">Numbers</th><th class="r">Saved size</th><th>Added</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>${c.recs.map(r => `<tr><td>${esc(r.label || 'Untitled')}</td><td class="r num">${r.n_values}</td><td class="r num">${(r.ciphertext_bytes / 1024).toFixed(0)} KiB</td><td>${rel(r.created_at)}</td><td class="r"><button class="btn ghost sm" data-peek="${r.record_id}">${icon('eye')}What the server sees</button></td></tr>`).join('')}</tbody></table></div>`
    : `<div class="card empty"><div class="big">${icon('db')}</div><h3>No rows yet</h3><p>${c.lvl >= 3 ? 'Add your first row above.' : 'Rows will show up here once someone adds them.'}</p></div>`)
    : `<div class="card empty"><div class="big">${icon('lock')}</div><h3>You can’t see the rows</h3><p>You can run calculations on this dataset, but not view the rows. Use the Analyze tab.</p></div>`;
  pane.innerHTML = `<div class="stack">${form}${table}</div>`;
  const add = async (label, vals) => { const ct = encryptValues(seal, ctxFor(c.ds.scheme), c.ds.scheme, c.ds.public_key, vals); await api('POST', `/datasets/${c.id}/records`, { label, ciphertext: ct, n_values: vals.length }); };
  $('#rf')?.addEventListener('submit', async e => { e.preventDefault(); const err = $('#rerr'); err.hidden = true;
    try { const vals = c.cols.map((n, i) => { const raw = $('#v' + i).value; if (raw === '') throw new Error(`Enter a number for “${n}”.`); const v = Number(raw); if (!Number.isFinite(v)) throw new Error(`“${n}” must be a number.`);
        if (bfv && (!Number.isInteger(v) || Math.abs(v) > BFV_MAX)) throw new Error(`“${n}” must be a whole number between −${BFV_MAX} and ${BFV_MAX}.`); return v; });
      await busy($('#rbtn'), 'Locking…', () => add($('#lbl').value.trim() || 'Untitled', vals)); toast('Row added', 'ok'); c.refresh();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; } });
  $('#cbtn')?.addEventListener('click', async e => { const err = $('#cerr'); err.hidden = true;
    try { const lines = $('#csv').value.split('\n').map(l => l.trim()).filter(Boolean); if (!lines.length) throw new Error('Paste at least one row.');
      const rows = lines.map((l, i) => { const p = l.split(',').map(s => s.trim()); const hasLabel = p.length === c.cols.length + 1 || (p.length > 0 && p[0] !== '' && isNaN(Number(p[0])) );
        const label = hasLabel ? p.shift() : `Row ${i + 1}`; if (p.length !== c.cols.length) throw new Error(`Line ${i + 1}: expected ${c.cols.length} number${c.cols.length === 1 ? '' : 's'}, found ${p.length}.`);
        const vals = p.map(Number); if (vals.some(v => !Number.isFinite(v))) throw new Error(`Line ${i + 1}: every value must be a number.`);
        if (bfv && vals.some(v => !Number.isInteger(v) || Math.abs(v) > BFV_MAX)) throw new Error(`Line ${i + 1}: whole numbers between −${BFV_MAX} and ${BFV_MAX} only.`); return [label, vals]; });
      const btn = e.currentTarget; await busy(btn, 'Locking…', async () => { for (const [n, [l, v]] of rows.entries()) { btn.lastChild.textContent = `Adding ${n + 1} of ${rows.length}…`; await add(l, v); } });
      toast(`${rows.length} row${rows.length === 1 ? '' : 's'} added`, 'ok'); c.refresh();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; } });
  $$('[data-peek]').forEach(b => b.onclick = async () => { try { const r = await api('GET', `/datasets/${c.id}/records/${b.dataset.peek}`);
    openDlg(`<div class="dlg-head"><h2>What the server stores</h2><button class="btn ghost sm" data-close aria-label="Close">✕</button></div><div class="stack-sm"><p class="muted small">This is all the server has for “${esc(r.label || 'Untitled')}”. Your numbers can’t be read from it.</p><p class="mono" style="background:var(--surface-2);padding:12px;border-radius:8px;max-height:200px;overflow:auto">${esc(r.ciphertext.slice(0, 420))}…</p><p class="faint small">${r.ciphertext.length.toLocaleString()} characters of scrambled data.</p></div>`); } catch (ex) { toast(ex.message, 'bad'); } });
}

const PERMS = [['compute', 'Run calculations', 'Can ask for totals and averages. Cannot see the rows.'], ['read', 'View rows', 'Can also see the rows (locked).'], ['write', 'Add rows', 'Can also add new rows.']];
function sharingPane(c) {
  $('#pane').innerHTML = `<div class="stack"><div class="card"><h2>Share this dataset</h2><p class="muted small" style="margin-bottom:14px">The person needs an account first. Sharing never gives them your key.</p>
  <form id="gf" class="stack" novalidate><div class="field" style="max-width:380px"><label for="ge">Their email</label><input id="ge" type="email" autocomplete="off" placeholder="colleague@company.com"></div>
  <fieldset style="border:0;padding:0;margin:0"><legend class="legend">What can they do?</legend><div class="choice">${PERMS.map(([v, t, d], i) => `<label><input type="radio" name="perm" value="${v}" ${i === 0 ? 'checked' : ''}><div><b>${t}</b><span>${d}</span></div></label>`).join('')}</div></fieldset>
  <div class="field" style="max-width:240px"><label for="gd">Access lasts</label><select id="gd"><option value="">Until I remove it</option><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option></select></div>
  <div class="form-err" id="gerr" role="alert" hidden></div><div><button class="btn" id="gbtn" type="submit">${icon('users')}Share</button></div></form></div>
  <div class="card"><h2>People with access</h2>${c.grants.length ? `<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Person</th><th>Can</th><th>Until</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>${c.grants.map(g => `<tr><td>${esc(g.name)}<br><span class="faint small">${esc(g.email)}</span></td><td>${esc(PERMS.find(p => p[0] === g.permission)?.[1])}</td><td>${g.expiry ? new Date(g.expiry).toLocaleDateString() : 'No end date'}</td><td class="r"><button class="btn danger sm" data-rv="${esc(g.grant_id)}">Remove</button></td></tr>`).join('')}</tbody></table></div>` : '<p class="muted" style="margin-top:8px">Only you can access this dataset right now.</p>'}</div>
  <div class="banner info">${icon('info')}<div><b>Want someone to read the answers too?</b><p class="small">Answers can only be opened with your key file. Send the file to them privately, for example in person. This platform never sends it.</p></div></div></div>`;
  $('#gf').onsubmit = async e => { e.preventDefault(); const err = $('#gerr'); err.hidden = true; try { const email = $('#ge').value.trim(); if (!/^\S+@\S+\.\S+$/.test(email)) throw new Error('Enter a valid email address.');
    await busy($('#gbtn'), 'Sharing…', () => api('POST', `/datasets/${c.id}/grants`, { email, permission: $('input[name=perm]:checked').value, expiry_days: Number($('#gd').value) || undefined })); toast('Shared', 'ok'); c.refresh(); } catch (ex) { err.textContent = ex.message; err.hidden = false; } };
  $$('[data-rv]').forEach(b => b.onclick = async () => { try { await api('DELETE', `/datasets/${c.id}/grants/${b.dataset.rv}`); toast('Access removed', 'ok'); c.refresh(); } catch (ex) { toast(ex.message, 'bad'); } });
}

function historyPane(c) {
  $('#pane').innerHTML = c.jobs.length ? `<div class="table-wrap"><table><thead><tr><th>When</th><th>Calculation</th><th>Run by</th><th class="r">Rows</th><th class="r">Server time</th><th>Status</th></tr></thead><tbody>${c.jobs.map(j => `<tr><td>${rel(j.created_at)}</td><td>${{ sum: 'Totals', sumsq: 'Spread (for variance)', scale: 'Factor × ' + j.scalar }[j.operation] || esc(j.operation)}</td><td>${esc(j.requester)}</td><td class="r num">${j.record_count}</td><td class="r num">${j.duration_ms.toFixed(0)} ms</td><td><span class="chip ${j.status === 'done' ? 'ok' : 'bad'}">${j.status === 'done' ? 'Done' : 'Failed'}</span></td></tr>`).join('')}</tbody></table></div>`
    : `<div class="card empty"><div class="big">${icon('chart')}</div><h3>No calculations yet</h3><p>Calculate some results and they will be listed here.</p></div>`;
}

/* ---------- activity ---------- */
const ACTION = { LOGIN_OK: ['Signed in', 'ok'], LOGIN_FAILED: ['Failed sign-in', 'bad'], LOGIN_LOCKED: ['Account locked', 'bad'], REGISTER: ['Account created', ''], DATASET_CREATE: ['Dataset created', ''], RECORD_UPLOAD: ['Record added', ''], RECORD_DOWNLOAD: ['Record viewed', ''], GRANT: ['Access shared', ''], REVOKE: ['Access removed', ''], JOB_OK: ['Calculation run', ''], JOB_FAILED: ['Calculation failed', 'bad'], REJECT_SECRET_KEY_UPLOAD: ['Private key blocked', 'bad'] };
async function activityView(my) {
  view().innerHTML = skeleton(1);
  let rows; try { rows = await api('GET', '/audit'); } catch (e) { if (stale(my)) return; view().innerHTML = errorState(e, 'retry'); $('#retry').onclick = () => activityView(my); return; }
  if (stale(my)) return;
  const isAdmin = session.user.role === 'admin'; let filter = 'all';
  const draw = () => { const f = rows.filter(r => filter === 'all' || (filter === 'blocked' ? /DENY|FAIL|LOCK|REJECT/.test(r.action) : /LOGIN|REGISTER/.test(r.action) ? filter === 'access' : filter === 'data'));
    $('#alist').innerHTML = f.length ? `<div class="table-wrap"><table><thead><tr><th>When</th>${isAdmin ? '<th>User</th>' : ''}<th>Event</th><th>Details</th></tr></thead><tbody>${f.map(r => { const [t, k] = ACTION[r.action] || [r.action.startsWith('DENY') ? 'Access denied' : r.action, r.action.startsWith('DENY') ? 'bad' : ''];
      return `<tr><td title="${esc(r.timestamp)}">${rel(r.timestamp)}</td>${isAdmin ? `<td>${esc(r.email || '—')}</td>` : ''}<td><span class="chip ${k}">${esc(t)}</span></td><td class="muted small">${esc(r.detail)}</td></tr>`; }).join('')}</tbody></table></div>` : `<div class="card empty"><h3>Nothing to show</h3><p>No events match this filter.</p></div>`; };
  view().innerHTML = `<div class="page-head"><div><h1>Activity</h1><p class="muted">${isAdmin ? 'Everything that happened on the platform.' : 'Your recent activity.'}</p></div>
    <div class="row" role="group" aria-label="Filter">${[['all', 'All'], ['access', 'Sign-ins'], ['data', 'Data'], ['blocked', 'Blocked']].map(([k, l]) => `<button class="btn ${k === 'all' ? '' : 'secondary'} sm" data-f="${k}" aria-pressed="${k === 'all'}">${l}</button>`).join('')}</div></div><div id="alist"></div>`;
  $$('[data-f]').forEach(b => b.onclick = () => { filter = b.dataset.f; $$('[data-f]').forEach(x => { const on = x === b; x.setAttribute('aria-pressed', on); x.classList.toggle('secondary', !on); }); draw(); }); draw();
}

/* ---------- boot ---------- */
seal = await SEAL();
route();
