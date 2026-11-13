import SEAL from 'node-seal';
import assert from 'node:assert/strict';
import { createApp } from '../server.js';
import { MemoryStore } from '../store.js';
import { makeContext, generateKeys, encryptValues, decryptValues } from '../public/he.js';

const { app } = await createApp({ store: new MemoryStore(), secret: 'test' });
const server = app.listen(0); const base = `http://localhost:${server.address().port}`;
const seal = await SEAL();
const api = async (m, p, body, tok) => {
  const r = await fetch(base + p, { method: m, headers: { 'content-type': 'application/json', ...(tok && { authorization: 'Bearer ' + tok }) }, body: body && JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};
const login = async e => (await api('POST', '/api/login', { email: e, password: 'password123' })).body.token;
let passed = 0; const ok = (n) => { passed++; console.log('  ✓', n); };
const near = (a, b, eps) => assert.ok(Math.abs(a - b) <= eps, `${a} vs ${b}`);

// --- users / RBAC ---
assert.equal((await api('POST', '/api/register', { name: 'Ada', email: 'ada@x.com', password: 'password123' })).body.role, 'admin'); // first user
await api('POST', '/api/register', { name: 'Mgr', email: 'mgr@x.com', password: 'password123', role: 'manager' });
await api('POST', '/api/register', { name: 'Ana', email: 'ana@x.com', password: 'password123', role: 'analyst' });
await api('POST', '/api/register', { name: 'Eve', email: 'eve@x.com', password: 'password123', role: 'analyst' });
assert.equal((await api('POST', '/api/register', { name: 'H', email: 'h@x.com', password: 'password123', role: 'admin' })).status, 400); ok('cannot self-register as admin');
assert.equal((await api('GET', '/api/datasets')).status, 401); ok('unauthenticated request rejected');
const [mgr, ana, eve, adm] = await Promise.all(['mgr@x.com', 'ana@x.com', 'eve@x.com', 'ada@x.com'].map(login));
assert.equal((await api('POST', '/api/login', { email: 'mgr@x.com', password: 'wrong' })).status, 401); ok('bad password rejected');
assert.equal((await api('POST', '/api/datasets', { title: 't', scheme: 'BFV', public_key: 'x', relin_keys: 'y' }, ana)).status, 403); ok('analyst cannot create datasets (RBAC)');

for (const scheme of ['BFV', 'CKKS']) {
  console.log(`\n[${scheme}]`);
  const ctx = makeContext(seal, scheme);
  const keys = generateKeys(seal, ctx);
  assert.equal((await api('POST', '/api/datasets', { title: 'x', scheme, public_key: keys.publicKey, relin_keys: keys.relinKeys, secret_key: keys.secretKey }, mgr)).status, 400); ok('server refuses an uploaded secret key');
  const ds = (await api('POST', '/api/datasets', { title: `Revenue ${scheme}`, scheme, public_key: keys.publicKey, relin_keys: keys.relinKeys }, mgr)).body.dataset_id;
  const rows = scheme === 'BFV' ? [[120, 80, 45, 10], [200, 15, 60, 7], [33, 90, 12, 5]] : [[1200.5, 80.25, 45.75, 10.1], [200.4, 15.5, 60.6, 7.7], [33.3, 90.9, 12.2, 5.5]];
  let t = performance.now(), bytes = 0; const slots = scheme === 'BFV' ? 8192 : 4096;
  for (const [i, r] of rows.entries()) {
    const ct = encryptValues(seal, ctx, scheme, keys.publicKey, r); bytes = ct.length;
    assert.equal((await api('POST', `/api/datasets/${ds}/records`, { label: 'Q' + i, ciphertext: ct, n_values: r.length }, mgr)).status, 201);
  }
  const encMs = (performance.now() - t) / rows.length;
  // the DB must hold nothing resembling plaintext
  const rid = (await api('GET', `/api/datasets/${ds}/records`, null, mgr)).body[0].record_id;
  const stored = (await api('GET', `/api/datasets/${ds}/records/${rid}`, null, mgr)).body.ciphertext;
  assert.ok(!stored.includes('1200') && stored.length > 1000); ok('stored value is opaque ciphertext');

  // --- authorization on the dataset ---
  assert.equal((await api('POST', `/api/datasets/${ds}/jobs`, { operation: 'sum' }, ana)).status, 403); ok('user without grant cannot compute');
  assert.equal((await api('POST', `/api/datasets/${ds}/grants`, { email: 'ana@x.com', permission: 'compute' }, ana)).status, 403); ok('non-owner cannot grant access');
  await api('POST', `/api/datasets/${ds}/grants`, { email: 'ana@x.com', permission: 'compute', expiry_days: 7 }, mgr);
  assert.equal((await api('GET', `/api/datasets/${ds}/records/${rid}`, null, ana)).status, 403); ok('compute-only grant cannot download ciphertext');
  assert.equal((await api('POST', `/api/datasets/${ds}/records`, { ciphertext: stored, n_values: 4 }, ana)).status, 403); ok('compute-only grant cannot upload');
  assert.equal((await api('GET', `/api/datasets`, null, eve)).body.length, 0); ok('ungranted user cannot see dataset');

  // --- correctness of computation on ciphertext (job requested by grantee) ---
  const cols = rows[0].map((_, j) => rows.reduce((s, r) => s + r[j], 0));
  const eps = scheme === 'BFV' ? 0 : 1e-3;
  t = performance.now();
  const sum = (await api('POST', `/api/datasets/${ds}/jobs`, { operation: 'sum' }, ana)).body;
  const sumMs = sum.duration_ms;
  assert.ok(sum.result_ciphertext);
  // grantee holds no secret key: cannot decrypt (wrong key yields garbage, not the answer)
  const other = generateKeys(seal, ctx);
  const garbage = decryptValues(seal, ctx, scheme, other.secretKey, sum.result_ciphertext, 4);
  assert.ok(garbage.some((g, i) => Math.abs(g - cols[i]) > 1)); ok('only the owner key decrypts the result');
  const got = decryptValues(seal, ctx, scheme, keys.secretKey, sum.result_ciphertext, 4);
  got.forEach((g, i) => near(g, cols[i], eps)); ok('encrypted SUM is correct: ' + got.map(g => +g.toFixed(2)));

  const sc = (await api('POST', `/api/datasets/${ds}/jobs`, { operation: 'scale', scalar: 3 }, mgr)).body;
  decryptValues(seal, ctx, scheme, keys.secretKey, sc.result_ciphertext, 4).forEach((g, i) => near(g, cols[i] * 3, eps * 10)); ok('encrypted scalar multiply is correct');

  const sq = (await api('POST', `/api/datasets/${ds}/jobs`, { operation: 'sumsq' }, mgr)).body;
  const exp = rows[0].map((_, j) => rows.reduce((s, r) => s + r[j] ** 2, 0));
  const gsq = decryptValues(seal, ctx, scheme, keys.secretKey, sq.result_ciphertext, 4);
  gsq.forEach((g, i) => near(g, exp[i], scheme === 'BFV' ? 0 : exp[i] * 1e-5 + 1e-2)); ok('encrypted ciphertext×ciphertext (sum of squares) is correct');

  // variance of column 0 from decrypted aggregates
  const n = rows.length, mean = cols[0] / n, variance = exp[0] / n - mean ** 2;
  const dv = gsq[0] / n - (got[0] / n) ** 2; near(dv, variance, scheme === 'BFV' ? 1e-6 : 0.1); ok('variance derived client-side matches plaintext');

  const bad = await api('POST', `/api/datasets/${ds}/jobs`, { operation: 'scale', scalar: 1.5 }, mgr);
  if (scheme === 'BFV') assert.equal(bad.status, 400);
  console.log(`  perf: encrypt ${encMs.toFixed(0)} ms/record, ciphertext ${(bytes / 1024).toFixed(0)} KiB (b64) per record (holds up to ${scheme === 'BFV' ? 8192 : 4096} packed values; ${(bytes / (slots * 8)).toFixed(1)}x vs 8-byte plaintext when full), SUM(3 recs) ${sumMs.toFixed(0)} ms, relin key ${(keys.relinKeys.length / 1048576).toFixed(1)} MiB`);
}

// --- audit ---
const a = (await api('GET', '/api/audit', null, adm)).body.map(x => x.action);
for (const k of ['LOGIN_FAILED', 'DENY_ROLE', 'DENY_DATASET', 'GRANT', 'JOB_OK', 'REJECT_SECRET_KEY_UPLOAD', 'DENY_UNAUTHENTICATED']) assert.ok(a.includes(k), k);
ok('audit log captured denials, grants, jobs');
assert.equal((await api('GET', '/api/audit', null, ana)).body.every(x => x.email === 'ana@x.com'), true); ok('non-admin sees only own audit events');
// brute-force lockout
for (let i = 0; i < 5; i++) await api('POST', '/api/login', { email: 'eve@x.com', password: 'nope' });
assert.equal((await api('POST', '/api/login', { email: 'eve@x.com', password: 'password123' })).status, 429); ok('login lockout after repeated failures');
console.log(`\n${passed} checks passed`);
server.close();
