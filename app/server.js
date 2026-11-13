import express from 'express';
import jwt from 'jsonwebtoken';
import SEAL from 'node-seal';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeContext, evaluate, validatePublic, validateCiphertext } from './public/he.js';
import { MemoryStore, storeFromEnv } from './store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OPS = ['sum', 'scale', 'sumsq'];
const RANK = { compute: 1, read: 2, write: 3 }; // grant permission levels
const ROLES = ['admin', 'manager', 'analyst'];
const now = () => new Date().toISOString();

export async function createApp({ store = new MemoryStore(), secret } = {}) {
  const JWT_SECRET = secret || process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
  if (!secret && !process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET not set; sessions reset on every restart.');
  const seal = await SEAL();
  const ctxCache = {};
  const ctxFor = s => (ctxCache[s] ??= makeContext(seal, s));
  const audit = (actor, action, detail) => store.audit(actor, action, detail);

  // ---- Password hashing (scrypt) ----
  const hash = pw => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
  const verify = (pw, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64), Buffer.from(k, 'hex')); };

  // ---- Login throttling: 5 failures / 15 min per email (per instance) ----
  const fails = new Map();
  const locked = email => { const f = (fails.get(email) || []).filter(t => Date.now() - t < 15 * 60e3); fails.set(email, f); return f.length >= 5; };

  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' }); next(); });
  app.use(express.json({ limit: '60mb' }));
  app.get('/healthz', (req, res) => res.json({ ok: true }));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use('/vendor/seal', express.static(path.join(__dirname, 'node_modules/node-seal/dist')));

  const wrap = fn => async (req, res) => { try { await fn(req, res); } catch (e) { if (!e.status) console.error(e); res.status(e.status || 500).json({ error: e.status ? e.message : 'internal error' }); } };
  const fail = (status, message) => Object.assign(new Error(message), { status });

  // ---- Application tier: auth + RBAC ----
  const auth = async (req, res, next) => {
    try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); next(); }
    catch { await audit(null, 'DENY_UNAUTHENTICATED', req.method + ' ' + req.path); res.status(401).json({ error: 'authentication required' }); }
  };
  const roles = (...allowed) => async (req, res, next) => {
    if (allowed.includes(req.user.role)) return next();
    await audit(req.user.id, 'DENY_ROLE', `${req.user.role} -> ${req.method} ${req.path}`);
    res.status(403).json({ error: 'role not permitted' });
  };
  const grantOf = async (ds, userId) => { const g = await store.get('access_grant', `${ds}-${userId}`); return g && (!g.expiry || g.expiry > now()) ? g : null; };
  // minRank 99 = owner only
  const need = async (req, minRank) => {
    const ds = await store.get('dataset', Number(req.params.id));
    if (!ds) throw fail(404, 'dataset not found');
    let lvl = ds.owner_id === req.user.id ? 'owner' : (await grantOf(ds.dataset_id, req.user.id))?.permission;
    if (!lvl || (lvl !== 'owner' && RANK[lvl] < minRank)) {
      await audit(req.user.id, 'DENY_DATASET', `dataset ${ds.dataset_id} ${req.method} ${req.path}`);
      throw fail(403, 'no permission on this dataset');
    }
    return { ds, lvl };
  };

  app.post('/api/register', wrap(async (req, res) => {
    const { name, email, password, role } = req.body || {};
    if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 8) throw fail(400, 'name, valid email and password (8+ chars) required');
    const em = email.toLowerCase();
    if ((await store.find('user', 'email', em)).length) throw fail(409, 'email already registered');
    if (role && !['manager', 'analyst'].includes(role)) throw fail(400, 'role must be manager or analyst');
    const id = await store.nextId('user');
    const r = id === 1 ? 'admin' : role;           // the very first account is the administrator
    if (!ROLES.includes(r)) throw fail(400, 'role must be manager or analyst');
    await store.put('user', id, { user_id: id, name, email: em, password_hash: hash(password), role: r, created_at: now() });
    await audit(id, 'REGISTER', r);
    res.status(201).json({ user_id: id, role: r });
  }));

  app.post('/api/login', wrap(async (req, res) => {
    const email = String(req.body?.email || '').toLowerCase();
    if (locked(email)) { await audit(null, 'LOGIN_LOCKED', email); throw fail(429, 'too many failed attempts, try again later'); }
    const u = (await store.find('user', 'email', email))[0];
    if (!u || !verify(String(req.body?.password || ''), u.password_hash)) {
      fails.get(email)?.push(Date.now()) || fails.set(email, [Date.now()]);
      await audit(u?.user_id, 'LOGIN_FAILED', email);
      throw fail(401, 'invalid credentials');
    }
    await audit(u.user_id, 'LOGIN_OK');
    const token = jwt.sign({ id: u.user_id, role: u.role, name: u.name, email: u.email }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: u.user_id, name: u.name, email: u.email, role: u.role } });
  }));

  app.get('/api/datasets', auth, wrap(async (req, res) => {
    res.json((await store.accessRows(req.user.id)).sort((a, b) => b.dataset_id - a.dataset_id));
  }));

  // Owner uploads PUBLIC material only. The secret key stays in the browser.
  app.post('/api/datasets', auth, roles('admin', 'manager'), wrap(async (req, res) => {
    const { title, scheme, public_key, relin_keys, columns } = req.body || {};
    if (columns != null && (!Array.isArray(columns) || columns.length < 1 || columns.length > 12 || columns.some(c => typeof c !== 'string' || !c.trim() || c.length > 40))) throw fail(400, 'columns must be 1-12 names of up to 40 characters');
    if (!title || !['BFV', 'CKKS'].includes(scheme) || !public_key || !relin_keys) throw fail(400, 'title, scheme, public_key, relin_keys required');
    if ('secret_key' in req.body) { await audit(req.user.id, 'REJECT_SECRET_KEY_UPLOAD'); throw fail(400, 'never send a secret key to the server'); }
    try { validatePublic(seal, ctxFor(scheme), public_key, relin_keys); }
    catch { throw fail(400, 'public/relin keys are not valid for the platform parameters'); }
    const id = await store.nextId('dataset');
    await Promise.all([store.putBlob(`datasets/${id}/public_key`, public_key), store.putBlob(`datasets/${id}/relin_keys`, relin_keys)]);
    await store.put('dataset', id, { dataset_id: id, owner_id: req.user.id, title: String(title).slice(0, 200), scheme, columns: columns ? columns.map(c => c.trim()) : null, created_at: now() });
    await audit(req.user.id, 'DATASET_CREATE', `${id} ${scheme}`);
    res.status(201).json({ dataset_id: id });
  }));

  app.get('/api/datasets/:id', auth, wrap(async (req, res) => {
    const { ds, lvl } = await need(req, 1);
    res.json({ dataset_id: ds.dataset_id, title: ds.title, scheme: ds.scheme, columns: ds.columns || null, owner_id: ds.owner_id, public_key: await store.getBlob(`datasets/${ds.dataset_id}/public_key`), access: lvl });
  }));

  app.get('/api/datasets/:id/records', auth, wrap(async (req, res) => {
    await need(req, RANK.read);
    res.json((await store.find('encrypted_record', 'dataset_id', Number(req.params.id))).sort((a, b) => a.record_id - b.record_id));
  }));

  app.post('/api/datasets/:id/records', auth, wrap(async (req, res) => {
    const { ds } = await need(req, RANK.write);
    const { label, ciphertext, n_values } = req.body || {};
    if (!ciphertext || !Number.isInteger(n_values) || n_values < 1 || n_values > 8192) throw fail(400, 'ciphertext and n_values required');
    if (ds.columns && n_values > ds.columns.length) throw fail(400, `this dataset has ${ds.columns.length} columns`);
    try { validateCiphertext(seal, ctxFor(ds.scheme), ciphertext); } catch { throw fail(400, 'ciphertext is not valid for this dataset'); }
    const id = await store.nextId('encrypted_record');
    await store.putBlob(`datasets/${ds.dataset_id}/records/${id}`, ciphertext);
    await store.put('encrypted_record', id, { record_id: id, dataset_id: ds.dataset_id, uploader_id: req.user.id, label: String(label || '').slice(0, 200), n_values, ciphertext_bytes: ciphertext.length, created_at: now() });
    await audit(req.user.id, 'RECORD_UPLOAD', `dataset ${ds.dataset_id} record ${id}`);
    res.status(201).json({ record_id: id });
  }));

  app.get('/api/datasets/:id/records/:rid', auth, wrap(async (req, res) => {
    await need(req, RANK.read);
    const r = await store.get('encrypted_record', Number(req.params.rid));
    if (!r || r.dataset_id !== Number(req.params.id)) throw fail(404, 'record not found');
    await audit(req.user.id, 'RECORD_DOWNLOAD', `record ${r.record_id}`);
    res.json({ ...r, ciphertext: await store.getBlob(`datasets/${r.dataset_id}/records/${r.record_id}`) });
  }));

  // ---- Access grants (owner only) ----
  app.get('/api/datasets/:id/grants', auth, wrap(async (req, res) => {
    await need(req, 99);
    const gs = await store.find('access_grant', 'dataset_id', Number(req.params.id));
    res.json(await Promise.all(gs.map(async g => { const u = await store.get('user', g.user_id); return { grant_id: g.grant_id, email: u?.email, name: u?.name, permission: g.permission, expiry: g.expiry }; })));
  }));
  app.post('/api/datasets/:id/grants', auth, wrap(async (req, res) => {
    const { ds } = await need(req, 99);
    const { email, permission, expiry_days } = req.body || {};
    if (!RANK[permission]) throw fail(400, 'permission must be compute, read or write');
    const u = (await store.find('user', 'email', String(email || '').toLowerCase()))[0];
    if (!u) throw fail(404, 'user not found');
    if (u.user_id === ds.owner_id) throw fail(400, 'owner already has full access');
    const expiry = expiry_days ? new Date(Date.now() + Number(expiry_days) * 864e5).toISOString() : null;
    const gid = `${ds.dataset_id}-${u.user_id}`;
    await store.put('access_grant', gid, { grant_id: gid, dataset_id: ds.dataset_id, user_id: u.user_id, permission, expiry });
    await audit(req.user.id, 'GRANT', `dataset ${ds.dataset_id} user ${u.user_id} ${permission}`);
    res.status(201).json({ ok: true });
  }));
  app.delete('/api/datasets/:id/grants/:gid', auth, wrap(async (req, res) => {
    const { ds } = await need(req, 99);
    const g = await store.get('access_grant', req.params.gid);
    if (g && g.dataset_id === ds.dataset_id) { await store.del('access_grant', req.params.gid); await audit(req.user.id, 'REVOKE', `grant ${req.params.gid}`); }
    res.json({ ok: true });
  }));

  // ---- Computation on ciphertext ----
  app.post('/api/datasets/:id/jobs', auth, wrap(async (req, res) => {
    const { ds } = await need(req, RANK.compute);
    const { operation, scalar } = req.body || {};
    if (!OPS.includes(operation)) throw fail(400, 'operation must be one of ' + OPS.join(', '));
    const recs = await store.find('encrypted_record', 'dataset_id', ds.dataset_id);
    if (!recs.length) throw fail(400, 'dataset has no records');
    const [relin, cts] = await Promise.all([store.getBlob(`datasets/${ds.dataset_id}/relin_keys`), Promise.all(recs.map(r => store.getBlob(`datasets/${ds.dataset_id}/records/${r.record_id}`)))]);
    const t0 = performance.now();
    let result = null, status = 'done';
    try { result = evaluate(seal, ctxFor(ds.scheme), ds.scheme, relin, cts, operation, scalar); }
    catch (e) { status = 'failed: ' + e.message; }
    const ms = performance.now() - t0, nVals = Math.max(...recs.map(r => r.n_values));
    const id = await store.nextId('computation_job');
    if (result) await store.putBlob(`jobs/${id}`, result);
    await store.put('computation_job', id, { job_id: id, dataset_id: ds.dataset_id, requester_id: req.user.id, operation, scalar: scalar ?? null, status, record_count: recs.length, n_values: nVals, duration_ms: ms, created_at: now() });
    await audit(req.user.id, 'JOB_' + (result ? 'OK' : 'FAILED'), `job ${id} ${operation} dataset ${ds.dataset_id} ${ms.toFixed(0)}ms`);
    if (!result) throw fail(400, status);
    res.status(201).json({ job_id: id, operation, scheme: ds.scheme, record_count: recs.length, n_values: nVals, duration_ms: ms, result_ciphertext: result });
  }));

  app.get('/api/datasets/:id/jobs', auth, wrap(async (req, res) => {
    const { lvl } = await need(req, RANK.compute);
    let jobs = await store.find('computation_job', 'dataset_id', Number(req.params.id));
    if (lvl !== 'owner') jobs = jobs.filter(j => j.requester_id === req.user.id);
    jobs = jobs.sort((a, b) => b.job_id - a.job_id).slice(0, 50);
    res.json(await Promise.all(jobs.map(async j => ({ ...j, requester: (await store.get('user', j.requester_id))?.name }))));
  }));

  // ---- Audit log: admin sees everything, others see own events ----
  app.get('/api/audit', auth, wrap(async (req, res) => {
    const rows = await store.recentAudit(req.user.role === 'admin' ? null : req.user.id, 200);
    const emails = {};
    for (const r of rows) if (r.actor_id != null && !(r.actor_id in emails)) emails[r.actor_id] = (await store.get('user', r.actor_id))?.email;
    res.json(rows.map(r => ({ ...r, email: emails[r.actor_id] })));
  }));

  return { app };
}

// Serverless entry (Vercel): lazily build the app once per instance and hand requests to it.
let ready;
export default function handler(req, res) {
  ready ??= storeFromEnv().then(store => createApp({ store })).then(r => r.app);
  ready.then(app => app(req, res)).catch(e => { console.error(e); ready = undefined; if (!res.headersSent) res.statusCode = 500; res.end('startup failed'); });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { app } = await createApp({ store: await storeFromEnv() });
  const port = process.env.PORT || 3000;
  app.listen(port, '0.0.0.0', () => console.log(`Secure Business Management Platform on port ${port}`));
}
