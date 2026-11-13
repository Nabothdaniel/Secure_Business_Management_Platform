// Performance + accuracy evaluation for Chapter 4. Run: node --no-warnings test/bench.js
import SEAL from 'node-seal';
import { makeContext, generateKeys, encryptValues, decryptValues, evaluate } from '../public/he.js';
const seal = await SEAL();
const med = a => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const time = (f, n) => { const t = []; let r; for (let i = 0; i < n; i++) { const s = performance.now(); r = f(); t.push(performance.now() - s); } return [med(t), r]; };
const out = {};
for (const scheme of ['BFV', 'CKKS']) {
  const ctx = makeContext(seal, scheme), slots = scheme === 'BFV' ? 8192 : 4096, r = {};
  let keys; [r.keygen] = time(() => (keys = generateKeys(seal, ctx)), 5);
  r.pk_kib = keys.publicKey.length / 1024; r.rk_mib = keys.relinKeys.length / 1048576; r.sk_kib = keys.secretKey.length / 1024;
  const rnd = n => Array.from({ length: n }, () => scheme === 'BFV' ? Math.floor(Math.random() * 201) - 100 : Math.round((Math.random() * 20000) * 100) / 100);
  const vals = rnd(slots); let ct;
  [r.enc, ct] = time(() => encryptValues(seal, ctx, scheme, keys.publicKey, vals), 15);
  [r.dec] = time(() => decryptValues(seal, ctx, scheme, keys.secretKey, ct, slots), 15);
  r.ct_kib = ct.length / 1024; r.plain_kib = slots * 8 / 1024;
  const pool = Array.from({ length: 20 }, () => encryptValues(seal, ctx, scheme, keys.publicKey, rnd(slots)));
  r.sum = {}; r.sumsq = {}; r.scale = {};
  for (const n of [10, 50, 100]) { const cts = Array.from({ length: n }, (_, i) => pool[i % 20]);
    [r.sum[n]] = time(() => evaluate(seal, ctx, scheme, keys.relinKeys, cts, 'sum'), 5);
    [r.sumsq[n]] = time(() => evaluate(seal, ctx, scheme, keys.relinKeys, cts, 'sumsq'), 3);
    [r.scale[n]] = time(() => evaluate(seal, ctx, scheme, keys.relinKeys, cts, 'scale', 3), 3); }
  // accuracy over 20 records x full slots, values as in a ledger
  const rows = Array.from({ length: 20 }, () => rnd(slots));
  const cts = rows.map(v => encryptValues(seal, ctx, scheme, keys.publicKey, v));
  const exp = Array.from({ length: slots }, (_, j) => rows.reduce((s, v) => s + v[j], 0));
  const got = decryptValues(seal, ctx, scheme, keys.secretKey, evaluate(seal, ctx, scheme, keys.relinKeys, cts, 'sum'), slots);
  r.sum_maxerr = Math.max(...got.map((g, j) => Math.abs(g - exp[j]))); r.sum_maxrel = Math.max(...got.map((g, j) => Math.abs(g - exp[j]) / Math.max(1, Math.abs(exp[j]))));
  const exq = Array.from({ length: slots }, (_, j) => rows.reduce((s, v) => s + v[j] ** 2, 0));
  if (scheme === 'CKKS') { const gq = decryptValues(seal, ctx, scheme, keys.secretKey, evaluate(seal, ctx, scheme, keys.relinKeys, cts, 'sumsq'), slots);
    r.sq_maxrel = Math.max(...gq.map((g, j) => Math.abs(g - exq[j]) / Math.max(1, Math.abs(exq[j])))); }
  else { const gq = decryptValues(seal, ctx, scheme, keys.secretKey, evaluate(seal, ctx, scheme, keys.relinKeys, cts, 'sumsq'), slots); r.sq_maxerr = Math.max(...gq.map((g, j) => Math.abs(g - exq[j]))); }
  out[scheme] = r;
}
console.log(JSON.stringify(out, null, 1));
