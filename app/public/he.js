// Shared homomorphic-encryption helpers (runs in the browser AND on the server).
// `seal` is the initialised node-seal (Microsoft SEAL / WASM) module.
export const DEG = 8192;
export const CKKS_SCALE = 2 ** 40;
export const BFV_MAX = 1000; // |v| limit so that sum of squares stays below the 20-bit plain modulus (see README)

// WASM objects are not garbage collected: `scope` frees every object created through it.
function scope(seal) {
  const live = [];
  const t = o => (live.push(o), o);
  return {
    t,
    zstd: seal.ComprModeType.zstd,
    free: () => live.forEach(o => { try { o.delete(); } catch {} }),
  };
}

export function makeContext(seal, scheme) {
  const p = new seal.EncryptionParameters(scheme === 'BFV' ? seal.SchemeType.bfv : seal.SchemeType.ckks);
  p.setPolyModulusDegree(DEG);
  if (scheme === 'BFV') {
    p.setCoeffModulus(seal.CoeffModulus.BFVDefault(DEG, seal.SecLevelType.tc128));
    p.setPlainModulus(seal.PlainModulus.Batching(DEG, 20));
  } else {
    p.setCoeffModulus(seal.CoeffModulus.Create(DEG, Int32Array.from([60, 40, 40, 60])));
  }
  return new seal.SEALContext(p, true, seal.SecLevelType.tc128); // long-lived, cached by callers
}

// Client only: generates the key set. The secret key must never be sent to the server.
export function generateKeys(seal, ctx) {
  const s = scope(seal);
  try {
    const kg = s.t(new seal.KeyGenerator(ctx));
    const sk = s.t(kg.secretKey()), pk = s.t(kg.createPublicKey()), rk = s.t(kg.createRelinKeys());
    return { secretKey: sk.saveToBase64(s.zstd), publicKey: pk.saveToBase64(s.zstd), relinKeys: rk.saveToBase64(s.zstd) };
  } finally { s.free(); }
}

export function encryptValues(seal, ctx, scheme, publicKeyB64, values) {
  const s = scope(seal);
  try {
    const pk = s.t(new seal.PublicKey()); pk.loadFromBase64(ctx, publicKeyB64);
    const enc = s.t(new seal.Encryptor(ctx, pk));
    const plain = s.t(new seal.Plaintext());
    if (scheme === 'BFV') {
      values.forEach(v => { if (!Number.isInteger(v) || Math.abs(v) > BFV_MAX) throw new Error(`BFV values must be integers with |v| <= ${BFV_MAX}`); });
      s.t(new seal.BatchEncoder(ctx)).encode(BigInt64Array.from(values.map(BigInt)), plain);
    } else {
      s.t(new seal.CKKSEncoder(ctx)).encode(Float64Array.from(values), CKKS_SCALE, plain);
    }
    const ct = s.t(new seal.Ciphertext()); enc.encrypt(plain, ct);
    return ct.saveToBase64(s.zstd);
  } finally { s.free(); }
}

export function decryptValues(seal, ctx, scheme, secretKeyB64, ctB64, n) {
  const s = scope(seal);
  try {
    const sk = s.t(new seal.SecretKey()); sk.loadFromBase64(ctx, secretKeyB64);
    const dec = s.t(new seal.Decryptor(ctx, sk));
    const ct = s.t(new seal.Ciphertext()); ct.loadFromBase64(ctx, ctB64);
    const plain = s.t(new seal.Plaintext()); dec.decrypt(ct, plain);
    const out = scheme === 'BFV' ? Array.from(s.t(new seal.BatchEncoder(ctx)).decodeBigInt64(plain), Number)
                                 : Array.from(s.t(new seal.CKKSEncoder(ctx)).decodeFloat64(plain));
    return out.slice(0, n);
  } finally { s.free(); }
}

export function validatePublic(seal, ctx, publicB64, relinB64) {
  const s = scope(seal);
  try {
    s.t(new seal.PublicKey()).loadFromBase64(ctx, publicB64);
    s.t(new seal.RelinKeys()).loadFromBase64(ctx, relinB64);
  } finally { s.free(); }
}
export function validateSecret(seal, ctx, secretB64) {
  const k = new seal.SecretKey();
  try { k.loadFromBase64(ctx, secretB64); } finally { k.delete(); }
}
export function validateCiphertext(seal, ctx, ctB64) {
  const c = new seal.Ciphertext();
  try { c.loadFromBase64(ctx, ctB64); } finally { c.delete(); }
}

// Server side: evaluates on ciphertext only. No secret key is ever involved.
export function evaluate(seal, ctx, scheme, relinB64, cts, op, scalar) {
  const s = scope(seal);
  try {
    const ev = s.t(new seal.Evaluator(ctx));
    const loaded = cts.map(b => { const c = s.t(new seal.Ciphertext()); c.loadFromBase64(ctx, b); return c; });
    const sumAll = list => { const acc = s.t(list[0].copy()); list.slice(1).forEach(c => ev.add(acc, c, acc)); return acc; };
    let result;
    if (op === 'sum') {
      result = sumAll(loaded);
    } else if (op === 'scale') {
      const k = Number(scalar);
      if (!Number.isFinite(k) || (scheme === 'BFV' && !Number.isInteger(k))) throw new Error('invalid scalar for scheme');
      const plain = s.t(new seal.Plaintext());
      if (scheme === 'BFV') s.t(new seal.BatchEncoder(ctx)).encode(new BigInt64Array(DEG).fill(BigInt(k)), plain);
      else s.t(new seal.CKKSEncoder(ctx)).encode(new Float64Array(DEG / 2).fill(k), CKKS_SCALE, plain);
      result = s.t(new seal.Ciphertext()); ev.multiplyPlain(sumAll(loaded), plain, result);
      if (scheme === 'CKKS') ev.rescaleToNext(result, result);
    } else if (op === 'sumsq') {
      const rk = s.t(new seal.RelinKeys()); rk.loadFromBase64(ctx, relinB64);
      result = sumAll(loaded.map(c => {
        const r = s.t(new seal.Ciphertext()); ev.square(c, r); ev.relinearize(r, rk, r);
        if (scheme === 'CKKS') ev.rescaleToNext(r, r);
        return r;
      }));
    } else throw new Error('unsupported operation');
    return result.saveToBase64(s.zstd);
  } finally { s.free(); }
}
