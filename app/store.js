// Data tier. Two interchangeable backends with the same async interface:
//  - FirebaseStore: Firestore only (metadata, plus big blobs split into <1 MiB chunk docs; no Storage bucket / paid plan needed)
//  - MemoryStore: in-process, for tests and local dev without Firebase credentials
const nowIso = () => new Date().toISOString();

class Base {
  // shared logic built on the primitives each backend implements
  async accessRows(userId) { // datasets visible to a user (owned or validly granted)
    const mine = await this.find('dataset', 'owner_id', userId);
    const grants = (await this.find('access_grant', 'user_id', userId)).filter(g => !g.expiry || g.expiry > nowIso());
    const granted = (await Promise.all(grants.map(g => this.get('dataset', g.dataset_id)))).filter(Boolean);
    const rows = [...mine.map(d => ({ d, access: 'owner', expiry: null })), ...granted.map(d => ({ d, access: grants.find(g => g.dataset_id === d.dataset_id).permission, expiry: grants.find(g => g.dataset_id === d.dataset_id).expiry }))];
    return Promise.all(rows.map(async ({ d, access, expiry }) => ({
      dataset_id: d.dataset_id, title: d.title, scheme: d.scheme, columns: d.columns || null, owner_id: d.owner_id, created_at: d.created_at,
      owner_name: (await this.get('user', d.owner_id))?.name, record_count: await this.count('encrypted_record', 'dataset_id', d.dataset_id), access, expiry })));
  }
  async audit(actor, action, detail = '') {
    const id = await this.nextId('audit_log');
    await this.put('audit_log', id, { log_id: id, actor_id: actor ?? null, action, detail: String(detail).slice(0, 300), timestamp: nowIso() });
  }
}

export class MemoryStore extends Base {
  constructor() { super(); this.t = {}; this.blobs = new Map(); this.c = {}; }
  tbl(n) { return (this.t[n] ??= new Map()); }
  async nextId(n) { return (this.c[n] = (this.c[n] || 0) + 1); }
  async put(n, id, doc) { this.tbl(n).set(String(id), structuredClone(doc)); }
  async get(n, id) { const d = this.tbl(n).get(String(id)); return d ? structuredClone(d) : null; }
  async del(n, id) { this.tbl(n).delete(String(id)); }
  async find(n, field, val) { return [...this.tbl(n).values()].filter(d => d[field] === val).map(d => structuredClone(d)); }
  async count(n, field, val) { return (await this.find(n, field, val)).length; }
  async all(n) { return [...this.tbl(n).values()].map(d => structuredClone(d)); }
  async putBlob(p, s) { this.blobs.set(p, s); }
  async getBlob(p) { return this.blobs.get(p); }
}

export class FirebaseStore extends Base {
  constructor({ fb, serviceAccount }) {
    super();
    const app = fb.app.initializeApp({ credential: fb.app.cert(serviceAccount) });
    this.fs = fb.firestore.getFirestore(app); this.fs.settings({ ignoreUndefinedProperties: true });
  }
  async nextId(n) { // atomic counter -> integer ids (the UI and JWTs use numeric ids)
    const ref = this.fs.collection('counters').doc(n);
    return this.fs.runTransaction(async tx => { const v = ((await tx.get(ref)).data()?.v || 0) + 1; tx.set(ref, { v }); return v; });
  }
  async put(n, id, doc) { await this.fs.collection(n).doc(String(id)).set(doc); }
  async get(n, id) { const s = await this.fs.collection(n).doc(String(id)).get(); return s.exists ? s.data() : null; }
  async del(n, id) { await this.fs.collection(n).doc(String(id)).delete(); }
  async find(n, field, val) { return (await this.fs.collection(n).where(field, '==', val).get()).docs.map(d => d.data()); }
  async count(n, field, val) { return (await this.fs.collection(n).where(field, '==', val).count().get()).data().count; }
  async all(n) { return (await this.fs.collection(n).get()).docs.map(d => d.data()); }
  // Blobs (keys, ciphertexts) exceed Firestore's 1 MiB doc limit, so store them as chunk docs in `blobs`.
  blobId(p, i) { return encodeURIComponent(p) + '~' + i; }
  async putBlob(p, s) {
    const CH = 700_000, n = Math.max(1, Math.ceil(s.length / CH)), col = this.fs.collection('blobs');
    for (let i = 0; i < n; i += 5) { // small batches keep each commit well under the request size cap
      const b = this.fs.batch();
      for (let j = i; j < Math.min(n, i + 5); j++) b.set(col.doc(this.blobId(p, j)), { path: p, i: j, n, data: s.slice(j * CH, (j + 1) * CH) });
      await b.commit();
    }
  }
  async getBlob(p) {
    const col = this.fs.collection('blobs'), first = await col.doc(this.blobId(p, 0)).get();
    if (!first.exists) return undefined;
    const { n, data } = first.data();
    const rest = await Promise.all(Array.from({ length: n - 1 }, (_, k) => col.doc(this.blobId(p, k + 1)).get()));
    return data + rest.map(d => d.data().data).join('');
  }
  async recentAudit(actor, limit) { // single-field queries only: no composite index needed
    const col = this.fs.collection('audit_log');
    if (actor == null) return (await col.orderBy('log_id', 'desc').limit(limit).get()).docs.map(d => d.data());
    return (await col.where('actor_id', '==', actor).get()).docs.map(d => d.data()).sort((a, b) => b.log_id - a.log_id).slice(0, limit);
  }
}
MemoryStore.prototype.recentAudit = async function (actor, limit) {
  return (await this.all('audit_log')).filter(a => actor == null || a.actor_id === actor).sort((a, b) => b.log_id - a.log_id).slice(0, limit);
};

export async function storeFromEnv() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const fb = { app: await import('firebase-admin/app'), firestore: await import('firebase-admin/firestore') };
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    console.log('Using Firebase project', sa.project_id);
    return new FirebaseStore({ fb, serviceAccount: sa });
  }
  console.warn('WARNING: no FIREBASE_SERVICE_ACCOUNT set. Using in-memory store; data is lost on restart.');
  return new MemoryStore();
}
