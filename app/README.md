# Secure Business Management Platform (homomorphic encryption)

Prototype for the project report (Chapters 1–3). The server stores and computes on **ciphertext only**;
keys are generated, and results decrypted, **in the user's browser**. Built on Microsoft SEAL (`node-seal`, WASM):
**BFV** (exact integers) and **CKKS** (approximate decimals), N = 8192, 128-bit security.

    npm install
    npm start          # http://localhost:3000 — without Firebase env vars it uses an in-memory store (data lost on restart)
    npm test           # 31 end-to-end checks + timing/size measurements

## Using the app
Sign in or create an account (the first account is the administrator) → **New dataset** (name it, pick Decimals/CKKS or Whole numbers/BFV, name the columns; download the key backup) → **Records** (one field per column, or paste many rows) → **Analyze** (totals, averages, variance, std. deviation, factor) → **Sharing** (compute / read / write, optional expiry) → **Activity** (audit log). Light/dark themes, keyboard accessible, works on phones.

## Mapping to Chapter 3
| Report | Implementation |
|---|---|
| Fig 3.2 tiers | `public/` client tier · `server.js` application tier (JWT, RBAC, validation) · `public/he.js` cryptographic tier (shared by browser and server) · Firebase data tier (Firestore for records of users/datasets/grants/jobs/audit; public keys, relinearization keys and ciphertexts are split into chunk documents because they exceed Firestore's 1 MiB document limit; no Storage bucket is used, so the free Spark plan is enough) |
| Fig 3.3 flowchart | register/login → encrypt with public key in browser → store ciphertext → authorised job → server computes → result decrypted client-side; denials are logged |
| Fig 3.4 ERD | Firestore collections `user, dataset, encrypted_record, access_grant, computation_job, audit_log` (`store.js`) |
| RBAC | roles admin / manager / analyst; per-dataset grants `compute < read < write` with optional expiry; owner-only grant management |
| Audit logging | login success/failure/lockout, every denial, uploads, downloads, grants, jobs |

## Server-side homomorphic operations
`sum` (add), `scale` (plaintext scalar multiply), `sumsq` (ciphertext×ciphertext multiply + relinearisation).
Mean and variance are finished by the key holder after decryption (`mean = sum/n`, `var = E[x²] − mean²`).
Each record is one ciphertext whose slots are a row of values (up to 8192 BFV / 4096 CKKS); operations are slot-wise across records.

## Known limits (state these in the report)
* BFV values must be integers with |v| ≤ 1000 so that sums of squares stay below the 20-bit plaintext modulus; use CKKS for money amounts.
* CKKS is approximate (error ≈ 1e-3 on the test data). Each exposed operation uses at most one ciphertext multiplication.
* Secret keys live in the browser's `localStorage` (+ downloadable backup). Losing it means losing the data; there is no recovery service by design.
* Still needed for production: HTTPS/TLS termination, persistent `JWT_SECRET`, CSRF/CSP headers, per-IP rate limiting, key rotation/backup policy.
* A grantee with `read` can download ciphertexts but cannot decrypt without the owner's key (verified in tests).

## Deploy: Vercel (server) + Firebase (database)
1. **Firebase console** → create a project → *Build → Firestore Database* (create, production mode).
2. *Project settings → Service accounts → Generate new private key* → keep the JSON file private (never commit it).
3. Deploy the rules in `firestore.rules` (deny all client access; only the server's admin credentials can read or write): `firebase deploy --only firestore:rules`.
4. Push this `app/` folder to a GitHub repo (set Vercel's *Root Directory* to `app`).
5. **Vercel** → import the repo, set Root Directory to `app` (uses `vercel.json` and `api/index.js`).
6. In Vercel's *Environment Variables* set `FIREBASE_SERVICE_ACCOUNT` (paste the whole JSON) and `JWT_SECRET` (a long random string).
7. Open the Vercel URL (HTTPS is provided). The first account you register becomes the administrator.

Note: login lockout counters are per instance and reset on cold start. Vercel functions cap request bodies at about 4.5 MB.
