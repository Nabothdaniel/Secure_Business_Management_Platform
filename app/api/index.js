// Vercel serverless entry: wraps the same Express app used by `npm start`.
import { createApp } from '../server.js';
import { storeFromEnv } from '../store.js';

let ready;
export default async function handler(req, res) {
  ready ??= storeFromEnv().then(store => createApp({ store })).then(r => r.app);
  const app = await ready;
  return app(req, res);
}
