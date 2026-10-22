import express from 'express';
import { JwksStore } from '../shared/jwks-store.mjs';
import { jwtAuth, requireScope, denylist, metrics } from '../shared/auth-middleware.mjs';
import { createRedis } from '../shared/redis.mjs';

const port = Number(process.env.PORT ?? 4002);
const host = process.env.HOST ?? '127.0.0.1';
const authUrl = process.env.AUTH_URL ?? 'http://localhost:4000';

const redis = createRedis();
const store = await new JwksStore({ jwksUrl: `${authUrl}/.well-known/jwks.json`, redis }).start();

const app = express();
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.get('/readyz', (req, res) => (store.ready ? res.json({ ready: true, jwks: store.source }) : res.status(503).json({ ready: false })));
app.get('/metrics', (req, res) => res.json(metrics));

app.use(jwtAuth({ store, issuer: authUrl, audience: 'billing-api', redis }));

app.get('/invoices', requireScope('billing:read'), (req, res) =>
  res.json({ caller: req.auth.sub, order: req.query.order ?? null, invoices: [{ id: 'inv-1', amount: 42 }] }));
app.post('/invoices', requireScope('billing:write'), denylist({ redis }), express.json(), (req, res) =>
  res.status(201).json({ id: 'inv-2', createdBy: req.auth.sub }));

const server = app.listen(port, host, () => console.log(`billing on :${port}`));
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { server.close(); store.stop(); redis.quit(); process.exit(0); });
