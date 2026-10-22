import express from 'express';
import { JwksStore } from '../shared/jwks-store.mjs';
import { jwtAuth, requireScope, denylist, metrics } from '../shared/auth-middleware.mjs';
import { serviceTokenClient } from '../shared/service-token.mjs';
import { createRedis } from '../shared/redis.mjs';

const port = Number(process.env.PORT ?? 4001);
const host = process.env.HOST ?? '127.0.0.1';
const authUrl = process.env.AUTH_URL ?? 'http://localhost:4000';
const billingUrl = process.env.BILLING_URL ?? 'http://localhost:4002';

const redis = createRedis();
const store = await new JwksStore({ jwksUrl: `${authUrl}/.well-known/jwks.json`, redis }).start();
const billingToken = serviceTokenClient({
  authUrl, clientId: 'orders-svc', clientSecret: process.env.ORDERS_CLIENT_SECRET ?? 'orders-secret',
  audience: 'billing-api', scope: 'billing:read',
});

const app = express();
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.get('/readyz', (req, res) => (store.ready ? res.json({ ready: true, jwks: store.source }) : res.status(503).json({ ready: false })));
app.get('/metrics', (req, res) => res.json(metrics));

app.use(jwtAuth({ store, issuer: authUrl, audience: 'orders-api', redis }));
app.use((req, res, next) => { // structured audit log (never the token itself)
  res.on('finish', () => console.log(JSON.stringify({ svc: 'orders', sub: req.auth?.sub, jti: req.auth?.jti, route: `${req.method} ${req.path}`, status: res.statusCode })));
  next();
});

app.get('/orders', requireScope('orders:read'), (req, res) =>
  res.json({ user: req.auth.sub, orders: [{ id: 1 }, { id: 2 }] }));

app.post('/orders', requireScope('orders:write'), denylist({ redis }), express.json(), (req, res) =>
  res.status(201).json({ id: 3, createdBy: req.auth.sub }));

// orders -> billing using a client-credentials token (not the user's)
app.get('/orders/:id/invoice', requireScope('orders:read'), async (req, res) => {
  try {
    const r = await fetch(`${billingUrl}/invoices?order=${req.params.id}`, {
      headers: { authorization: `Bearer ${await billingToken()}` },
    });
    res.status(r.status).json(await r.json());
  } catch (e) { res.status(502).json({ error: 'billing_unreachable' }); }
});

const server = app.listen(port, host, () => console.log(`orders on :${port}`));
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { server.close(); store.stop(); redis.quit(); process.exit(0); });
