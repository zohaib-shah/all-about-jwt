// Capstone acceptance suite. Needs Redis on localhost:6379 (uses DB 15, flushed at start).
//   docker compose up -d redis && node --test test/acceptance.test.mjs
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { SignJWT, importJWK, generateKeyPair, exportJWK } from 'jose';
import { createRedis } from '../services/shared/redis.mjs';
import { Client } from './cookie-client.mjs';

const REDIS_URL = 'redis://localhost:6379/15';
const AUTH = 'http://localhost:4000', ORDERS = 'http://localhost:4001', BILLING = 'http://localhost:4002';
const ADMIN = { 'x-admin-token': 'test-admin' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

let redis, keysFile;
const procs = {};

async function waitFor(url, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { if ((await fetch(url)).ok) return; } catch {}
    await sleep(100);
  }
  throw new Error(`timeout waiting for ${url}`);
}
function start(name, script, port, extraEnv = {}) {
  const p = spawn('node', [script], {
    env: { ...process.env, PORT: port, REDIS_URL, KEYS_FILE: keysFile, ADMIN_TOKEN: 'test-admin', ...extraEnv },
    stdio: process.env.DEBUG_SVC ? 'inherit' : 'ignore',
  });
  procs[name] = p;
  return p;
}
const stop = (name) => new Promise((r) => { const p = procs[name]; if (!p || p.exitCode !== null) return r(); p.once('exit', r); p.kill('SIGKILL'); });
const startAuth = async () => { start('auth', 'services/auth/index.mjs', 4000); await waitFor(`${AUTH}/healthz`); };
const startOrders = async () => { start('orders', 'services/orders/index.mjs', 4001); await waitFor(`${ORDERS}/readyz`); };
const startBilling = async () => { start('billing', 'services/billing/index.mjs', 4002); await waitFor(`${BILLING}/readyz`); };

async function resetLimits() {
  const ks = await redis.keys('rl:*');
  if (ks.length) await redis.del(...ks);
}
async function login(username = 'alice', audience = 'orders-api') {
  await resetLimits();
  const c = new Client(AUTH);
  const r = await c.json('/auth/login', { username, password: 'pw', audience });
  assert.equal(r.status, 200);
  c.access = (await r.json()).access_token;
  return c;
}
const call = (base, path, token, opts = {}) =>
  fetch(base + path, { ...opts, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(opts.headers ?? {}) } });
const tokenFor = async (username, audience) => (await login(username, audience)).access;

/** sign a token that auth's own key would sign (reads the private key from the keys file) */
async function signWithAuthKey({ aud = 'orders-api', exp, scope = 'orders:read' }) {
  const data = JSON.parse(await readFile(keysFile, 'utf8'));
  const { privateJwk } = data.keys[0];
  const { calculateJwkThumbprint } = await import('jose');
  const kid = await calculateJwkThumbprint({ kty: 'EC', crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y });
  return new SignJWT({ scope }).setProtectedHeader({ alg: 'ES256', kid })
    .setSubject('alice').setIssuer(AUTH).setAudience(aud).setJti('t-' + Math.random())
    .setIssuedAt(exp - 600).setExpirationTime(exp).sign(await importJWK(privateJwk, 'ES256'));
}

before(async () => {
  keysFile = join(await mkdtemp(join(tmpdir(), 'jwt-keys-')), 'keys.json');
  redis = createRedis(REDIS_URL);
  await redis.flushdb();
  await startAuth();
  await Promise.all([startOrders(), startBilling()]);
});
after(async () => {
  await Promise.all(Object.keys(procs).map(stop));
  await redis.quit();
});

// ---------------------------------------------------------------- Authentication
test('login returns an access token and an HttpOnly refresh cookie', async () => {
  await resetLimits();
  const r = await new Client(AUTH).json('/auth/login', { username: 'alice', password: 'pw' });
  assert.equal(r.status, 200);
  assert.ok((await r.json()).access_token);
  const sc = r.headers.getSetCookie()[0];
  assert.match(sc, /HttpOnly/); assert.match(sc, /Path=\/auth/); assert.match(sc, /SameSite=Strict/i);
});

test('orders accepts an orders-api token and serves data', async () => {
  const r = await call(ORDERS, '/orders', await tokenFor('alice'));
  assert.equal(r.status, 200);
  assert.equal((await r.json()).user, 'alice');
});

test('orders rejects billing-api audience, expired, tampered and alg=none tokens', async () => {
  const wrongAud = await tokenFor('alice', 'billing-api');
  assert.equal((await call(ORDERS, '/orders', wrongAud)).status, 401);

  const expired = await signWithAuthKey({ exp: Math.floor(Date.now() / 1000) - 3600 });
  const r = await call(ORDERS, '/orders', expired);
  assert.equal(r.status, 401);
  assert.equal((await r.json()).reason, 'ERR_JWT_EXPIRED');

  const good = await tokenFor('bob');
  const [h, p, s] = good.split('.');
  const tampered = `${h}.${b64u({ ...JSON.parse(Buffer.from(p, 'base64url')), scope: 'orders:read orders:write' })}.${s}`;
  assert.equal((await call(ORDERS, '/orders', tampered)).status, 401);

  const none = `${b64u({ alg: 'none' })}.${p}.`;
  assert.equal((await call(ORDERS, '/orders', none)).status, 401);
});

test('missing scope -> 403, missing token -> 401', async () => {
  assert.equal((await call(ORDERS, '/orders', await tokenFor('bob'), { method: 'POST' })).status, 403);
  assert.equal((await call(ORDERS, '/orders')).status, 401);
});

// ---------------------------------------------------------------- Refresh
test('refresh rotates the cookie; replaying an old token revokes the whole family', async () => {
  const c = await login('alice');
  const thief = c.clone();
  const before = c.cookies.rt;
  assert.equal((await c.json('/auth/refresh')).status, 200);
  assert.notEqual(c.cookies.rt, before);
  assert.equal((await thief.json('/auth/refresh')).status, 401); // replay of consumed token
  assert.equal((await c.json('/auth/refresh')).status, 401);     // family revoked -> legit client must re-login
});

test('6th login attempt within a minute -> 429', async () => {
  await resetLimits();
  const codes = [];
  for (let i = 0; i < 6; i++) codes.push((await new Client(AUTH).json('/auth/login', { username: 'mallory', password: 'x' })).status);
  assert.deepEqual(codes, [401, 401, 401, 401, 401, 429]);
});

test('spoofed X-Forwarded-For does not reset the login rate limit', async () => {
  await resetLimits();
  const codes = [];
  for (let i = 0; i < 6; i++) {
    const r = await fetch(`${AUTH}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.0.0.${i}` },
      body: JSON.stringify({ username: 'mallory', password: 'x' }),
    });
    codes.push(r.status);
  }
  assert.equal(codes.at(-1), 429);
});

// ---------------------------------------------------------------- Revocation
test('revoking a jti kills write routes immediately; redis keys carry a TTL', async () => {
  const t = await tokenFor('alice');
  assert.equal((await call(ORDERS, '/orders', t, { method: 'POST' })).status, 201);
  assert.equal((await call(AUTH, '/auth/revoke', t, { method: 'POST' })).status, 204);
  assert.equal((await call(ORDERS, '/orders', t, { method: 'POST' })).status, 401);
  const key = (await redis.keys('deny:jti:*'))[0];
  assert.ok((await redis.ttl(key)) > 0);
});

test('logout-all invalidates every earlier access token on every service', async () => {
  const c1 = await login('alice', 'orders-api');
  const billingTok = await tokenFor('alice', 'billing-api');
  assert.equal((await call(ORDERS, '/orders', c1.access)).status, 200);
  assert.equal((await call(BILLING, '/invoices', billingTok)).status, 200);

  const r = await call(AUTH, '/auth/logout-all', c1.access, { method: 'POST' });
  assert.equal(r.status, 200);
  assert.equal((await call(ORDERS, '/orders', c1.access)).status, 401);
  assert.equal((await call(BILLING, '/invoices', billingTok)).status, 401);
  assert.equal((await c1.json('/auth/refresh')).status, 401);

  const key = 'user:alice:valid-after';
  assert.ok((await redis.ttl(key)) > 0);
  // a fresh login right afterwards must work (iat is bumped past the watermark)
  assert.equal((await call(ORDERS, '/orders', await tokenFor('alice'))).status, 200);
});

test('refresh/family keys carry TTLs', async () => {
  await login('alice');
  for (const k of [...(await redis.keys('rt:*')), ...(await redis.keys('family-revoked:*'))]) assert.ok((await redis.ttl(k)) > 0, k);
});

// ---------------------------------------------------------------- Service-to-service
test('orders -> billing works via client credentials; user token without scope is refused', async () => {
  const r = await call(ORDERS, '/orders/7/invoice', await tokenFor('alice'));
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.caller, 'client:orders-svc');
  assert.equal(body.order, '7');

  assert.equal((await call(BILLING, '/invoices', await tokenFor('bob', 'billing-api'))).status, 403);

  const bad = await fetch(`${AUTH}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant_type: 'client_credentials', client_id: 'orders-svc', client_secret: 'nope', audience: 'billing-api' }) });
  assert.equal(bad.status, 401);
});

// ---------------------------------------------------------------- JWKS attacks
test('jku / embedded jwk headers are ignored and never fetched', async () => {
  let hits = 0;
  const evil = http.createServer((req, res) => { hits++; res.end('{"keys":[]}'); }).listen(9999);
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const mk = (header) => new SignJWT({ scope: 'orders:read orders:write' }).setProtectedHeader({ alg: 'ES256', ...header })
    .setSubject('attacker').setIssuer(AUTH).setAudience('orders-api').setJti('x').setExpirationTime('5m').sign(privateKey);

  const viaJku = await mk({ kid: 'evil', jku: 'http://localhost:9999/jwks.json' });
  const viaJwk = await mk({ kid: 'evil', jwk });
  assert.equal((await call(ORDERS, '/orders', viaJku)).status, 401);
  assert.equal((await call(ORDERS, '/orders', viaJwk)).status, 401);
  await sleep(200);
  evil.close();
  assert.equal(hits, 0, 'no request may reach the attacker server');
});

// ---------------------------------------------------------------- Rotation under load
test('key rotation under constant load produces zero failed requests', async () => {
  let token = await tokenFor('alice');
  let stopLoad = false, ok = 0; const bad = [];
  const loader = (async () => {
    while (!stopLoad) {
      const r = await call(ORDERS, '/orders', token);
      r.status === 200 ? ok++ : bad.push(r.status);
      await sleep(20);
    }
  })();

  const kidA = (await (await fetch(`${AUTH}/admin/keys`, { headers: ADMIN })).json()).find((k) => k.active).kid;
  const { kid: B } = await (await fetch(`${AUTH}/admin/keys`, { method: 'POST', headers: ADMIN })).json();
  await sleep(400);                                                         // verifiers learn B via pub/sub
  assert.equal((await fetch(`${AUTH}/admin/keys/${B}/activate`, { method: 'POST', headers: ADMIN })).status, 204);
  const newTok = await tokenFor('alice');
  assert.equal(JSON.parse(Buffer.from(newTok.split('.')[0], 'base64url')).kid, B);
  token = newTok;                                                          // new tokens carry kid B
  await sleep(600);
  assert.equal((await call(ORDERS, '/orders', newTok)).status, 200);
  assert.equal((await fetch(`${AUTH}/admin/keys/${kidA}`, { method: 'DELETE', headers: ADMIN })).status, 204);
  await sleep(600);

  stopLoad = true; await loader;
  assert.deepEqual(bad, [], `failed statuses during rotation (ok=${ok})`);
  assert.ok(ok > 20);
});

// ---------------------------------------------------------------- Auth outage
test('orders restarted while auth is down still verifies tokens (JWKS from Redis)', async () => {
  const token = await tokenFor('alice');
  await stop('auth');
  await stop('orders');
  await startOrders();                                           // cold start with auth unreachable
  const ready = await (await fetch(`${ORDERS}/readyz`)).json();
  assert.equal(ready.jwks, 'redis');
  assert.equal((await call(ORDERS, '/orders', token)).status, 200);
  await startAuth();                                             // same KEYS_FILE -> same keys
});
