import express from 'express';
import cookieParser from 'cookie-parser';
import { SignJWT, jwtVerify, createLocalJWKSet } from 'jose';
import { randomUUID, timingSafeEqual, createHash } from 'node:crypto';
import { createRefreshStore } from './refresh-store.mjs';
import { createLimiter } from './rate-limit.mjs';

const ACCESS_TTL_S = 300;
const REFRESH_TTL_S = 7 * 24 * 3600;

// toy directories: scopes per audience
const USERS = {
  alice: { id: 'alice', password: 'pw', aud: { 'orders-api': 'orders:read orders:write', 'billing-api': 'billing:read billing:write' } },
  bob:   { id: 'bob',   password: 'pw', aud: { 'orders-api': 'orders:read', 'billing-api': '' } },
};
const CLIENTS = {
  'orders-svc': { secret: process.env.ORDERS_CLIENT_SECRET ?? 'orders-secret', aud: { 'billing-api': 'billing:read' } },
};
const DEFAULT_AUD = 'orders-api';

const safeEq = (a, b) => {
  const [x, y] = [createHash('sha256').update(String(a)).digest(), createHash('sha256').update(String(b)).digest()];
  return timingSafeEqual(x, y);
};
const narrow = (allowed, requested) => {
  const have = new Set(allowed.split(' ').filter(Boolean));
  return (requested ? requested.split(' ') : [...have]).filter((s) => have.has(s)).join(' ');
};

export function createApp({ issuer, keys, redis, adminToken = process.env.ADMIN_TOKEN ?? 'dev-admin', secureCookies = false }) {
  const app = express();
  // Only trust X-Forwarded-For when a known proxy sits in front. With `true`, any client can send
  // `X-Forwarded-For: <random ip>` and get a fresh rate-limit bucket on every request.
  app.set('trust proxy', process.env.TRUST_PROXY ?? false);
  app.use(express.json(), express.urlencoded({ extended: false }), cookieParser());

  const refreshStore = createRefreshStore(redis, REFRESH_TTL_S);
  const allow = createLimiter(redis);

  async function signAccess({ sub, aud, scope, extra = {} }) {
    const k = keys.signingKey();
    const now = Math.floor(Date.now() / 1000);
    // iat must be strictly after the user's logout-all watermark, otherwise a fresh login in the same second is rejected
    const wm = Number(await redis.get(`user:${sub}:valid-after`).catch(() => 0)) || 0;
    const iat = Math.max(now, wm + 1);
    return new SignJWT({ scope, ...extra })
      .setProtectedHeader({ alg: 'ES256', kid: k.kid, typ: 'at+jwt' })
      .setSubject(sub).setIssuer(issuer).setAudience(aud)
      .setIssuedAt(iat).setExpirationTime(iat + ACCESS_TTL_S).setJti(randomUUID())
      .sign(k.privateKey);
  }

  const setRefreshCookie = (res, token) =>
    res.cookie('rt', token, { httpOnly: true, sameSite: 'strict', secure: secureCookies, path: '/auth', maxAge: REFRESH_TTL_S * 1000 });

  async function bearer(req, res, next) {
    try {
      const t = /^Bearer (.+)$/.exec(req.get('authorization') ?? '')?.[1];
      const { payload } = await jwtVerify(t, createLocalJWKSet(keys.jwks()), { issuer, algorithms: ['ES256'] });
      req.auth = payload;
      next();
    } catch { res.status(401).json({ error: 'invalid_token' }); }
  }

  // ---- discovery + keys
  app.get('/.well-known/jwks.json', (req, res) => {
    res.set('Cache-Control', 'public, max-age=60').json(keys.jwks());
  });
  app.get('/.well-known/openid-configuration', (req, res) => res.json({
    issuer, jwks_uri: `${issuer}/.well-known/jwks.json`, token_endpoint: `${issuer}/oauth/token`,
    id_token_signing_alg_values_supported: ['ES256'], grant_types_supported: ['client_credentials'],
  }));
  app.get('/healthz', (req, res) => res.json({ ok: true }));

  // ---- user flows
  app.post('/auth/login', async (req, res) => {
    const { username, password, audience = DEFAULT_AUD } = req.body ?? {};
    if (!(await allow(`rl:login:${req.ip}:${username}`, 5, 60))) return res.status(429).json({ error: 'too_many_requests' });
    const u = USERS[username];
    if (!u || !safeEq(u.password, password) || !(audience in u.aud)) return res.status(401).json({ error: 'bad_credentials' });

    const family = randomUUID();
    setRefreshCookie(res, await refreshStore.issue(u.id, family));
    res.json({ access_token: await signAccess({ sub: u.id, aud: audience, scope: u.aud[audience] }), token_type: 'Bearer', expires_in: ACCESS_TTL_S });
  });

  app.post('/auth/refresh', async (req, res) => {
    if (!(await allow(`rl:refresh:${req.ip}`, 30, 60))) return res.status(429).json({ error: 'too_many_requests' });
    const presented = req.cookies.rt;
    if (!presented) return res.status(401).json({ error: 'invalid_refresh_token' });

    const r = await refreshStore.consume(presented);
    if (r.status === 'reuse') {
      await refreshStore.revokeFamily(r.family); // stolen token replayed: kill the whole family
      return res.status(401).json({ error: 'refresh_token_reuse_detected' });
    }
    if (r.status !== 'ok' || (await refreshStore.isFamilyRevoked(r.family)))
      return res.status(401).json({ error: 'invalid_refresh_token' });

    const audience = req.body?.audience ?? DEFAULT_AUD;
    const u = USERS[r.userId];
    if (!u || !(audience in u.aud)) return res.status(400).json({ error: 'invalid_audience' });
    setRefreshCookie(res, await refreshStore.issue(r.userId, r.family));
    res.json({ access_token: await signAccess({ sub: u.id, aud: audience, scope: u.aud[audience] }), token_type: 'Bearer', expires_in: ACCESS_TTL_S });
  });

  app.post('/auth/logout', async (req, res) => {
    // revoke this device's family only
    const t = req.cookies.rt;
    if (t) {
      const r = await refreshStore.consume(t); // consuming it also invalidates it
      if (r.family) await refreshStore.revokeFamily(r.family);
    }
    res.clearCookie('rt', { path: '/auth' }).sendStatus(204);
  });

  app.post('/auth/logout-all', bearer, async (req, res) => {
    const n = await refreshStore.revokeAllForUser(req.auth.sub);
    // every access token issued up to now is dead; TTL = longest remaining token life
    await redis.set(`user:${req.auth.sub}:valid-after`, Math.floor(Date.now() / 1000), 'EX', ACCESS_TTL_S + 60);
    res.clearCookie('rt', { path: '/auth' }).json({ revokedSessions: n });
  });

  // revoke the presented access token (by jti) until it would have expired anyway
  app.post('/auth/revoke', bearer, async (req, res) => {
    const ttl = req.auth.exp - Math.floor(Date.now() / 1000);
    if (ttl > 0) await redis.set(`deny:jti:${req.auth.jti}`, 1, 'EX', ttl);
    res.sendStatus(204);
  });

  app.get('/auth/sessions', bearer, async (req, res) => res.json({ sessions: await refreshStore.familiesFor(req.auth.sub) }));

  // ---- service-to-service (client credentials)
  app.post('/oauth/token', async (req, res) => {
    const { grant_type, client_id, client_secret, audience, scope } = req.body ?? {};
    if (grant_type !== 'client_credentials') return res.status(400).json({ error: 'unsupported_grant_type' });
    const c = CLIENTS[client_id];
    if (!c || !safeEq(c.secret, client_secret)) return res.status(401).json({ error: 'invalid_client' });
    if (!c.aud[audience]) return res.status(400).json({ error: 'invalid_audience' });
    const granted = narrow(c.aud[audience], scope);
    res.json({
      access_token: await signAccess({ sub: `client:${client_id}`, aud: audience, scope: granted, extra: { client_id } }),
      token_type: 'Bearer', expires_in: ACCESS_TTL_S, scope: granted,
    });
  });

  // ---- key admin (rotation); publishes a pub/sub hint so verifiers refetch immediately
  const admin = (req, res, next) =>
    safeEq(req.get('x-admin-token') ?? '', adminToken) ? next() : res.status(403).json({ error: 'forbidden' });
  const announce = (kid) => redis.publish('jwks:rotated', JSON.stringify({ kid })).catch(() => {});

  app.get('/admin/keys', admin, (req, res) => res.json(keys.list()));
  app.post('/admin/keys', admin, async (req, res) => { const kid = await keys.add(); await announce(kid); res.json({ kid }); });
  app.post('/admin/keys/:kid/activate', admin, async (req, res) => {
    try { await keys.activate(req.params.kid); await announce(req.params.kid); res.sendStatus(204); }
    catch (e) { res.status(404).json({ error: e.message }); }
  });
  app.delete('/admin/keys/:kid', admin, async (req, res) => {
    try { await keys.retire(req.params.kid); await announce(req.params.kid); res.sendStatus(204); }
    catch (e) { res.status(409).json({ error: e.message }); }
  });

  return app;
}
