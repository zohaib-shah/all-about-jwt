import express from 'express';
import cookieParser from 'cookie-parser';
import { SignJWT, jwtVerify } from 'jose';
import { randomBytes, createHash, randomUUID } from 'node:crypto';

const SECRET = new TextEncoder().encode('dev-only-secret-dev-only-secret-32b!');
const ISS = 'https://auth.local', AUD = 'lab04-api';
const REFRESH_TTL_MS = 7 * 24 * 3600 * 1000;
const ABSOLUTE_SESSION_MS = 30 * 24 * 3600 * 1000;
const GRACE_MS = 10_000; // retry window for a just-used refresh token (multi-tab / flaky network)

export function createApp({ accessTtl = '1m', graceMs = GRACE_MS } = {}) {
  const app = express();
  app.use(express.json(), cookieParser());

  // sha256(token) -> { userId, family, used, usedAt, successor, expiresAt }
  const refreshStore = new Map();
  const families = new Map(); // family -> { userId, startedAt, revoked, ua }
  const hash = (t) => createHash('sha256').update(t).digest('hex');

  const signAccess = (userId) =>
    new SignJWT({}).setProtectedHeader({ alg: 'HS256' })
      .setSubject(userId).setIssuer(ISS).setAudience(AUD)
      .setIssuedAt().setExpirationTime(accessTtl).setJti(randomUUID())
      .sign(SECRET);

  function issueRefresh(userId, family) {
    const token = randomBytes(32).toString('base64url');
    refreshStore.set(hash(token), { userId, family, used: false, expiresAt: Date.now() + REFRESH_TTL_MS });
    return token;
  }

  const setCookie = (res, token) =>
    res.cookie('rt', token, {
      httpOnly: true, sameSite: 'strict', secure: false /* true behind HTTPS */,
      path: '/auth', maxAge: REFRESH_TTL_MS,
    });

  app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body ?? {};
    if (!username || password !== 'pw') return res.status(401).json({ error: 'bad credentials' });
    const family = randomUUID();
    families.set(family, { userId: username, startedAt: Date.now(), revoked: false, ua: req.get('user-agent') });
    setCookie(res, issueRefresh(username, family));
    res.json({ access_token: await signAccess(username) });
  });

  app.post('/auth/refresh', async (req, res) => {
    const presented = req.cookies.rt;
    const rec = presented && refreshStore.get(hash(presented));
    const fam = rec && families.get(rec.family);
    if (!rec || !fam || rec.expiresAt < Date.now() || fam.revoked
        || Date.now() - fam.startedAt > ABSOLUTE_SESSION_MS)
      return res.status(401).json({ error: 'invalid refresh token' });

    if (rec.used) {
      // grace window: allow a retry of a token consumed moments ago, hand back the same successor
      if (Date.now() - rec.usedAt <= graceMs && rec.successor) {
        setCookie(res, rec.successor);
        return res.json({ access_token: await signAccess(rec.userId), grace: true });
      }
      fam.revoked = true; // REUSE DETECTED
      return res.status(401).json({ error: 'refresh token reuse detected' });
    }
    rec.used = true;
    rec.usedAt = Date.now();
    rec.successor = issueRefresh(rec.userId, rec.family);
    setCookie(res, rec.successor);
    res.json({ access_token: await signAccess(rec.userId) });
  });

  app.post('/auth/logout', (req, res) => {
    const rec = req.cookies.rt && refreshStore.get(hash(req.cookies.rt));
    if (rec) families.get(rec.family).revoked = true;
    res.clearCookie('rt', { path: '/auth' }).sendStatus(204);
  });

  async function bearer(req, res, next) {
    try {
      const t = /^Bearer (.+)$/.exec(req.get('authorization') ?? '')?.[1];
      req.user = (await jwtVerify(t, SECRET, { algorithms: ['HS256'], issuer: ISS, audience: AUD })).payload;
      next();
    } catch { res.status(401).json({ error: 'invalid or expired token' }); }
  }

  app.get('/api/me', bearer, (req, res) => res.json(req.user));

  // sessions: list / revoke ("log out other devices")
  app.get('/auth/sessions', bearer, (req, res) => {
    res.json([...families].filter(([, f]) => f.userId === req.user.sub && !f.revoked)
      .map(([id, f]) => ({ id, startedAt: f.startedAt, ua: f.ua })));
  });
  app.delete('/auth/sessions/:id', bearer, (req, res) => {
    const f = families.get(req.params.id);
    if (!f || f.userId !== req.user.sub) return res.sendStatus(404);
    f.revoked = true;
    res.sendStatus(204);
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  createApp().listen(3004, () => console.log('lab04 on :3004'));
}
