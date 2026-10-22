import express from 'express';
import { SignJWT, jwtVerify, errors } from 'jose';

export const SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET ?? 'dev-only-secret-dev-only-secret-32b!'
);
export const ISSUER = 'https://auth.local';
export const AUDIENCE = 'lab02-api';

const users = {
  alice: { id: 'u1', password: 'pw', role: 'admin' },
  bob: { id: 'u2', password: 'pw', role: 'user' },
};

export function createApp() {
  const app = express();
  app.use(express.json());

  app.post('/login', async (req, res) => {
    const { username, password } = req.body ?? {};
    const u = users[username];
    if (!u || u.password !== password) return res.status(401).json({ error: 'bad credentials' });

    const token = await new SignJWT({ role: u.role })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(u.id)
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(SECRET);
    res.json({ access_token: token, token_type: 'Bearer', expires_in: 900 });
  });

  async function requireAuth(req, res, next) {
    const m = /^Bearer (.+)$/.exec(req.get('authorization') ?? '');
    if (!m) return res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'missing token' });
    try {
      const { payload } = await jwtVerify(m[1], SECRET, {
        algorithms: ['HS256'], // ALWAYS pin algorithms
        issuer: ISSUER,
        audience: AUDIENCE,
        clockTolerance: 5,
      });
      req.user = payload;
      next();
    } catch (e) {
      const expired = e instanceof errors.JWTExpired;
      res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"')
        .json({ error: expired ? 'token expired' : 'invalid token' });
    }
  }

  const requireRole = (role) => (req, res, next) =>
    req.user.role === role ? next() : res.status(403).json({ error: 'forbidden' });

  app.get('/me', requireAuth, (req, res) => res.json(req.user));
  app.get('/admin', requireAuth, requireRole('admin'), (req, res) => res.json({ secret: 'admin data' }));
  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  createApp().listen(3002, () => console.log('lab02 on :3002'));
}
