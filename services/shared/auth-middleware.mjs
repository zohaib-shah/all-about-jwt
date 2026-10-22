import { jwtVerify } from 'jose';

export const metrics = { verified: 0, failed: {}, denylistHits: 0, watermarkHits: 0 };
const fail = (code) => { metrics.failed[code] = (metrics.failed[code] ?? 0) + 1; };

/**
 * Verifies the bearer token via the JWKS store. Pins alg/iss/aud, requires exp.
 * If `redis` is supplied also enforces the per-user `valid-after` watermark ("log out everywhere").
 */
export function jwtAuth({ store, issuer, audience, algorithms = ['ES256'], redis = null, failOpen = true }) {
  return async function authenticate(req, res, next) {
    const m = /^Bearer (.+)$/.exec(req.get('authorization') ?? '');
    if (!m) { fail('missing_token'); return res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'missing_token' }); }
    let payload;
    try {
      ({ payload } = await jwtVerify(m[1], store.getKey, {
        issuer, audience, algorithms, clockTolerance: 5, requiredClaims: ['exp', 'sub'],
      }));
    } catch (e) {
      fail(e.code ?? 'invalid');
      return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"')
        .json({ error: 'invalid_token', reason: e.code });
    }
    if (redis) {
      try {
        const wm = await redis.get(`user:${payload.sub}:valid-after`);
        if (wm && payload.iat <= Number(wm)) {
          metrics.watermarkHits++; fail('watermark');
          return res.status(401).json({ error: 'invalid_token', reason: 'session_revoked' });
        }
      } catch (e) {
        if (!failOpen) return res.status(503).json({ error: 'revocation_check_unavailable' });
      }
    }
    metrics.verified++;
    req.auth = payload;
    next();
  };
}

/** Per-route denylist check by jti. Defaults to fail-closed: use on sensitive (write) routes. */
export function denylist({ redis, failOpen = false }) {
  return async (req, res, next) => {
    try {
      if (await redis.exists(`deny:jti:${req.auth.jti}`)) {
        metrics.denylistHits++; fail('denylist');
        return res.status(401).json({ error: 'invalid_token', reason: 'revoked' });
      }
      next();
    } catch {
      if (failOpen) return next();
      res.status(503).json({ error: 'revocation_check_unavailable' });
    }
  };
}

export const requireScope = (...needed) => (req, res, next) => {
  const have = new Set(String(req.auth.scope ?? '').split(' ').filter(Boolean));
  return needed.every((s) => have.has(s)) ? next() : res.status(403).json({ error: 'insufficient_scope', needed });
};
