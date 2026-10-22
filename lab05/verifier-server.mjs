// Long-lived verifier process for the rotation drill. :4010, verifies bearer tokens via remote JWKS.
import express from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export function createVerifier({ authUrl, cooldownDuration = 10_000, cacheMaxAge = 60_000 }) {
  const JWKS = createRemoteJWKSet(new URL('/.well-known/jwks.json', authUrl), { cooldownDuration, cacheMaxAge });
  const app = express();
  app.get('/check', async (req, res) => {
    try {
      const t = /^Bearer (.+)$/.exec(req.get('authorization') ?? '')?.[1];
      const { payload, protectedHeader } = await jwtVerify(t, JWKS, {
        issuer: authUrl, audience: 'demo-api', algorithms: ['ES256'],
      });
      res.json({ ok: true, kid: protectedHeader.kid, sub: payload.sub });
    } catch (e) { res.status(401).json({ ok: false, code: e.code }); }
  });
  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  createVerifier({ authUrl: 'http://localhost:4000' }).listen(4010, () => console.log('verifier on :4010'));
}
