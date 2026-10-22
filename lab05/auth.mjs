import express from 'express';
import { SignJWT } from 'jose';
import * as keys from './keys.mjs';

export const AUDIENCE = 'demo-api';

export function createApp({ issuer }) {
  const app = express();

  app.get('/.well-known/jwks.json', (req, res) => {
    res.set('Cache-Control', 'public, max-age=60');
    res.json(keys.jwks());
  });

  app.post('/token', async (req, res) => {
    const k = keys.signingKey();
    const token = await new SignJWT({ role: 'user' })
      .setProtectedHeader({ alg: keys.ALGORITHM, kid: k.kid })
      .setSubject('u1').setIssuer(issuer).setAudience(AUDIENCE)
      .setIssuedAt().setExpirationTime('5m')
      .sign(k.privateKey);
    res.json({ access_token: token });
  });

  // rotation drill endpoints (never expose publicly!)
  app.post('/admin/keys', async (_, res) => res.json({ kid: await keys.addKey() }));
  app.post('/admin/keys/:kid/activate', (req, res) => {
    try { keys.activate(req.params.kid); res.sendStatus(204); } catch (e) { res.status(404).json({ error: e.message }); }
  });
  app.delete('/admin/keys/:kid', (req, res) => {
    try { keys.retire(req.params.kid); res.sendStatus(204); } catch (e) { res.status(409).json({ error: e.message }); }
  });
  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await keys.addKey();
  createApp({ issuer: 'http://localhost:4000' }).listen(4000, () => console.log('auth on :4000'));
}
