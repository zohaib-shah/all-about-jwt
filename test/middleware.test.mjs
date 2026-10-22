// Guide 08 Lab B: negative tests for the shared middleware, fully in-process (no Redis, no other services).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { JwksStore } from '../services/shared/jwks-store.mjs';
import { jwtAuth, requireScope } from '../services/shared/auth-middleware.mjs';

const ISS = 'http://issuer.test', AUD = 'api';
let jwksSrv, apiSrv, privateKey, base, store;
const now = () => Math.floor(Date.now() / 1000);

before(async () => {
  const kp = await generateKeyPair('ES256', { extractable: true });
  privateKey = kp.privateKey;
  const jwks = { keys: [{ ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' }] };
  jwksSrv = http.createServer((q, r) => r.end(JSON.stringify(jwks))).listen(0);
  store = await new JwksStore({ jwksUrl: `http://localhost:${jwksSrv.address().port}/jwks.json` }).start();
  const app = express();
  app.use(jwtAuth({ store, issuer: ISS, audience: AUD }));
  app.get('/r', requireScope('read'), (req, res) => res.json({ sub: req.auth.sub }));
  apiSrv = app.listen(0);
  base = `http://localhost:${apiSrv.address().port}`;
});
after(async () => { await store.stop(); jwksSrv.close(); apiSrv.close(); });

const mk = ({ iss = ISS, aud = AUD, exp = now() + 300, nbf, scope = 'read', alg = 'ES256', key = () => privateKey } = {}) => {
  let j = new SignJWT({ scope }).setProtectedHeader({ alg, kid: 'k1' }).setSubject('u1').setIssuer(iss).setAudience(aud).setIssuedAt();
  if (exp !== null) j = j.setExpirationTime(exp);
  if (nbf) j = j.setNotBefore(nbf);
  return j.sign(key());
};
const get = (auth) => fetch(`${base}/r`, { headers: auth ? { authorization: auth } : {} });

test('missing header -> 401', async () => assert.equal((await get()).status, 401));
test('malformed bearer -> 401', async () => assert.equal((await get('Bearer')).status, 401));
test('Basic scheme -> 401', async () => assert.equal((await get('Basic dTpw')).status, 401));
test('valid token -> 200', async () => assert.equal((await get(`Bearer ${await mk()}`)).status, 200));
test('wrong audience -> 401', async () => assert.equal((await get(`Bearer ${await mk({ aud: 'other' })}`)).status, 401));
test('wrong issuer -> 401', async () => assert.equal((await get(`Bearer ${await mk({ iss: 'http://evil' })}`)).status, 401));
test('no exp -> 401', async () => assert.equal((await get(`Bearer ${await mk({ exp: null })}`)).status, 401));
test('expired 1s ago is within the 5s clockTolerance', async () => assert.equal((await get(`Bearer ${await mk({ exp: now() - 1 })}`)).status, 200));
test('expired 60s ago -> 401', async () => assert.equal((await get(`Bearer ${await mk({ exp: now() - 60 })}`)).status, 401));
test('nbf in the future -> 401', async () => assert.equal((await get(`Bearer ${await mk({ nbf: now() + 300 })}`)).status, 401));
test('insufficient scope -> 403', async () => assert.equal((await get(`Bearer ${await mk({ scope: 'other' })}`)).status, 403));
test('unknown kid -> 401 (and does not crash)', async () => {
  const t = await new SignJWT({}).setProtectedHeader({ alg: 'ES256', kid: 'nope' }).setSubject('u').setIssuer(ISS).setAudience(AUD).setExpirationTime('5m').sign(privateKey);
  assert.equal((await get(`Bearer ${t}`)).status, 401);
});
test('JwksStore refuses a JWKS containing private key material', async () => {
  const kp = await generateKeyPair('ES256', { extractable: true });
  const leakyJwk = { ...(await exportJWK(kp.privateKey)), kid: 'x' };
  const leaky = http.createServer((q, r) => r.end(JSON.stringify({ keys: [leakyJwk] }))).listen(0);
  const s = new JwksStore({ jwksUrl: `http://localhost:${leaky.address().port}/` });
  await assert.rejects(s.refresh(), /private key material/);
  leaky.close();
});
