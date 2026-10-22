// Automated rotation drill (guide 05, Lab 3). Runs auth + verifier in-process.
import http from 'node:http';
import * as keys from './keys.mjs';
import { createApp } from './auth.mjs';
import { createVerifier } from './verifier-server.mjs';

const listen = (app) => new Promise((r) => { const s = http.createServer(app).listen(0, () => r(s)); });
const authSrv = http.createServer().listen(0);
await new Promise((r) => authSrv.once('listening', r));
const authUrl = `http://localhost:${authSrv.address().port}`;
authSrv.on('request', createApp({ issuer: authUrl }));
const vSrv = await listen(createVerifier({ authUrl, cooldownDuration: 1500, cacheMaxAge: 600 }));
const vUrl = `http://localhost:${vSrv.address().port}`;

const A = await keys.addKey();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const token = async () => (await (await fetch(authUrl + '/token', { method: 'POST' })).json()).access_token;
const check = async (label, t) => {
  const r = await fetch(vUrl + '/check', { headers: { authorization: `Bearer ${t}` } });
  const b = await r.json();
  console.log(label.padEnd(44), r.status, b.ok ? `kid=${b.kid.slice(0, 6)}…` : b.code);
  return r.status;
};
const admin = (path, method = 'POST') => fetch(authUrl + path, { method });
const ringSize = async () => (await (await fetch(authUrl + '/.well-known/jwks.json')).json()).keys.length;

const T1 = await token();
await check('1. T1 (key A)', T1);

const { kid: B } = await (await admin('/admin/keys')).json();
console.log('2. key B published, not active; JWKS keys =', await ringSize());
await sleep(700); // > cacheMaxAge: verifier will refresh
await check('3. T1 still ok after B published', T1);

await admin(`/admin/keys/${B}/activate`);
const T2 = await token();
await check('4. T2 (signed by B)', T2);
await check('4. T1 (signed by A) still ok', T1);

// BAD drill: a fresh verifier with a warm cache sees a token from a brand-new key immediately
const { kid: C } = await (await admin('/admin/keys')).json();
await admin(`/admin/keys/${C}/activate`);
const T3 = await token();
await check('5. T3 (key C) right away (cooldown!)', T3);
await sleep(1600);
await check('5b. T3 after cooldown elapsed', T3);

await admin(`/admin/keys/${A}`, 'DELETE');
await sleep(700);
await check('6. T1 after key A retired', T1);
await check('6. T2 still fine', T2);

authSrv.close(); vSrv.close();
