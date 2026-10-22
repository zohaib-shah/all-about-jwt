// Guide 02 "Try to break it": runs attacks 1, 2, 4 against an in-process server
import { createHmac } from 'node:crypto';
import { SignJWT } from 'jose';
import { createApp, SECRET, ISSUER, AUDIENCE } from './server.mjs';

const server = createApp().listen(0);
const base = `http://localhost:${server.address().port}`;
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const call = async (path, token) =>
  (await fetch(base + path, { headers: token ? { authorization: `Bearer ${token}` } : {} })).status;

const login = async (username) =>
  (await (await fetch(base + '/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password: 'pw' }),
  })).json()).access_token;

const bob = await login('bob');
console.log('baseline: bob /admin ->', await call('/admin', bob), '(expect 403)');

// Attack 1: tamper claims, keep signature
const [h, p, s] = bob.split('.');
const evil = { ...JSON.parse(Buffer.from(p, 'base64url')), role: 'admin' };
console.log('1. tampered role     ->', await call('/admin', `${h}.${b64u(evil)}.${s}`), '(expect 401)');

// Attack 2: alg none
const none = `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u({ ...evil, exp: Math.floor(Date.now() / 1000) + 300 })}.`;
console.log('2. alg=none          ->', await call('/admin', none), '(expect 401)');

// Attack 4: valid signature but wrong audience
const wrongAud = await new SignJWT({ role: 'admin' }).setProtectedHeader({ alg: 'HS256' })
  .setSubject('u9').setIssuer(ISSUER).setAudience('other-api').setExpirationTime('5m').sign(SECRET);
console.log('4. wrong audience    ->', await call('/admin', wrongAud), '(expect 401)');

// Attack 4b: wrong issuer
const wrongIss = await new SignJWT({ role: 'admin' }).setProtectedHeader({ alg: 'HS256' })
  .setSubject('u9').setIssuer('https://evil.example').setAudience(AUDIENCE).setExpirationTime('5m').sign(SECRET);
console.log('4b. wrong issuer     ->', await call('/admin', wrongIss), '(expect 401)');

// Control: a token forged WITH the secret is accepted (why leaking HS256 secrets is fatal)
const hh = b64u({ alg: 'HS256', typ: 'JWT' });
const pp = b64u({ sub: 'attacker', role: 'admin', iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 300 });
const sig = createHmac('sha256', Buffer.from(SECRET)).update(`${hh}.${pp}`).digest('base64url');
console.log('control: forged w/ secret ->', await call('/admin', `${hh}.${pp}.${sig}`), '(expect 200: secret = full compromise)');

server.close();
