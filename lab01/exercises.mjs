// Guide 01 exercises: tamper, expire, size, decode-vs-verify
import { SignJWT, jwtVerify, decodeJwt } from 'jose';

const key = new TextEncoder().encode('demo-secret-demo-secret-demo-secret!');
const mk = (claims = {}, exp = '5m') =>
  new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).setExpirationTime(exp).sign(key);
const tryVerify = async (label, t) => {
  try { await jwtVerify(t, key); console.log(label, '-> ACCEPTED'); }
  catch (e) { console.log(label, '-> rejected:', e.code, '|', e.message); }
};

// 1. tamper payload, keep signature
const t = await mk({ role: 'user' });
const [h, p, s] = t.split('.');
const evil = { ...JSON.parse(Buffer.from(p, 'base64url')), role: 'admin' };
const tampered = [h, Buffer.from(JSON.stringify(evil)).toString('base64url'), s].join('.');
await tryVerify('1. tampered payload', tampered);

// 2. expiry
const short = await mk({}, '1s');
await new Promise((r) => setTimeout(r, 2100));
await tryVerify('2. expired', short);

// 3. size
const big = await mk({ blob: 'x'.repeat(2048) });
console.log('3. token with 2KB claim is', big.length, 'chars (cookies cap ~4KB, sent on every request)');

// 4. decode does not verify
console.log('4. decodeJwt on tampered token (no throw!):', decodeJwt(tampered));
