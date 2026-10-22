import { generateKeyPair, SignJWT, jwtVerify, exportJWK } from 'jose';
import { randomBytes } from 'node:crypto';

const algs = [['RS256', {}], ['PS256', {}], ['ES256', {}], ['ES384', {}], ['EdDSA', { crv: 'Ed25519' }]];
const N = 300;
const rows = [];

async function bench(alg, signKey, verifyKey, kty) {
  const make = () => new SignJWT({ sub: 'u1' }).setProtectedHeader({ alg }).setExpirationTime('5m').sign(signKey);
  const token = await make();
  let t = performance.now();
  for (let i = 0; i < N; i++) await make();
  const signMs = (performance.now() - t) / N;
  t = performance.now();
  for (let i = 0; i < N; i++) await jwtVerify(token, verifyKey, { algorithms: [alg] });
  const verifyMs = (performance.now() - t) / N;
  rows.push({ alg, kty, tokenChars: token.length,
    sigBytes: Buffer.from(token.split('.')[2], 'base64url').length,
    signMs: +signMs.toFixed(3), verifyMs: +verifyMs.toFixed(3) });
}

for (const [alg, opts] of algs) {
  const { privateKey, publicKey } = await generateKeyPair(alg, { ...opts, extractable: true });
  await bench(alg, privateKey, publicKey, (await exportJWK(publicKey)).kty);
}
const k = randomBytes(32);
await bench('HS256', k, k, 'oct');
console.table(rows);

// determinism: identical inputs signed twice
const fixed = { sub: 'u1', exp: 2_000_000_000 };
for (const [alg, opts] of [['RS256', {}], ['ES256', {}], ['EdDSA', { crv: 'Ed25519' }]]) {
  const { privateKey } = await generateKeyPair(alg, opts);
  const s = () => new SignJWT(fixed).setProtectedHeader({ alg }).sign(privateKey);
  console.log(alg, 'deterministic:', (await s()) === (await s()));
}
