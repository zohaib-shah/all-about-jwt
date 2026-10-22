// Guide 08 Lab A: attack the running services. Start redis + auth + orders + billing first:
//   docker compose up -d redis; node services/auth/index.mjs & node services/orders/index.mjs & node services/billing/index.mjs
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

const AUTH = 'http://localhost:4000', ORDERS = 'http://localhost:4001';
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);
const claims = { sub: 'attacker', scope: 'orders:read orders:write', iss: AUTH, aud: 'orders-api', jti: 'evil', exp: now() + 300 };

let attackerHits = 0;
const attackerSrv = http.createServer((req, res) => { attackerHits++; res.end('{"keys":[]}'); }).listen(9999);

const jwks = await (await fetch(`${AUTH}/.well-known/jwks.json`)).json();
const realKid = jwks.keys[0].kid;
const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
const evilJwk = await exportJWK(publicKey);
const evil = (header, payload = claims) => new SignJWT(payload).setProtectedHeader({ alg: 'ES256', ...header }).sign(privateKey);
const hs = (header, secret, payload = claims) => {
  const h = b64u(header), p = b64u(payload);
  return `${h}.${p}.${createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')}`;
};

const attacks = {
  'alg=none': `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u(claims)}.`,
  'HS256 with public JWK x as secret (confusion)': hs({ alg: 'HS256', kid: realKid }, jwks.keys[0].x),
  'HS256 with JWKS JSON as secret': hs({ alg: 'HS256', kid: realKid }, JSON.stringify(jwks)),
  'foreign key, real kid': await evil({ kid: realKid }),
  'foreign key, jku -> attacker': await evil({ kid: 'evil', jku: 'http://localhost:9999/jwks.json' }),
  'foreign key, x5u -> attacker': await evil({ kid: 'evil', x5u: 'http://localhost:9999/cert.pem' }),
  'foreign key, embedded jwk': await evil({ kid: 'evil', jwk: evilJwk }),
  'kid path traversal': await evil({ kid: '../../../../etc/passwd' }),
  "kid SQL injection": await evil({ kid: "x' OR '1'='1" }),
  'garbage token': 'a.b.c',
  'empty signature': `${b64u({ alg: 'ES256', kid: realKid })}.${b64u(claims)}.`,
};

let failures = 0;
console.log('attack'.padEnd(48), 'status', 'result');
for (const [name, token] of Object.entries(attacks)) {
  const status = (await fetch(`${ORDERS}/orders`, { headers: { authorization: `Bearer ${token}` } })).status;
  const pass = status === 401 || status === 403;
  if (!pass) failures++;
  console.log(name.padEnd(48), String(status).padEnd(6), pass ? 'PASS' : 'FAIL <-- fix me');
}
await new Promise((r) => setTimeout(r, 300));
const noContact = attackerHits === 0;
if (!noContact) failures++;
console.log('attacker server contacted by orders?'.padEnd(48), String(attackerHits).padEnd(6), noContact ? 'PASS' : 'FAIL <-- SSRF/jku bug');
attackerSrv.close();
process.exit(failures ? 1 : 0);
