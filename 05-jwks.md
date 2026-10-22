# 05 - JWKS (JSON Web Key Set)

## Goal
Publish public keys at a URL, identify them with `kid`, and rotate keys with zero downtime.

## Concepts

### The key distribution problem
After guide 03 every verifier needs the issuer's public key. Copying `public.pem` into each service's config works on day one, but then:
- adding a service means another manual copy;
- rotating the key means updating every service **at the same moment**, or tokens fail;
- an emergency rotation after a key compromise becomes an outage.

**JWKS** turns this into a pull model: the issuer publishes its current public keys at a well-known URL, and verifiers fetch and cache them. Rotation becomes "change what the URL returns", and verifiers catch up by themselves.

### JWK and JWKS
A **JWK** (RFC 7517) is a key written as JSON. A **JWKS** is simply `{ "keys": [ JWK, … ] }`.

```json
{
  "keys": [
    {
      "kty": "EC", "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "use": "sig", "alg": "ES256", "kid": "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `kty` | key type: `RSA`, `EC`, `OKP` (Ed25519), `oct` (symmetric; never publish) |
| `crv`, `x`, `y` | EC curve and public point (RSA instead has modulus `n` and exponent `e`) |
| `use` | `sig` (signatures) or `enc` (encryption) |
| `alg` | the one algorithm this key may be used with |
| `kid` | key ID; tokens point at it |

Only **public** parameters are published. If you ever see `d` (EC/OKP) or `p`, `q`, `dp`, `dq`, `qi` (RSA) in a JWKS, you are leaking the private key. The reference `JwksStore` refuses such documents outright.

### `kid`: which key signed this token?
The token header carries `kid`; the verifier selects the JWK with the same `kid` (and a compatible `alg`). That one indirection is what makes rotation possible, because **several keys can be valid at the same time** and each token says which one it needs.

```
header: { "alg": "ES256", "kid": "oKIywvGU…" }  ──►  find keys[].kid == "oKIywvGU…"
```

Generating `kid`s: any unique string works, but this course uses the **JWK thumbprint** (RFC 7638), a SHA-256 hash of the key's public parameters. It is stable (the same key always gets the same `kid`), unique, and reveals nothing.

Treat `kid` as **untrusted input**: it came from the token. Use it only as a lookup key in an in-memory map, never in a file path, SQL query or URL (guide 08, attack 7).

### Where the JWKS lives
`https://auth.example.com/.well-known/jwks.json` by convention. OpenID Connect providers advertise it in their discovery document (`/.well-known/openid-configuration` → `jwks_uri`), which is how libraries find Google's, Microsoft's or Auth0's keys automatically.

The verifier must take this URL from **its own configuration**. Tokens can carry `jku` or `x5u` headers ("fetch my key from here"); honouring them lets an attacker point you at *their* key server. Ignore them.

### Caching: how fresh does a verifier need to be?
Fetching the JWKS on every request would put the auth service back on the hot path. Instead verifiers:
1. **cache** the set (here: honour `Cache-Control: max-age=60`, or the library's `cacheMaxAge`);
2. on an **unknown `kid`**, refetch once, because it might be a brand-new key;
3. enforce a **cooldown** between such refetches, because an attacker can send tokens with random `kid`s to make every verifier hammer the auth service.

That cooldown creates a window in which a genuinely new key isn't known yet. The rotation procedure below exists to make sure that window never matters.

### Rotation procedure (zero downtime)
```
time ─────────────────────────────────────────────────────────────►
key A  [ signing ......................... ][ verify-only ........ ] retired
key B             [ published ][ signing ................................
                  ▲            ▲                                   ▲
                  1 publish    2 switch (≥ cache TTL later)        3 retire A
                                                                   (≥ max token TTL
                                                                    after step 2)
```
1. **Publish**: generate key B and add its public half to the JWKS. Keep signing with A. Verifiers pick up B on their next refresh.
2. **Switch**: once every verifier's cache has had time to refresh (≥ cache TTL), start signing with B.
3. **Retire**: once the last token signed by A has expired (max token TTL + clock skew after step 2), remove A.

Skip step 1 and verifiers with a warm cache reject B-signed tokens until their cooldown or TTL expires. Rush step 3 and still-valid A-signed tokens fail. The automated drill below demonstrates both.

**Emergency rotation** (private key leaked): do all three steps at once and accept that every outstanding token is rejected. Users re-authenticate, which is exactly what you want when an attacker may be minting tokens.

> **Reference implementation:** [lab05/keys.mjs](lab05/keys.mjs), [lab05/auth.mjs](lab05/auth.mjs) (exports `createApp({issuer})`), [lab05/verify.mjs](lab05/verify.mjs), [lab05/verifier-server.mjs](lab05/verifier-server.mjs), [lab05/rotation-drill.mjs](lab05/rotation-drill.mjs). The production-shaped key ring (persisted to disk, mode 0600) lives in [services/auth/keys.mjs](services/auth/keys.mjs).

## Lab 1: A key manager and JWKS endpoint

`lab05/keys.mjs`:
```js
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';

const ALG = 'ES256';
const ring = [];            // [{ kid, privateKey, publicJwk, createdAt }]
let signingKid = null;

export async function addKey({ activate = false } = {}) {
  const { privateKey, publicKey } = await generateKeyPair(ALG, { extractable: true });
  const jwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(jwk);       // stable, derived from key
  ring.push({ kid, privateKey, publicJwk: { ...jwk, kid, alg: ALG, use: 'sig' }, createdAt: Date.now() });
  if (activate || !signingKid) signingKid = kid;
  return kid;
}

export const activate = (kid) => { if (!ring.some(k => k.kid === kid)) throw new Error('unknown kid'); signingKid = kid; };
export const retire = (kid) => {
  if (kid === signingKid) throw new Error('cannot retire the active signing key');   // guard rail
  const i = ring.findIndex(k => k.kid === kid);
  if (i >= 0) ring.splice(i, 1);
};
export const signingKey = () => ring.find(k => k.kid === signingKid);
export const jwks = () => ({ keys: ring.map(k => k.publicJwk) });
export const ALGORITHM = ALG;
```

`lab05/auth.mjs`:
```js
import express from 'express';
import { SignJWT } from 'jose';
import * as keys from './keys.mjs';

await keys.addKey();                                  // initial key
const app = express();

app.get('/.well-known/jwks.json', (req, res) => {
  res.set('Cache-Control', 'public, max-age=60');     // verifiers may cache for 60s
  res.json(keys.jwks());
});

app.post('/token', async (req, res) => {
  const k = keys.signingKey();
  const token = await new SignJWT({ role: 'user' })
    .setProtectedHeader({ alg: keys.ALGORITHM, kid: k.kid })
    .setSubject('u1').setIssuer('http://localhost:4000').setAudience('demo-api')
    .setIssuedAt().setExpirationTime('5m')
    .sign(k.privateKey);
  res.json({ access_token: token });
});

// admin endpoints for the rotation drill (never expose publicly!)
app.post('/admin/keys', async (_, res) => res.json({ kid: await keys.addKey() }));
app.post('/admin/keys/:kid/activate', (req, res) => { keys.activate(req.params.kid); res.sendStatus(204); });
app.delete('/admin/keys/:kid', (req, res) => { keys.retire(req.params.kid); res.sendStatus(204); });

app.listen(4000, () => console.log('auth on :4000'));
```

Check: `curl -s localhost:4000/.well-known/jwks.json | jq`. Confirm there is no `d` field.

## Lab 2: Verify through the JWKS

`lab05/verify.mjs`:
```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('http://localhost:4000/.well-known/jwks.json'), {
  cooldownDuration: 10_000,   // min time between refetches on kid miss
  cacheMaxAge: 60_000,
});

const token = process.argv[2];
const { payload, protectedHeader } = await jwtVerify(token, JWKS, {
  issuer: 'http://localhost:4000', audience: 'demo-api', algorithms: ['ES256'],
});
console.log(protectedHeader, payload);
```

`createRemoteJWKSet` does the hard parts: fetch, cache, select key by `kid`/`alg`, refetch on unknown `kid` (rate-limited by `cooldownDuration`), and de-duplicate concurrent fetches.

## Lab 3: Rotation drill
Run a verifier as a long-lived process (`lab05/verifier-server.mjs`, a tiny Express route that verifies the bearer token). Then:

1. Get token T1 (signed by key A). Verify OK.
2. `POST /admin/keys` → key B added, **not** active. Check JWKS shows 2 keys.
3. Wait past the cache TTL (or restart verifier). Verify T1 still OK.
4. `POST /admin/keys/<B>/activate`. New token T2 has `kid=B`. Verify T1 and T2: both OK.
5. After T1's expiry: `DELETE /admin/keys/<A>`. Verify T1 now fails (key gone) and T2 works.

Then the **bad** drill: activate B immediately in a fresh verifier process that has cached the old JWKS. Observe how `createRemoteJWKSet` recovers by refetching on `kid` miss, and what the `cooldownDuration` does under a burst of requests.

## What the automated drill shows
`node lab05/rotation-drill.mjs` runs the auth service and a verifier in one process and prints:

```
1. T1 (key A)                          200
2. key B published, not active; JWKS keys = 2
3. T1 still ok after B published       200
4. T2 (signed by B)                    200
4. T1 (signed by A) still ok           200
5. T3 (key C) right away (cooldown!)   401 ERR_JWKS_NO_MATCHING_KEY   <- the "bad" drill
5b. T3 after cooldown elapsed          200
6. T1 after key A retired              401 ERR_JWKS_NO_MATCHING_KEY
6. T2 still fine                       200
```
Step 5 is the lesson: a verifier that fetched the JWKS moments ago will not refetch on an unknown `kid` until `cooldownDuration` passes, so **always publish a key before you sign with it** (step 1 of the rotation procedure). Guide 07 adds a pub/sub nudge to close that gap.

## Exercises
1. Persist the key ring to disk (encrypted or file permissions 600) so restarts don't invalidate all tokens.
2. Add automated rotation: every N minutes add a key, activate the previous-added one, retire keys older than `maxTokenTtl + 2*cacheTtl`.
3. Support RS256 and ES256 keys simultaneously in the JWKS. Verifier uses `algorithms: ['ES256','RS256']`.
4. Implement your own minimal JWKS fetcher (fetch + `createLocalJWKSet`) to understand what the library does, including `Cache-Control` handling.

## Checkpoint questions
- Why is publishing a JWKS safe?
- Why must the old key stay in JWKS after you switch signing?
- What does a verifier do on an unknown `kid`? Why cap refetch frequency?
- Why does the verifier still pin `iss`, `aud`, and `algorithms` even though it trusts the JWKS?
