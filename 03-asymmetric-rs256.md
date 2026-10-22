# 03 - Asymmetric Signing (RS256 / ES256 / EdDSA)

## Goal
Sign with a private key, verify with a public key, and see why this fits microservices.

## Concepts

### The core idea: two different keys
Asymmetric (public-key) cryptography generates a **key pair** whose halves are mathematically linked but cannot be derived from each other in practice:

- the **private key** creates signatures. Exactly one service (the issuer) holds it.
- the **public key** checks signatures. It can be published to the world.

An analogy: the issuer has a unique stamp (private key). It publishes photos of the stamp's imprint (public key). Anyone can compare a seal against the photo, but nobody can carve the stamp from the photo.

```
            issuer (auth)                         any number of verifiers
  sign(PRIVATE key, data) ── token ──►   verify(PUBLIC key, data, signature) → true/false
                                          (cannot create signatures)
```

This fixes the HS256 trust problem from guide 02: a compromised verifier leaks only a public key, which was public anyway.

### What "signing" means under the hood (intuition, not maths class)
All JWT signature algorithms follow **hash-then-sign**:
1. Hash the signing input (`header.payload`) to a fixed-size digest, e.g. SHA-256 → 32 bytes.
2. Apply a private-key operation to the digest. That result is the signature.
3. The verifier hashes the same input and uses the public key to check that the signature "matches" that digest.

- **RSA**: the private operation is modular exponentiation with the secret exponent `d`; verification raises the signature to the small public exponent `e` (usually 65537). Security rests on factoring a 2048+-bit number being infeasible. Because `e` is small, **verification is cheap and signing is expensive**.
- **ECDSA (ES256)**: based on elliptic-curve point multiplication. Security rests on the elliptic-curve discrete-log problem, so a 256-bit EC key matches roughly a 3072-bit RSA key, with far smaller keys and signatures. ECDSA needs a fresh secret random number per signature; reusing it **leaks the private key** (this broke the PlayStation 3's code signing). Libraries handle it; never hand-roll ECDSA.
- **EdDSA (Ed25519)**: a modern curve design that derives the per-signature number deterministically from the key and message, removing that whole class of bugs.

### Security levels
"Bits of security" ≈ log₂ of the work needed to break it. 128 bits is the modern baseline.

| Algorithm / key | Approx. security |
|---|---|
| RSA-2048 (RS256/PS256) | ~112 bits (acceptable today) |
| RSA-3072 | ~128 bits |
| ECDSA P-256 (ES256), Ed25519 (EdDSA) | ~128 bits |
| HS256 with a 32-byte random secret | ≥128 bits |

### Key formats you will juggle
The *same* key can be written down in several ways:

| Format | Looks like | Holds |
|---|---|---|
| PEM / **PKCS#8** | `-----BEGIN PRIVATE KEY-----` | a private key (any algorithm) |
| PEM / **SPKI** | `-----BEGIN PUBLIC KEY-----` | a public key |
| PEM / PKCS#1 | `-----BEGIN RSA PRIVATE KEY-----` | older RSA-only private key format |
| **JWK** | `{"kty":"EC","crv":"P-256","x":"…","y":"…"}` | either; private JWKs add `d` (guide 05) |
| X.509 certificate | `-----BEGIN CERTIFICATE-----` | a public key + identity, signed by a CA |

PEM is just base64 of binary DER data between header lines. `jose` imports them with `importPKCS8`, `importSPKI` and `importJWK`.

### Algorithm confusion: the bug asymmetric keys introduce
A verifier that reads the `alg` from the token header and then uses "the configured key" with *that* algorithm can be tricked:

1. Server is configured with an RSA **public** key and expects RS256.
2. Attacker sends a token with `alg: HS256`, HMAC-signed using the **public key bytes as the HMAC secret**.
3. Naive verifier: "header says HS256 → HMAC-verify using my key" → it uses the public key as an HMAC secret, recomputes the same HMAC, and accepts.

The attacker forged a token using only public information. Two independent defences, both used in this course:
- **pin `algorithms`** in the verifier, so the token's header can never choose;
- **typed keys**: `jose` will not use an RSA/EC `KeyObject` for HMAC at all.

Rule: **the verifier decides the algorithm; the token's header only has to agree.**

### Choosing quickly
| Alg | Type | Key | Sig size | Notes |
|-----|------|-----|----------|-------|
| RS256 | RSA PKCS#1 v1.5 + SHA-256 | 2048+ bit | 256 B | Most widely supported |
| PS256 | RSA-PSS | 2048+ bit | 256 B | Better RSA padding, less supported |
| ES256 | ECDSA P-256 | 256 bit | 64 B | Small, fast; good default |
| EdDSA | Ed25519 | 256 bit | 64 B | Modern, deterministic; check ecosystem support |

Recommendation: **ES256** (or EdDSA) for new systems, **RS256** when you need broad compatibility with third parties. The full comparison is in [03a](03a-algorithms-explained.md).

### What asymmetric signing does *not* solve
Verifiers still need to *get* the right public key, trust that it really belongs to the issuer, and learn about new keys when the issuer rotates. Copying `public.pem` into every service by hand doesn't scale; that is guide 05 (JWKS).

## Lab 1: Generate keys

### With OpenSSL
```bash
mkdir -p lab03/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out lab03/keys/private.pem
openssl rsa -in lab03/keys/private.pem -pubout -out lab03/keys/public.pem
```
Add `lab03/keys/` to a `.gitignore` (habit matters even in training). The repo's `.gitignore` already ignores `*.pem`.

> If you generate keys with your own script (e.g. `lab03/generate_keys.mjs`), make it write into `lab03/keys/` so the scripts below find them. The reference scripts resolve paths relative to their own file, so they work from any directory.

### With `jose` in code
```js
import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
console.log(await exportPKCS8(privateKey));
console.log(await exportSPKI(publicKey));
```
Formats: **PKCS8** = private PEM (`BEGIN PRIVATE KEY`), **SPKI** = public PEM (`BEGIN PUBLIC KEY`).

## Lab 2: Sign and verify

`lab03/sign_verify.mjs` (the snippet reads keys relative to the repo root; if your version reads `keys/…`, run it from inside `lab03/`):
```js
import { readFile } from 'node:fs/promises';
import { importPKCS8, importSPKI, SignJWT, jwtVerify } from 'jose';

const privateKey = await importPKCS8(await readFile('lab03/keys/private.pem', 'utf8'), 'RS256');
const publicKey  = await importSPKI(await readFile('lab03/keys/public.pem', 'utf8'), 'RS256');

const jwt = await new SignJWT({ role: 'user' })
  .setProtectedHeader({ alg: 'RS256' })
  .setSubject('u1').setIssuer('https://auth.local').setAudience('orders-api')
  .setExpirationTime('15m')
  .sign(privateKey);

const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
  algorithms: ['RS256'], issuer: 'https://auth.local', audience: 'orders-api',
});
console.log(protectedHeader, payload);
console.log('token length', jwt.length);
```

Compare token length with an HS256 token and with ES256 (change `generateKeyPair('ES256')`).

## Lab 3: Split the roles
> **Reference implementation:** [lab03/issuer.mjs](lab03/issuer.mjs) and [lab03/verifier.mjs](lab03/verifier.mjs). Run `T=$(node lab03/issuer.mjs) && node lab03/verifier.mjs "$T"`.

Create two scripts that share **nothing** but a file:
- `lab03/issuer.mjs`: has `private.pem`, prints a token.
- `lab03/verifier.mjs`: has only `public.pem`, reads a token from `argv[2]`, verifies it.

Confirm the verifier cannot sign: try `new SignJWT(...).sign(publicKey)`. What error?

## Try to break it: Algorithm confusion
Classic attack: server expects RS256, but verification code lets the token header pick the algorithm. Attacker takes the **public key** (it's public!), signs a token with **HS256 using the public key bytes as the HMAC secret**, and sets `alg: HS256`. A naive library verifies with the public key as an HMAC secret → forged token accepted.

> **Reference implementation:** [lab03/confusion.mjs](lab03/confusion.mjs) runs both a correct verifier (rejects with `ERR_JOSE_ALG_NOT_ALLOWED`) and a deliberately bad one (accepts the forged admin token).

Reproduce the idea safely:
1. Create `lab03/confusion.mjs`: read `public.pem` as a string, HMAC-sign `header.payload` with it using `createHmac('sha256', pem)`, build the token with `alg: HS256`.
2. Send it to `jwtVerify(token, publicKey, { algorithms: ['RS256'] })`. It fails: pinned algorithm, and `jose` also refuses to use an asymmetric key for HMAC.
3. Now write a deliberately **bad** verifier that reads `alg` from the header and picks HMAC verification. Watch the forgery succeed. Delete it afterward.

Takeaway: **verifiers decide the algorithm, never the token.**

## Exercises
> The comparison/benchmark exercises are implemented in [lab03/compare-algs.mjs](lab03/compare-algs.mjs); see also [03a - Algorithms explained](03a-algorithms-explained.md).

1. Repeat Lab 2 with ES256 and EdDSA. Compare signature and token sizes.
2. Benchmark sign vs verify for RS256 and ES256 (loop 2000x). RSA verify is fast, sign is slow; ECDSA the reverse-ish. What does that imply when the auth service signs a lot?
3. Write a verifier that accepts only tokens signed by key A, then swap to key B. Observe failure. This is the setup for `kid` and JWKS in guide 05.

## Checkpoint questions
- Why can a leaked public key not be used to mint tokens?
- What are PKCS8 and SPKI?
- How does algorithm confusion work and what is the defence?
- Who needs the private key? (Exactly one service.)
