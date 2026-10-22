# 03a - JWT Signing Algorithms Explained

Companion to [03 - Asymmetric signing](03-asymmetric-rs256.md). Read this to understand *what each `alg` value means*, how they differ, and how to choose.

## 1. The `alg` header
The `alg` value in the JWT header names the signature algorithm (defined in JWA, RFC 7518, plus RFC 8037 for EdDSA). Naming pattern: **scheme + hash size**.

```
HS256  = HMAC     + SHA-256
RS256  = RSASSA-PKCS1-v1_5 + SHA-256
PS256  = RSASSA-PSS        + SHA-256
ES256  = ECDSA (P-256)     + SHA-256
EdDSA  = Ed25519 (hash is built in)
```

Two families:

| Family | Keys | Who can verify | Who can sign |
|---|---|---|---|
| **Symmetric** (HS*) | one shared secret | anyone with the secret | anyone with the secret |
| **Asymmetric** (RS*, PS*, ES*, EdDSA) | private + public key pair | anyone with the public key | only the private-key holder |

The signature is always computed over `base64url(header) + "." + base64url(payload)`.

---

## 2. HS256 / HS384 / HS512: HMAC
- **How it works**: `HMAC-SHA256(secret, signingInput)`. Verifying recomputes the HMAC and compares in constant time.
- **Key**: random bytes, at least as long as the hash output (32 B for HS256, 48 B for HS384, 64 B for HS512).
- **Signature size**: 32 / 48 / 64 bytes.
- **Pros**: fastest, trivial to set up, tiny tokens.
- **Cons**: verifier = signer. Any service that can check tokens can forge them. Key distribution is a secret-sharing problem.
- **Use when**: one service both issues and verifies (monolith, BFF, internal tool).
- Bigger hash (384/512) adds no practical safety beyond a strong key; HS256 is fine.

```js
const key = new TextEncoder().encode(process.env.JWT_SECRET); // ≥ 32 bytes
new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).sign(key);
```

---

## 3. RS256 / RS384 / RS512: RSA PKCS#1 v1.5
- **How it works**: hash the signing input, pad it per PKCS#1 v1.5, then apply the RSA private-key operation. Verify with the public key.
- **Key**: RSA, **2048 bits minimum** (3072 for long-term). Public key is large (~450 B as SPKI PEM body).
- **Signature size**: equals key size: 256 B for 2048-bit, 384 B for 3072-bit, so tokens are noticeably big (~340 base64url chars for the signature alone).
- **Performance**: signing is slow (private-key exponentiation), **verifying is very fast** (small public exponent, usually 65537). Good for many verifiers.
- **Pros**: universally supported (every library, every IdP, every API gateway). Deterministic signatures.
- **Cons**: large keys/signatures; the v1.5 padding is older and less robust than PSS (no practical break for JWT use, but not the modern pick).
- **Use when**: you need maximum interoperability with third parties; this is the default of many identity providers (Auth0, Okta, Azure AD, Google).

```js
const { privateKey, publicKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
```

---

## 4. PS256 / PS384 / PS512: RSA-PSS
- Same RSA keys as RS*, but with the **probabilistic signature scheme** (random salt per signature) which has a security proof in the random-oracle model.
- Signatures are **not deterministic**: signing the same input twice gives different outputs.
- Same size/performance profile as RS256.
- **Support**: widespread but not universal (older libraries/gateways may lack it).
- **Use when**: you want RSA but with the better padding and control both ends. Required by some profiles (e.g. FAPI/open banking).
- Do not reuse one RSA key for both RS* and PS*; keep one key per algorithm.

---

## 5. ES256 / ES384 / ES512: ECDSA
- **How it works**: elliptic-curve signatures. Each algorithm is bound to a curve:

| Alg | Curve | Hash | Sig size |
|---|---|---|---|
| ES256 | P-256 (secp256r1) | SHA-256 | 64 B |
| ES384 | P-384 | SHA-384 | 96 B |
| ES512 | **P-521** (not 512!) | SHA-512 | 132 B |
| ES256K | secp256k1 | SHA-256 | 64 B (blockchain-flavoured, rare) |

- **Key size**: 256-bit curve ≈ security of RSA-3072, with much smaller keys and signatures. JWT signature is the raw `r||s` concatenation (not DER; `jose` handles this).
- **Performance**: fast signing, slower verifying than RSA, still sub-millisecond.
- **Pros**: small tokens, small keys, strong security. Widely supported in modern stacks.
- **Cons**: needs a good random nonce per signature. A broken RNG can leak the private key (library handles this; never hand-roll ECDSA). Signatures are non-deterministic.
- **Use when**: default for new systems that you control. **This course uses ES256 for the microservices/JWKS part.**

```js
const { privateKey, publicKey } = await generateKeyPair('ES256');
```

---

## 6. EdDSA (Ed25519, Ed448)
- **How it works**: Edwards-curve signatures. Ed25519 uses Curve25519 and SHA-512 internally; the hash is part of the algorithm, so there are no `EdDSA256` variants. In JWK this is `kty: "OKP"`, `crv: "Ed25519"`.
- **Signature size**: 64 B (Ed25519). Keys are 32 B.
- **Pros**: fastest sign *and* verify of the group, **deterministic** (no RNG pitfall), designed to avoid implementation traps, small.
- **Cons**: less universal support (older libraries, some HSMs/cloud KMS, some IdPs lack it). Verify your whole chain supports it before choosing.
- **Use when**: modern greenfield systems where all verifiers are under your control.

```js
const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
```

---

## 7. `none`
`alg: "none"` means unsigned. It exists in the spec for contexts where integrity is guaranteed elsewhere. **Never accept it** in an API. Libraries reject it by default; pinning `algorithms` guarantees it.

---

## 8. Side-by-side comparison

| Alg | Type | Key material | Sig bytes | Sign speed | Verify speed | Deterministic | Support |
|---|---|---|---|---|---|---|---|
| HS256 | symmetric | 32 B secret | 32 | ★★★★★ | ★★★★★ | yes | everywhere |
| RS256 | RSA | 2048-bit | 256 | ★★ | ★★★★ | yes | everywhere |
| PS256 | RSA | 2048-bit | 256 | ★★ | ★★★★ | no | wide |
| ES256 | ECDSA P-256 | 256-bit | 64 | ★★★★ | ★★★ | no | wide |
| EdDSA | Ed25519 | 256-bit | 64 | ★★★★★ | ★★★★ | yes | growing |

(Star ratings are relative; measure on your hardware in the lab below.)

## 9. Choosing
```
Single service issues + verifies?            → HS256 (strong random secret)
Multiple services verify, you control all?   → ES256 (or EdDSA if everything supports it)
Third parties / legacy / IdP interop?        → RS256
Regulated profile requiring RSA-PSS?         → PS256
```
Rule of thumb: **ES256 unless something forces your hand.**

## 10. How the key format maps to JWK
| Alg | `kty` | Public JWK fields | Private-only fields (never publish) |
|---|---|---|---|
| RS*/PS* | `RSA` | `n`, `e` | `d`, `p`, `q`, `dp`, `dq`, `qi` |
| ES* | `EC` | `crv`, `x`, `y` | `d` |
| EdDSA | `OKP` | `crv`, `x` | `d` |
| HS* | `oct` | n/a: never publish | `k` (the secret itself) |

This is why symmetric keys can never appear in a JWKS: publishing them would publish the signing secret.

## 11. Lab: generate, compare, benchmark

Reference implementation: [lab03/compare-algs.mjs](lab03/compare-algs.mjs). It extends the snippet below with an HS256 row and a determinism check (identical input signed twice). Sample result on one dev machine: RS256/PS256 tokens ~403 chars (256 B signature), ES256/EdDSA ~147 chars (64 B), HS256 ~104 chars (32 B); RS256 and EdDSA signatures are deterministic, ES256 is not.

```js
import { generateKeyPair, SignJWT, jwtVerify, exportJWK } from 'jose';

const algs = [
  ['RS256', {}], ['PS256', {}], ['ES256', {}], ['ES384', {}],
  ['EdDSA', { crv: 'Ed25519' }],
];
const N = 300;
const rows = [];

for (const [alg, opts] of algs) {
  const { privateKey, publicKey } = await generateKeyPair(alg, { ...opts, extractable: true });
  const jwk = await exportJWK(publicKey);
  const make = () => new SignJWT({ sub: 'u1' }).setProtectedHeader({ alg })
    .setExpirationTime('5m').sign(privateKey);

  const token = await make();
  let t = performance.now();
  for (let i = 0; i < N; i++) await make();
  const signMs = (performance.now() - t) / N;

  t = performance.now();
  for (let i = 0; i < N; i++) await jwtVerify(token, publicKey, { algorithms: [alg] });
  const verifyMs = (performance.now() - t) / N;

  rows.push({ alg, kty: jwk.kty, tokenChars: token.length,
              sigBytes: Buffer.from(token.split('.')[2], 'base64url').length,
              signMs: +signMs.toFixed(3), verifyMs: +verifyMs.toFixed(3) });
}
console.table(rows);
```
Run `node lab03/compare-algs.mjs`.

Questions:
1. Which algorithm produces the shortest token? Which the slowest sign? Which the slowest verify?
2. Run twice and check determinism: do two RS256 signatures of the same input match? Two ES256? (Use a fixed `iat`/`exp` to make inputs identical.)
3. Add an HS256 row (use `crypto.randomBytes(32)` as the key). How does it compare?

## 12. Exercises
1. Use `exportJWK(privateKey)` for each type and list which fields appear. Confirm against the table in section 10.
2. Make a verifier that accepts `['ES256','RS256']` and prove it rejects an EdDSA-signed token.
3. Try `jwtVerify(token, rsaPublicKey, { algorithms: ['ES256'] })` on an RS256 token. Read the error; this is key/algorithm binding in action.
4. Generate a 1024-bit RSA key with `modulusLength: 1024`. Observe what `jose` does. Why is this refused/discouraged?

## Checkpoint questions
- Why is `ES512` a P-521 curve and not "512-bit"?
- Why does RS256 verification run faster than signing?
- What does "deterministic signature" mean, and why does it matter for ECDSA implementations?
- Which algorithms can appear in a public JWKS, and which can never?
