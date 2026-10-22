# 01 - JWT Fundamentals

## Goal
Understand exactly what bytes a JWT contains, and what a signature does and does not give you.

## Concepts

### Why tokens exist at all
HTTP is stateless: every request arrives with no memory of the previous one. After a user proves who they are (password, SSO, passkey), the server needs a way to recognise them on the *next* request. There are two families of answers:

| | **Session (reference) token** | **Self-contained token (JWT)** |
|---|---|---|
| What the client holds | random ID, e.g. `sid=9f2c…` | the facts themselves: `sub=alice, scope=…, exp=…` + a signature |
| How the server checks it | look up the ID in a session store | verify the signature with a key; no lookup |
| Revoking | delete the row: instant | hard: the token stays valid until `exp` (guides 04 and 07) |
| Scales across services | every service needs the session store | any service with the key can verify on its own |

A JWT is a **signed claim**: "the issuer says these statements about this subject are true until time X". Anyone holding the right key can check that the statement is genuine without asking the issuer. That property, *verification without a round trip*, is the entire reason JWTs exist, and almost every trade-off in this course follows from it.

### Authentication vs authorization
- **Authentication (AuthN)**: *who are you?* Logging in. The token is the *result* of authentication.
- **Authorization (AuthZ)**: *what may you do?* Checked on every request, using claims inside the token (`scope`, `roles`) plus the service's own rules.

HTTP mirrors this: **401 Unauthorized** really means "unauthenticated" (no or bad token), **403 Forbidden** means "authenticated but not allowed".

### Bearer tokens
JWTs used as access tokens are **bearer tokens**: whoever *bears* (holds) the token can use it, like cash. No extra proof is required. This is why transport (HTTPS), storage (guide 04) and short lifetimes matter so much: a leaked token *is* the user until it expires.

### Structure
A (signed) JWT is three base64url strings joined by dots:

```
eyJhbGciOiJIUzI1NiJ9 . eyJzdWIiOiJ1MSIsImV4cCI6MTc5Mn0 . 3q2-7wX…
└──── header ───────┘   └──────── payload (claims) ────┘   └ signature ┘
```

- **Header**: how to verify. `{"alg":"HS256","typ":"JWT"}`, later also `kid` (which key).
- **Payload**: the claims, a JSON object.
- **Signature**: `SIGN(key, ASCII(base64url(header) + "." + base64url(payload)))`.

Note what is signed: the **encoded** header and payload, joined by a dot. The verifier never re-serialises JSON; it checks exactly the bytes it received. That is why changing a single character anywhere in the first two parts breaks the signature.

### The JOSE family (names you will meet)
| Spec | RFC | What it defines |
|---|---|---|
| JWS (JSON Web Signature) | 7515 | how to sign content, compact `a.b.c` format |
| JWE (JSON Web Encryption) | 7516 | how to encrypt content (`a.b.c.d.e`, five parts) |
| JWK (JSON Web Key) | 7517 | keys as JSON, key sets (JWKS) |
| JWA (JSON Web Algorithms) | 7518 | the `alg` names: HS256, RS256, ES256… |
| JWT (JSON Web Token) | 7519 | claim names (`iss`, `exp`…) on top of JWS/JWE |
| JWT Best Current Practices | 8725 | how not to get JWTs wrong; worth reading after guide 08 |

So a "JWT" in everyday speech is almost always a **JWS whose payload is a JSON claim set**.

> **Signed ≠ encrypted.** Anyone can read the payload by base64url-decoding it. The signature stops people *changing* it, not *reading* it. Never put secrets or sensitive personal data in it. (JWE gives confidentiality but is rare for access tokens; we skip it.)

### Registered claims you will use
| Claim | Meaning | Who sets it | Who must check it |
|-------|---------|-------------|-------------------|
| `iss` | issuer: who minted the token | issuer | verifier pins the exact expected value |
| `sub` | subject: whom it is about (user id, client id) | issuer | application logic |
| `aud` | audience: which service(s) it is meant for | issuer | **every verifier**: "is this token for *me*?" |
| `exp` | expiry, NumericDate | issuer | verifier rejects if `now > exp` (+ tolerance) |
| `nbf` | not before | issuer (optional) | verifier rejects if `now < nbf` |
| `iat` | issued at | issuer | used for "log out everywhere" (guide 07) |
| `jti` | unique token id | issuer | used for revocation lists (guide 07) |

**NumericDate** = seconds (not milliseconds!) since 1970-01-01 UTC. `Date.now()` returns milliseconds, so divide by 1000. Mixing these up is a classic bug that produces tokens valid for 50,000 years.

Custom (private) claims such as `scope`, `roles` and `tenant` are fine. Keep them few and small: the token travels on **every** request.

### base64url
Like base64 but URL-safe: `+`→`-`, `/`→`_`, and no `=` padding, so tokens fit in headers, URLs and cookies without escaping. Every 3 bytes become 4 characters (≈33% overhead). It is **encoding, not encryption**: anyone can reverse it.

### What verifying a JWT actually means
"Verify" is not one check. A correct verifier does all of the following, in roughly this order, and rejects on the first failure:

1. **Parse** three parts; reject anything malformed.
2. **Pick the key and algorithm from *your own configuration***, not from the token. The header's `alg` must be one you explicitly allow (guide 03 shows what happens otherwise).
3. **Check the signature** over `header.payload`.
4. **Check time claims**: `exp` (required), `nbf`, with a small clock tolerance (a few seconds) for skew between servers.
5. **Check `iss`** equals the issuer you trust.
6. **Check `aud`** contains *your* service.
7. Only now treat the claims as facts and do **authorization** (`scope`/`roles`).

`jose`'s `jwtVerify(token, key, { algorithms, issuer, audience })` does steps 1-6 for you, *but only for the options you pass*. Leave out `audience` and step 6 silently doesn't happen.

### decode vs verify
`decodeJwt()` just base64url-decodes the payload. It performs **zero** security checks and will happily return the claims of a forged token. Use it only for debugging or for reading a hint *before* verification (e.g. which tenant's keys to load), and never for an access decision.

### What the signature proves, and what it doesn't
It proves:
- **Integrity**: the header and payload are byte-for-byte what the signer produced.
- **Authenticity**: the signer held the signing key.

It does **not** prove:
- that the token is still *wanted* (the user may have logged out: revocation),
- that the user is still *allowed* (their role may have changed since issuance),
- that the token was meant for *your* service (that is `aud`),
- that the person sending it is the person it was issued to (bearer tokens can be stolen).

Keep this list in mind; guides 04-08 are largely about closing these gaps.

## Lab 1: Decode by hand (no libraries)

Create `lab01/anatomy.mjs`:

```js
import { SignJWT } from 'jose';

const key = new TextEncoder().encode('demo-secret-demo-secret-demo-secret!');
const token = await new SignJWT({ role: 'admin' })
  .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
  .setSubject('user-42')
  .setIssuer('https://auth.local')
  .setAudience('orders-api')
  .setIssuedAt()
  .setExpirationTime('15m')
  .setJti(crypto.randomUUID())
  .sign(key);

const [h, p, s] = token.split('.');
const decode = (b64u) => JSON.parse(Buffer.from(b64u, 'base64url').toString());

console.log('token  :', token);
console.log('header :', decode(h));
console.log('payload:', decode(p));
console.log('sig    :', s, `(${Buffer.from(s, 'base64url').length} bytes)`);
```

Answer from the output:
1. How many bytes is an HS256 signature? Why?
2. What does `exp` look like and how do you convert it to a date? (`new Date(exp*1000)`)

## Lab 2: Forge a token with only Node's `crypto`

Prove to yourself there is no magic. Create `lab01/manual-hs256.mjs`:

```js
import { createHmac } from 'node:crypto';

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const secret = 'demo-secret-demo-secret-demo-secret!';

const header  = b64u({ alg: 'HS256', typ: 'JWT' });
const payload = b64u({ sub: 'user-1', exp: Math.floor(Date.now() / 1000) + 300 });
const sig = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');

const token = `${header}.${payload}.${sig}`;
console.log(token);
```

Now verify the output with `jose`'s `jwtVerify` (key = `new TextEncoder().encode(secret)`). It must pass.

> **Reference implementations:** [lab01/anatomy.mjs](lab01/anatomy.mjs), [lab01/manual-hs256.mjs](lab01/manual-hs256.mjs) (also verifies the hand-made token with `jose`), and [lab01/exercises.mjs](lab01/exercises.mjs) (answers to exercises 1-4 below; try them yourself first, then compare).

## Exercises
1. Edit the payload of a token (change `role` to `admin`) without touching the signature. Verify it. What error do you get?
2. Take the token from Lab 1, wait for `exp` to pass (use `'2s'` expiry), verify. Which error class is thrown? (`err.code`)
3. Put a 2 KB claim into a token. Note the token size. Why does this matter for cookies/headers?
4. Run `decodeJwt` on a tampered token. Does it throw? What lesson does that teach?

## Checkpoint questions
- Why are JWTs safe to store client-side despite being readable?
- What are the three parts and which are secret?
- Who is supposed to check `aud` and `iss`: the issuer or the verifier?
- Why is `exp` mandatory in practice?
