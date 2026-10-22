# 02 - Symmetric Signing (HS256)

## Goal
Build a login + protected API using one shared secret, then understand its limits.

## Concepts

### What "symmetric" means
With a symmetric algorithm the **same secret** is used to create and to check the signature. Think of a wax seal where the stamp that makes the seal is also the only way to recognise a genuine one: whoever can check seals can also forge them.

```
      issuer                         verifier
  sign(secret, data) ── token ──►  sign(secret, data) == signature ?
          ▲                                  ▲
          └────────── same secret ───────────┘
```

### How HMAC works (and why not just `sha256(secret + data)`)
HS256 is **HMAC-SHA-256**. Conceptually:

```
HMAC(K, m) = SHA256( (K ⊕ opad) ‖ SHA256( (K ⊕ ipad) ‖ m ) )
```

The key is mixed in twice, inside and outside a nested hash. The naive construction `sha256(secret ‖ data)` is broken: SHA-256 is vulnerable to **length extension**, so an attacker who sees one valid `(data, hash)` pair can compute a valid hash for `data ‖ padding ‖ anything` *without knowing the secret*. HMAC's double wrapping is specifically designed to prevent that. Lesson: use the standard construction, never invent your own.

Verification simply recomputes the HMAC and compares. The comparison must be **constant time** (`crypto.timingSafeEqual`): an early-exit `===` leaks, through response timing, how many leading bytes matched, which lets an attacker discover a valid signature byte by byte. Libraries handle this; your own code (e.g. comparing client secrets) must too.

### Secret strength: why "at least 32 random bytes"
An HS256 token is a perfect offline brute-force target: the attacker needs **one** captured token, then can guess secrets on their own hardware as fast as they like, with no rate limit and no logs. Each guess is one HMAC computation.

| Secret | Guess space | Time at 1 billion guesses/s (a modest GPU rig) |
|---|---|---|
| `secret` (dictionary word) | ~10⁶ wordlist | instant |
| 8 random lowercase letters | 26⁸ ≈ 2×10¹¹ | ~3.5 minutes |
| 12 random alphanumerics | 62¹² ≈ 3×10²¹ | ~100,000 years |
| 32 random bytes | 2²⁵⁶ ≈ 10⁷⁷ | far longer than the age of the universe |

So: generate the secret with a CSPRNG, never type it by hand, and keep it at least as long as the hash output (32 bytes for HS256).

### The trust problem: verifier = forger
Because the secret both signs and verifies, **every party that can verify can also mint tokens**. In a monolith that is fine: there is one party. In a system of N services sharing one secret:

- the secret lives in N config files, N deploy pipelines, N memory images;
- the *least* secure of those N services decides the security of all of them;
- a compromise of a low-value service (say, a newsletter service) lets the attacker mint admin tokens for the payments service.

`aud` limits *accidental* misuse (a token for A replayed to B), but it does not help against a stolen secret: the attacker simply writes whatever `aud` they want. That is the motivation for asymmetric keys in guide 03.

### Rotation with a shared secret
Changing the secret instantly invalidates every outstanding token, unless verifiers accept the old secret for a while. With a shared secret you also have to update every service at the same time. Guide 05's `kid` + JWKS mechanism is the clean solution; exercise 1 below shows the manual version.

### When HS256 is the right tool
- One service both issues and verifies (monolith, backend-for-frontend, a single API).
- Short-lived internal tokens where both ends are the same codebase.
- Never when third parties or many independent teams must verify.

## Lab: Login API with HS256

> **Reference implementation:** [lab02/server.mjs](lab02/server.mjs), [lab02/attacks.mjs](lab02/attacks.mjs), [lab02/crack.mjs](lab02/crack.mjs), [lab02/server.test.mjs](lab02/server.test.mjs). The repo version wraps the app in `createApp()` and exports `SECRET/ISSUER/AUDIENCE` so the attack script and tests can import it. The snippet below is the same code in its simplest form.

Create `lab02/server.mjs`:

```js
import express from 'express';
import { SignJWT, jwtVerify, errors } from 'jose';

const app = express();
app.use(express.json());

const SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET ?? 'dev-only-secret-dev-only-secret-32b!'
);
const ISSUER = 'https://auth.local';
const AUDIENCE = 'lab02-api';

// toy user store
const users = { alice: { id: 'u1', password: 'pw', role: 'admin' },
                bob:   { id: 'u2', password: 'pw', role: 'user' } };

app.post('/login', async (req, res) => {
  const { username, password } = req.body ?? {};
  const u = users[username];
  if (!u || u.password !== password) return res.status(401).json({ error: 'bad credentials' });

  const token = await new SignJWT({ role: u.role })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(u.id)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(SECRET);
  res.json({ access_token: token, token_type: 'Bearer', expires_in: 900 });
});

// middleware
async function requireAuth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.get('authorization') ?? '');
  if (!m) return res.status(401).json({ error: 'missing token' });
  try {
    const { payload } = await jwtVerify(m[1], SECRET, {
      algorithms: ['HS256'],       // ALWAYS pin algorithms
      issuer: ISSUER,
      audience: AUDIENCE,
      clockTolerance: 5,           // seconds of skew
    });
    req.user = payload;
    next();
  } catch (e) {
    const expired = e instanceof errors.JWTExpired;
    res.status(401).json({ error: expired ? 'token expired' : 'invalid token' });
  }
}

const requireRole = (role) => (req, res, next) =>
  req.user.role === role ? next() : res.status(403).json({ error: 'forbidden' });

app.get('/me', requireAuth, (req, res) => res.json(req.user));
app.get('/admin', requireAuth, requireRole('admin'), (req, res) => res.json({ secret: 'admin data' }));

app.listen(3002, () => console.log('lab02 on :3002'));
```

Run it and exercise it:
```bash
node lab02/server.mjs

TOKEN=$(curl -s localhost:3002/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"pw"}' | jq -r .access_token)

curl -s localhost:3002/me    -H "authorization: Bearer $TOKEN"
curl -s localhost:3002/admin -H "authorization: Bearer $TOKEN"
# log in as bob and try /admin -> 403
```

Note 401 (who are you?) vs 403 (I know you, no).

## Try to break it

`node lab02/attacks.mjs` runs attacks 1, 2 and 4 against an in-process server, plus a *control*: a token forged **with** the real secret is accepted (status 200), which is exactly why leaking an HS256 secret is a total compromise. `node lab02/crack.mjs` demonstrates attack 3: a weak secret like `secret` falls in under a millisecond; the script also measures guesses/second to show why 32 random bytes are infeasible to brute-force. Try writing them yourself first.

### Attack 1: Tamper with claims
Take bob's token, change `role` to `admin` in the payload (base64url decode, edit, encode), keep the old signature. Expect `invalid token`.

### Attack 2: `alg: none`
Craft `{"alg":"none"}` header + payload + empty signature. Send it. Modern `jose` rejects it, and your `algorithms` pin would too. Write the forging script yourself (the reference version is part of `lab02/attacks.mjs`).

### Attack 3: Weak secret brute force
Change the secret to `secret`. Capture a token. Write `lab02/crack.mjs` that tries a wordlist of candidates with `createHmac` until the signature matches. Time it. Then try with a 32-byte random secret and reason about the cost.

### Attack 4: Wrong audience
Issue a token with `aud: 'other-api'` using the same secret, and send it to this API. It must be rejected. This is why `aud` matters when many services share a secret.

## Exercises
1. Support two secrets (current + previous) so rotating the secret does not log everyone out. Hint: try verifying with current, fall back to previous. (This is what `kid` solves properly in guide 05.)
2. Return a specific `WWW-Authenticate: Bearer error="invalid_token"` header on 401s.
3. Reduce expiry to `10s` and watch the client experience. This motivates guide 04.

## Checkpoint questions
- In a 5-service system sharing one HS256 secret, what happens if the least-secure service is breached?
- Why must you pass `algorithms` explicitly?
- When is HS256 the right choice?
