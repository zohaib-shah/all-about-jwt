# 04 - Access + Refresh Tokens

## Goal
Solve "JWTs cannot be revoked" pragmatically: short-lived access tokens plus a stateful refresh token with rotation.

## Concepts

### The revocation problem
A JWT is valid until `exp` because verifiers check it **without asking anyone**. That is its strength (no lookup, no shared store) and its weakness: if a user logs out, changes their password, or has their laptop stolen, tokens already issued keep working until they expire.

You can't have both "no lookup per request" *and* "instant revocation". The industry compromise is to split the job between two tokens:

| | Access token | Refresh token |
|---|---|---|
| Purpose | call APIs | get new access tokens |
| Format | JWT (self-contained) | opaque random string (a reference) |
| Lifetime | short: 5-15 min | long: days-weeks |
| Sent to | every API, on every request | **only** the auth service's `/refresh` |
| Checked | statelessly (signature) | statefully (store lookup) |
| Revocable? | not really (wait for expiry, or see guide 07) | yes: delete it from the store |
| Browser storage | JS memory | `HttpOnly; Secure; SameSite` cookie |

The access token gives you **speed** where it matters (every request); the refresh token gives you **control** where it matters (every few minutes). Revoking a session = revoking the refresh token; the user is locked out within one access-token lifetime at most. The short access TTL *is* the revocation mechanism.

### Why the refresh token is opaque, not a JWT
- It is only ever read by the auth service, which has a store anyway, so self-containment buys nothing.
- An opaque random value has nothing to decode, no claims to leak and no algorithm to attack.
- Revocation is a simple delete.
- It is stored **hashed** (SHA-256). It's a bearer credential like a password, so a database dump must not yield usable tokens. A fast hash is fine here (unlike for passwords) because the token has 256 bits of entropy and cannot be guessed.

### The flow
```
Client                         Auth service                     API
  │ POST /login (password) ──────►│
  │◄── access(5m) + Set-Cookie rt ┤  store hash(rt) → {user, family}
  │ GET /orders  Bearer access ──────────────────────────────────►│ verify signature only
  │◄──────────────────────────────────────────────────────── 200 ─┤
  │   … 5 minutes later …
  │ GET /orders  Bearer access ──────────────────────────────────►│
  │◄──────────────────────────────────────────── 401 expired ─────┤
  │ POST /auth/refresh (cookie rt) ►│ rt valid & unused? mark used,
  │◄── new access + new rt cookie ──┤ issue rt' in same family
  │ retry GET /orders ───────────────────────────────────────────►│
```

### Rotation + reuse detection: catching a thief
If a refresh token is stolen, the thief and the real user both hold it. **Rotation** issues a new refresh token on every use and invalidates the old one. Now consider the two orders of events:

```
family F:  rt1 ──used──► rt2 ──used──► rt3 …

Case A: user refreshes first (rt1→rt2), thief later presents rt1
        → rt1 is already USED → reuse detected → revoke family F
Case B: thief refreshes first (rt1→rt2'), user later presents rt1
        → same thing: reuse detected → revoke family F
```

The server can't tell *who* is the thief, but it doesn't need to: **any reuse means two parties hold the same token**, so it kills the whole family (every token descended from that login). Both parties are logged out and the real user signs in again. A thief who stays silent gets at most one access-token lifetime.

The cost: honest races (two tabs refreshing at once, a retry after a network blip) look like reuse. Exercise 2 adds a short **grace window** to tolerate them.

### Where to keep tokens in a browser
The two threats are **XSS** (attacker's JavaScript runs in your page) and **CSRF** (another site makes the browser send requests to yours, with your cookies).

| Storage | Readable by XSS? | Sent automatically (CSRF risk)? | Verdict |
|---|---|---|---|
| `localStorage` / `sessionStorage` | yes | no | don't put tokens here |
| JS memory (a variable) | only while the attacker's code runs in the page | no | good for the short-lived access token |
| `HttpOnly` cookie | **no** | yes | good for the refresh token, with CSRF defences |

Cookie attributes, one by one:
- **`HttpOnly`**: JavaScript can't read it, so XSS can't exfiltrate the refresh token (it can still *use* the session while it runs, which is why CSP and output encoding still matter).
- **`Secure`**: sent over HTTPS only.
- **`SameSite=Strict`**: never sent on cross-site requests. `Lax` allows top-level GET navigations; `None` is always sent and requires `Secure`. Strict or Lax are the main CSRF defence.
- **`Path=/auth`**: the browser only attaches it to `/auth/*` requests, so it isn't sprayed onto every API call or logged by unrelated services.
- **`Max-Age`**: matches the refresh token lifetime.

For extra CSRF safety on `/auth/refresh`, also check the `Origin` header. Many production systems go one step further with a **backend-for-frontend (BFF)**: the browser holds only a session cookie and a small server-side component keeps the tokens.

> **Reference implementation:** [lab04/server.mjs](lab04/server.mjs) (exports `createApp({accessTtl, graceMs})`), [lab04/cookie-client.mjs](lab04/cookie-client.mjs) (a tiny cookie-jar `fetch` that stands in for a browser), [lab04/client.mjs](lab04/client.mjs), [lab04/theft.mjs](lab04/theft.mjs), [lab04/server.test.mjs](lab04/server.test.mjs).
> The repo server already includes the extras from exercises 2-4 (grace window, absolute 30-day session cap, `/auth/sessions`). The snippet below is the core only, so implement the extras yourself first.

## Lab: Auth server with rotation (in-memory first)

`lab04/server.mjs`. We use an in-memory `Map` now and swap to Redis in guide 07.

```js
import express from 'express';
import cookieParser from 'cookie-parser';
import { SignJWT, jwtVerify } from 'jose';
import { randomBytes, createHash, randomUUID } from 'node:crypto';

const app = express();
app.use(express.json(), cookieParser());

const SECRET = new TextEncoder().encode('dev-only-secret-dev-only-secret-32b!');
const ISS = 'https://auth.local', AUD = 'lab04-api';
const REFRESH_TTL_MS = 7 * 24 * 3600 * 1000;

// refresh store: sha256(token) -> { userId, family, used, expiresAt }
const refreshStore = new Map();
const revokedFamilies = new Set();

const hash = (t) => createHash('sha256').update(t).digest('hex');

const signAccess = (userId) =>
  new SignJWT({}).setProtectedHeader({ alg: 'HS256' })
    .setSubject(userId).setIssuer(ISS).setAudience(AUD)
    .setIssuedAt().setExpirationTime('1m').setJti(randomUUID())
    .sign(SECRET);

function issueRefresh(userId, family = randomUUID()) {
  const token = randomBytes(32).toString('base64url');
  refreshStore.set(hash(token), {
    userId, family, used: false, expiresAt: Date.now() + REFRESH_TTL_MS,
  });
  return token;
}

const setCookie = (res, token) =>
  res.cookie('rt', token, {
    httpOnly: true, sameSite: 'strict', secure: false /* true behind HTTPS */,
    path: '/auth', maxAge: REFRESH_TTL_MS,
  });

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body ?? {};
  if (password !== 'pw') return res.status(401).json({ error: 'bad credentials' });
  setCookie(res, issueRefresh(username));
  res.json({ access_token: await signAccess(username) });
});

app.post('/auth/refresh', async (req, res) => {
  const presented = req.cookies.rt;
  const rec = presented && refreshStore.get(hash(presented));
  if (!rec || rec.expiresAt < Date.now() || revokedFamilies.has(rec.family))
    return res.status(401).json({ error: 'invalid refresh token' });

  if (rec.used) {                          // REUSE DETECTED
    revokedFamilies.add(rec.family);
    return res.status(401).json({ error: 'refresh token reuse detected' });
  }
  rec.used = true;
  setCookie(res, issueRefresh(rec.userId, rec.family));
  res.json({ access_token: await signAccess(rec.userId) });
});

app.post('/auth/logout', (req, res) => {
  const rec = req.cookies.rt && refreshStore.get(hash(req.cookies.rt));
  if (rec) revokedFamilies.add(rec.family);
  res.clearCookie('rt', { path: '/auth' }).sendStatus(204);
});

// protected API
app.get('/api/me', async (req, res) => {
  try {
    const t = /^Bearer (.+)$/.exec(req.get('authorization') ?? '')?.[1];
    const { payload } = await jwtVerify(t, SECRET, { algorithms: ['HS256'], issuer: ISS, audience: AUD });
    res.json(payload);
  } catch { res.status(401).json({ error: 'invalid or expired token' }); }
});

app.listen(3004, () => console.log('lab04 on :3004'));
```

Note: we store a **hash** of the refresh token so a DB leak does not leak usable tokens.

### Drive it with curl
```bash
curl -i -c jar.txt -X POST localhost:3004/auth/login -H 'content-type: application/json' -d '{"username":"alice","password":"pw"}'
curl -i -b jar.txt -c jar.txt -X POST localhost:3004/auth/refresh      # works, cookie rotated
```

### Simulate theft (automated)
`node lab04/theft.mjs` plays all three roles and prints `200 / 401 (reuse detected) / 401`.

### Simulate theft (by hand)
1. Copy the cookie jar: `cp jar.txt stolen.txt`.
2. Legit client refreshes with `jar.txt` (token A → B).
3. Attacker replays `stolen.txt` (token A, already used) → **reuse detected**, family revoked.
4. Legit client's next refresh with B is now rejected too. Everyone must log in again: the safe failure mode.

## Exercises
1. Write `lab04/client.mjs` that logs in, calls `/api/me`, and when it gets 401 transparently refreshes once and retries (single-flight: only one refresh at a time even with 5 parallel requests).
2. Add a grace window (e.g. 10 s) during which a just-used refresh token can be retried, to tolerate network retries and multi-tab races. What is the trade-off?
3. Add an absolute session lifetime (e.g. 30 days) independent of rotation.
4. Add `GET /auth/sessions` listing active families for a user and `DELETE` to revoke one ("log out other devices").

## Reference solutions
- Exercise 1 (single-flight client): [lab04/client.mjs](lab04/client.mjs). Five parallel calls after the access token expires trigger **one** refresh call (the in-flight promise is shared).
- Exercise 2 (grace window): the used record keeps `usedAt` and its `successor`; a retry inside `graceMs` returns the *same* successor instead of triggering reuse detection. Trade-off: a thief who replays within the window also gets a valid token, so keep it to a few seconds.
- Exercise 3 (absolute lifetime): each family stores `startedAt`; refresh fails once older than 30 days regardless of rotation.
- Exercise 4 (sessions): `GET /auth/sessions`, `DELETE /auth/sessions/:id` (the family id).

## Checkpoint questions
- Why is the refresh token opaque instead of a JWT?
- What attack does reuse detection catch?
- Why is a short access-token lifetime the main revocation mechanism?
- What breaks if two browser tabs refresh at the same instant? How would you mitigate?
