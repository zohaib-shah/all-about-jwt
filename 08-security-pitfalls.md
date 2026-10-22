# 08 - Security Pitfalls & Checklist

## Goal
Consolidate the attack catalogue and produce a review checklist you can apply to any JWT system.

## Concepts

### Thinking like an attacker
Almost every real-world JWT vulnerability falls into one of four buckets. When you review a system, walk through them in order:

| Bucket | Attacker's question | Typical bugs |
|---|---|---|
| **1. Forge** | Can I make the verifier accept a token I created? | `alg:none`, algorithm confusion, weak HMAC secret, attacker-supplied keys (`jku`/`jwk`), leaked private key |
| **2. Misuse** | Can I use a *genuine* token somewhere it wasn't meant for? | missing `aud`/`iss` checks, ID token accepted as access token, user token forwarded to internal services |
| **3. Steal** | Can I get someone else's genuine token? | XSS + `localStorage`, tokens in URLs/logs, no HTTPS, CSRF on cookie endpoints |
| **4. Outlive** | Can I keep using a token after it should have died? | no/long `exp`, no refresh rotation, no revocation on logout or password change |

Notice that "the signature is valid" only closes bucket 1. Buckets 2-4 are about *claims*, *transport* and *lifecycle*, which is why a "we use JWT, so we're secure" argument is never enough.

### Why the header is the most dangerous part
The header is **attacker-controlled input** that the verifier reads *before* it knows whether the token is genuine. Every header field the verifier acts on is a potential lever:
- `alg` decides *how* to verify → pin it in configuration (attacks 1, 2).
- `kid` decides *which key* → treat it as an opaque map key, never as a path or query (attack 7).
- `jku`, `x5u`, `jwk`, `x5c` say *where to get the key*, or embed one → ignore them unless you have a very specific, allow-listed reason (attack 8). Honouring them means the attacker supplies the key that checks their own signature: always valid. Fetching an attacker-supplied URL is also an SSRF hole into your internal network.

### Defence in depth
No single control is enough, so layer them so each one limits the damage when another fails:

```
short exp ─► limits how long a stolen token works
  aud/iss ─► limits where a token works
   scopes ─► limits what a token can do
rotation  ─► detects stolen refresh tokens
denylist/watermark ─► lets you cut access early
HttpOnly/SameSite/CSP ─► make stealing harder in the first place
```

## Attack catalogue (each is a mini-lab: reproduce, then fix)

| # | Attack | How it works | Defence |
|---|---|---|---|
| 1 | `alg: none` | Unsigned token accepted | Pin `algorithms`; use a maintained library |
| 2 | Algorithm confusion | RS256 key used as HS256 secret | Pin `algorithms`; key types bound to algs |
| 3 | Weak HMAC secret | Offline brute force from one token | ≥32 random bytes; prefer asymmetric |
| 4 | Missing `aud` check | Token for service A replayed to B | Verify `aud` always |
| 5 | Missing `iss` check | Token from another issuer with same keys/JWKS host | Pin `iss` |
| 6 | No/long `exp` | Stolen token valid forever | Short TTL + refresh |
| 7 | `kid` injection | `kid` used in file path / SQL lookup → traversal/injection | Treat `kid` as opaque; look up in an in-memory map only |
| 8 | `jku` / `x5u` / embedded `jwk` header | Attacker points verifier to their own key URL | Ignore these headers; fetch only from configured JWKS URL |
| 9 | Token in URL | Leaks through logs, referrers | Use `Authorization` header or HttpOnly cookie |
| 10 | XSS token theft | JS reads `localStorage` | Memory + HttpOnly refresh cookie, CSP |
| 11 | CSRF on cookie auth | Browser auto-sends cookies | `SameSite`, Origin check, CSRF token |
| 12 | Refresh token theft | Long-lived credential stolen | Rotation + reuse detection, hashed storage |
| 13 | Stale authorization | Role in token outdated for 15 min | Short TTL, watermark, re-check sensitive actions |
| 14 | Sensitive data in payload | Payload is readable | Keep PII/secrets out |
| 15 | Trusting `decode` | Used `decodeJwt` instead of verify | Lint/grep for `decode*` outside tooling |
| 16 | Rate-limit bypass via `X-Forwarded-For` | App trusts any proxy header, so every request with a new fake IP gets a fresh limiter bucket | Trust proxy headers only from known proxies (`trust proxy` = `loopback` or a hop count), never `true` on an exposed port |

> **Attack 16 was a real bug in this repo's first version** (`app.set('trust proxy', true)` in the auth service). Eight login attempts, each with a different `X-Forwarded-For`, all returned 401 and never 429. It is fixed, and `test/acceptance.test.mjs` now has a regression test for it. It is worth remembering because it's an infrastructure setting, not JWT code: the token logic was fine, and the protection around it was silently off.

## Labs

### Lab A: Build the "evil" suite
> **Reference implementation:** [lab08/attacks.mjs](lab08/attacks.mjs). Start Redis and the three services, then `npm run attacks`. It prints a PASS/FAIL table and exits non-zero on any failure.

Create `lab08/attacks.mjs` that targets your guide-06 services and tries each of: none-alg, confusion, expired, wrong-aud, wrong-iss, tampered payload, `jku` header pointing to `http://localhost:9999/jwks.json` (run an attacker JWKS server there), embedded `jwk` header, `kid` of `../../etc/passwd`, token with no `exp`.

Expected result: every attack returns 401/403 and the service never contacts :9999. Print a table PASS/FAIL. Any FAIL is a bug to fix before moving on.

The reference suite covers 11 attacks (`alg=none`; HS256 confusion using the public `x` value and using the whole JWKS JSON as the secret; foreign key with a real `kid`; `jku`; `x5u`; embedded `jwk`; `kid` path traversal; `kid` SQL injection; garbage token; empty signature) plus the "attacker server was never contacted" check.

*Note:* attacks that need a **validly signed** token (expired, wrong issuer, missing `exp`, `nbf`) can't be forged against a live service without its key. Those are covered in Lab B with a key pair you control.

### Lab B: Negative-test your middleware
> **Reference implementation:** [test/middleware.test.mjs](test/middleware.test.mjs): 13 tests, fully in-process (own key pair, a tiny JWKS HTTP server, no Redis).

Write `node --test` tests for the shared middleware: missing header, malformed bearer, wrong scheme (`Basic`), valid token wrong aud, expired by 1 s with and without `clockTolerance`, `nbf` in the future.

### Lab C: Log hygiene
```bash
grep -rnE "console\.[a-z]+\(.*(authorization|token)" services --include=*.mjs   # expect: nothing
grep -rnE "decodeJwt|decodeProtectedHeader" --include=*.mjs . --exclude-dir=node_modules   # only tools/ and lab01/
```
The orders service logs a JSON audit line per request with `sub`, `jti`, route and status. Never the token.

Grep your services for anything logging `authorization` headers or full tokens. Replace with `jti` + `sub`. Add a redaction helper.

## Hardening checklist (copy into your reviews)

**Signing**
- [ ] Asymmetric algorithm (ES256/EdDSA/RS256) for multi-service setups
- [ ] Private key held by exactly one service, loaded from a secret manager, never in git
- [ ] Rotation procedure documented and rehearsed
- [ ] `kid` set on every token

**Verification**
- [ ] `algorithms` pinned
- [ ] `iss`, `aud` verified; `exp` required; small `clockTolerance`
- [ ] `jku`/`x5u`/`jwk` headers ignored
- [ ] JWKS fetched only from configured HTTPS URL, with timeout, caching and refetch cooldown
- [ ] Authorization (scopes/roles) checked per route, 401 vs 403 used correctly

**Lifecycle**
- [ ] Access TTL ≤ 15 min
- [ ] Refresh tokens opaque, hashed at rest, rotated, reuse-detected, expiring
- [ ] Revocation strategy chosen (denylist and/or watermark) and fail-open/closed decision recorded
- [ ] Logout revokes server-side state

**Transport & client**
- [ ] HTTPS only; `Secure` cookies; HSTS
- [ ] Refresh token in `HttpOnly; SameSite` cookie scoped to its path
- [ ] No tokens in URLs or logs
- [ ] Proxy headers trusted only from known proxies; services and Redis not exposed beyond what is needed

## When NOT to use JWTs
- Plain browser session for a single web app: a server-side session ID in an HttpOnly cookie is simpler and trivially revocable.
- Need instant revocation everywhere with no extra lookup: opaque tokens + introspection.
JWTs shine for distributed verification without a shared session store. Pick the tool for the problem.

## Checkpoint questions
- Which three checks do verifiers frequently forget?
- Why are `jku`/`jwk` headers dangerous even though signatures are verified?
- Which defences did *you* verify with a failing attack, not just by reading?
