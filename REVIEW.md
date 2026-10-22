# Self-review against the [08 checklist](08-security-pitfalls.md)

Evidence is a file + symbol; "T:" names the test that proves it (`npm test`, `npm run attacks`).

## Signing
| Item | Result | Evidence |
|---|---|---|
| Asymmetric alg for multi-service | PASS | ES256 in [services/auth/keys.mjs](services/auth/keys.mjs) `ALGORITHM` |
| Private key held by one service, not in git | PASS (dev) | only auth loads `privateKey`; `.gitignore` covers `*.pem`; ring file is mode 0600 (`KEYS_FILE`). **Prod: use a secret manager/KMS.** |
| Rotation documented and rehearsed | PASS | [05-jwks.md](05-jwks.md), `lab05/rotation-drill.mjs`, T: "key rotation under constant load" |
| `kid` on every token | PASS | `signAccess` in [services/auth/app.mjs](services/auth/app.mjs) |

## Verification
| Item | Result | Evidence |
|---|---|---|
| `algorithms` pinned | PASS | `jwtAuth` in [auth-middleware.mjs](services/shared/auth-middleware.mjs); T: HS256 confusion attacks in `lab08/attacks.mjs` |
| `iss`, `aud`, `exp` required, small tolerance | PASS | `jwtVerify(... requiredClaims: ['exp','sub'], clockTolerance: 5)`; T: middleware.test.mjs |
| `jku`/`x5u`/`jwk` ignored | PASS | keys come only from `JwksStore`; T: "jku / embedded jwk headers are ignored" (attacker server saw 0 hits) |
| JWKS from configured URL, timeout, cache, cooldown | PASS | [jwks-store.mjs](services/shared/jwks-store.mjs) `#fetchRemote`, `#onKidMiss`; rejects JWKS with private fields |
| 401 vs 403 | PASS | `requireScope`; T: "missing scope -> 403" |

## Lifecycle
| Item | Result | Evidence |
|---|---|---|
| Access TTL ≤ 15 min | PASS | `ACCESS_TTL_S = 300` |
| Refresh opaque, hashed, rotated, reuse-detected, expiring | PASS | [refresh-store.mjs](services/auth/refresh-store.mjs) (Lua `consumeRefresh`, sha256 keys, TTLs); T: "replaying an old token revokes the family" |
| Revocation strategy + fail mode recorded | PASS | denylist on write routes **fail-closed** (503), watermark on all routes **fail-open**; see `denylist` / `jwtAuth` options |
| Logout revokes server-side state | PASS | `/auth/logout`, `/auth/logout-all`; T: logout-all test |

## Transport & client
| Item | Result | Evidence |
|---|---|---|
| HTTPS only / Secure cookies / HSTS | **GAP** | `secureCookies` is off for localhost; terminate TLS at a proxy and enable it. No HSTS set. |
| Refresh in HttpOnly SameSite cookie scoped to path | PASS | `setRefreshCookie`; T: login test asserts attributes |
| No tokens in URLs/logs | PASS | audit log records `sub`/`jti` only (orders/index.mjs); grep found no token logging |
| Proxy headers trusted only from known proxies | PASS (fixed) | was `trust proxy: true`, which let spoofed `X-Forwarded-For` bypass the login limiter; now `TRUST_PROXY` env, default off. T: "spoofed X-Forwarded-For does not reset the login rate limit" |
| Not exposed beyond need | PASS (dev) | services bind `HOST` (default `127.0.0.1`); Redis published on `127.0.0.1:6379` only |

## Known gaps / next steps
- **Single-region, single Redis**: Redis down => denylist routes return 503; add replicas/Sentinel.
- **Login limiter is per IP+username** and fixed-window; sliding window demo in `lab07/demo.mjs`.
- **User store is a toy** (plaintext demo passwords). Use argon2/bcrypt in real life.
- **Refresh has no grace window** in the Redis version (the in-memory lab04 version does).
- **Admin endpoints** rely on a shared header token; put them on a private network.
- Not implemented (stretch): DPoP/mTLS binding, introspection endpoint, Sentinel/cluster.
