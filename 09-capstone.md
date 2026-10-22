# 09 - Capstone: Production-Shaped Auth System

## Goal
Combine everything into one system and prove it with an automated acceptance suite.

## Deliverables

### Services
1. **auth** (:4000)
   - `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/logout-all`
   - `POST /oauth/token` (client_credentials) for service tokens
   - `GET /.well-known/jwks.json` with `Cache-Control`
   - ES256 keys, `kid` thumbprints, scripted rotation
   - Refresh tokens in Redis: hashed, rotated, reuse-detecting
   - Rate-limited login and refresh
2. **orders** (:4001) and **billing** (:4002)
   - Shared middleware: JWKS verification, pinned `alg/iss/aud`, scope checks
   - Denylist (`jti`) check on write routes
   - Watermark (`valid-after`) check on all routes
   - JWKS persisted to Redis for cold-start resilience
   - Orders calls billing using a service token
3. **redis** via docker compose

### Project structure (as built)
```
services/
  shared/{auth-middleware,jwks-store,service-token,redis}.mjs
  auth/{index,app,keys,refresh-store,rate-limit}.mjs
  orders/index.mjs
  billing/index.mjs
test/{acceptance.test.mjs,middleware.test.mjs,cookie-client.mjs}
docker-compose.yml
REVIEW.md
```

### Run it
```bash
docker compose up -d redis
npm test                          # 36 tests across labs 02, 04, the middleware and the capstone
npm run auth & npm run orders & npm run billing &
npm run attacks
```
The acceptance suite spawns the three services itself on :4000-4002 with `KEYS_FILE` in a temp dir and Redis DB 15, so stop any manually started copies first.

## Acceptance suite (`node --test test/acceptance.test.mjs`)

Write tests, then make them pass. Each is a required behaviour. **The reference suite in [test/acceptance.test.mjs](test/acceptance.test.mjs) covers every group below (14 tests); build your own first, then compare.**

**Authentication**
- [ ] Login returns access token + sets HttpOnly refresh cookie
- [ ] Orders accepts an `orders-api` token, rejects `billing-api`, expired, tampered, and `alg=none` tokens
- [ ] Missing scope → 403, missing token → 401

**Refresh**
- [ ] Refresh returns new access token and rotates cookie
- [ ] Replaying an old refresh token → 401 and the whole family is revoked
- [ ] 6th login attempt within a minute → 429, even when each attempt spoofs a different `X-Forwarded-For`

**Revocation**
- [ ] After `POST /auth/revoke` for a token's `jti`, a write route returns 401 immediately
- [ ] After `logout-all`, all earlier access tokens for that user are rejected on every service
- [ ] Redis keys for the above carry a TTL (`TTL key > 0`)

**JWKS & rotation**
- [ ] Rotation (add → activate → retire) under constant load produces **zero** failed requests
- [ ] Orders restarted while auth is down still verifies tokens (JWKS from Redis)
- [ ] A forged token with a `jku` pointing at an attacker server is rejected and no request reaches the attacker

**Service-to-service**
- [ ] Orders → billing call succeeds with a client-credentials token and fails with a user token lacking the scope

## Stretch goals
- ~~OIDC-style discovery document~~ (done: `/.well-known/openid-configuration`).
- ~~Persist the key ring~~ (done, mode 0600 via `KEYS_FILE`). Still open: encrypt it at rest with a passphrase from env or use a KMS.
- Redis Sentinel or cluster, with a fail-closed/fail-open switch per route and tests for both.
- Token introspection endpoint (RFC 7662) and compare latency against local verification.
- Add DPoP or mTLS-bound tokens to prevent replay of stolen access tokens (research task; write a one-page design note).
- Observability: counters for verifications, failures by reason (`e.code`), JWKS refetches, denylist hits.

## Self-review
Run the checklist from [08](08-security-pitfalls.md) against your code and write `REVIEW.md` listing each item as pass/fail with the file and line that proves it. The reference answer, including the known gaps (no HTTPS/HSTS, toy user store, single Redis), is [REVIEW.md](REVIEW.md).

## Wrap-up questions
1. Draw the full request flow for "user logs in, calls orders, orders calls billing, user logs out everywhere".
2. Which components are stateless and which are stateful? What happens when each fails?
3. If you had to choose between HS256 and ES256 for a team of 12 microservices, how would you justify it in one paragraph?
4. What is the weakest part of your design now? How would you attack it?
