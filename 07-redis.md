# 07 - Redis in the JWT Ecosystem

## Goal
Use Redis to add the stateful features that stateless JWTs lack, while keeping the hot path fast.

> **Reference implementation map**
>
> | Lab | Where it lives |
> |---|---|
> | 1 Refresh store | [services/auth/refresh-store.mjs](services/auth/refresh-store.mjs) |
> | 2 Denylist | `POST /auth/revoke` in [services/auth/app.mjs](services/auth/app.mjs); `denylist()` in [services/shared/auth-middleware.mjs](services/shared/auth-middleware.mjs) (used on write routes) |
> | 3 Watermark | `POST /auth/logout-all`; check inside `jwtAuth` |
> | 4 JWKS cache | [services/shared/jwks-store.mjs](services/shared/jwks-store.mjs) |
> | 5 Rate limit | [services/auth/rate-limit.mjs](services/auth/rate-limit.mjs) |
> | 6 Pub/Sub | `announce()` in auth admin routes; subscriber in `JwksStore.start()` |
> | Standalone demos | `node lab07/demo.mjs` (race on refresh consume, limiter race, sliding window, TTLs) |
>
> Redis key conventions and their TTLs are listed in the Lab 1 and Lab 3 sections below. Tests use **DB 15**, the demo uses **DB 14**, so they never touch your dev data.

## Concepts

### Adding state back, deliberately
Guides 01-06 were about removing state from the request path. But four real requirements need *some* shared, fast-changing state:

1. refresh tokens must be stored, rotated and revoked (guide 04);
2. sometimes an access token must die *before* `exp` (stolen token, admin "kill this session");
3. "log out everywhere" after a password change;
4. defending login against password guessing (rate limits need counters).

The goal is not to abandon JWTs. It is to add **just enough** state, in a store fast enough (sub-millisecond, in memory) that it barely touches latency, and shaped so it **cleans itself up**.

### Why Redis fits
- **In-memory key/value**: lookups take tens of microseconds plus a network hop.
- **TTL on every key**: Redis deletes keys when they expire. Revocation data only matters until the token it refers to would have expired anyway, so `EX <remaining token life>` makes the data set self-cleaning: it can never grow beyond what is currently relevant.
- **Atomic operations and Lua scripts**: check-and-update flows can't be interleaved by concurrent requests.
- **Pub/Sub**: cheap fan-out notifications ("keys rotated").

### Redis data types used here
| Type | Commands | Used for |
|---|---|---|
| String | `SET k v EX ttl`, `GET`, `EXISTS`, `INCR` | refresh records, denylist entries, watermarks, counters |
| Set | `SADD`, `SMEMBERS` | a user's session families |
| Sorted set | `ZADD`, `ZREMRANGEBYSCORE`, `ZCARD` | sliding-window rate limiting |
| Pub/Sub channel | `PUBLISH`, `SUBSCRIBE` | key-rotation nudges |

### Race conditions and atomicity (why Lua shows up)
Consider refresh-token rotation written as two separate commands:

```
request 1: GET rt:abc  → exists ┐
request 2: GET rt:abc  → exists │  both saw "valid, unused"
request 1: DEL rt:abc; issue rt' │
request 2: DEL rt:abc; issue rt''┘  → two live token chains from one token
```

That is a **TOCTOU** (time-of-check to time-of-use) bug: the state changed between checking and acting. A thief racing the real user would never be detected. Redis runs a Lua script as a single, uninterruptible step, so "check, delete, mark used" happens all-or-nothing. `node lab07/demo.mjs` fires 20 concurrent consumes at one token and gets exactly **one** `ok` and 19 `reuse`.

The same applies to the fixed-window limiter: `INCR` then `EXPIRE` as two calls can leave a counter **without** a TTL if the process dies in between, and that user is locked out forever. Doing both in one script fixes it.

### Three ways to kill access tokens early
| Technique | Redis state | Kills | Cost per request | Use for |
|---|---|---|---|---|
| Short TTL alone | none | everything, eventually (≤ TTL) | 0 | the default baseline |
| **Denylist by `jti`** | one key per revoked token | exactly one token | 1 `EXISTS` | "this specific token leaked" |
| **Watermark** (`valid-after`) | one key per user | every token of a user issued before *T* | 1 `GET` | logout-all, password change, role downgrade |

The denylist is precise but needs to know each token's `jti`. The watermark is blunt but needs no knowledge of which tokens exist. Its key is set with `EX = max access TTL`, because after that every older token has expired by itself.

### Fail-open vs fail-closed
Once a request depends on Redis, you must decide what happens when Redis is unreachable:
- **fail-open**: skip the check and allow. Availability wins; revocation is briefly unenforced (bounded by the access TTL).
- **fail-closed**: refuse (503). Safety wins; an outage of Redis becomes an outage of the route.

There's no universal right answer, so decide **per route** and write the decision down. The reference code fails open on reads and closed on writes (table at the end).

### Where Redis fits
| Use case | Redis feature | Where |
|---|---|---|
| Refresh-token store with rotation | `STRING` + TTL, Lua for atomicity | auth |
| Access-token revocation (denylist by `jti`) | `SET key EX ttl` / `EXISTS` | resource services |
| "Log out everywhere" / force re-login | per-user `valid-after` timestamp | resource services |
| JWKS persistence across restarts | `STRING` with TTL | resource services |
| Login & refresh rate limiting | `INCR` + `EXPIRE` in Lua | auth |
| Key rotation notifications | Pub/Sub | auth → services |
| Sessions list per user | `SET` of family ids | auth |

## Setup
`docker-compose.yml`:
```yaml
services:
  redis:
    image: redis:7
    ports: ["6379:6379"]
    command: ["redis-server", "--appendonly", "yes"]
```
```bash
docker compose up -d redis
docker compose exec redis redis-cli ping    # PONG
```

`shared/redis.mjs`:
```js
import Redis from 'ioredis';
export const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
```

## Lab 1: Refresh tokens in Redis (replace the Map from guide 04)

Key design:
- `rt:{sha256}` → JSON `{ userId, family }` with `EX` = refresh TTL
- `rt-used:{sha256}` → `family` with `EX` = refresh TTL (marks consumed tokens)
- `family-revoked:{family}` → `1` with `EX` = refresh TTL
- `user-families:{userId}` → `SET` of family ids

Atomic "consume" with a Lua script (check-and-mark must not race):
```js
const consume = redis.defineCommand('consumeRefresh', {
  numberOfKeys: 2,
  lua: `
    -- KEYS[1] = rt:{hash}, KEYS[2] = rt-used:{hash}; ARGV[1] = ttl seconds
    local v = redis.call('GET', KEYS[1])
    if not v then
      local fam = redis.call('GET', KEYS[2])        -- was it used before?
      if fam then return {'reuse', fam} end
      return {'invalid'}
    end
    redis.call('DEL', KEYS[1])
    redis.call('SET', KEYS[2], cjson.decode(v).family, 'EX', ARGV[1])
    return {'ok', v}
  `,
});
```
Use it:
```js
const h = hash(presented);
const [status, data] = await redis.consumeRefresh(`rt:${h}`, `rt-used:${h}`, REFRESH_TTL_S);
if (status === 'reuse') { await redis.set(`family-revoked:${data}`, 1, 'EX', REFRESH_TTL_S); /* 401 */ }
if (status === 'ok')    { const { userId, family } = JSON.parse(data); /* check family-revoked, issue new */ }
```
Exercise: also `SADD`/`SREM` the family in `user-families:{userId}` inside the script so "list my sessions" stays consistent.

Observe with `redis-cli`: `KEYS rt:*`, `TTL rt:<hash>`, `MONITOR` while refreshing.

## Lab 2: Access-token revocation (denylist)
Idea: access tokens are valid for 5-15 min. To revoke one early, store its `jti` until its natural expiry.

**Issuer side** (`POST /auth/revoke` or on logout):
```js
const ttl = payload.exp - Math.floor(Date.now() / 1000);
if (ttl > 0) await redis.set(`deny:jti:${payload.jti}`, 1, 'EX', ttl);
```

**Verifier side** (extend the middleware from 06, after signature verification):
```js
if (await redis.exists(`deny:jti:${payload.jti}`)) return res.status(401).json({ error: 'revoked' });
```

Cost: one Redis round-trip per request (sub-millisecond locally). You have traded pure statelessness for revocation. Decide per route: sensitive endpoints check the denylist, cheap ones don't.

Measure: add `console.time` around the check and run 1000 requests.

## Lab 3: "Log out everywhere" with a not-before watermark
Instead of denylisting every `jti`, store one value per user:
```js
await redis.set(`user:${sub}:valid-after`, Math.floor(Date.now() / 1000), 'EX', MAX_ACCESS_TTL_S);
```
Verifier rejects tokens where `payload.iat <= valid-after`. One key invalidates all existing tokens of that user. Use it for password change, account compromise, role downgrade.

Why `EX = MAX_ACCESS_TTL`? After that time every older token has expired anyway.

**A subtle trap (found while building the reference code):** `iat` has one-second resolution. If a user logs out everywhere at second *T* and logs in again in the same second, the new token has `iat == T` and would be rejected by a check of `iat <= valid-after`. The fix used in `signAccess`: when issuing, read the watermark and set `iat = max(now, watermark + 1)`. Old tokens (`iat <= T`) are rejected, new ones (`iat >= T+1`) pass, and the 5-second `clockTolerance` already covers the one-second "future" `iat`.

## Lab 4: JWKS cache in Redis
Goal: services survive auth outages and cold starts.

```js
async function loadJwks() {
  try {
    const r = await fetch(JWKS_URL, { signal: AbortSignal.timeout(2000) });
    const body = await r.text();
    await redis.set('jwks:auth', body, 'EX', 24 * 3600);          // stale-tolerant copy
    return JSON.parse(body);
  } catch {
    const cached = await redis.get('jwks:auth');
    if (cached) return JSON.parse(cached);
    throw new Error('no JWKS available');
  }
}
```
Build the verifier with `createLocalJWKSet(await loadJwks())` and refresh it on a timer and on `kid` miss (with a cooldown, guarded by `SET jwks:refresh-lock 1 NX EX 10` so only one instance refetches).

Test: stop auth, restart orders → still verifies, because Redis holds the last-known JWKS. `GET /readyz` on orders reports `{"jwks":"redis"}` when it started from the cache. (Automated in `test/acceptance.test.mjs`.)

The reference `JwksStore` also: refuses JWKS documents containing private fields (`d`, `p`, `q`, ...), enforces a `cooldownMs` between kid-miss refetches, and on a kid miss uses the `SET jwks:refresh-lock NX EX 10` lock so only one instance hits the auth service while the others re-read the Redis copy.

## Lab 5: Rate limiting login/refresh
Fixed window (simple):
```js
async function limit(key, max, windowS) {
  const n = await redis.incr(key);
  if (n === 1) await redis.expire(key, windowS);
  return n <= max;
}
// POST /auth/login
if (!(await limit(`rl:login:${req.ip}:${username}`, 5, 60))) return res.status(429).json({ error: 'slow down' });
```
Exercise: race condition between `INCR` and `EXPIRE`? Fix it with a Lua script or `SET NX EX` + `INCR`. Then implement a sliding window with a sorted set.

## Lab 6: Key rotation via Pub/Sub
Auth publishes on `jwks:rotated` after adding a key; services subscribe and refetch immediately instead of waiting for TTL.
```js
// auth
await redis.publish('jwks:rotated', JSON.stringify({ kid }));
// services (needs a dedicated subscriber connection)
const sub = redis.duplicate();
await sub.subscribe('jwks:rotated');
sub.on('message', () => refreshJwks());
```
Pub/Sub is fire-and-forget: keep the TTL-based refresh as the safety net.

## Failure modes chosen in the reference code
| Check | When Redis is down | Why |
|---|---|---|
| Watermark (all routes) | fail-open | availability of reads; damage window is one access-token TTL |
| Denylist (write routes) | **fail-closed** (503) | sensitive actions should not proceed if revocation can't be checked |
| Login/refresh rate limit | fail-open | Redis outage shouldn't lock everyone out |
| JWKS fallback copy | n/a | verification continues from the in-memory copy |

## Design trade-offs to discuss
- **Revocation vs stateless**: each Redis check adds latency + a dependency. Fail-open (allow if Redis down) or fail-closed (deny)? Pick per route sensitivity.
- **Redis as a SPOF**: use replicas/Sentinel/managed Redis; persist the refresh store (AOF) or users get logged out on a Redis wipe.
- **Data minimization**: store token hashes, `jti`s, not raw tokens.
- **Memory**: TTL on everything; check with `INFO memory` and `DBSIZE`.
- **Atomicity**: use Lua/`MULTI` for check-and-set flows.

## Checkpoint questions
- Why does each Redis key have a TTL equal to the token's remaining life?
- Why use a watermark instead of denylisting every token for "logout everywhere"?
- What happens to your API when Redis is down? What did you choose, and why?
- Why must refresh consumption be atomic?
