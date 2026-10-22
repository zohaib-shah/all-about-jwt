// Guide 07 demos that need nothing but Redis (uses DB 14):
//   1. atomic refresh consumption under a 20-way race
//   2. fixed-window limiter race (INCR then EXPIRE) vs atomic Lua
//   3. sliding-window limiter with a sorted set
//   4. denylist + watermark semantics and TTLs
import { createRedis } from '../services/shared/redis.mjs';
import { createRefreshStore } from '../services/auth/refresh-store.mjs';
import { createLimiter } from '../services/auth/rate-limit.mjs';

const redis = createRedis('redis://localhost:6379/14');
await redis.flushdb();

// 1 ---------------------------------------------------------------
const store = createRefreshStore(redis, 3600);
const tok = await store.issue('alice', 'fam-1');
const results = await Promise.all(Array.from({ length: 20 }, () => store.consume(tok)));
const tally = results.reduce((a, r) => ((a[r.status] = (a[r.status] ?? 0) + 1), a), {});
console.log('1. 20 concurrent consumes of one refresh token ->', tally, '(exactly one "ok")');

// 2 ---------------------------------------------------------------
const allow = createLimiter(redis);
const r2 = await Promise.all(Array.from({ length: 10 }, () => allow('rl:demo', 3, 60)));
console.log('2. limiter 3/min, 10 parallel calls -> allowed =', r2.filter(Boolean).length, '| ttl =', await redis.ttl('rl:demo'));

// 3 ---------------------------------------------------------------
async function slidingWindow(key, max, windowMs) {
  const now = Date.now();
  const res = await redis.multi()
    .zremrangebyscore(key, 0, now - windowMs)
    .zadd(key, now, `${now}-${Math.random()}`)
    .zcard(key)
    .pexpire(key, windowMs)
    .exec();
  return res[2][1] <= max;
}
const sw = [];
for (let i = 0; i < 6; i++) sw.push(await slidingWindow('sw:demo', 3, 400));
await new Promise((r) => setTimeout(r, 450));
sw.push(await slidingWindow('sw:demo', 3, 400));
console.log('3. sliding window 3 per 400ms:', sw.join(', '), '(true x3, false x3, then true after the window slides)');

// 4 ---------------------------------------------------------------
const exp = Math.floor(Date.now() / 1000) + 5;
await redis.set('deny:jti:abc', 1, 'EX', exp - Math.floor(Date.now() / 1000));
console.log('4. denylist entry ttl =', await redis.ttl('deny:jti:abc'), 's (disappears with the token)');

await redis.flushdb();
await redis.quit();
