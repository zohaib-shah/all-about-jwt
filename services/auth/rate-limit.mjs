/** Fixed-window limiter; INCR+EXPIRE run atomically in Lua (no key left without a TTL). */
export function createLimiter(redis) {
  redis.defineCommand('rlIncr', {
    numberOfKeys: 1,
    lua: `local n = redis.call('INCR', KEYS[1])
          if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
          return n`,
  });
  return async function allow(key, max, windowS) {
    try { return (await redis.rlIncr(key, windowS)) <= max; }
    catch { return true; } // fail-open on limiter outage; flip for stricter policy
  };
}
