import Redis from 'ioredis';

export function createRedis(url = process.env.REDIS_URL ?? 'redis://localhost:6379', opts = {}) {
  const r = new Redis(url, { maxRetriesPerRequest: 1, ...opts });
  r.on('error', (e) => { if (process.env.DEBUG_REDIS) console.error('[redis]', e.message); });
  return r;
}
