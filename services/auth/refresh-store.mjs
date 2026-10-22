import { createHash, randomBytes } from 'node:crypto';

const hash = (t) => createHash('sha256').update(t).digest('hex');

/**
 * Redis layout (all keys carry a TTL):
 *   rt:{sha256}              JSON {userId, family}      live refresh token
 *   rt-used:{sha256}         family                     consumed token (reuse detection)
 *   family-revoked:{family}  1
 *   user-families:{userId}   SET of families
 * Only hashes are stored, never raw tokens.
 */
export function createRefreshStore(redis, ttlS) {
  redis.defineCommand('consumeRefresh', {
    numberOfKeys: 2,
    lua: `
      local v = redis.call('GET', KEYS[1])
      if not v then
        local fam = redis.call('GET', KEYS[2])
        if fam then return {'reuse', fam} end
        return {'invalid'}
      end
      redis.call('DEL', KEYS[1])
      local rec = cjson.decode(v)
      redis.call('SET', KEYS[2], rec.family, 'EX', ARGV[1])
      return {'ok', v}
    `,
  });

  return {
    async issue(userId, family) {
      const token = randomBytes(32).toString('base64url');
      await redis.multi()
        .set(`rt:${hash(token)}`, JSON.stringify({ userId, family }), 'EX', ttlS)
        .sadd(`user-families:${userId}`, family)
        .expire(`user-families:${userId}`, ttlS)
        .exec();
      return token;
    },
    /** atomically consume -> {status:'ok', userId, family} | {status:'reuse', family} | {status:'invalid'} */
    async consume(token) {
      const h = hash(token);
      const [status, data] = await redis.consumeRefresh(`rt:${h}`, `rt-used:${h}`, ttlS);
      if (status === 'ok') return { status, ...JSON.parse(data) };
      if (status === 'reuse') return { status, family: data };
      return { status };
    },
    revokeFamily: (family) => redis.set(`family-revoked:${family}`, 1, 'EX', ttlS),
    isFamilyRevoked: async (family) => (await redis.exists(`family-revoked:${family}`)) === 1,
    async revokeAllForUser(userId) {
      const fams = await redis.smembers(`user-families:${userId}`);
      if (fams.length) await redis.multi(fams.map((f) => ['set', `family-revoked:${f}`, 1, 'EX', ttlS])).exec();
      return fams.length;
    },
    async familiesFor(userId) {
      const fams = await redis.smembers(`user-families:${userId}`);
      const alive = [];
      for (const f of fams) if (!(await this.isFamilyRevoked(f))) alive.push(f);
      return alive;
    },
  };
}
