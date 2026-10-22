import { createLocalJWKSet } from 'jose';

const NO_MATCH = 'ERR_JWKS_NO_MATCHING_KEY';
const PRIVATE_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

/**
 * Keeps a local copy of the issuer's JWKS.
 *  - fetches from the configured URL only (never from token headers: jku/x5u/jwk are ignored)
 *  - persists the last good copy to Redis so cold starts survive an auth outage
 *  - refreshes on a timer, on `jwks:rotated` pub/sub, and (rate-limited) on unknown kid
 */
export class JwksStore {
  #local = null;
  #lastFetch = 0;
  #timer = null;
  #sub = null;
  ready = false;
  source = 'none'; // 'remote' | 'redis'

  constructor({ jwksUrl, redis = null, refreshMs = 5 * 60_000, cooldownMs = 5_000,
                fetchTimeoutMs = 2_000, cacheKey = 'jwks:auth', cacheTtlS = 24 * 3600 }) {
    Object.assign(this, { jwksUrl, redis, refreshMs, cooldownMs, fetchTimeoutMs, cacheKey, cacheTtlS });
    this.getKey = this.getKey.bind(this);
  }

  async start() {
    await this.refresh().catch((e) => console.warn('[jwks] initial load failed:', e.message));
    this.#timer = setInterval(() => this.refresh().catch(() => {}), this.refreshMs);
    this.#timer.unref();
    if (this.redis) {
      this.#sub = this.redis.duplicate();
      this.#sub.on('error', () => {});
      await this.#sub.subscribe('jwks:rotated').catch(() => {});
      this.#sub.on('message', () => this.refresh().catch(() => {}));
    }
    return this;
  }

  async stop() {
    clearInterval(this.#timer);
    await this.#sub?.quit().catch(() => {});
  }

  #install(jwks, source) {
    if (!jwks || !Array.isArray(jwks.keys)) throw new Error('malformed JWKS');
    if (jwks.keys.some((k) => PRIVATE_FIELDS.some((f) => f in k))) throw new Error('JWKS contains private key material!');
    this.#local = createLocalJWKSet(jwks);
    this.ready = true;
    this.source = source;
  }

  async #fetchRemote() {
    const res = await fetch(this.jwksUrl, { signal: AbortSignal.timeout(this.fetchTimeoutMs) });
    if (!res.ok) throw new Error(`JWKS fetch HTTP ${res.status}`);
    return res.text();
  }

  async refresh() {
    this.#lastFetch = Date.now();
    try {
      const body = await this.#fetchRemote();
      this.#install(JSON.parse(body), 'remote');
      await this.redis?.set(this.cacheKey, body, 'EX', this.cacheTtlS).catch(() => {});
    } catch (err) {
      const cached = await this.redis?.get(this.cacheKey).catch(() => null);
      if (!cached) throw err;
      this.#install(JSON.parse(cached), 'redis'); // stale-tolerant fallback
    }
  }

  async #onKidMiss() {
    if (Date.now() - this.#lastFetch < this.cooldownMs) return; // protect the auth service
    const locked = !this.redis || (await this.redis.set('jwks:refresh-lock', '1', 'EX', 10, 'NX').catch(() => 'OK'));
    if (locked) await this.refresh().catch(() => {});
    else {
      await new Promise((r) => setTimeout(r, 250)); // another instance is refetching; read its result
      const cached = await this.redis.get(this.cacheKey).catch(() => null);
      if (cached) this.#install(JSON.parse(cached), 'redis');
    }
  }

  /** key resolver for jose's jwtVerify(token, store.getKey, opts) */
  async getKey(header, token) {
    if (!this.#local) {
      await this.refresh().catch(() => {});
      if (!this.#local) throw Object.assign(new Error('JWKS unavailable'), { code: 'ERR_JWKS_UNAVAILABLE' });
    }
    try {
      return await this.#local(header, token);
    } catch (e) {
      if (e.code !== NO_MATCH) throw e;
      await this.#onKidMiss();
      return this.#local(header, token);
    }
  }
}
