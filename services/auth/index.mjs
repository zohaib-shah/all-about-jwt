import { createApp } from './app.mjs';
import { createKeyRing } from './keys.mjs';
import { createRedis } from '../shared/redis.mjs';

const port = Number(process.env.PORT ?? 4000);
const host = process.env.HOST ?? '127.0.0.1'; // loopback only: admin routes + demo creds must not face a network
const issuer = process.env.ISSUER ?? `http://localhost:${port}`;
const keys = await createKeyRing({ file: process.env.KEYS_FILE ?? null }).init();
const redis = createRedis();

createApp({ issuer, keys, redis }).listen(port, host, () => console.log(`auth on :${port} (issuer ${issuer})`));
