// Client that refreshes transparently on 401, single-flight (5 parallel calls -> 1 refresh)
import { createApp } from './server.mjs';
import { Client } from './cookie-client.mjs';

const server = createApp({ accessTtl: '2s' }).listen(0);
const c = new Client(`http://localhost:${server.address().port}`);

let refreshes = 0, inflight = null;
async function refresh() {
  inflight ??= (async () => {
    refreshes++;
    const r = await c.json('/auth/refresh');
    if (!r.ok) throw new Error('refresh failed ' + r.status);
    c.access = (await r.json()).access_token;
  })().finally(() => { inflight = null; });
  return inflight;
}
async function api(path) {
  let r = await c.fetch(path);
  if (r.status === 401) { await refresh(); r = await c.fetch(path); }
  return r;
}

c.access = (await (await c.json('/auth/login', { username: 'alice', password: 'pw' })).json()).access_token;
console.log('me:', (await (await api('/api/me')).json()).sub);

await new Promise((r) => setTimeout(r, 2500)); // access token expires
const results = await Promise.all(Array.from({ length: 5 }, () => api('/api/me')));
console.log('5 parallel calls after expiry ->', results.map((r) => r.status), '| refresh calls:', refreshes);
server.close();
