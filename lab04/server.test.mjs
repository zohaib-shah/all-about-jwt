import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from './server.mjs';
import { Client } from './cookie-client.mjs';

const mk = (opts) => {
  const s = createApp(opts).listen(0);
  return { s, c: new Client(`http://localhost:${s.address().port}`) };
};
const creds = { username: 'alice', password: 'pw' };

test('login sets HttpOnly cookie scoped to /auth; refresh rotates', async () => {
  const { s, c } = mk();
  const r = await c.json('/auth/login', creds);
  const sc = r.headers.getSetCookie()[0];
  assert.match(sc, /HttpOnly/); assert.match(sc, /Path=\/auth/); assert.match(sc, /SameSite=Strict/i);
  const before = c.cookies.rt;
  assert.equal((await c.json('/auth/refresh')).status, 200);
  assert.notEqual(c.cookies.rt, before);
  s.close();
});

test('reuse of an old refresh token revokes the family', async () => {
  const { s, c } = mk({ graceMs: 0 });
  await c.json('/auth/login', creds);
  const thief = c.clone();
  assert.equal((await c.json('/auth/refresh')).status, 200);
  assert.equal((await thief.json('/auth/refresh')).status, 401);
  assert.equal((await c.json('/auth/refresh')).status, 401);
  s.close();
});

test('grace window tolerates an immediate retry', async () => {
  const { s, c } = mk({ graceMs: 5000 });
  await c.json('/auth/login', creds);
  const tab2 = c.clone();
  assert.equal((await c.json('/auth/refresh')).status, 200);
  assert.equal((await tab2.json('/auth/refresh')).status, 200);
  s.close();
});

test('logout revokes; sessions list and revoke work', async () => {
  const { s, c } = mk();
  c.access = (await (await c.json('/auth/login', creds)).json()).access_token;
  const list = await (await c.fetch('/auth/sessions')).json();
  assert.equal(list.length, 1);
  assert.equal((await c.fetch(`/auth/sessions/${list[0].id}`, { method: 'DELETE' })).status, 204);
  assert.equal((await c.json('/auth/refresh')).status, 401);
  s.close();
});
