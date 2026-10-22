import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from './server.mjs';

const server = createApp().listen(0);
const base = `http://localhost:${server.address().port}`;
test.after(() => server.close());

const login = async (u) => (await (await fetch(base + '/login', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ username: u, password: 'pw' }),
})).json()).access_token;
const get = (path, t) => fetch(base + path, { headers: t ? { authorization: `Bearer ${t}` } : {} });

test('no token -> 401', async () => assert.equal((await get('/me')).status, 401));
test('bad login -> 401', async () => {
  const r = await fetch(base + '/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"username":"alice","password":"x"}' });
  assert.equal(r.status, 401);
});
test('alice /admin -> 200', async () => assert.equal((await get('/admin', await login('alice'))).status, 200));
test('bob /admin -> 403', async () => assert.equal((await get('/admin', await login('bob'))).status, 403));
test('garbage token -> 401', async () => assert.equal((await get('/me', 'a.b.c')).status, 401));
