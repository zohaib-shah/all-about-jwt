// Simulate refresh-token theft and reuse detection
import { createApp } from './server.mjs';
import { Client } from './cookie-client.mjs';

const server = createApp({ graceMs: 0 }).listen(0);
const legit = new Client(`http://localhost:${server.address().port}`);
await legit.json('/auth/login', { username: 'alice', password: 'pw' });

const attacker = legit.clone(); // copy of the cookie jar: token A
console.log('legit refresh (A->B)      :', (await legit.json('/auth/refresh')).status);
console.log('attacker replays A        :', (await attacker.json('/auth/refresh')).status, '(reuse detected, family revoked)');
console.log('legit refresh again (B)   :', (await legit.json('/auth/refresh')).status, '(safe failure: re-login)');
server.close();
