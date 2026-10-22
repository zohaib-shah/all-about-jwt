import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
const privatePem = await exportPKCS8(privateKey);
const publicPem = await exportSPKI(publicKey);

await writeFile(fileURLToPath(new URL('keys/private.pem', import.meta.url)), privatePem);
await writeFile(fileURLToPath(new URL('keys/public.pem', import.meta.url)), publicPem);

console.log('Saved private.pem and public.pem');
