import { decodeJwt, decodeProtectedHeader } from 'jose';
const t = process.argv[2];
console.log('header ', decodeProtectedHeader(t));
console.log('payload', decodeJwt(t));
