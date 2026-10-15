'use strict';

const { randomBytes, scrypt: scryptCallback, timingSafeEqual, createHash } = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(scryptCallback);

const emailAddress = (value) => {
  const email = String(value || '').trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
  return email;
};
async function passwordHash(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) throw Object.assign(new Error('Password must be 12 to 128 characters.'), { status: 400 });
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}
async function passwordMatches(password, encoded) {
  const [algorithm, saltPart, keyPart] = String(encoded || '').split('$');
  if (algorithm !== 'scrypt' || !saltPart || !keyPart || typeof password !== 'string') return false;
  const expected = Buffer.from(keyPart, 'base64url');
  const actual = await scrypt(password.slice(0, 128), Buffer.from(saltPart, 'base64url'), expected.length, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
const newSessionToken = () => randomBytes(32).toString('base64url');
const hashToken = (token) => createHash('sha256').update(String(token)).digest('hex');

module.exports = { emailAddress, passwordHash, passwordMatches, newSessionToken, hashToken };
