'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { sign, claims, config } = require('./helpers');

const provider = createAvroneProvider(config);

test('accepts a valid HS256 token', async () => {
  const c = await provider.verify(sign(claims({ roles: ['viewer'] })));
  assert.equal(c.sub, 'user-1');
});

test('rejects bad signature', async () => {
  await assert.rejects(provider.verify(sign(claims(), { secret: 'x'.repeat(40) })), /Invalid signature/);
});

test('rejects alg none', async () => {
  await assert.rejects(provider.verify(sign(claims(), { alg: 'none' })), /Algorithm not allowed/);
});

test('rejects RS256 header when only a secret is configured (alg confusion)', async () => {
  await assert.rejects(provider.verify(sign(claims(), { alg: 'RS256' })), /Algorithm not allowed/);
});

test('rejects expired, wrong issuer, wrong audience, missing sub, malformed', async () => {
  const now = Math.floor(Date.now() / 1000);
  await assert.rejects(provider.verify(sign(claims({ exp: now - 10 }))), /expired/);
  await assert.rejects(provider.verify(sign(claims({ iss: 'evil' }))), /issuer/);
  await assert.rejects(provider.verify(sign(claims({ aud: 'other' }))), /audience/);
  await assert.rejects(provider.verify(sign(claims({ sub: '' }))), /sub/);
  await assert.rejects(provider.verify(sign(claims({ nbf: now + 600 }))), /not yet valid/);
  await assert.rejects(provider.verify('abc'), /three segments/);
  await assert.rejects(provider.verify(''), /Missing/);
});

test('config validation: requires issuer, audience, strong key', () => {
  assert.throws(() => createAvroneProvider({ ...config, issuer: '' }), /AVRONE_ISSUER/);
  assert.throws(() => createAvroneProvider({ ...config, audience: '' }), /AVRONE_AUDIENCE/);
  assert.throws(() => createAvroneProvider({ ...config, secret: '' }), /AVRONE_JWT_SECRET/);
  assert.throws(() => createAvroneProvider({ ...config, secret: 'short' }), /at least 32/);
});

test('RS256 with public key', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const p = createAvroneProvider({ ...config, secret: '', publicKey: publicKey.export({ type: 'spki', format: 'pem' }) });
  const h = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(claims())).toString('base64url');
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${body}`), privateKey).toString('base64url');
  assert.equal((await p.verify(`${h}.${body}.${sig}`)).sub, 'user-1');
  // HS256 forged with the public key as secret must fail
  await assert.rejects(p.verify(sign(claims(), { secret: publicKey.export({ type: 'spki', format: 'pem' }) })), /Algorithm not allowed/);
});
