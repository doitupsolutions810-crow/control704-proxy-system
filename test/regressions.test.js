'use strict';
// Explicit regression locks: one test per bug fixed in rounds 2 and 3.
// Round 2 bugs: R2-1..R2-8. Round 3 bugs: R3-1..R3-11.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider, loadConfigFromEnv, AuthError } = require('../src/auth/avroneProvider');
const { effectiveScopes } = require('../src/access/authorize');
const { toPrincipal } = require('../src/auth');
const { DatasetStore } = require('../src/datasets/store');
const { sign, claims, config, SECRET, ISSUER, AUDIENCE, startServer, raw, bearer, fakeClock } = require('./helpers');

const nowS = () => Math.floor(Date.now() / 1000);

// ---------------- Round 2 ----------------
test('R2-1: NaN/invalid clock skew must never make expired tokens verify', async () => {
  assert.throws(() => createAvroneProvider({ ...config, clockSkewSec: NaN }), /CLOCK_SKEW/);
  const env = { AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_SECRET: SECRET };
  assert.equal(loadConfigFromEnv({ ...env, AVRONE_CLOCK_SKEW_SEC: '' }).clockSkewSec, 30); // unset -> default
  for (const v of ['abc', 'NaN', '  ', 'Infinity', '1e3']) {
    assert.throws(() => loadConfigFromEnv({ ...env, AVRONE_CLOCK_SKEW_SEC: v }), /AVRONE_CLOCK_SKEW_SEC/, v);
  }
  const p = createAvroneProvider({ ...config, clockSkewSec: 0 });
  await assert.rejects(p.verify(sign(claims({ exp: 1 }))), /expired/);
});
test('R2-2: future iat and non-numeric nbf/iat rejected', async () => {
  const p = createAvroneProvider(config);
  await assert.rejects(p.verify(sign(claims({ iat: nowS() + 3600 }))), /future/);
  await assert.rejects(p.verify(sign(claims({ nbf: 'later' }))), /nbf/);
  await assert.rejects(p.verify(sign(claims({ iat: 'now' }))), /iat/);
});
test('R2-3: prototype role names never crash authorization', () => {
  for (const r of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
    assert.equal(effectiveScopes(toPrincipal({ sub: 's', roles: [r] }, 't')).size, 0);
  }
});
test('R2-3 (HTTP): prototype role -> 403 not 500', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { path: '/proxy/x', headers: bearer(sign(claims({ roles: ['__proto__'] }))) });
  assert.equal(r.status, 403);
});
test('R2-4: JSON body null -> 400 not 500', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(sign(claims({ roles: ['admin'] }))), 'content-type': 'application/json' }, body: 'null' });
  assert.equal(r.status, 400);
});
test('R2-5: oversized body -> clean 413 response (not connection reset)', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(sign(claims({ roles: ['admin'] }))), 'content-type': 'application/json' }, body: 'x'.repeat(100000) });
  assert.equal(r.status, 413);
  assert.equal(r.json.error, 'payload_too_large');
});
test('R2-6: malformed request target -> 400 and server keeps serving', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  assert.equal((await raw(s.port, { path: 'http://[' })).status, 400);
  assert.equal((await raw(s.port, { path: '/health' })).status, 200);
});
test('R2-7: revert cannot restore an endpoint now owned by another dataset', () => {
  const s = new DatasetStore();
  const r = s.override('Y', { endpoint: '/proxy/moved' }, { actor: 'a', reason: 'move y' });
  s.override('X', { endpoint: '/proxy/y' }, { actor: 'a', reason: 'x takes y' });
  assert.throws(() => s.revert(r.id, { actor: 'a' }), /now used by dataset X/);
  const eps = Object.values(s.all()).map((d) => d.endpoint);
  assert.equal(new Set(eps).size, 3);
});
test('R2-8: non-canonical base64url signature rejected (malleability)', async () => {
  const p = createAvroneProvider(config);
  const [h, pl, sg] = sign(claims()).split('.');
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const tweaked = sg.slice(0, -1) + A[A.indexOf(sg.at(-1)) ^ 1];
  await assert.rejects(p.verify(`${h}.${pl}.${tweaked}`), /Non-canonical/);
});

// ---------------- Round 3 ----------------
test('R3-1: blank / whitespace-only secret rejected', () => {
  for (const secret of [' '.repeat(40), '\t'.repeat(40), '\n'.repeat(64), ' \u00a0'.repeat(20)]) {
    assert.throws(() => createAvroneProvider({ ...config, secret }), /blank|whitespace|variety/);
  }
});
test('R3-2: secret with leading/trailing whitespace (copy-paste newline) rejected', () => {
  assert.throws(() => createAvroneProvider({ ...config, secret: `${SECRET}\n` }), /whitespace/);
  assert.throws(() => createAvroneProvider({ ...config, secret: ` ${SECRET}` }), /whitespace/);
});
test('R3-2b: low-variety secret ("aaaa...") rejected', () => {
  assert.throws(() => createAvroneProvider({ ...config, secret: 'a'.repeat(64) }), /variety/);
  assert.throws(() => createAvroneProvider({ ...config, secret: 'ab'.repeat(32) }), /variety/);
});
test('R3-3: PRIVATE key PEM in AVRONE_JWT_PUBLIC_KEY rejected', () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  for (const type of ['pkcs8', 'pkcs1']) {
    assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: privateKey.export({ type, format: 'pem' }) }), /PRIVATE key/);
  }
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
  assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: ec.export({ type: 'sec1', format: 'pem' }) }), /PRIVATE key/);
});
test('R3-4: malformed PEM gives a clear config error (not raw OpenSSL text)', () => {
  assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----' }), /not a valid PEM/);
});
test('R3-5: mutating the config object after creation cannot change trusted keys/issuer', async () => {
  const cfg = { ...config };
  const p = createAvroneProvider(cfg);
  const attacker = 'attacker-controlled-secret-0123456789abcdef';
  cfg.secret = attacker; cfg.issuer = 'evil'; cfg.audience = 'evil'; cfg.clockSkewSec = 300;
  await assert.rejects(p.verify(sign(claims(), { secret: attacker })), /Invalid signature/);
  await assert.rejects(p.verify(sign(claims({ iss: 'evil', aud: 'evil' }))), /issuer/);
  assert.ok(await p.verify(sign(claims())));
});
test('R3-6: fractional exp is enforced with sub-second precision', async () => {
  const clock = fakeClock(1_800_000_000_000);
  const p = createAvroneProvider({ ...config, now: clock.now });
  const tok = sign(claims({ iat: 1_799_999_990, exp: 1_800_000_000.5 }));
  clock.set(1_800_000_000_400); assert.ok(await p.verify(tok));
  clock.set(1_800_000_000_500); await assert.rejects(p.verify(tok), /expired/);
  clock.set(1_800_000_000_900); await assert.rejects(p.verify(tok), /expired/); // was accepted before fix
});
test('R3-7: zero-width / bidi / format chars in sub rejected', async () => {
  const p = createAvroneProvider(config);
  for (const sub of ['admin\u200b', 'evil\u202enimda', '\ufeffadmin', 'a\u2066b', 'a\u2028b', 'a\u00adb', 'a\u0085b']) {
    await assert.rejects(p.verify(sign(claims({ sub }))), /sub/, JSON.stringify(sub));
  }
});
test('R3-8: bidi/control chars in reason and metadata values rejected', () => {
  const s = new DatasetStore();
  assert.throws(() => s.override('X', { enabled: false }, { actor: 'a', reason: 'ok \u202e reversed' }), /control or bidi/);
  const metaErr = (e) => /Invalid value for metadata/.test((e.details || []).join(' '));
  assert.throws(() => s.override('X', { metadata: { a: 'x\u202ey' } }, { actor: 'a', reason: 'meta' }), metaErr);
  assert.throws(() => s.override('X', { metadata: { a: 'x\u0000y' } }, { actor: 'a', reason: 'meta' }), metaErr);
});
test('R3-9: override history is bounded (default 1000)', () => {
  const s = new DatasetStore();
  for (let i = 0; i < 2500; i++) s.override('X', { rateLimitPerMinute: (i % 100) + 1 }, { actor: 'a', reason: 'growth' });
  assert.equal(s.listOverrides().length, 1000);
  assert.equal(s.compacted, 1500);
});
test('R3-10: server has finite timeouts and a connection cap', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  assert.ok(s.server.requestTimeout > 0 && s.server.requestTimeout <= 30000);
  assert.ok(s.server.headersTimeout > 0 && s.server.headersTimeout <= s.server.requestTimeout);
  assert.ok(Number.isInteger(s.server.maxConnections) && s.server.maxConnections > 0);
});
test('R3-11: invalid / overlong UTF-8 body rejected instead of stored as U+FFFD', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const body = Buffer.concat([Buffer.from('{"patch":{"metadata":{"a":"'), Buffer.from([0xc0, 0xaf]), Buffer.from('"}},"reason":"overlong utf8"}')]);
  const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(sign(claims({ roles: ['admin'] }))), 'content-type': 'application/json' }, body });
  assert.equal(r.status, 400);
  assert.match(r.json.message, /UTF-8/);
});
test('R3-12: >100 headers (where Node would silently truncate) -> 431, so a hidden 2nd Authorization cannot slip through', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const headers = { authorization: `Bearer ${sign(claims({ roles: ['admin'] }))}` };
  for (let i = 0; i < 120; i++) headers[`x-p${i}`] = '1';
  const r = await raw(s.port, { path: '/admin/audit', headers });
  assert.equal(r.status, 431);
  assert.ok(AuthError);
});
